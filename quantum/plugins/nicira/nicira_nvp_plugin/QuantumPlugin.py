# Copyright 2012 Nicira, Inc.
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless equired by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# @author: Somik Behera, Nicira Networks, Inc.
# @author: Brad Hall, Nicira Networks, Inc.
# @author: Aaron Rosen, Nicira Networks, Inc.


import hashlib
import logging

import webob.exc

# FIXME(salvatore-orlando): get rid of relative imports
from common import config
from nvp_plugin_version import PLUGIN_VERSION
from sqlalchemy.orm import exc as sa_exc

from quantum.api.v2 import attributes
from quantum.api.v2 import base
from quantum.common import constants
from quantum.common import exceptions as q_exc
from quantum.common import topics
from quantum.common import utils
from quantum.db import api as db
from quantum.db import db_base_plugin_v2
from quantum.db import dhcp_rpc_base
from quantum.db import l3_db
from quantum.db import models_v2
from quantum.db import securitygroups_db
from quantum.db import portsecurity_db
from quantum.extensions import l3
from quantum.extensions import portsecurity as psec
from quantum.extensions import securitygroup as ext_sg
from quantum.extensions import l3
from quantum.extensions import nvp_qos as ext_qos
from quantum.extensions import providernet as pnet
from quantum.openstack.common import cfg
from quantum.openstack.common import context
from quantum.openstack.common import rpc

from quantum.openstack.common.rpc import dispatcher
from quantum import policy
from quantum.plugins.nicira.nicira_nvp_plugin.common import (exceptions
                                                             as nvp_exc)
from quantum.plugins.nicira.nicira_nvp_plugin import nvp_cluster
from quantum.plugins.nicira.nicira_nvp_plugin import nicira_db
from quantum.plugins.nicira.nicira_nvp_plugin import nicira_qos_db as qos

import NvpApiClient
import nvplib


LOG = logging.getLogger("QuantumPlugin")


# Provider network extension - allowed network types for the NVP Plugin
class NetworkTypes:
    """ Allowed provider network types for the NVP Plugin """
    STT = 'stt'
    GRE = 'gre'
    FLAT = 'flat'
    VLAN = 'vlan'


def parse_config():
    """Parse the supplied plugin configuration.

    :param config: a ConfigParser() object encapsulating nvp.ini.
    :returns: A tuple: (clusters, plugin_config). 'clusters' is a list of
        NVPCluster objects, 'plugin_config' is a dictionary with plugin
        parameters (currently only 'max_lp_per_bridged_ls').
    """
    if (cfg.CONF.PORTSECURITY.require_port_security not in
        ['False', 'both', 'private', 'shared', False]):
        LOG.error("require_port_security setting invalid on server!")
        raise psec.PortSecurityInvalidConfiguration()
    db_options = {"sql_connection": cfg.CONF.DATABASE.sql_connection}
    db_options.update({'base': models_v2.model_base.BASEV2})
    sql_max_retries = cfg.CONF.DATABASE.sql_max_retries
    db_options.update({"sql_max_retries": sql_max_retries})
    reconnect_interval = cfg.CONF.DATABASE.reconnect_interval
    db_options.update({"reconnect_interval": reconnect_interval})
    nvp_options = cfg.CONF.NVP
    nvp_conf = config.ClusterConfigOptions(cfg.CONF)
    cluster_names = config.register_cluster_groups(nvp_conf)
    nvp_conf.log_opt_values(LOG, logging.DEBUG)

    clusters_options = []
    for cluster_name in cluster_names:
        clusters_options.append(
            {'name': cluster_name,
             'default_tz_uuid':
             nvp_conf[cluster_name].default_tz_uuid,
             'nvp_cluster_uuid':
             nvp_conf[cluster_name].nvp_cluster_uuid,
             'nova_zone_id':
             nvp_conf[cluster_name].nova_zone_id,
             'nvp_controller_connection':
             nvp_conf[cluster_name].nvp_controller_connection,
             'default_l3_gw_uuid':
             nvp_conf[cluster_name].default_l3_gw_uuid})
    LOG.debug("cluster options:%s", clusters_options)
    return db_options, nvp_options, clusters_options


class NVPRpcCallbacks(dhcp_rpc_base.DhcpRpcCallbackMixin):

    # Set RPC API version to 1.0 by default.
    RPC_API_VERSION = '1.0'

    def __init__(self, rpc_context):
        self.rpc_context = rpc_context

    def create_rpc_dispatcher(self):
        '''Get the rpc dispatcher for this manager.

        If a manager would like to set an rpc API version, or support more than
        one class as the target of rpc messages, override this method.
        '''
        return dispatcher.RpcDispatcher([self])


class NvpPluginV2(db_base_plugin_v2.QuantumDbPluginV2,
                  securitygroups_db.SecurityGroupDbMixin,
                  portsecurity_db.PortSecurityDbMixin,
                  qos.NVPQoSDbMixin,
                  l3_db.L3_NAT_db_mixin):
    """
    NvpPluginV2 is a Quantum plugin that provides L2 Virtual Network
    functionality using NVP.
    """

    __native_bulk_support = True

    supported_extension_aliases = ["provider", "security-group", "router",
                                   "port-security", "nvp-qos"]
    sg_supported_protocols = ['tcp', 'udp', 'icmp']
    sg_supported_ethertypes = ['IPv4', 'IPv6']

    # Map nova zones to cluster for easy retrieval
    novazone_cluster_map = {}
    # Default controller cluster (to be used when nova zone id is unspecified)
    default_cluster = None

    def __init__(self, loglevel=None):
        if loglevel:
            logging.basicConfig(level=loglevel)
            nvplib.LOG.setLevel(loglevel)
            NvpApiClient.LOG.setLevel(loglevel)

        # Routines for managing logical ports in NVP
        self._port_drivers = {
            'create': {l3_db.DEVICE_OWNER_ROUTER_GW:
                       self._nvp_create_ext_gw_port,
                       l3_db.DEVICE_OWNER_FLOATINGIP:
                       self._nvp_create_fip_port,
                       'default': self._nvp_create_port},
            'delete': {l3_db.DEVICE_OWNER_ROUTER_GW:
                       self._nvp_delete_ext_gw_port,
                       l3_db.DEVICE_OWNER_FLOATINGIP:
                       self._nvp_delete_fip_port,
                       'default': self._nvp_delete_port}
        }

        self.db_opts, self.nvp_opts, self.clusters_opts = parse_config()
        self.clusters = {}
        # Will store the first cluster in case is needed for default
        # cluster assignment
        first_cluster = None
        for c_opts in self.clusters_opts:
            # Password is guaranteed to be the same across all controllers
            # in the same NVP cluster.
            cluster = nvp_cluster.NVPCluster(c_opts['name'])
            try:
                for controller_connection in c_opts['nvp_controller_connection']:
                    args = controller_connection.split(':')
                    try:
                        args.extend([c_opts['default_tz_uuid'],
                                     c_opts['nvp_cluster_uuid'],
                                     c_opts['nova_zone_id'],
                                     c_opts['default_l3_gw_uuid']])
                        cluster.add_controller(*args)
                    except Exception:
                        LOG.exception("Invalid connection parameters for "
                                      "controller %s in cluster %s",
                                      controller_connection,
                                      c_opts['name'])
                        raise nvp_exc.NvpInvalidConnection(
                            conn_params=controller_connection)
            except TypeError:
                msg = _("No controller connection specified in cluster "
                        "configuration. Please ensure at least a value for "
                        "'nvp_controller_connection' is specified in the "
                        "[CLUSTER:%s] section") % c_opts['name']
                LOG.exception(msg)
                raise nvp_exc.NvpPluginException(err_desc=msg)

            api_providers = [(x['ip'], x['port'], True)
                             for x in cluster.controllers]
            cluster.api_client = NvpApiClient.NVPApiHelper(
                api_providers, cluster.user, cluster.password,
                request_timeout=cluster.request_timeout,
                http_timeout=cluster.http_timeout,
                retries=cluster.retries,
                redirects=cluster.redirects,
                concurrent_connections=self.nvp_opts.concurrent_connections,
                nvp_gen_timeout=self.nvp_opts.nvp_gen_timeout)

            # TODO(pjb): What if the cluster isn't reachable this
            # instant?  It isn't good to fall back to invalid cluster
            # strings.
            if len(self.clusters) == 0:
                first_cluster = cluster
            self.clusters[c_opts['name']] = cluster

        # Connect and configure ovs_quantum db
        options = {
            'sql_connection': self.db_opts['sql_connection'],
            'sql_max_retries': self.db_opts['sql_max_retries'],
            'reconnect_interval': self.db_opts['reconnect_interval'],
            'base': models_v2.model_base.BASEV2,
        }
        def_cluster_name = self.nvp_opts.default_cluster_name
        if def_cluster_name and def_cluster_name in self.clusters:
            self.default_cluster = self.clusters[def_cluster_name]
        else:
            self.default_cluster = first_cluster
        db.configure_db(options)
        # Extend the fault map
        self._extend_fault_map()
        # Set up RPC interface for DHCP agent
        self.setup_rpc()

    def _nvp_lqueue(self, queue):
        """Convert fields to nvp fields."""
        nvp_queue = {}
        params = [{'name': 'display_name'},
                  {'qos_marking': 'qos_marking'},
                  {'min': 'min_bandwidth_rate'},
                  {'max': 'max_bandwidth_rate'},
                  {'dscp': 'dscp'}]
        for param in params:
            for api_name, nvp_name in param.items():
                val = queue.get(api_name)
                # TODO API attribute map should do this.
                if api_name == 'dscp' or api_name == 'min':
                    if val is None:
                        val = 0
                        queue[api_name] = 0
                if val or val == 0:
                    nvp_queue[nvp_name] = val
        return nvp_queue

    def _validate_qos_queue(self, context, qos_queue):
        if qos_queue.get('default') is True and not context.is_admin:
            raise  ext_qos.DefaultQueueCreateNotAdmin()
        elif qos_queue.get('default') is True and context.is_admin:
            # Check if there is already a default queue in the system
            filters = {'default': [True]}
            if self.get_qos_queues(context, filters):
                raise ext_qos.DefaultQueueAlreadyExists()
        if (qos_queue.get('qos_marking') == 'trusted' and
            not qos_queue.get('dscp')):
            raise ext_qos.MissingDSCPForTrusted()
        max = qos_queue.get('max')
        min = qos_queue.get('min')
        if max >= 0 and min >= 0:
            if min > max:
                raise ext_qos.QueueMinGreaterMax()

    def create_qos_queue(self, context, qos_queue):
        q = qos_queue.get('qos_queue')
        self._validate_qos_queue(context, q)
        q['id'] = nvplib.create_lqueue(self.default_cluster,
                                       self._nvp_lqueue(q))
        return super(NvpPluginV2, self).create_qos_queue(context, qos_queue)

    def delete_qos_queue(self, context, id, raise_in_use=True):
        filters = {'queue_id': [id]}
        queues = self._get_port_queue_bindings(context, filters)
        if len(queues):
            if raise_in_use:
                raise ext_qos.QueueInUseByPort()
            else:
                return
        nvplib.delete_lqueue(self.default_cluster, id)
        return super(NvpPluginV2, self).delete_qos_queue(context, id)

    def _build_ip_address_list(self, context, fixed_ips, subnet_ids=None):
        """  Build ip_addresses data structure for logical router port

        No need to perform validation on IPs - this has already been
        done in the l3_db mixin class
        """
        ip_addresses = []
        for ip in fixed_ips:
            if not subnet_ids or (ip['subnet_id'] in subnet_ids):
                subnet = self._get_subnet(context, ip['subnet_id'])
                ip_prefix = '%s/%s' % (ip['ip_address'],
                                       subnet['cidr'].split('/')[1])
                ip_addresses.append(ip_prefix)
        return ip_addresses

    def _create_and_attach_router_port(self, cluster, context,
                                       router_id, port_data,
                                       attachment_type, attachment,
                                       subnet_ids=None):
        # Use a fake IP address if gateway port is not 'real'
        ip_addresses = (port_data.get('fake_ext_gw') and
                        ['0.0.0.0/31'] or
                        self._build_ip_address_list(context,
                                                    port_data['fixed_ips'],
                                                    subnet_ids))
        try:
            lrouter_port = nvplib.create_router_lport(
                cluster, router_id, port_data.get('tenant_id', 'fake'),
                port_data.get('id', 'fake'), port_data.get('name', 'fake'),
                port_data.get('admin_state_up', True), ip_addresses)
            LOG.debug("Created NVP router port:%s", lrouter_port['uuid'])
        except NvpApiClient.NvpApiException:
            LOG.exception("Unable to create port on NVP logical router %s",
                          router_id)
            raise nvp_exc.NvpPluginException("Unable to create logical "
                                             "router port for quantum port "
                                             "id %s on router %s",
                                             port_data.get('id'),
                                             router_id)
        try:
            # Add a L3 gateway attachment
            # TODO(Salvatore-Orlando): Allow per router specification of
            # l3 gw service uuid as well as per-tenant specification
            nvplib.plug_router_port_attachment(cluster, router_id,
                                               lrouter_port['uuid'],
                                               attachment,
                                               attachment_type)
            LOG.debug("Attached %s to NVP router port %s",
                      attachment, lrouter_port['uuid'])
        except NvpApiClient.NvpApiException:
            # Must remove NVP logical port
            nvplib.delete_router_lport(cluster, router_id,
                                       lrouter_port['uuid'])
            LOG.exception("Unable to plug attachment in NVP logical "
                          "port %s, associated with Quantum port %s",
                          lrouter_port['uuid'], port_data.get('id'))
            raise nvp_exc.NvpPluginException(
                err_desc=("Unable to plug attachment in router port %s "
                          "for quantum port id %s on router %s" %
                          (lrouter_port['uuid'],
                           port_data.get('id'),
                           router_id)))
        return lrouter_port

    def _get_port_by_device_id(self, context, device_id, device_owner):
        """ Retrieve ports associated with a specific device id.

        Used for retrieving all quantum ports attached to a given router.
        """
        port_qry = context.session.query(models_v2.Port)
        return port_qry.filter_by(
            device_id=device_id,
            device_owner=device_owner,).all()

    def _find_router_subnets_cidrs(self, context, router_id):
        """ Retrieve subnets attached to the specified router """
        ports = self._get_port_by_device_id(context, router_id,
                                            l3_db.DEVICE_OWNER_ROUTER_INTF)
        # No need to check for overlapping CIDRs
        cidrs = []
        for port in ports:
            for ip in port.get('fixed_ips', []):
                cidrs.append(self._get_subnet(context,
                                              ip.subnet_id).cidr)
        return cidrs

    def _nvp_create_port(self, context, port_data):
        """ Driver for creating a logical switch port on NVP platform """
        # FIXME(salvatore-orlando): On the NVP platform we do not really have
        # external networks. So if as user tries and create a "regular" VIF
        # port on an external network we are unable to actually create.
        # However, in order to not break unit tests, we need to still create
        # the DB object and return success
        if self._network_is_external(context, port_data['network_id']):
            LOG.error("NVP plugin does not support regular VIF ports on "
                      "external networks. Port %s will be down.",
                      port_data['network_id'])
            # No need to actually update the DB state - the default is down
            return port_data
        network = self._get_network(context, port_data['network_id'])
        network_binding = nicira_db.get_network_binding(
            context.session, port_data['network_id'])
        max_ports = self.nvp_opts.max_lp_per_overlay_ls
        allow_extra_lswitches = False
        if (network_binding and
            network_binding.binding_type in (NetworkTypes.FLAT,
                                             NetworkTypes.VLAN)):
            max_ports = self.nvp_opts.max_lp_per_bridged_ls
            allow_extra_lswitches = True
        try:
            q_net_id = port_data['network_id']
            cluster = self._find_target_cluster(port_data)
            selected_lswitch = self._handle_lswitch_selection(
                cluster, network, network_binding, max_ports,
                allow_extra_lswitches)
            lswitch_uuid = selected_lswitch['uuid']
            do_port_security = (port_data['device_owner'] !=
                                l3_db.DEVICE_OWNER_ROUTER_INTF)
            lport = nvplib.create_lport(cluster,
                                        lswitch_uuid,
                                        port_data['tenant_id'],
                                        port_data['id'],
                                        port_data['name'],
                                        port_data['device_id'],
                                        port_data['admin_state_up'],
                                        port_data['mac_address'],
                                        port_data['fixed_ips'],
                                        port_data.get(psec.PORTSECURITY),
                                        port_data.get(ext_sg.SECURITYGROUP),
                                        port_data.get(ext_qos.QUEUE),
                                        do_port_security
                                        )
            nicira_db.add_quantum_nvp_port_mapping(
                context.session, port_data['id'], lport['uuid'])
            d_owner = port_data['device_owner']
            if (not d_owner in (l3_db.DEVICE_OWNER_ROUTER_GW,
                                l3_db.DEVICE_OWNER_ROUTER_INTF)):
                nvplib.plug_interface(cluster, q_net_id,
                                      lport['uuid'], "VifAttachment",
                                      port_data['id'])
            LOG.debug("_nvp_create_port completed for port %s on network %s. "
                      "The new port id is %s. NVP port id is %s",
                      port_data['name'],
                      port_data['network_id'],
                      port_data['id'],
                      lport['uuid'])
        except Exception:
            # failed to create port in NVP delete port from quantum_db
            LOG.exception("An exception occured while plugging the interface")
            super(NvpPluginV2, self).delete_port(context, port_data["id"])
            raise

    def _nvp_delete_port(self, context, port_data):
        # FIXME(salvatore-orlando): On the NVP platform we do not really have
        # external networks. So deleting regular ports from external networks
        # does not make sense. However we cannot raise as this would break
        # unit tests.
        if self._network_is_external(context, port_data['network_id']):
            LOG.error("NVP plugin does not support regular VIF ports on "
                      "external networks. Port %s will be down.",
                      port_data['network_id'])
            return

        port = nicira_db.get_nvp_port_id(context.session, port_data['id'])
        if port is None:
            raise q_exc.PortNotFound(port_id=port_data['id'])
        # TODO(bgh): if this is a bridged network and the lswitch we just got
        # back will have zero ports after the delete we should garbage collect
        # the lswitch.
        nvplib.delete_port(self.default_cluster,
                           port_data['network_id'],
                           port)

        self._delete_port_security_group_bindings(context, port_data['id'])
        LOG.debug("_nvp_delete_port completed for port %s on network %s",
                  port_data['id'], port_data['network_id'])

    def _find_router_gw_port(self, context, port_data):
        router_id = port_data['device_id']
        cluster = self._find_target_cluster(port_data)
        if not router_id:
            raise q_exc.BadRequest("device_id field must be populated in "
                                   "order to create an external gateway "
                                   "port for network %s",
                                   port_data['network_id'])

        lr_port = nvplib.find_router_gw_port(context, cluster, router_id)
        if not lr_port:
            raise nvp_exc.NvpPluginException(
                err_desc=("The gateway port for the router %s "
                          "was not found on the NVP backend"
                          % router_id))
        return lr_port

    def _nvp_create_ext_gw_port(self, context, port_data):
        """ Driver for creating an external gateway port on NVP platform """
        lr_port = self._find_router_gw_port(context, port_data)
        ip_addresses = self._build_ip_address_list(context,
                                                   port_data['fixed_ips'])
        # This operation actually always updates a NVP logical port
        # instead of creating one. This is because the gateway port
        # is created at the same time as the NVP logical router, otherwise
        # the fabric status of the NVP router will be down.
        # admin_status should always be up for the gateway port
        # regardless of what the user specifies in quantum
        cluster = self._find_target_cluster(port_data)
        router_id = port_data['device_id']
        nvplib.update_router_lport(cluster,
                                   router_id,
                                   lr_port['uuid'],
                                   port_data['tenant_id'],
                                   port_data['id'],
                                   port_data['name'],
                                   True,
                                   ip_addresses)
        # Set the SNAT rule for each subnet (only first IP)
        for cidr in self._find_router_subnets_cidrs(context, router_id):
            nvplib.create_lrouter_snat_rule(
                cluster, router_id,
                ip_addresses[0].split('/')[0],
                ip_addresses[0].split('/')[0],
                source_ip_addresses=cidr)

        LOG.debug("_nvp_create_ext_gw_port completed on external network %s, "
                  "attached to router:%s. NVP port id is %s",
                  port_data['network_id'],
                  router_id,
                  lr_port['uuid'])

    def _nvp_delete_ext_gw_port(self, context, port_data):
        lr_port = self._find_router_gw_port(context, port_data)
        try:
            # Delete is actually never a real delete, otherwise the NVP
            # logical router will stop working
            cluster = self._find_target_cluster(port_data)
            router_id = port_data['device_id']
            nvplib.update_router_lport(cluster,
                                       router_id,
                                       lr_port['uuid'],
                                       port_data['tenant_id'],
                                       port_data['id'],
                                       port_data['name'],
                                       True,
                                       ['0.0.0.0/31'])
            # Delete the SNAT rule for each subnet
            for cidr in self._find_router_subnets_cidrs(context, router_id):
                nvplib.delete_nat_rules_by_match(
                    cluster, router_id, "SourceNatRule",
                    max_num_expected=1, min_num_expected=1,
                    source_ip_addresses=cidr)

        except NvpApiClient.ResourceNotFound:
            raise nvp_exc.NvpPluginException(
                err_desc=("Logical router resource %s not found "
                          "on NVP platform", router_id))
        except NvpApiClient.NvpApiException:
            raise nvp_exc.NvpPluginException(
                err_desc=("Unable to update logical router"
                          "on NVP Platform"))
        LOG.debug("_nvp_delete_ext_gw_port completed on external network %s, "
                  "attached to router:%s",
                  port_data['network_id'],
                  router_id)

    def _nvp_create_fip_port(self, context, port_data):
        # As we do not create ports for floating IPs in NVP,
        # this is a no-op driver
        pass

    def _nvp_delete_fip_port(self, context, port_data):
        # As we do not create ports for floating IPs in NVP,
        # this is a no-op driver
        pass

    def _extend_fault_map(self):
        """ Extends the Quantum Fault Map

        Exceptions specific to the NVP Plugin are mapped to standard
        HTTP Exceptions
        """
        base.FAULT_MAP.update({nvp_exc.NvpInvalidNovaZone:
                               webob.exc.HTTPBadRequest,
                               nvp_exc.NvpPortSecurityNoIpException:
                               webob.exc.HTTPBadRequest,
                               nvp_exc.NvpNoMorePortsException:
                               webob.exc.HTTPBadRequest})

    def _novazone_to_cluster(self, novazone_id):
        if novazone_id in self.novazone_cluster_map:
            return self.novazone_cluster_map[novazone_id]
        LOG.debug("Looking for nova zone: %s" % novazone_id)
        for x in self.clusters:
            LOG.debug("Looking for nova zone %s in cluster: %s",
                      novazone_id, x)
            if x.zone == str(novazone_id):
                self.novazone_cluster_map[x.zone] = x
                return x
        LOG.error("Unable to find cluster config entry for nova zone: %s" %
                  novazone_id)
        raise nvp_exc.NvpInvalidNovaZone(nova_zone=novazone_id)

    def _find_target_cluster(self, resource):
        if 'nova_id' in resource:
            return self._novazone_to_cluster(resource['nova_id'])
        else:
            return self.default_cluster

    def _check_provider_view_auth(self, context, network):
        return policy.check(context,
                            "extension:provider_network:view",
                            network)

    def _enforce_provider_set_auth(self, context, network):
        return policy.enforce(context,
                              "extension:provider_network:set",
                              network)

    def _handle_provider_create(self, context, attrs):
        # NOTE(salvatore-orlando): This method has been borrowed from
        # the OpenvSwtich plugin, altough changed to match NVP specifics.
        # It might be worth investigating whether
        # a sort of mixin implementing the provider extension
        # might be a good idea
        network_type = attrs.get(pnet.NETWORK_TYPE)
        physical_network = attrs.get(pnet.PHYSICAL_NETWORK)
        segmentation_id = attrs.get(pnet.SEGMENTATION_ID)
        network_type_set = attributes.is_attr_set(network_type)
        physical_network_set = attributes.is_attr_set(physical_network)
        segmentation_id_set = attributes.is_attr_set(segmentation_id)
        if not (network_type_set or physical_network_set or
                segmentation_id_set):
            return (None, None, None)

        # Authorize before exposing plugin details to client
        self._enforce_provider_set_auth(context, attrs)
        err_msg = None
        if not network_type_set:
            err_msg = _("%s required" % pnet.NETWORK_TYPE)
        elif network_type in (NetworkTypes.GRE, NetworkTypes.STT):
            if segmentation_id_set:
                err_msg = _("%s not allowed for %s networks"
                            % (segmentation_id, network_type))
        elif network_type == NetworkTypes.FLAT:
            if segmentation_id_set:
                err_msg = _("Segmentation ID cannot be specified with "
                            "flat network type")
        elif network_type == NetworkTypes.VLAN:
            if not segmentation_id_set:
                err_msg = _("Segmentation ID must be specified with "
                            "vlan network type")
            elif (segmentation_id_set and
                  (segmentation_id < 1 or segmentation_id > 4094)):
                err_msg = _("%s out of range (1 through 4094)"
                            % segmentation_id)
            else:
                # Verify segment is not already allocated
                binding = nicira_db.get_network_binding_by_vlanid(
                    context.session, segmentation_id)
                if binding:
                    raise q_exc.VlanIdInUse(vlan_id=segmentation_id,
                                            physical_network=physical_network)
        else:
            err_msg = _("%s %s not supported"
                        % (pnet.NETWORK_TYPE, network_type))
        if err_msg:
            raise q_exc.InvalidInput(error_message=err_msg)
        # TODO(salvatore-orlando): Validate tranport zone uuid
        # which should be specified in physical_network
        return (network_type, physical_network, segmentation_id)

    def _extend_network_dict_provider(self, context, network, binding=None):
        if self._check_provider_view_auth(context, network):
            if not binding:
                binding = nicira_db.get_network_binding(context.session,
                                                        network['id'])
            # With the NVP plugin it is fine to have a network
            # without any binding
            if binding:
                network[pnet.NETWORK_TYPE] = binding.binding_type
                network[pnet.PHYSICAL_NETWORK] = binding.tz_uuid
                network[pnet.SEGMENTATION_ID] = binding.vlan_id

    def _handle_lswitch_selection(self, cluster, network,
                                  network_binding, max_ports,
                                  allow_extra_lswitches):
        selected_lswitch = None
        lswitches = nvplib.get_lswitches(cluster, network.id)
        eligible_ls = [ls for ls in lswitches
                       if (ls['_relations']['LogicalSwitchStatus']
                           ['lport_count'] < max_ports)]
        main_ls = [ls for ls in lswitches if ls['uuid'] == network.id]
        if eligible_ls:
            selected_lswitch = eligible_ls[0]
        else:
            if allow_extra_lswitches:
                nvplib.update_lswitch(cluster,
                                      main_ls[0]['uuid'],
                                      main_ls[0]['display_name'],
                                      network['tenant_id'],
                                      tags=[{'tag': 'True',
                                             'scope':
                                             'quantum_multi_lswitch'}])
                selected_lswitch = nvplib.create_lswitch(
                    cluster, network.tenant_id,
                    "%s-ext-%s" % (network.name, len(lswitches)),
                    network_binding.binding_type,
                    network_binding.tz_uuid,
                    network_binding.vlan_id,
                    network.id)
            else:
                LOG.error("Maximum number of logical ports reached for "
                          "logical switch %s")
                raise nvp_exc.NvpNoMorePortsException(network=network.id)
        return selected_lswitch

    def _ensure_metadata_host_route(self, context, fixed_ip_data,
                                    is_delete=False):
        subnet = self._get_subnet(context, fixed_ip_data['subnet_id'])
        metadata_routes = [r for r in subnet.routes
                           if r['destination'] == '169.254.169.254/32']
        if metadata_routes:
            # We should have only a single metadata route at any time
            # because the route logic forbids two routes with the same
            # destination. Update next hop with the provided IP address
            if not is_delete:
                metadata_routes[0].nexthop = fixed_ip_data['ip_address']
            else:
                context.session.delete(metadata_routes[0])
        else:
            # add the metadata route
            route = models_v2.Route(subnet_id=subnet.id,
                                    destination='169.254.169.254/32',
                                    nexthop=fixed_ip_data['ip_address'])
            context.session.add(route)

    def setup_rpc(self):
        # RPC support for dhcp
        self.topic = topics.PLUGIN
        self.rpc_context = context.RequestContext('quantum', 'quantum',
                                                  is_admin=False)
        self.conn = rpc.create_connection(new=True)
        self.callbacks = NVPRpcCallbacks(self.rpc_context)
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        self.conn.create_consumer(self.topic, self.dispatcher,
                                  fanout=False)
        # Consume from all consumers in a thread
        self.conn.consume_in_thread()

    @property
    def cluster(self):
        if len(self.clusters):
            return self.clusters[0]
        return None

    def create_security_group(self, context, security_group, default_sg=False):
        """Create security group.
        If default_sg is true that means a we are creating a default security
        group and we don't need to check if one exists.
        """
        s = security_group.get('security_group')
        if (cfg.CONF.SECURITYGROUP.proxy_mode and not context.is_admin):
            raise ext_sg.SecurityGroupProxyModeNotAdmin()
        if (cfg.CONF.SECURITYGROUP.proxy_mode and not s.get('external_id')):
            raise ext_sg.SecurityGroupProxyMode()
        if not cfg.CONF.SECURITYGROUP.proxy_mode and s.get('external_id'):
            raise ext_sg.SecurityGroupNotProxyMode()

        tenant_id = self._get_tenant_id_for_create(context, s)
        if not default_sg and not cfg.CONF.SECURITYGROUP.proxy_mode:
            self._ensure_default_security_group(context, tenant_id,
                                                security_group)
        if s.get('external_id'):
            filters = {'external_id': [(s.get('external_id'))]}
            security_groups = super(NvpPluginV2, self).get_security_groups(
                context, filters=filters)
            if security_groups:
                raise ext_sg.SecurityGroupAlreadyExists(
                    name=s.get('name', ''), external_id=s.get('external_id'))
        nvp_secgroup = nvplib.create_security_profile(self.default_cluster,
                                                      tenant_id, s)
        security_group['security_group']['id'] = nvp_secgroup['uuid']
        return super(NvpPluginV2, self).create_security_group(
            context, security_group, default_sg)

    def _convert_to_nvp_rule(self, rule):
        """Convert/validate to nvp fields"""
        supported_protocols = {'tcp': 6, 'icmp': 1, 'udp': 17}
        nvp_rule = {}

        if rule['port_range_min'] and rule['port_range_max']:
            nvp_rule['port_range_min'] = rule['port_range_min']
            nvp_rule['port_range_max'] = rule['port_range_max']

        if rule['protocol']:
            nvp_rule['protocol'] = supported_protocols[rule['protocol']]

        if rule['source_ip_prefix']:
            nvp_rule['ip_prefix'] = rule['source_ip_prefix']
        if rule['source_group_id']:
            nvp_rule['profile_uuid'] = rule['source_group_id']

        nvp_rule['ethertype'] = rule['ethertype']

        return nvp_rule

    def _get_profile_uuid(self, context, source_group_id):
        """Return profile id from novas group id. """
        security_group = super(NvpPluginV2, self).get_security_group(
            context, source_group_id)
        if not security_group:
            raise ext_sg.SecurityGroupNotFound(id=source_group_id)
        return security_group['id']

    def _remove_none_values_and_convert(self, rules):
        """Remove none values or NVP will complain about them.
        """
        supported_protocols = {'tcp': 6, 'icmp': 1, 'udp': 17}
        delete_if_present = ['source_ip_prefix', 'protocol',
                             'source_group_id', 'port_range_min',
                             'port_range_max']

        for rule in rules['logical_port_ingress_rules']:
            for key in delete_if_present:
                val = rule.get(key)
                if not val and key in rule:
                    del rule[key]
                if 'source_ip_prefix' == key and key in rule:
                    rule['ip_prefix'] = rule['source_ip_prefix']
                    del rule['source_ip_prefix']
                elif 'source_group_id' == key and key in rule:
                    rule['profile_uuid'] = rule['source_group_id']
                    del rule['source_group_id']
                elif 'protocol' == key and key in rule:
                    rule['protocol'] = supported_protocols[rule['protocol']]

        for rule in rules['logical_port_egress_rules']:
            for key in delete_if_present:
                val = rule.get(key)
                if not val and key in rule:
                    del rule[key]
                if 'source_ip_prefix' == key and key in rule:
                    rule['ip_prefix'] = rule['source_ip_prefix']
                    del rule['source_ip_prefix']
                elif 'source_group_id' == key and key in rule:
                    rule['profile_uuid'] = rule['source_group_id']
                    del rule['source_group_id']
                elif 'protocol' == key and key in rule:
                    rule['protocol'] = supported_protocols[rule['protocol']]
        return rules

    def create_security_group_rule(self, context, security_group_rule):
        """create a single security group rule"""
        bulk_rule = {'security_group_rules': [security_group_rule]}
        return  self.create_security_group_rule_bulk(context, bulk_rule)[0]

    def create_security_group_rule_bulk(self, context, security_group_rule):
        """ create security group rules
        :param security_group_rule: list of rules to create
        """
        s = security_group_rule.get('security_group_rules')
        tenant_id = self._get_tenant_id_for_create(context, s)
        self._ensure_default_security_group(context, tenant_id)

        security_group_id = self._validate_security_group_rules(
            context, security_group_rule)

        # Check to make sure security group exists and retrieve:
        # nvp id that corresponds to nova.
        security_group = super(NvpPluginV2, self).get_security_group(
            context, security_group_id)

        if not security_group:
            raise ext_sg.SecurityGroupNotFound(id=security_group_id)

        # Check for duplicate rules
        self._check_for_duplicate_rules(context, s)

        # keep id that maps nvp_id to external_id
        nvp_id = security_group['id']

        # gather all the existing security group rules since we need all
        # of them to PUT to NVP.
        current_rules = self._remove_none_values_and_convert(
            self._get_security_group_rules_by_nvp_id(context, nvp_id))

        # combine old rules with new rules
        for r in s:
            rule = r['security_group_rule']
            rule['security_group_id'] = nvp_id
            if rule['source_group_id']:
                rule['source_group_id'] = self._get_profile_uuid(
                    context, rule['source_group_id'])
            if rule['direction'] == 'ingress':
                current_rules['logical_port_egress_rules'].append(
                    self._convert_to_nvp_rule(rule))
            elif rule['direction'] == 'egress':
                current_rules['logical_port_ingress_rules'].append(
                    self._convert_to_nvp_rule(rule))

        nvplib.update_security_group_rules(self.default_cluster,
                                           nvp_id,
                                           current_rules)
        return super(NvpPluginV2, self).create_security_group_rule_bulk_native(
            context, security_group_rule)

    def _get_security_group_rules_by_nvp_id(self, context, nvp_id,
                                            want_id=False):
        """Query quantum db for security group rules. If external_id is
        provided the external_id will also be returned.
        """
        fields = ['source_ip_prefix', 'source_group_id', 'protocol',
                  'port_range_min', 'port_range_max', 'protocol', 'ethertype']

        if want_id:
            fields.append('id')

        filters = {'security_group_id': [nvp_id], 'direction': ['ingress']}
        ingress_rules = super(NvpPluginV2, self).get_security_group_rules(
            context, filters, fields)
        filters = {'security_group_id': [nvp_id], 'direction': ['egress']}
        egress_rules = super(NvpPluginV2, self).get_security_group_rules(
            context, filters, fields)
        return {'logical_port_ingress_rules': egress_rules,
                'logical_port_egress_rules': ingress_rules}

    def _remove_id_from_rules(self, rules, id):
        """This function recieves all of the current rules
        associated with a security group and then removes
        the rule that makes the id and the id field in the dict.
        """
        found = -1
        ingress_rules = rules['logical_port_ingress_rules']
        for i in range(0, len(ingress_rules)):
            if  ingress_rules[i]['id'] == id:
                found = i
            del ingress_rules[i]['id']

        if found >= 0:
            del ingress_rules[found]
            found = -1

        egress_rules = rules['logical_port_egress_rules']
        for i in range(0, len(egress_rules)):
            if  egress_rules[i]['id'] == id:
                found = i
            del egress_rules[i]['id']

        if found >= 0:
            del egress_rules[found]

    def delete_security_group_rule(self, context, sgrid):
        """ Delete a security group rule
        :param sgrid: security group id to remove.
        """
        if (cfg.CONF.SECURITYGROUP.proxy_mode and not context.is_admin):
            raise ext_sg.SecurityGroupProxyModeNotAdmin()

        # determine security profile id
        security_group = super(NvpPluginV2, self).get_security_group_rule(
            context, sgrid)
        if not security_group:
            raise ext_sg.SecurityGroupRuleNotFound(id=sgrid)

        nvp_id = security_group['security_group_id']
        security_group_id = security_group['id']
        current_rules = self._get_security_group_rules_by_nvp_id(
            context, nvp_id, True)

        self._remove_id_from_rules(current_rules, security_group_id)
        self._remove_none_values_and_convert(current_rules)
        nvplib.update_security_group_rules(self.default_cluster, nvp_id,
                                           current_rules)
        return super(NvpPluginV2, self).delete_security_group_rule(context,
                                                                   sgrid)

    def delete_security_group(self, context, security_group_id):
        """Delete a security group
        :param security_group_id: security group rule to remove.
        """
        if (cfg.CONF.SECURITYGROUP.proxy_mode and not context.is_admin):
            raise ext_sg.SecurityGroupProxyModeNotAdmin()

        security_group = super(NvpPluginV2, self).get_security_group(
            context, security_group_id)
        if not security_group:
            raise ext_sg.SecurityGroupNotFound(id=security_group_id)

        if security_group['name'] == 'default':
            raise ext_sg.SecurityGroupCannotRemoveDefault()

        nvp_id = security_group['id']
        filters = {'security_group_id': [nvp_id]}
        if super(NvpPluginV2, self)._get_port_security_group_bindings(context,
                                                                      filters):
            raise ext_sg.SecurityGroupInUse(id=nvp_id)
        nvplib.delete_security_profile(self.default_cluster, nvp_id)

        return super(NvpPluginV2, self).delete_security_group(
            context, security_group_id)

    def get_all_networks(self, tenant_id, **kwargs):
        networks = []
        for c in self.clusters:
            networks.extend(nvplib.get_all_networks(c, tenant_id, networks))
        LOG.debug("get_all_networks() completed for tenant %s: %s" % (
            tenant_id, networks))
        return networks

    def create_network(self, context, network):
        """
        :returns: a sequence of mappings with the following signature:
                    {'id': UUID representing the network.
                     'name': Human-readable name identifying the network.
                     'tenant_id': Owner of network. only admin user
                                  can specify a tenant_id other than its own.
                     'admin_state_up': Sets admin state of network. if down,
                                       network does not forward packets.
                     'status': Indicates whether network is currently
                               operational (limit values to "ACTIVE", "DOWN",
                               "BUILD", and "ERROR"?
                     'subnets': Subnets associated with this network. Plan
                                to allow fully specified subnets as part of
                                network create.
                   }
        :raises: exception.NoImplementedError
        """
        tenant_id = self._get_tenant_id_for_create(context, network['network'])
        self._ensure_default_security_group(context, tenant_id)
        net_data = network['network'].copy()

        # Process qos queue extension
        if network['network'].get(ext_qos.QUEUE):
            # This raises if not found
            self._get_qos_queue(context, network['network'].get(ext_qos.QUEUE))

        # Process the provider network extension
        self._handle_provider_create(context, net_data)
        # Replace ATTR_NOT_SPECIFIED with None before sending to NVP
        for attr, value in network['network'].iteritems():
            if value == attributes.ATTR_NOT_SPECIFIED:
                net_data[attr] = None
        # FIXME(arosen) implement admin_state_up = False in NVP
        if net_data['admin_state_up'] is False:
            LOG.warning("Network with admin_state_up=False are not yet "
                        "supported by this plugin. Ignoring setting for "
                        "network %s", net_data.get('name', '<unknown>'))

        # Extract tenant id from context if not specified in resource
        tenant_id = self._get_tenant_id_for_create(context, net_data)
        # When we create a network we create the first lswitch for this
        # network, and we let NVP choose the identifier
        target_cluster = self._find_target_cluster(net_data)
        # An external network is a Quantum with no equivalent in NVP
        # so do not create a logical switch for an external network
        external = net_data.get(l3.EXTERNAL)
        if not attributes.is_attr_set(external):
            lswitch = nvplib.create_lswitch(
                target_cluster, tenant_id, net_data.get('name'),
                net_data.get(pnet.NETWORK_TYPE),
                net_data.get(pnet.PHYSICAL_NETWORK),
                net_data.get(pnet.SEGMENTATION_ID))
            network['network']['id'] = lswitch['uuid']

        with context.session.begin(subtransactions=True):
            new_net = super(NvpPluginV2, self).create_network(context,
                                                              network)
            # DB Operations for setting the network as external
            self._process_l3_create(context, net_data, new_net['id'])
            if net_data.get(pnet.NETWORK_TYPE):
                net_binding = nicira_db.add_network_binding(
                    context.session, new_net['id'],
                    net_data.get(pnet.NETWORK_TYPE),
                    net_data.get(pnet.PHYSICAL_NETWORK),
                    net_data.get(pnet.SEGMENTATION_ID))
                self._extend_network_dict_provider(context, new_net,
                                                   net_binding)
            self._extend_network_dict_l3(context, new_net)
            if network['network'].get(ext_qos.QUEUE):
                new_net[ext_qos.QUEUE] = network['network'].get(ext_qos.QUEUE)
                self._process_network_queue_mapping(context,
                                                    new_net)
                self._extend_network_qos_queue(context, new_net)
        return new_net

    def delete_network(self, context, id):
        """
        Deletes the network with the specified network identifier
        belonging to the specified tenant.

        :returns: None
        :raises: exception.NetworkInUse
        :raises: exception.NetworkNotFound
        """
        external = self._network_is_external(context, id)
        super(NvpPluginV2, self).delete_network(context, id)
        # Do not go to NVP for external networks
        if not external:
            # FIXME(salvatore-orlando): Failures here might lead NVP
            # and quantum state to diverge
            pairs = self._get_lswitch_cluster_pairs(id, context.tenant_id)
            for (cluster, switches) in pairs:
                nvplib.delete_networks(cluster, id, switches)

        LOG.debug("delete_network() completed for tenant: %s" %
                  context.tenant_id)

    def _get_lswitch_cluster_pairs(self, netw_id, tenant_id):
        """Figure out the set of lswitches on each cluster that maps to this
           network id"""
        pairs = []
        for c in self.clusters.itervalues():
            lswitches = []
            try:
                results = nvplib.get_lswitches(c, netw_id)
                lswitches.extend([ls['uuid'] for ls in results])
            except q_exc.NetworkNotFound:
                continue
            pairs.append((c, lswitches))
        if len(pairs) == 0:
            raise q_exc.NetworkNotFound(net_id=netw_id)
        LOG.debug("Returning pairs for network: %s" % (pairs))
        return pairs

    def get_network(self, context, id, fields=None):
        """
        Retrieves all attributes of the network, NOT including
        the ports of that network.

        :returns: a sequence of mappings with the following signature:
                    {'id': UUID representing the network.
                     'name': Human-readable name identifying the network.
                     'tenant_id': Owner of network. only admin user
                                  can specify a tenant_id other than its own.
                     'admin_state_up': Sets admin state of network. if down,
                                       network does not forward packets.
                     'status': Indicates whether network is currently
                               operational (limit values to "ACTIVE", "DOWN",
                               "BUILD", and "ERROR"?
                     'subnets': Subnets associated with this network. Plan
                                to allow fully specified subnets as part of
                                network create.
                   }

        :raises: exception.NetworkNotFound
        :raises: exception.QuantumException
        """
        # goto to the plugin DB and fecth the network
        network = self._get_network(context, id)
        # if the network is external, do not go to NVP
        if not self._network_is_external(context, id):
            # verify the fabric status of the corresponding
            # logical switch(es) in nvp
            try:
                # FIXME(salvatore-orlando): This is not going to work
                # unless we store the nova_id in the database once we'l
                # enable multiple clusters
                cluster = self._find_target_cluster(network)
                lswitches = nvplib.get_lswitches(cluster, id)
                net_op_status = constants.NET_STATUS_ACTIVE
                for lswitch in lswitches:
                    relations = lswitch.get('_relations')
                    if relations:
                        lswitch_status = relations.get('LogicalSwitchStatus',
                                                       None)
                        # FIXME(salvatore-orlando): Being unable to fetch the
                        # logical switch status should be an exception.
                        if (lswitch_status and
                            not lswitch_status.get('fabric_status', None)):
                            net_op_status = constants.NET_STATUS_DOWN
                            break
                LOG.debug("Current network status:%s;"
                          "Status in Quantum DB:%s",
                          net_op_status, network.status)
                if net_op_status != network.status:
                    # update the network status
                    with context.session.begin(subtransactions=True):
                        network.status = net_op_status
            except Exception:
                err_msg = "Unable to get logical switches"
                LOG.exception(err_msg)
                raise nvp_exc.NvpPluginException(err_desc=err_msg)

        # Don't do filtering for fields here otherwise we won't be able
        # to add provider networks fields
        net_result = self._make_network_dict(network, None)
        self._extend_network_dict_provider(context, net_result)
        return self._fields(net_result, fields)

    def get_networks(self, context, filters=None, fields=None):
        """
        Retrieves all attributes of the network, NOT including
        the ports of that network.

        :returns: a sequence of mappings with the following signature:
                    {'id': UUID representing the network.
                     'name': Human-readable name identifying the network.
                     'tenant_id': Owner of network. only admin user
                                  can specify a tenant_id other than its own.
                     'admin_state_up': Sets admin state of network. if down,
                                       network does not forward packets.
                     'status': Indicates whether network is currently
                               operational (limit values to "ACTIVE", "DOWN",
                               "BUILD", and "ERROR"?
                     'subnets': Subnets associated with this network. Plan
                                to allow fully specified subnets as part of
                                network create.
                   }

        :raises: exception.NetworkNotFound
        :raises: exception.QuantumException
        """
        nvp_lswitches = []
        quantum_lswitches = (
            super(NvpPluginV2, self).get_networks(context, filters))
        for net in quantum_lswitches:
            self._extend_network_dict_provider(context, net)
            self._extend_network_dict_l3(context, net)
            self._extend_network_qos_queue(context, net)
        quantum_lswitches = self._filter_nets_l3(context,
                                                 quantum_lswitches,
                                                 filters)
        if context.is_admin and not filters.get("tenant_id"):
            tenant_filter = ""
        elif filters.get("tenant_id"):
            tenant_filter = ""
            for tenant in filters.get("tenant_id"):
                tenant_filter += "&tag=%s&tag_scope=os_tid" % tenant
        else:
            tenant_filter = "&tag=%s&tag_scope=os_tid" % context.tenant_id

        lswitch_filters = "uuid,display_name,fabric_status,tags"
        lswitch_url_path = (
            "/ws.v1/lswitch?fields=%s&relations=LogicalSwitchStatus%s"
            % (lswitch_filters, tenant_filter))
        try:
            for c in self.clusters.itervalues():
                res = nvplib.get_all_query_pages(
                    lswitch_url_path, c)

                nvp_lswitches.extend(res)
        except Exception:
            err_msg = "Unable to get logical switches"
            LOG.exception(err_msg)
            raise nvp_exc.NvpPluginException(err_desc=err_msg)

        # TODO (Aaron) This can be optimized
        if filters.get("id"):
            filtered_lswitches = []
            for nvp_lswitch in nvp_lswitches:
                for id in filters.get("id"):
                    if id == nvp_lswitch['uuid']:
                        filtered_lswitches.append(nvp_lswitch)
            nvp_lswitches = filtered_lswitches

        for quantum_lswitch in quantum_lswitches:
            # External networks should not be counted as they do not
            # exist in NVP
            if quantum_lswitch[l3.EXTERNAL]:
                continue
            Found = False
            for nvp_lswitch in nvp_lswitches:
                # TODO(salvatore-orlando): be careful about "extended"
                # logical switches
                # TODO(salvatore-orlando): Also store permanently the
                # updated operational status
                if nvp_lswitch['uuid'] == quantum_lswitch["id"]:
                    if (nvp_lswitch["_relations"]["LogicalSwitchStatus"]
                            ["fabric_status"]):
                        quantum_lswitch["status"] = constants.NET_STATUS_ACTIVE
                    else:
                        quantum_lswitch["status"] = constants.NET_STATUS_DOWN
                    quantum_lswitch["name"] = nvp_lswitch["display_name"]
                    nvp_lswitches.remove(nvp_lswitch)
                    Found = True
                    break

            if not Found:
                raise nvp_exc.NvpOutOfSyncException()
        # do not make the case in which switches are found in NVP
        # but not in Quantum catastrophic.
        if len(nvp_lswitches):
            LOG.warning("Found %s logical switches not bound "
                        "to Quantum networks. Quantum and NVP are "
                        "potentially out of sync", len(nvp_lswitches))

        LOG.debug("get_networks() completed for tenant %s" % context.tenant_id)

        if fields:
            ret_fields = []
            for quantum_lswitch in quantum_lswitches:
                row = {}
                for field in fields:
                    row[field] = quantum_lswitch[field]
                ret_fields.append(row)
            return ret_fields

        return quantum_lswitches

    def update_network(self, context, id, network):
        """
        Updates the properties of a particular Virtual Network.

        :returns: a sequence of mappings with the following signature:
        {'id': UUID representing the network.
         'name': Human-readable name identifying the network.
         'tenant_id': Owner of network. only admin user
                      can specify a tenant_id other than its own.
        'admin_state_up': Sets admin state of network. if down,
                          network does not forward packets.
        'status': Indicates whether network is currently
                  operational (limit values to "ACTIVE", "DOWN",
                               "BUILD", and "ERROR"?
        'subnets': Subnets associated with this network. Plan
                   to allow fully specified subnets as part of
                   network create.
                   }

        :raises: exception.NetworkNotFound
        :raises: exception.NoImplementedError
        """

        if network["network"].get("admin_state_up"):
            if network['network']["admin_state_up"] is False:
                raise q_exc.NotImplementedError("admin_state_up=False "
                                                "networks are not "
                                                "supported.")

        # Process qos queue extension
        if network['network'].get(ext_qos.QUEUE):
            # This raises if not found
            self._get_qos_queue(context, network['network'].get(ext_qos.QUEUE))

        params = {}
        params["network"] = network["network"]
        pairs = self._get_lswitch_cluster_pairs(id, context.tenant_id)

        #Only field to update in NVP is name
        if network['network'].get("name"):
            for (cluster, switches) in pairs:
                for switch in switches:
                    nvplib.update_lswitch(cluster, switch,
                                          network['network']['name'])

        LOG.debug("update_network() completed for tenant: %s" %
                  context.tenant_id)
        with context.session.begin(subtransactions=True):
            net = super(NvpPluginV2, self).update_network(context, id, network)

            if network['network'].get(ext_qos.QUEUE):
                net[ext_qos.QUEUE] = network['network'].get(ext_qos.QUEUE)
                self._delete_network_queue_mapping(context, id)
                self._process_network_queue_mapping(context,
                                                    net)

            self._process_l3_update(context, network['network'], id)
            self._extend_network_dict_provider(context, net)
            self._extend_network_dict_l3(context, net)
        return net

    def get_ports(self, context, filters=None, fields=None):
        """
        Returns all ports from given tenant

        :returns: a sequence of mappings with the following signature:
        {'id': UUID representing the network.
         'name': Human-readable name identifying the network.
         'tenant_id': Owner of network. only admin user
                      can specify a tenant_id other than its own.
        'admin_state_up': Sets admin state of network. if down,
                          network does not forward packets.
        'status': Indicates whether network is currently
                  operational (limit values to "ACTIVE", "DOWN",
                               "BUILD", and "ERROR"?
        'subnets': Subnets associated with this network. Plan
                   to allow fully specified subnets as part of
                   network create.
                   }

        :raises: exception.NetworkNotFound
        """
        quantum_lports = super(NvpPluginV2, self).get_ports(context, filters)
        if (filters.get('network_id') and len(filters.get('network_id')) and
            self._network_is_external(context, filters.get('network_id')[0])):
            # Do not perform check on NVP platform
            return quantum_lports

        vm_filter = ""
        tenant_filter = ""
        # This is used when calling delete_network. Quantum checks to see if
        # the network has any ports.
        if filters.get("network_id"):
            # FIXME (Aaron) If we get more than one network_id this won't work
            lswitch = filters["network_id"][0]
        else:
            lswitch = "*"

        if filters.get("device_id"):
            for vm_id in filters.get("device_id"):
                vm_filter = ("%stag_scope=vm_id&tag=%s&" % (vm_filter,
                             hashlib.sha1(vm_id).hexdigest()))
        else:
            vm_id = ""

        if filters.get("tenant_id"):
            for tenant in filters.get("tenant_id"):
                tenant_filter = ("%stag_scope=os_tid&tag=%s&" %
                                 (tenant_filter, tenant))

        nvp_lports = {}

        lport_fields_str = ("tags,admin_status_enabled,display_name,"
                            "fabric_status_up")
        try:
            for c in self.clusters.itervalues():
                lport_query_path = (
                    "/ws.v1/lswitch/%s/lport?fields=%s&%s%stag_scope=q_port_id"
                    "&relations=LogicalPortStatus" %
                    (lswitch, lport_fields_str, vm_filter, tenant_filter))

                ports = nvplib.get_all_query_pages(lport_query_path, c)
                if ports:
                    for port in ports:
                        for tag in port["tags"]:
                            if tag["scope"] == "q_port_id":
                                nvp_lports[tag["tag"]] = port

        except Exception:
            err_msg = "Unable to get ports"
            LOG.exception(err_msg)
            raise nvp_exc.NvpPluginException(err_desc=err_msg)

        lports = []
        for quantum_lport in quantum_lports:
            # if a quantum port is not found in NVP, this migth be because
            # such port is not mapped to a logical switch - ie: floating ip
            if quantum_lport['device_owner'] == l3_db.DEVICE_OWNER_FLOATINGIP:
                lports.append(quantum_lport)
                continue
            try:
                quantum_lport["admin_state_up"] = (
                    nvp_lports[quantum_lport["id"]]["admin_status_enabled"])

                quantum_lport["name"] = (
                    nvp_lports[quantum_lport["id"]]["display_name"])

                self._extend_port_dict_security_group(context, quantum_lport)
                self._extend_port_dict_port_security(context, quantum_lport)

                if (nvp_lports[quantum_lport["id"]]
                        ["_relations"]
                        ["LogicalPortStatus"]
                        ["fabric_status_up"]):
                    quantum_lport["status"] = constants.PORT_STATUS_ACTIVE
                else:
                    quantum_lport["status"] = constants.PORT_STATUS_DOWN

                del nvp_lports[quantum_lport["id"]]
                lports.append(quantum_lport)
            except KeyError:
                pass

        # do not make the case in which ports are found in NVP
        # but not in Quantum catastrophic.
        if len(nvp_lports):
            LOG.warning("Found %s logical ports not bound "
                        "to Quantum ports. Quantum and NVP are "
                        "potentially out of sync", len(nvp_lports))

        if fields:
            ret_fields = []
            for lport in lports:
                row = {}
                for field in fields:
                    row[field] = lport[field]
                ret_fields.append(row)
            return ret_fields
        return lports

    def create_port(self, context, port):
        """
        Creates a port on the specified Virtual Network.
        Returns:

        {"id": uuid represeting the port.
         "network_id": uuid of network.
         "tenant_id": tenant_id
         "mac_address": mac address to use on this port.
         "admin_state_up": Sets admin state of port. if down, port
                           does not forward packets.
         "status": dicates whether port is currently operational
                   (limit values to "ACTIVE", "DOWN", "BUILD", and "ERROR")
         "fixed_ips": list of subnet ID's and IP addresses to be used on
                      this port
         "device_id": identifies the device (e.g., virtual server) using
                      this port.
        }

        :raises: exception.NetworkNotFound
        :raises: exception.StateInvalid
        """
        # Set admin_state_up False since not created in NVP set
        # TODO(salvatore-orlando) : verify whether subtransactions can help
        # us avoiding multiple operations on the db. This might also allow
        # us to use the same identifier for the NVP and the Quantum port
        # Set admin_state_up False since not created in NVP yet
        requested_admin_state = port["port"]["admin_state_up"]
        port["port"]["admin_state_up"] = False
        p = port['port']
        tenant_id = self._get_tenant_id_for_create(context, port['port'])
        # First, we allocate port in quantum database
        quantum_db = super(NvpPluginV2, self).create_port(context, port)
        # If we have just created a dhcp port, and metadata request are
        # forwarded there, we need to verify the appropriate host route is
        # in place
        if (cfg.CONF.metadata_dhcp_host_route and
            quantum_db.get('device_owner') == 'network:dhcp'):
            if (quantum_db.get('fixed_ips') and
                len(quantum_db.get('fixed_ips'))):
                self._ensure_metadata_host_route(
                    context, quantum_db.get('fixed_ips')[0])
        # Update fields obtained from quantum db (eg: MAC address)
        port["port"].update(quantum_db)
        try:
            # QoS Queue
            p[ext_qos.QUEUE] = self._check_for_queue_and_create(context, p)
            # TODO(salvatore-orlando): Verify whether security group and port
            # secutiy settings can be moved in port_driver
            default_sg = self._ensure_default_security_group(
                context, tenant_id)
            self._validate_security_groups_on_port(context, port)
            port_security = self._validate_port_security(context, p)
            p[psec.PORTSECURITY] = port_security

            if (not p.get(ext_sg.SECURITYGROUP) and port_security == 'mac_ip'):
                # For now let's not apply security groups to dhcp ports
                if (p.get('device_owner') == 'network:dhcp'
                    and context.is_admin):
                    pass
                elif not cfg.CONF.SECURITYGROUP.proxy_mode:
                    port['port'][ext_sg.SECURITYGROUP] = [default_sg]

            elif p.get(ext_sg.SECURITYGROUP) and port_security != 'mac_ip':
                raise psec.NoPortSecurityWithSecurityGroups()

            port_data = port['port'].copy()
            port_data['admin_state_up'] = requested_admin_state
            port_create_func = self._port_drivers['create'].get(
                port_data['device_owner'],
                self._port_drivers['create']['default'])

            port_create_func(context, port_data)
        except Exception as e:
            # failed to create port in NVP delete port from quantum_db
            LOG.exception("An exception occured while creating the "
                          "logical port %s on NVP", port['port']['id'])
            # FIXME(salvatore-orlando): This check is already performed in
            # drivers. It is not redundant because of the extra checks
            # we peform here.
            try:
                super(NvpPluginV2, self).delete_port(context,
                                                     port['port']['id'])
            except q_exc.PortNotFound:
                LOG.warning("The delete port operation faile for %s. This "
                            "means the port was already deleted",
                            port['port']['id'])
            raise e

        # Saves the security group that port is on.
        if p.get(ext_sg.SECURITYGROUP) and port_security == 'mac_ip':
            self._process_port_create_security_group(context, p['id'],
                                                     p[ext_sg.SECURITYGROUP])

        self._process_port_security_create(context, p)
        self._process_port_queue_mapping(context, p)
        # update port on Quantum DB with admin_state_up True
        # TODO only if requested_admin_state is True
        port_update = {"port": {"admin_state_up": requested_admin_state}}
        port = super(NvpPluginV2, self).update_port(context,
                                                    port["port"]["id"],
                                                    port_update)
        self._extend_port_dict_security_group(context, port)
        self._extend_port_dict_port_security(context, port)
        self._extend_port_qos_queue(context, port)

        LOG.debug("create_port completed for tenant %s, on network %s."
                  "New port id:%s" % (tenant_id, port_data['network_id'],
                                      port_data['id']))
        return port

    def update_port(self, context, id, port):
        """
        Updates the properties of a specific port on the
        specified Virtual Network.
        Returns:

        {"id": uuid represeting the port.
         "network_id": uuid of network.
         "tenant_id": tenant_id
         "mac_address": mac address to use on this port.
         "admin_state_up": sets admin state of port. if down, port
                           does not forward packets.
         "status": dicates whether port is currently operational
                   (limit values to "ACTIVE", "DOWN", "BUILD", and
                   "ERROR"?)
        "fixed_ips": list of subnet ID's and IP addresses to be used on
                     this port
        "device_id": identifies the device (e.g., virtual server) using
                     this port.
        }

        :raises: exception.StateInvalid
        :raises: exception.PortNotFound
        """
        params = {}
        rollback_port = super(NvpPluginV2, self).get_port(context, id)

        # If value is not passed in it gets assigned False
        if psec.PORTSECURITY in port['port']:
            update_port_security = port['port'].get(psec.PORTSECURITY)
        else:
            update_port_security = False

        if ext_sg.SECURITYGROUP in port['port']:
            update_security_groups = port['port'].get(ext_sg.SECURITYGROUP)
            if (update_security_groups == [] or
                update_security_groups == "None"):
                update_security_groups = None
        else:
            update_security_groups = False

        # TODO(salvatore-orlando): We might need transaction management here
        # But the change for metadata support should not be too disruptive
        fixed_ip_data = port['port'].get('fixed_ips')
        if (cfg.CONF.metadata_dhcp_host_route and
            rollback_port.get('device_owner') == 'network:dhcp' and
            fixed_ip_data):
                self._ensure_metadata_host_route(context,
                                                 fixed_ip_data[0],
                                                 is_delete=True)
        ret_port = super(NvpPluginV2, self).update_port(context, id, port)
        # Copy of addition fields we want to update but
        # are not in the _make_port-dict
        ret_port.update(port['port'])

        # validate the update remove_ip/port_security
        if update_port_security:
            ret_port[psec.PORTSECURITY] = update_port_security
        else:
            ret_port[psec.PORTSECURITY] = (
                self._get_port_security_binding(context, ret_port['id']))

        ret_port[psec.PORTSECURITY] = self._validate_port_security(context,
                                                                   ret_port)

        # validate security groups with port security type
        if ret_port[psec.PORTSECURITY] != 'mac_ip':
            if (update_security_groups is False):
                filters = {'port_id': [id]}
                security_groups = (
                    super(NvpPluginV2, self)._get_port_security_group_bindings(
                        context, filters))
                if security_groups:
                    raise ext_sg.SecurityGroupNoIpMacPortUpdate()
            elif update_security_groups:
                raise ext_sg.SecurityGroupNoIpMacPortUpdate()

        # Request to set port security is mac or off
        if (ret_port[psec.PORTSECURITY] in ['mac', 'off']):
            # update_security_groups will be set to None if we are removing
            # them from a port. if update_security_groups == False there are
            # no updates for the the security groups but since the request
            # turns port_security to mac/off we need to confirm there are
            # not any security_groups on the port because security groups
            # require port_security mac_ip
            if (update_security_groups is False):
                filters = {'port_id': [id]}
                security_groups = (
                    super(NvpPluginV2, self)._get_port_security_group_bindings(
                        context, filters))
                if security_groups:
                    raise psec.SecurityGroupsOnPortCannotRemovePortSecurity()
            elif update_security_groups:
                raise psec.SecurityGroupsOnPortCannotRemovePortSecurity()

        # adding security groups
        if update_security_groups:
            # get the port_security type on port if not in update
            if ret_port[psec.PORTSECURITY] != 'mac_ip':
                raise psec.PortSecurityNotEnabled()
            ret_port[ext_sg.SECURITYGROUP] = (
                self._validate_security_groups_on_port(context, port))
        # didn't modify
        elif update_security_groups is False:
            filters = {'port_id': [id]}
            security_groups = (
                super(NvpPluginV2, self)._get_port_security_group_bindings(
                    context, filters))
            ret_port[ext_sg.SECURITYGROUP] = security_groups
        # delete security group on port
        else:
            ret_port[ext_sg.SECURITYGROUP] = None

        # Qos
        ret_port[ext_qos.QUEUE] = self._check_for_queue_and_create(context,
                                                                   ret_port)

        # TODO Can this use a transaction instead?
        try:
            nvp_id = nicira_db.get_nvp_port_id(context.session, id)
            params["cluster"] = self.default_cluster
            params["port"] = ret_port
            do_port_security = (ret_port['device_owner'] !=
                                l3_db.DEVICE_OWNER_ROUTER_INTF)
            params['do_port_security'] = do_port_security
            nvplib.update_port(ret_port["network_id"],
                               nvp_id, **params)
            LOG.debug("update_port() completed for tenant: %s" %
                      context.tenant_id)

        except:
            super(NvpPluginV2, self).update_port(context, id,
                                                 {'port': rollback_port})

        # TODO have some kind of roll back for this
        if (update_security_groups is not False):
            # delete the port binding and read it with the new rules.
            self._delete_port_security_group_bindings(context, id)
            self._process_port_create_security_group(context, id,
                                                     ret_port.get(
                                                     ext_sg.SECURITYGROUP))

        if update_port_security is not False:
            self._delete_port_security_bindings(context, id)
            self._process_port_security_create(context, ret_port)
        self._extend_port_dict_port_security(context, ret_port)
        self._extend_port_dict_security_group(context, ret_port)
        return ret_port

    def delete_port(self, context, id, l3_port_check=True):
        """
        Deletes a port on a specified Virtual Network,
        if the port contains a remote interface attachment,
        the remote interface is first un-plugged and then the port
        is deleted.

        :returns: None
        :raises: exception.PortInUse
        :raises: exception.PortNotFound
        :raises: exception.NetworkNotFound
        """
        queue = self._get_port_queue_bindings(context, {'port_id': [id]})
        # if needed, check to see if this is a port owned by
        # and l3-router.  If so, we should prevent deletion here
        if l3_port_check:
            self.prevent_l3_port_deletion(context, id)
        quantum_db_port = self._get_port(context, id)

        port_delete_func = self._port_drivers['delete'].get(
            quantum_db_port.device_owner,
            self._port_drivers['delete']['default'])

        port_delete_func(context, quantum_db_port)
        self.disassociate_floatingips(context, id)
        with context.session.begin(subtransactions=True):
            if (cfg.CONF.metadata_dhcp_host_route and
                quantum_db_port.device_owner == 'network:dhcp'):
                    self._ensure_metadata_host_route(
                        context, quantum_db_port.fixed_ips[0], is_delete=True)
            super(NvpPluginV2, self).delete_port(context, id)

            # Delete qos queue if possible
            if len(queue):
                self.delete_qos_queue(context, queue[0]['queue_id'], False)

    def get_port(self, context, id, fields=None):
        """
        This method allows the user to retrieve a remote interface
        that is attached to this particular port.

        :returns: a mapping sequence with the following signature:
                    {'port-id': uuid representing the port on
                                 specified quantum network
                     'attachment': uuid of the virtual interface
                                   bound to the port, None otherwise
                     'port-op-status': operational status of the port
                     'port-state': admin status of the port
                    }
        :raises: exception.PortNotFound
        :raises: exception.NetworkNotFound
        """

        quantum_db_port = super(NvpPluginV2, self).get_port(context,
                                                            id, fields)
        self._extend_port_dict_security_group(context, quantum_db_port)
        self._extend_port_dict_port_security(context, quantum_db_port)
        self._extend_port_qos_queue(context, quantum_db_port)
        if self._network_is_external(context, quantum_db_port['network_id']):
            return quantum_db_port

        nvp_id = nicira_db.get_nvp_port_id(context.session, id)
        #TODO: pass the appropriate cluster here
        port = nvplib.get_logical_port_status(
            self.default_cluster, quantum_db_port['network_id'], nvp_id)
        quantum_db_port["admin_state_up"] = port["admin_status_enabled"]
        if port["fabric_status_up"]:
            quantum_db_port["status"] = constants.PORT_STATUS_ACTIVE
        else:
            quantum_db_port["status"] = constants.PORT_STATUS_DOWN

        LOG.debug("Port details for tenant %s: %s" %
                  (context.tenant_id, quantum_db_port))
        return quantum_db_port

    def create_router(self, context, router):
        # NOTE(salvatore-orlando): We completely override this method in
        # order to be able to use the NVP ID as Quantum ID
        # TODO(salvatore-orlando): Propose upstream patch for allowing
        # 3rd parties to specify IDs as we do with l2 plugin
        r = router['router']
        has_gw_info = False
        tenant_id = self._get_tenant_id_for_create(context, r)
        # default value to set - nvp wants it (even if we don't have it)
        nexthop = '1.1.1.1'
        try:
            # if external gateway info are set, then configure nexthop to
            # default external gateway
            if 'external_gateway_info' in r and r.get('external_gateway_info'):
                has_gw_info = True
                gw_info = r['external_gateway_info']
                del r['external_gateway_info']
                # The following DB read will be performed again when updating
                # gateway info. This is not great, but still better than
                # creating NVP router here and updating it later
                network_id = (gw_info.get('network_id', None) if gw_info
                              else None)
                if network_id:
                    ext_net = self._get_network(context, network_id)
                    if not self._network_is_external(context, network_id):
                        msg = ("Network %s is not a valid external "
                               "network" % network_id)
                        raise q_exc.BadRequest(resource='router', msg=msg)
                    if len(ext_net.subnets):
                        ext_subnet = ext_net.subnets[0]
                        nexthop = ext_subnet.gateway_ip
            cluster = self._find_target_cluster(router)
            lrouter = nvplib.create_lrouter(cluster, tenant_id,
                                            router['router']['name'],
                                            nexthop)
            # Use NVP identfier for Quantum resource
            router['router']['id'] = lrouter['uuid']
        except NvpApiClient.NvpApiException:
            raise nvp_exc.NvpPluginException(
                err_desc="Unable to create logical router on NVP Platform")
        if not has_gw_info:
            fake_port_data = {'fake_ext_gw': True}
            self._create_and_attach_router_port(cluster,
                                                context,
                                                lrouter['uuid'],
                                                fake_port_data,
                                                "L3GatewayAttachment",
                                                cluster.default_l3_gw_uuid)

        with context.session.begin(subtransactions=True):
            router_db = l3_db.Router(id=lrouter['uuid'],
                                     tenant_id=tenant_id,
                                     name=r['name'],
                                     admin_state_up=r['admin_state_up'],
                                     status="ACTIVE")
            context.session.add(router_db)
            if has_gw_info:
                self._update_router_gw_info(context, router_db['id'], gw_info)
        return self._make_router_dict(router_db)

    def update_router(self, context, id, router):
        try:
            # Either nexthop is updated or should be kept as it was before
            r = router['router']
            nexthop = None
            if 'external_gateway_info' in r and r.get('external_gateway_info'):
                gw_info = r['external_gateway_info']
                # The following DB read will be performed again when updating
                # gateway info. This is not great, but still better than
                # creating NVP router here and updating it later
                network_id = (gw_info.get('network_id', None) if gw_info
                              else None)
                if network_id:
                    ext_net = self._get_network(context, network_id)
                    if not self._network_is_external(context, network_id):
                        msg = ("Network %s is not a valid external "
                               "network" % network_id)
                        raise q_exc.BadRequest(resource='router', msg=msg)
                    if len(ext_net.subnets):
                        ext_subnet = ext_net.subnets[0]
                        nexthop = ext_subnet.gateway_ip
            cluster = self._find_target_cluster(router)
            nvplib.update_lrouter(cluster, id,
                                  router['router'].get('name'), nexthop)
        except NvpApiClient.ResourceNotFound:
            raise nvp_exc.NvpPluginException(
                err_desc="Logical router %s not found on NVP Platform" % id)
        except NvpApiClient.NvpApiException:
            raise nvp_exc.NvpPluginException(
                err_desc="Unable to update logical router on NVP Platform")
        return super(NvpPluginV2, self).update_router(context, id, router)

    def delete_router(self, context, id):
        with context.session.begin(subtransactions=True):
            super(NvpPluginV2, self).delete_router(context, id)
            # If removal is successful in Quantum it should be so on
            # the NVP platform too - otherwise the transaction should
            # be automatically aborted
            # TODO(salvatore-orlando): Extend the object models in order to
            # allow an extra field for storing the cluster information
            # together with the resource
            try:
                nvplib.delete_lrouter(self.default_cluster, id)
            except NvpApiClient.ResourceNotFound:
                raise nvp_exc.NvpPluginException(
                    err_desc=("Logical router %s not found "
                              "on NVP Platform" % id))
            except NvpApiClient.NvpApiException:
                raise nvp_exc.NvpPluginException(
                    err_desc=("Unable to update logical router"
                              "on NVP Platform"))

    def get_router(self, context, id, fields=None):
        router = self._get_router(context, id)
        try:
            # FIXME(salvatore-orlando): We need to
            # find the appropriate cluster!
            cluster = self.default_cluster
            lrouter = nvplib.get_lrouter(cluster, id)
            router_op_status = constants.NET_STATUS_DOWN
            relations = lrouter.get('_relations')
            if relations:
                lrouter_status = relations.get('LogicalRouterStatus')
            # FIXME(salvatore-orlando): Being unable to fetch the
            # logical router status should be an exception.
            if (lrouter_status and
                not lrouter_status.get('fabric_status', None)):
                router_op_status = constants.NET_STATUS_DOWN
            LOG.debug("Current router status:%s;"
                      "Status in Quantum DB:%s",
                      router_op_status, router.status)
            if router_op_status != router.status:
                # update the network status
                with context.session.begin(subtransactions=True):
                    router.status = router_op_status
        except NvpApiClient.NvpApiException:
            err_msg = "Unable to get logical router"
            LOG.exception(err_msg)
            raise nvp_exc.NvpPluginException(err_desc=err_msg)
        return self._make_router_dict(router, fields)

    def get_routers(self, context, filters=None, fields=None):
        router_query = self._apply_filters_to_query(
            self._model_query(context, l3_db.Router),
            l3_db.Router, filters)
        routers = router_query.all()
        # Query routers on NVP for updating operational status
        if context.is_admin and not filters.get("tenant_id"):
            tenant_id = None
        elif 'tenant_id' in filters:
            tenant_id = filters.get('tenant_id')[0]
            del filters['tenant_id']
        else:
            tenant_id = context.tenant_id
        try:
            nvp_lrouters = nvplib.get_lrouters(self.default_cluster,
                                               tenant_id,
                                               fields)
        except NvpApiClient.NvpApiException:
            err_msg = "Unable to get logical routers from NVP controller"
            LOG.exception(err_msg)
            raise nvp_exc.NvpPluginException(err_desc=err_msg)

        nvp_lrouters_dict = {}
        for nvp_lrouter in nvp_lrouters:
            nvp_lrouters_dict[nvp_lrouter['uuid']] = nvp_lrouter
        for router in routers:
            nvp_lrouter = nvp_lrouters_dict.get(router['id'])
            if nvp_lrouter:
                if (nvp_lrouter["_relations"]["LogicalRouterStatus"]
                        ["fabric_status"]):
                    router.status = constants.NET_STATUS_ACTIVE
                else:
                    router.status = constants.NET_STATUS_DOWN
                nvp_lrouters.remove(nvp_lrouter)

        # do not make the case in which switches are found in NVP
        # but not in Quantum catastrophic.
        if len(nvp_lrouters):
            LOG.warning("Found %s logical routers not bound "
                        "to Quantum routers. Quantum and NVP are "
                        "potentially out of sync", len(nvp_lrouters))

        LOG.debug("get_routers() completed for tenant %s" % context.tenant_id)

        return [self._make_router_dict(router, fields)
                for router in routers]

    def add_router_interface(self, context, router_id, interface_info):
        router_iface_info = super(NvpPluginV2, self).add_router_interface(
            context, router_id, interface_info)
        # If the above operation succeded interface_info contains a reference
        # to a logical switch port
        port_id = router_iface_info['port_id']
        subnet_id = router_iface_info['subnet_id']
        # Add port to the logical router as well
        # TODO(salvatore-orlando): Identify the appropriate cluster, instead
        # of always defaulting to self.default_cluster
        cluster = self.default_cluster
        # The owner of the router port is always the same as the owner of the
        # router. Use tenant_id from the port instead of fetching more records
        # from the Quantum database
        port = self._get_port(context, port_id)
        # Find the NVP port corresponding to quantum port_id
        results = nvplib.query_lswitch_lports(
            cluster, '*',
            filters={'tag': port_id, 'tag_scope': 'q_port_id'})
        if len(results):
            ls_port = results[0]
        else:
            raise nvp_exc.NvpPluginException(
                err_desc=("The port %s, connected to the router %s "
                          "was not found on the NVP backend"
                          % (port_id, router_id)))

        # Create logical router port and patch attachment
        self._create_and_attach_router_port(
            cluster, context, router_id, port,
            "PatchAttachment", ls_port['uuid'],
            subnet_ids=[subnet_id])

        # If there is an external gateway we need to configure the SNAT rule.
        # Fetch router from DB
        router = self._get_router(context, router_id)
        gw_port = router.gw_port
        if gw_port:
            # There is a change gw_port might have multiple IPs
            # In that case we will consider only the first one
            if gw_port.get('fixed_ips'):
                snat_ip = gw_port['fixed_ips'][0]['ip_address']
                subnet = self._get_subnet(context, subnet_id)
                nvplib.create_lrouter_snat_rule(
                    cluster, router_id, snat_ip, snat_ip,
                    source_ip_addresses=subnet['cidr'])

        LOG.debug("add_router_interface completed for subnet:%s and router:%s",
                  subnet_id, router_id)
        return router_iface_info

    def remove_router_interface(self, context, router_id, interface_info):
        # TODO(salvatore-orlando): Usual thing about cluster selection
        cluster = self.default_cluster
        # The code below is duplicated from base class, but comes handy
        # as we need to retrieve the router port id before removing the port
        subnet = None
        subnet_id = None
        if 'port_id' in interface_info:
            port_id = interface_info['port_id']
            # find subnet_id - it is need for removing the SNAT rule
            port = self._get_port(context, port_id)
            if port.get('fixed_ips'):
                subnet_id = port['fixed_ips'][0]['subnet_id']
        elif 'subnet_id' in interface_info:
            subnet_id = interface_info['subnet_id']
            subnet = self._get_subnet(context, subnet_id)
            rport_qry = context.session.query(models_v2.Port)
            ports = rport_qry.filter_by(
                device_id=router_id,
                device_owner=l3_db.DEVICE_OWNER_ROUTER_INTF,
                network_id=subnet['network_id']).all()
            for p in ports:
                if p['fixed_ips'][0]['subnet_id'] == subnet_id:
                    port_id = p['id']
                    break
        results = nvplib.query_lswitch_lports(
            cluster, '*', relations="LogicalPortAttachment",
            filters={'tag': port_id, 'tag_scope': 'q_port_id'})
        if len(results):
            lport = results[0]
            attachment_data = lport['_relations'].get('LogicalPortAttachment')
            lrouter_port_id = (attachment_data and
                               attachment_data.get('peer_port_uuid'))
        else:
            LOG.warning("The port %s, connected to the router %s "
                        "was not found on the NVP backend",
                        port_id, router_id)
        # Finally remove the data from the Quantum DB
        # This will also destroy the port on the logical switch
        super(NvpPluginV2, self).remove_router_interface(context,
                                                         router_id,
                                                         interface_info)
        # Destroy router port (no need to unplug the attachment)
        # FIXME(salvatore-orlando): In case of failures in the Quantum plugin
        # this migth leave a dangling port. We perform the operation here
        # to leverage validation performed in the base class
        if not lrouter_port_id:
            LOG.warning("Unable to find NVP logical router port corresponding "
                        "to Quantum port id:%s (NVP id:%s). Was this port "
                        "ever paired with a logical router?",
                        port_id, lport['uuid'])
            return
        try:
            if not subnet:
                subnet = self._get_subnet(context, subnet_id)
            router = self._get_router(context, router_id)
            # Remove SNAT rule if external gateway is configured
            if router.gw_port:
                nvplib.delete_nat_rules_by_match(
                    cluster, router_id, "SourceNatRule",
                    max_num_expected=1, min_num_expected=1,
                    source_ip_addresses=subnet['cidr'])
            nvplib.delete_router_lport(cluster, router_id, lrouter_port_id)
        except NvpApiClient.ResourceNotFound:
            raise nvp_exc.NvpPluginException(
                err_desc=("Logical router port resource %s not found "
                          "on NVP platform", lrouter_port_id))
        except NvpApiClient.NvpApiException:
            raise nvp_exc.NvpPluginException(
                err_desc=("Unable to update logical router"
                          "on NVP Platform"))

    def _retrieve_and_delete_nat_rules(self, floating_ip_address,
                                       internal_ip, router_id,
                                       min_num_rules_expected=0):
        #TODO(salvatore-orlando): Multiple cluster support
        cluster = self.default_cluster
        try:
            nvplib.delete_nat_rules_by_match(
                cluster, router_id, "DestinationNatRule",
                max_num_expected=1,
                min_num_expected=min_num_rules_expected,
                destination_ip_addresses=floating_ip_address)

            # Remove SNAT rule associated with the single fixed_ip
            # to floating ip
            nvplib.delete_nat_rules_by_match(
                cluster, router_id, "SourceNatRule",
                max_num_expected=1,
                min_num_expected=min_num_rules_expected,
                source_ip_addresses=internal_ip)
        except NvpApiClient.NvpApiException:
            LOG.exception("An error occurred while removing NAT rules "
                          "on the NVP platform for floating ip:%s",
                          floating_ip_address)
            raise
        except nvp_exc.NvpNatRuleMismatch:
            # Do not surface to the user
            LOG.warning("An incorrect number of matching NAT rules "
                        "was found on the NVP platform")

    def _update_fip_assoc(self, context, fip, floatingip_db, external_port):
        """ Update floating IP association data.

        Overrides method from base class.
        The method is augmented for creating NAT rules in the process.

        """
        if (('fixed_ip_address' in fip and fip['fixed_ip_address']) and
            not ('port_id' in fip and fip['port_id'])):
            msg = "fixed_ip_address cannot be specified without a port_id"
            raise q_exc.BadRequest(resource='floatingip', msg=msg)
        port_id = internal_ip = router_id = None
        if 'port_id' in fip and fip['port_id']:
            port_qry = context.session.query(l3_db.FloatingIP)
            try:
                port_qry.filter_by(fixed_port_id=fip['port_id']).one()
                raise l3.FloatingIPPortAlreadyAssociated(
                    port_id=fip['port_id'])
            except sa_exc.NoResultFound:
                pass
            port_id, internal_ip, router_id = self.get_assoc_data(
                context,
                fip,
                floatingip_db['floating_network_id'])

        cluster = self._find_target_cluster(fip)
        floating_ip = floatingip_db['floating_ip_address']
        # Retrieve and delete existing NAT rules, if any
        if not router_id and floatingip_db.get('fixed_port_id'):
            # This happens if we're disassociating. Need to explicitly
            # find the router serving this floating IP
            tmp_fip = fip.copy()
            tmp_fip['port_id'] = floatingip_db['fixed_port_id']
            _pid, internal_ip, router_id = self.get_assoc_data(
                context, tmp_fip, floatingip_db['floating_network_id'])
        self._retrieve_and_delete_nat_rules(floating_ip,
                                            internal_ip,
                                            router_id)
        # Re-create NAT rules only if a port id is specified
        if 'port_id' in fip and fip['port_id']:
            try:
                # Create new NAT rules
                nvplib.create_lrouter_dnat_rule(
                    cluster, router_id, internal_ip, internal_ip,
                    destination_ip_addresses=floating_ip)
                # setup snat rule such that src ip of a IP packet when using
                # floating is the floating ip itself.
                nvplib.create_lrouter_snat_rule(
                    cluster, router_id, floating_ip, floating_ip,
                    source_ip_addresses=internal_ip)
            except NvpApiClient.NvpApiException:
                LOG.exception("An error occurred while creating NAT rules "
                              "on the NVP platform for floating ip:%s mapped "
                              "to internal ip:%s", floating_ip, internal_ip)
                raise

        floatingip_db.update({'fixed_ip_address': internal_ip,
                              'fixed_port_id': port_id,
                              'router_id': router_id})

    def delete_floatingip(self, context, id):
        fip_db = self._get_floatingip(context, id)
        # Check whether the floating ip is associated or not
        if fip_db.fixed_port_id:
            internal_port = self._get_port(context, fip_db.fixed_port_id)
            for fixed_ip in internal_port['fixed_ips']:
                if fixed_ip['ip_address'] == fip_db.fixed_ip_address:
                    internal_subnet_id = fixed_ip['subnet_id']
            router_id = self._get_router_for_internal_subnet(
                context, internal_port, internal_subnet_id)
            self._retrieve_and_delete_nat_rules(fip_db.floating_ip_address,
                                                fip_db.fixed_ip_address,
                                                router_id,
                                                min_num_rules_expected=1)
        return super(NvpPluginV2, self).delete_floatingip(context, id)

    def disassociate_floatingips(self, context, port_id):
        try:
            fip_qry = context.session.query(l3_db.FloatingIP)
            fip_db = fip_qry.filter_by(fixed_port_id=port_id).one()
            internal_port = self._get_port(context, port_id)
            for fixed_ip in internal_port['fixed_ips']:
                if fixed_ip['ip_address'] == fip_db.fixed_ip_address:
                    internal_subnet_id = fixed_ip['subnet_id']
            router_id = self._get_router_for_internal_subnet(
                context, internal_port, internal_subnet_id)
            self._retrieve_and_delete_nat_rules(fip_db.floating_ip_address,
                                                fip_db.fixed_ip_address,
                                                router_id,
                                                min_num_rules_expected=1)
            # And finally update the database
            fip_db.update({'fixed_port_id': None,
                           'fixed_ip_address': None,
                           'router_id': None})
        except sa_exc.NoResultFound:
            return

    def get_plugin_version(self):
        return PLUGIN_VERSION
