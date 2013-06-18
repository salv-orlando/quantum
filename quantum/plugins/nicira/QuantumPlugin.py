# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Nicira, Inc.
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# @author: Somik Behera, Nicira Networks, Inc.
# @author: Brad Hall, Nicira Networks, Inc.
# @author: Aaron Rosen, Nicira Networks, Inc.


import logging
import os

from oslo.config import cfg
from sqlalchemy.orm import exc as sa_exc
import webob.exc

from quantum.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from quantum.api.v2 import attributes as attr
from quantum.api.v2 import base
from quantum.common import constants
from quantum.common import exceptions as q_exc
from quantum.common import rpc as q_rpc
from quantum.common import topics
from quantum.common import utils
from quantum import context as q_context
from quantum.db import agents_db
from quantum.db import agentschedulers_db
from quantum.db import api as db
from quantum.db import db_base_plugin_v2
from quantum.db import dhcp_rpc_base
from quantum.db import l3_db
from quantum.db import models_v2
from quantum.db import portsecurity_db
from quantum.db import quota_db  # noqa
from quantum.db import securitygroups_db
from quantum.extensions import l3
from quantum.extensions import portsecurity as psec
from quantum.extensions import providernet as pnet
from quantum.extensions import securitygroup as ext_sg
from quantum.openstack.common import excutils
from quantum.openstack.common import importutils
from quantum.openstack.common import rpc
from quantum.plugins.nicira.common import config  # noqa
from quantum.plugins.nicira.common import exceptions as nvp_exc
from quantum.plugins.nicira.common import metadata_access as nvp_meta
from quantum.plugins.nicira.common import securitygroups as nvp_sec
from quantum.plugins.nicira.drivers import nvp_synch_driver
from quantum.plugins.nicira.extensions import nvp_networkgw as networkgw
from quantum.plugins.nicira.extensions import nvp_qos as ext_qos
from quantum.plugins.nicira import nicira_db
from quantum.plugins.nicira import nicira_networkgw_db as networkgw_db
from quantum.plugins.nicira import nicira_qos_db as qos_db
from quantum.plugins.nicira import nvp_cluster
from quantum.plugins.nicira.nvp_plugin_version import PLUGIN_VERSION
from quantum.plugins.nicira import NvpApiClient
from quantum.plugins.nicira import nvplib


LOG = logging.getLogger("QuantumPlugin")
NVP_NOSNAT_RULES_ORDER = 10
NVP_FLOATINGIP_NAT_RULES_ORDER = 224
NVP_EXTGW_NAT_RULES_ORDER = 255
NVP_EXT_PATH = os.path.join(os.path.dirname(__file__), 'extensions')

# Operation status for NVP object being deleted
STATUS_DELETING = 'deleting'


# Provider network extension - allowed network types for the NVP Plugin
class NetworkTypes:
    """Allowed provider network types for the NVP Plugin."""
    L3_EXT = 'l3_ext'
    STT = 'stt'
    GRE = 'gre'
    FLAT = 'flat'
    VLAN = 'vlan'


def create_nvp_cluster(cluster_opts, concurrent_connections,
                       nvp_gen_timeout):
    # NOTE(armando-migliaccio): remove this block once we no longer
    # want to support deprecated options in the nvp config file
    # ### BEGIN
    config.register_deprecated(cfg.CONF)
    # ### END
    cluster = nvp_cluster.NVPCluster(**cluster_opts)
    api_providers = [ctrl.split(':') + [True]
                     for ctrl in cluster.nvp_controllers]
    cluster.api_client = NvpApiClient.NVPApiHelper(
        api_providers, cluster.nvp_user, cluster.nvp_password,
        request_timeout=cluster.req_timeout,
        http_timeout=cluster.http_timeout,
        retries=cluster.retries,
        redirects=cluster.redirects,
        concurrent_connections=concurrent_connections,
        nvp_gen_timeout=nvp_gen_timeout)
    return cluster


class NVPRpcCallbacks(dhcp_rpc_base.DhcpRpcCallbackMixin):

    # Set RPC API version to 1.0 by default.
    RPC_API_VERSION = '1.0'

    def create_rpc_dispatcher(self):
        '''Get the rpc dispatcher for this manager.

        If a manager would like to set an rpc API version, or support more than
        one class as the target of rpc messages, override this method.
        '''
        return q_rpc.PluginRpcDispatcher([self,
                                          agents_db.AgentExtRpcCallback()])


class NvpPluginV2(db_base_plugin_v2.QuantumDbPluginV2,
                  l3_db.L3_NAT_db_mixin,
                  portsecurity_db.PortSecurityDbMixin,
                  securitygroups_db.SecurityGroupDbMixin,
                  networkgw_db.NetworkGatewayMixin,
                  qos_db.NVPQoSDbMixin,
                  nvp_sec.NVPSecurityGroups,
                  nvp_meta.NvpMetadataAccess,
                  agentschedulers_db.AgentSchedulerDbMixin):
    """L2 Virtual network plugin.

    NvpPluginV2 is a Quantum plugin that provides L2 Virtual Network
    functionality using NVP.
    """

    supported_extension_aliases = ["provider", "quotas", "port-security",
                                   "router", "security-group", "nvp-qos",
                                   "network-gateway"]

    __native_bulk_support = True

    # Map nova zones to cluster for easy retrieval
    novazone_cluster_map = {}

    port_security_enabled_update = "update_port:port_security_enabled"

    def _create_network_handler(self, context, network_data, response):
        """Helper function for handling create_network responses.

        This function must be passed to the NVP driver.
        """
        with context.session.begin(subtransactions=True):
            # NOTE(salv-orlando): Consider adding nvp mappings
            # for lswitches to the quantum db
            net = self._get_network(context, network_data['id'])
            net['status'] = constants.NET_STATUS_ACTIVE

    def _delete_network_handler(self, context, network_data, ports_to_delete):
        """Helper function for handling delete_network responses.

        Perform the actual removal of the network from the Quantum DB
        This function must be passed to the NVP driver.
        """
        # NOTE(salv-orlando): Try to avoid this extra load from the DB
        network = self._get_network(context, network_data['id'])
        self._delete_network(context, network, ports_to_delete)

    def _create_port_handler(self, context, port_data, response):
        """Helper function for handling create_port responses.

        This function must be passed to the NVP driver.
        """
        with context.session.begin(subtransactions=True):
            port = self._get_port(context, port_data['id'])
            if response:
                nicira_db.add_quantum_nvp_port_mapping(
                    context.session, port_data['id'], response['uuid'])
                port['status'] = constants.PORT_STATUS_ACTIVE
            else:
                port['status'] = constants.PORT_STATUS_ERROR
            # Update also the information which are going to be returned
            port_data['status'] = port['status']

    def _delete_port_handler(self, context, port_data):
        with context.session.begin(subtransactions=True):
            self.disassociate_floatingips(context, port_data['id'])
            queue = self._get_port_queue_bindings(
                context, {'port_id': [port_data['id']]})
            # Delete qos queue if possible
            if queue:
                self.delete_qos_queue(context, queue[0]['queue_id'], False)
            super(NvpPluginV2, self).delete_port(context, port_data['id'])

    def _create_router_handler(self, context, router_data, response):
        """Helper function for handling create_router responses.

        This function must be passed to the NVP driver.
        """
        with context.session.begin(subtransactions=True):
            router = self._get_router(context, router_data['id'])
            nicira_db.add_quantum_nvp_router_mapping(
                context.session, router_data['id'],
                response['uuid'], response.get('gw_port_uuid')['uuid'])
            router['status'] = constants.NET_STATUS_ACTIVE

    def _delete_router_handler(self, context, router_data):
        """Helper function for handling delete_router responses.

        Perform the actual removal of the router from the Quantum DB
        This function must be passed to the NVP driver.
        """
        router = self._get_router(context, router_data['id'])
        self._delete_router(context, router)

    def _create_network_exception_handler(self, context,
                                          network_data, exception):
        """Helper function for handling faulty create_network responses.

        This function must be passed to the NVP driver
        """
        # Regardless of the exception, delete the network
        self._delete_network(context, network_data['id'])

    def _create_port_exception_handler(self, context, port_data, exception):
        """Helper function for handling faulty create_port responses.

        This function must be passed to the NVP driver
        """
        # Regardless of the exception, delete the port
        with context.session.begin(subtransactions=True):
            self._delete_port(context, port_data['id'])

    def _create_router_exception_handler(self, context,
                                         router_data, exception):
        """Helper function for handling faulty create_router responses.

        This function must be passed to the NVP driver
        """
        # Regardless of the exception, delete the router
        self._delete_router(context, router_data)

    def _update_port_exception_handler(self, context, port_data, exception):
        """Helper function for handling faulty update_port responses.

        This function must be passed to the NVP driver
        """
        with context.session.begin(subtransactions=True):
            port_data['status'] = constants.PORT_STATUS_ERROR
            LOG.error(_("Unable to update port id: %s."), port_data['id'])

    def _update_router_exception_handler(self, context,
                                         router_data, exception):
        """Helper function for handling faulty update_router responses.

        This function must be passed to the NVP driver
        """
        with context.session.begin(subtransactions=True):
            router_data['status'] = constants.NET_STATUS_ERROR
            LOG.error(_("Unable to update router id: %s."), router_data['id'])

    def _add_router_interface_exception_handler(self, context,
                                                port_data, exception):
        """Helper function for handling faulty add_router_interface responses.

        This function must be passed to the NVP driver
        """
        # Remove the router interface from the database
        super(NvpPluginV2, self).remove_router_interface(
            context, port_data['device_id'], {'port_id': port_data['id']})

    def _associate_floating_ip_exception_handler(self, context,
                                                 fip_data, exception):
        """Helper function for handling faulty floating IP associations.

        This function must be passed to the NVP driver
        """
        pass

    def _disassociate_floating_ip_exception_handler(self, context,
                                                    fip_data, exception):
        """Helper function for handling faulty floating IP disassociations.

        This function must be passed to the NVP driver
        """
        pass

    def __init__(self, loglevel=None):
        if loglevel:
            logging.basicConfig(level=loglevel)
            nvplib.LOG.setLevel(loglevel)
            NvpApiClient.LOG.setLevel(loglevel)

        # If no api_extensions_path is provided set the following
        if not cfg.CONF.api_extensions_path:
            cfg.CONF.set_override('api_extensions_path', NVP_EXT_PATH)
        self.nvp_opts = cfg.CONF.NVP
        self.cluster = create_nvp_cluster(cfg.CONF,
                                          self.nvp_opts.concurrent_connections,
                                          self.nvp_opts.nvp_gen_timeout)

        db.configure_db()
        # Extend the fault map
        self._extend_fault_map()
        # Set up RPC interface for DHCP agent
        self.setup_rpc()
        self.network_scheduler = importutils.import_object(
            cfg.CONF.network_scheduler_driver)
        # Set this flag to false as the default gateway has not
        # been yet updated from the config file
        self._is_default_net_gw_in_sync = False

        response_handlers = {
            'create_network': self._create_network_handler,
            'delete_network': self._delete_network_handler,
            'create_port': self._create_port_handler,
            'delete_port': self._delete_port_handler,
            'create_router': self._create_router_handler,
            'delete_router': self._delete_router_handler}
        exception_handlers = {
            'create_network': self._create_network_exception_handler,
            'create_port': self._create_port_exception_handler,
            'update_port': self._update_port_exception_handler,
            'create_router': self._create_router_exception_handler,
            'add_router_interface':
            self._add_router_interface_exception_handler}
        self.driver = nvp_synch_driver.NvpSynchDriver(
            self.cluster, response_handlers, exception_handlers)

    def _ensure_default_network_gateway(self):
        if self._is_default_net_gw_in_sync:
            return
        # Add the gw in the db as default, and unset any previous default
        def_l2_gw_uuid = self.cluster.default_l2_gw_service_uuid
        try:
            ctx = q_context.get_admin_context()
            self._unset_default_network_gateways(ctx)
            if not def_l2_gw_uuid:
                return
            try:
                def_network_gw = self._get_network_gateway(ctx,
                                                           def_l2_gw_uuid)
            except sa_exc.NoResultFound:
                # Create in DB only - don't go on NVP
                def_gw_data = {'id': def_l2_gw_uuid,
                               'name': 'default L2 gateway service',
                               'devices': []}
                gw_res_name = networkgw.RESOURCE_NAME.replace('-', '_')
                def_network_gw = super(
                    NvpPluginV2, self).create_network_gateway(
                        ctx, {gw_res_name: def_gw_data})
            # In any case set is as default
            self._set_default_network_gateway(ctx, def_network_gw['id'])
            # Ensure this method is executed only once
            self._is_default_net_gw_in_sync = True
        except Exception:
            LOG.exception(_("Unable to process default l2 gw service:%s"),
                          def_l2_gw_uuid)
            raise

    def _build_ip_address_list(self, context, fixed_ips, subnet_ids=None):
        """Build ip_addresses data structure for logical router port.

        No need to perform validation on IPs - this has already been
        done in the l3_db mixin class.
        """
        ip_addresses = []
        for ip in fixed_ips:
            if not subnet_ids or (ip['subnet_id'] in subnet_ids):
                subnet = self._get_subnet(context, ip['subnet_id'])
                ip_prefix = '%s/%s' % (ip['ip_address'],
                                       subnet['cidr'].split('/')[1])
                ip_addresses.append(ip_prefix)
        return ip_addresses

    def _get_port_by_device_id(self, context, device_id, device_owner):
        """Retrieve ports associated with a specific device id.

        Used for retrieving all quantum ports attached to a given router.
        """
        port_qry = context.session.query(models_v2.Port)
        return port_qry.filter_by(
            device_id=device_id,
            device_owner=device_owner,).all()

    def _find_router_subnets_cidrs(self, context, router_id):
        """Retrieve subnets attached to the specified router."""
        ports = self._get_port_by_device_id(context, router_id,
                                            l3_db.DEVICE_OWNER_ROUTER_INTF)
        # No need to check for overlapping CIDRs
        cidrs = []
        for port in ports:
            for ip in port.get('fixed_ips', []):
                cidrs.append(self._get_subnet(context,
                                              ip.subnet_id).cidr)
        return cidrs

    def _nvp_find_lswitch_for_port(self, context, port_data):
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
            return self._handle_lswitch_selection(self.cluster, network,
                                                  network_binding, max_ports,
                                                  allow_extra_lswitches)
        except NvpApiClient.NvpApiException:
            err_desc = _("An exception occured while selecting logical "
                         "switch for the port")
            LOG.exception(err_desc)
            raise nvp_exc.NvpPluginException(err_msg=err_desc)

    def _nvp_create_port_helper(self, cluster, ls_uuid, port_data,
                                do_port_security=True):
        return nvplib.create_lport(cluster, ls_uuid, port_data['tenant_id'],
                                   port_data['id'], port_data['name'],
                                   port_data['device_id'],
                                   port_data['admin_state_up'],
                                   port_data['mac_address'],
                                   port_data['fixed_ips'],
                                   port_data[psec.PORTSECURITY],
                                   port_data[ext_sg.SECURITYGROUPS],
                                   port_data[ext_qos.QUEUE])


    def _nvp_create_l2_gw_port(self, context, port_data):
        """Create a switch port, and attach it to a L2 gateway attachment."""
        # FIXME(salvatore-orlando): On the NVP platform we do not really have
        # external networks. So if as user tries and create a "regular" VIF
        # port on an external network we are unable to actually create.
        # However, in order to not break unit tests, we need to still create
        # the DB object and return success
        if self._network_is_external(context, port_data['network_id']):
            LOG.error(_("NVP plugin does not support regular VIF ports on "
                        "external networks. Port %s will be down."),
                      port_data['network_id'])
            # No need to actually update the DB state - the default is down
            return port_data
        try:
            selected_lswitch = self._nvp_find_lswitch_for_port(context,
                                                               port_data)
            lport = self._nvp_create_port_helper(self.cluster,
                                                 selected_lswitch['uuid'],
                                                 port_data,
                                                 True)
            nicira_db.add_quantum_nvp_port_mapping(
                context.session, port_data['id'], lport['uuid'])
            nvplib.plug_l2_gw_service(
                self.cluster,
                port_data['network_id'],
                lport['uuid'],
                port_data['device_id'],
                int(port_data.get('gw:segmentation_id') or 0))
            LOG.debug(_("_nvp_create_port completed for port %(name)s "
                        "on network %(network_id)s. The new port id "
                        "is %(id)s."), port_data)
        except NvpApiClient.NvpApiException:
            # failed to create port in NVP delete port from quantum_db
            msg = (_("An exception occured while plugging the gateway "
                     "interface into network:%s") % port_data['network_id'])
            LOG.exception(msg)
            super(NvpPluginV2, self).delete_port(context, port_data["id"])
            raise q_exc.QuantumException(message=msg)

    def _extend_fault_map(self):
        """Extends the Quantum Fault Map.

        Exceptions specific to the NVP Plugin are mapped to standard
        HTTP Exceptions.
        """
        base.FAULT_MAP.update({nvp_exc.NvpInvalidNovaZone:
                               webob.exc.HTTPBadRequest,
                               nvp_exc.NvpNoMorePortsException:
                               webob.exc.HTTPBadRequest})

    def _handle_provider_create(self, context, attrs):
        # NOTE(salvatore-orlando): This method has been borrowed from
        # the OpenvSwitch plugin, altough changed to match NVP specifics.
        # It should be in the pnet extension file
        network_type = attrs.get(pnet.NETWORK_TYPE)
        physical_network = attrs.get(pnet.PHYSICAL_NETWORK)
        segmentation_id = attrs.get(pnet.SEGMENTATION_ID)
        network_type_set = attr.is_attr_set(network_type)
        physical_network_set = attr.is_attr_set(physical_network)
        segmentation_id_set = attr.is_attr_set(segmentation_id)
        if not (network_type_set or physical_network_set or
                segmentation_id_set):
            return

        err_msg = None
        if not network_type_set:
            err_msg = _("%s required") % pnet.NETWORK_TYPE
        elif network_type in (NetworkTypes.GRE, NetworkTypes.STT,
                              NetworkTypes.FLAT):
            if segmentation_id_set:
                err_msg = _("Segmentation ID cannot be specified with "
                            "flat network type")
        elif network_type == NetworkTypes.VLAN:
            if not segmentation_id_set:
                err_msg = _("Segmentation ID must be specified with "
                            "vlan network type")
            elif (segmentation_id_set and
                  not utils.is_valid_vlan_tag(segmentation_id)):
                err_msg = (_("%(segmentation_id)s out of range "
                             "(%(min_id)s through %(max_id)s)") %
                           {'segmentation_id': segmentation_id,
                            'min_id': constants.MIN_VLAN_TAG,
                            'max_id': constants.MAX_VLAN_TAG})
            else:
                # Verify segment is not already allocated
                binding = nicira_db.get_network_binding_by_vlanid(
                    context.session, segmentation_id)
                if binding:
                    raise q_exc.VlanIdInUse(vlan_id=segmentation_id,
                                            physical_network=physical_network)
        elif network_type == NetworkTypes.L3_EXT:
            if (segmentation_id_set and
                not utils.is_valid_vlan_tag(segmentation_id)):
                err_msg = (_("%(segmentation_id)s out of range "
                             "(%(min_id)s through %(max_id)s)") %
                           {'segmentation_id': segmentation_id,
                            'min_id': constants.MIN_VLAN_TAG,
                            'max_id': constants.MAX_VLAN_TAG})
        else:
            err_msg = _("%(net_type_param)s %(net_type_value)s not "
                        "supported") % {'net_type_param': pnet.NETWORK_TYPE,
                                        'net_type_value': network_type}
        if err_msg:
            raise q_exc.InvalidInput(error_message=err_msg)
        # TODO(salvatore-orlando): Validate tranport zone uuid
        # which should be specified in physical_network

    def _extend_network_dict_provider(self, context, network, binding=None):
        if not binding:
            binding = nicira_db.get_network_binding(context.session,
                                                    network['id'])
        # With NVP plugin 'normal' overlay networks will have no binding
        # TODO(salvatore-orlando) make sure users can specify a distinct
        # phy_uuid as 'provider network' for STT net type
        if binding:
            network[pnet.NETWORK_TYPE] = binding.binding_type
            network[pnet.PHYSICAL_NETWORK] = binding.phy_uuid
            network[pnet.SEGMENTATION_ID] = binding.vlan_id

    def _handle_lswitch_selection(self, cluster, network,
                                  network_binding, max_ports,
                                  allow_extra_lswitches):
        lswitches = nvplib.get_lswitches(cluster, network.id)
        try:
            # TODO(salvatore-orlando) find main_ls too!
            return [ls for ls in lswitches
                    if (ls['_relations']['LogicalSwitchStatus']
                        ['lport_count'] < max_ports)].pop(0)
        except IndexError:
            # Too bad, no switch available
            LOG.debug(_("No switch has available ports (%d checked)"),
                      len(lswitches))
        if allow_extra_lswitches:
            main_ls = [ls for ls in lswitches if ls['uuid'] == network.id]
            tag_dict = dict((x['scope'], x['tag']) for x in main_ls[0]['tags'])
            if 'multi_lswitch' not in tag_dict:
                tags = main_ls[0]['tags']
                tags.append({'tag': 'True', 'scope': 'multi_lswitch'})
                nvplib.update_lswitch(cluster,
                                      main_ls[0]['uuid'],
                                      main_ls[0]['display_name'],
                                      network['tenant_id'],
                                      tags=tags)
            selected_lswitch = nvplib.create_lswitch(
                cluster, network.tenant_id,
                "%s-ext-%s" % (network.name, len(lswitches)),
                network_binding.binding_type,
                network_binding.phy_uuid,
                network_binding.vlan_id,
                network.id)
            return selected_lswitch
        else:
            LOG.error(_("Maximum number of logical ports reached for "
                        "logical network %s"), network.id)
            raise nvp_exc.NvpNoMorePortsException(network=network.id)

    def setup_rpc(self):
        # RPC support for dhcp
        self.topic = topics.PLUGIN
        self.conn = rpc.create_connection(new=True)
        self.dispatcher = NVPRpcCallbacks().create_rpc_dispatcher()
        self.conn.create_consumer(self.topic, self.dispatcher,
                                  fanout=False)
        self.dhcp_agent_notifier = dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        # Consume from all consumers in a thread
        self.conn.consume_in_thread()

    def create_network(self, context, network):
        net_data = network['network']
        # Replace ATTR_NOT_SPECIFIED with None for each attribute
        for key, value in net_data.iteritems():
            if value is attr.ATTR_NOT_SPECIFIED:
                net_data[key] = None
        tenant_id = self._get_tenant_id_for_create(context, net_data)
        self._ensure_default_security_group(context, tenant_id)
        # Process the provider network extension
        self._handle_provider_create(context, net_data)

        with context.session.begin(subtransactions=True):
            new_net = super(NvpPluginV2, self).create_network(context,
                                                              network)
            # Ensure there's an id in net_data
            net_data['id'] = new_net['id']
            # Process port security extension
            self._process_network_create_port_security(context, net_data)
            # DB Operations for setting the network as external
            self._process_l3_create(context, net_data, new_net['id'])
            # Process QoS queue extension
            if net_data.get(ext_qos.QUEUE):
                new_net[ext_qos.QUEUE] = net_data[ext_qos.QUEUE]
                # Raises if not found
                self.get_qos_queue(context, new_net[ext_qos.QUEUE])
                self._process_network_queue_mapping(context, new_net)
                self._extend_network_qos_queue(context, new_net)
            if net_data.get(pnet.NETWORK_TYPE):
                net_binding = nicira_db.add_network_binding(
                    context.session, new_net['id'],
                    net_data.get(pnet.NETWORK_TYPE),
                    net_data.get(pnet.PHYSICAL_NETWORK),
                    net_data.get(pnet.SEGMENTATION_ID, 0))
                self._extend_network_dict_provider(context, new_net,
                                                   net_binding)
            self._extend_network_port_security_dict(context, new_net)
            self._extend_network_dict_l3(context, new_net)
        # Invoke the NVP driver
        self.driver.create_network(context, tenant_id, new_net)
        self.schedule_network(context, new_net)
        return new_net

    def delete_network(self, context, id):
        external = self._network_is_external(context, id)
        # Retrieve router interfaces ports as they might be
        # required by the NVP driver
        ports_to_delete = self._pre_delete_network_checks(context, id)
        # Update status of the network
        with context.session.begin(subtransactions=True):
            net = self._get_network(context, id)
            net['status'] = STATUS_DELETING
        # Let the driver response handler delete the network from the database
        self.driver.delete_network(
            context,
            {'id': id, l3.EXTERNAL: external},
            ports_to_delete=ports_to_delete)

    def get_network(self, context, id, fields=None):
        status = self.driver.get_network_status(id)
        with context.session.begin(subtransactions=True):
            network = self._get_network(context, id)
            network['status'] = status
            # Don't do field selection here otherwise we won't be able
            # to add provider networks fields
            net_result = self._make_network_dict(network, None)
            self._extend_network_dict_provider(context, net_result)
            self._extend_network_port_security_dict(context, net_result)
            self._extend_network_dict_l3(context, net_result)
            self._extend_network_qos_queue(context, net_result)
        return self._fields(net_result, fields)

    def get_networks(self, context, filters=None, fields=None):
        filters = filters or {}
        with context.session.begin(subtransactions=True):
            nets = super(NvpPluginV2, self).get_networks(context, filters)
            for net in nets:
                self._extend_network_dict_provider(context, net)
                self._extend_network_port_security_dict(context, net)
                self._extend_network_dict_l3(context, net)
                self._extend_network_qos_queue(context, net)
        return [self._fields(net, fields) for net in nets]

    def update_network(self, context, id, network):
        if network["network"].get("admin_state_up"):
            if network['network']["admin_state_up"] is False:
                raise q_exc.NotImplementedError(_("admin_state_up=False "
                                                  "networks are not "
                                                  "supported."))
        with context.session.begin(subtransactions=True):
            net = super(NvpPluginV2, self).update_network(context, id, network)
            if psec.PORTSECURITY in network['network']:
                self._update_network_security_binding(
                    context, id, network['network'][psec.PORTSECURITY])
            if network['network'].get(ext_qos.QUEUE):
                net[ext_qos.QUEUE] = network['network'][ext_qos.QUEUE]
                self._delete_network_queue_mapping(context, id)
                self._process_network_queue_mapping(context, net)
            self._extend_network_port_security_dict(context, net)
            self._process_l3_update(context, network['network'], id)
            self._extend_network_dict_provider(context, net)
            self._extend_network_dict_l3(context, net)
            self._extend_network_qos_queue(context, net)
        # TODO(salv-orlando): Probably restore capability for updating name
        # in nvp - might also be needed for provider networks
        return net

    def get_ports(self, context, filters=None, fields=None):
        with context.session.begin(subtransactions=True):
            ports = super(NvpPluginV2, self).get_ports(
                context, filters)
            # NOTE(salv-orlando): Extend for queue_id too?
            for port in ports:
                self._extend_port_port_security_dict(context, port)
        return ports

    def create_port(self, context, port):
        port_data = port['port']
        notify_dhcp_agent = False
        with context.session.begin(subtransactions=True):
            # The transaction will commit before the driver operation is
            # performed. Then the server might yield to anther request which
            # will read the status of this port. Hence, set it to 'build'
            # until driver operation is confirmed successful
            port['port']['status'] = constants.PORT_STATUS_BUILD
            quantum_db = super(NvpPluginV2, self).create_port(context, port)
            # Update fields obtained from quantum db (eg: MAC address)
            port["port"].update(quantum_db)
            # metadata_dhcp_host_route
            if (cfg.CONF.NVP.metadata_mode == "dhcp_host_route" and
                quantum_db.get('device_owner') == constants.DEVICE_OWNER_DHCP):
                if quantum_db.get('fixed_ips'):
                    notify_dhcp_agent = self._ensure_metadata_host_route(
                        context, quantum_db['fixed_ips'][0])
            # port security extension checks
            (port_security, has_ip) = self._determine_port_security_and_has_ip(
                context, port_data)
            port_data[psec.PORTSECURITY] = port_security
            self._process_port_security_create(context, port_data)
            # security group extension checks
            if port_security and has_ip:
                self._ensure_default_security_group_on_port(context, port)
            elif attr.is_attr_set(port_data.get(ext_sg.SECURITYGROUPS)):
                raise psec.PortSecurityAndIPRequiredForSecurityGroups()
            port_data[ext_sg.SECURITYGROUPS] = (
                self._get_security_groups_on_port(context, port))
            self._process_port_create_security_group(
                context, port_data, port_data[ext_sg.SECURITYGROUPS])
            # QoS extension checks
            port_data[ext_qos.QUEUE] = self._check_for_queue_and_create(
                context, port_data)
            self._process_port_queue_mapping(context, port_data)
            # remove since it will be added in extend based on policy
            del port_data[ext_qos.QUEUE]
            # MA VA CAC
            self._extend_port_port_security_dict(context, port_data)
            self._extend_port_qos_queue(context, port_data)

        # Peform driver operation
        net = self._get_network(context, port_data['network_id'])
        # Apply at least the provider and l3 networks extensions
        self._extend_network_dict_provider(context, net)
        self._extend_network_dict_l3(context, net)
        if port_data['device_owner'] == l3_db.DEVICE_OWNER_ROUTER_GW:
            # We need to add prefixes to ip addresses
            port_data['ip_addresses'] = self._build_ip_address_list(
                context, port_data['fixed_ips'])
            port_data['subnet_cidrs'] = self._find_router_subnets_cidrs(
                context, port_data['device_id'])
        self.driver.create_port(context, port_data, net)

        self.schedule_network(context, net)
        if notify_dhcp_agent:
            self._send_subnet_update_end(
                context, quantum_db['fixed_ips'][0]['subnet_id'])
        return port_data

    def update_port(self, context, id, port):
        delete_security_groups = self._check_update_deletes_security_groups(
            port)
        has_security_groups = self._check_update_has_security_groups(port)

        with context.session.begin(subtransactions=True):
            ret_port = super(NvpPluginV2, self).update_port(
                context, id, port)
            # copy values over - except fixed_ips as
            # they've already been processed
            port['port'].pop('fixed_ips', None)
            ret_port.update(port['port'])
            # populate port_security setting
            if psec.PORTSECURITY not in port['port']:
                ret_port[psec.PORTSECURITY] = self._get_port_security_binding(
                    context, id)
            has_ip = self._ip_on_port(ret_port)
            # checks if security groups were updated adding/modifying
            # security groups, port security is set and port has ip
            if not (has_ip and ret_port[psec.PORTSECURITY]):
                if has_security_groups:
                    raise psec.PortSecurityAndIPRequiredForSecurityGroups()
                # Update did not have security groups passed in. Check
                # that port does not have any security groups already on it.
                filters = {'port_id': [id]}
                # TODO(salv-orlando): This is probably not necessary anymore
                security_groups = (
                    super(NvpPluginV2, self)._get_port_security_group_bindings(
                        context, filters)
                )
                if security_groups and not delete_security_groups:
                    raise psec.PortSecurityPortHasSecurityGroup()

            if (delete_security_groups or has_security_groups):
                # delete the port binding and read it with the new rules.
                self._delete_port_security_group_bindings(context, id)
                sgids = self._get_security_groups_on_port(context, port)
                self._process_port_create_security_group(context, ret_port,
                                                         sgids)
            if psec.PORTSECURITY in port['port']:
                self._update_port_security_binding(
                    context, id, ret_port[psec.PORTSECURITY])

            ret_port[ext_qos.QUEUE] = self._check_for_queue_and_create(
                context, ret_port)
            # TODO(salv-orlando): try to avoid delete and process
            self._delete_port_queue_mapping(context, ret_port['id'])
            self._process_port_queue_mapping(context, ret_port)
            self._extend_port_port_security_dict(context, ret_port)

        # Invoke NVP driver
        self.driver.update_port(context, ret_port)

        return ret_port

    def delete_port(self, context, id, l3_port_check=True,
                    nw_gw_port_check=True):
        """Deletes a port on a specified Virtual Network."""
        # if needed, check to see if this is a port owned by
        # a l3 router.  If so, we should prevent deletion here
        if l3_port_check:
            self.prevent_l3_port_deletion(context, id)
        quantum_db_port = self.get_port(context, id)
        # Perform the same check for ports owned by layer-2 gateways
        if nw_gw_port_check:
            self.prevent_network_gateway_port_deletion(context,
                                                       quantum_db_port)
        # Update status of the port
        with context.session.begin(subtransactions=True):
            quantum_db_port['status'] = STATUS_DELETING

        if quantum_db_port['device_owner'] == l3_db.DEVICE_OWNER_ROUTER_GW:
            quantum_db_port['subnet_cidrs'] = self._find_router_subnets_cidrs(
                context, quantum_db_port['device_id'])
        # Let the driver response handler delete the port from the database
        # Peform driver operation
        net = self._get_network(context, quantum_db_port['network_id'])
        # Apply at least the l3 networks extensions
        self._extend_network_dict_l3(context, net)
        self.driver.delete_port(context, quantum_db_port, net)

        notify_dhcp_agent = False
        with context.session.begin(subtransactions=True):
            # metadata_dhcp_host_route
            port_device_owner = quantum_db_port['device_owner']
            if (cfg.CONF.NVP.metadata_mode == "dhcp_host_route" and
                port_device_owner == constants.DEVICE_OWNER_DHCP):
                    notify_dhcp_agent = self._ensure_metadata_host_route(
                        context, quantum_db_port['fixed_ips'][0],
                        is_delete=True)
        if notify_dhcp_agent:
            self._send_subnet_update_end(
                context, quantum_db_port['fixed_ips'][0]['subnet_id'])

    def get_port(self, context, id, fields=None):
        with context.session.begin(subtransactions=True):
            port = super(NvpPluginV2, self).get_port(context, id, fields)
            self._extend_port_port_security_dict(context, port)
            self._extend_port_qos_queue(context, port)
            if self._network_is_external(context, port['network_id']):
                return port
            port['status'] = self.driver.get_port_status(
                context, id, port['network_id'])
        return port

    def create_router(self, context, router):
        r = router['router']
        gw_info = r.get(l3_db.EXTERNAL_GW_INFO)
        tenant_id = self._get_tenant_id_for_create(context, r)
        ext_subnet = None
        if gw_info:
            # The following DB read will be performed again when updating
            # gateway info. This is not great, but still better than
            # creating NVP router and the having to remove it if something
            # goes wrong. Also, this will allow us to create the NVP
            # router and set the correct nexthop in a single call
            network_id = gw_info.get('network_id')
            if network_id:
                ext_net = self._get_network(context, network_id)
                if not self._network_is_external(context, network_id):
                    msg = (_("Network '%s' is not a valid external "
                             "network") % network_id)
                    raise q_exc.BadRequest(resource='router', msg=msg)
                if ext_net.subnets:
                    ext_subnet = ext_net.subnets[0]
                else:
                    msg = (_("No subnet found on external network "
                             "'%s'. Unable to set external gateway"),
                           network_id)
                    raise q_exc.BadRequest(resource='router', msg=msg)
        router_db = self._create_router(
            context, tenant_id, r, status=constants.NET_STATUS_BUILD)
        self.driver.create_router(context, tenant_id,
                                  router_db, ext_subnet)
        try:
            with context.session.begin(subtransactions=True):
                if gw_info:
                    self._update_router_gw_info(context,
                                                router_db['id'], gw_info)
        except Exception:
            # If anything goes wrong router must be deleted from NVP and DB
            LOG.exception(_("Unable to update external gateway info for "
                            "newly created router %(router_name)s "
                            "[%(router_id)s]. The router will be destroyed"),
                          {'router_id': router_db['id'],
                           'router_name': router_db['bname']})
            with excutils.save_and_reraise_exception():
                self.delete_router(context, router_db['id'])
            raise
        return self._make_router_dict(router_db)

    def update_router(self, context, id, router):
        r = router['router']
        # An empty EXTERNAL_GW_INFO is used for removing ext gateway
        has_gw_info = l3_db.EXTERNAL_GW_INFO in r
        gw_info = r.get(l3_db.EXTERNAL_GW_INFO)
        ext_subnet = None
        if gw_info:
            # The following DB read will be performed again when updating
            # gateway info. This is not great, but still better than
            # creating NVP router and the having to remove it if something
            # goes wrong. Also, this will allow us to create the NVP
            # router and set the correct nexthop in a single call
            network_id = gw_info.get('network_id')
            if network_id:
                ext_net = self._get_network(context, network_id)
                if not self._network_is_external(context, network_id):
                    msg = (_("Network '%s' is not a valid external "
                             "network") % network_id)
                    raise q_exc.BadRequest(resource='router', msg=msg)
                if ext_net.subnets:
                    ext_subnet = ext_net.subnets[0]
                else:
                    msg = (_("No subnet found on external network "
                             "'%s'. Unable to set external gateway"),
                           network_id)
                    raise q_exc.BadRequest(resource='router', msg=msg)
        router_db = self._update_router(context, id, r)
        self.driver.update_router(
            context, router_db, ext_subnet)
        try:
            with context.session.begin(subtransactions=True):
                if has_gw_info:
                    self._update_router_gw_info(context,
                                                router_db['id'], gw_info)
        except Exception as e:
            # TODO(salv-orlando): Need to rollback!
            LOG.exception(_("Unable to update external gateway info for "
                            "router %(router_name)s [%(router_id)s]."),
                          {'router_id': router_db['id'],
                           'router_name': router_db['name']})
            raise e
        return self._make_router_dict(router_db)

    def delete_router(self, context, id):
        router = self._get_router(context, id)
        # Ensure metadata access network is detached and destroyed
        # This will also destroy relevant objects on NVP platform.
        # TODO(salvatore-orlando): Ensure failure during metadata
        # handling are properly managed
        self._handle_metadata_access_network(context, id, do_create=False)
        self._pre_delete_router_checks(context, router)
        with context.session.begin(subtransactions=True):
            router = self._get_router(context, id)
            router['status'] = STATUS_DELETING
            self.driver.delete_router(context, {'id': id})

    def get_router(self, context, id, fields=None):
        status = self.driver.get_router_status(context, id)
        with context.session.begin(subtransactions=True):
            router = self._get_router(context, id)
            router['status'] = status
        return self._make_router_dict(router, fields)

    def add_router_interface(self, context, router_id, interface_info):
        # This call will also create the logical switch port
        router_iface_info = super(NvpPluginV2, self).add_router_interface(
            context, router_id, interface_info)

        # load required info from DB and invoke NVP driver
        port = self._get_port(context, router_iface_info['port_id'])
        subnet = self._get_subnet(context, router_iface_info['subnet_id'])
        router = self._get_router(context, router_id)
        port['ip_addresses'] = self._build_ip_address_list(
            context, port['fixed_ips'])
        self.driver.add_router_interface(context, router, port, subnet)

        # TODO(salv-orlando): Handle failures in metadata access network
        # Ensure the NVP logical router has a connection to a 'metadata access'
        # network (with a proxy listening on its DHCP port), by creating it
        # if needed.
        self._handle_metadata_access_network(context, router_id)
        LOG.debug(_("Add_router_interface completed for subnet:%(subnet_id)s "
                    "and router:%(router_id)s"),
                  {'subnet_id': subnet['id'], 'router_id': router_id})
        return router_iface_info

    def remove_router_interface(self, context, router_id, interface_info):
        # This call will also remove the logical switch port
        info = super(NvpPluginV2, self).remove_router_interface(
            context, router_id, interface_info)

        # TODO(salv-orlando): Ensure driver works fine with metadata
        # access network
        # Ensure the connection to the 'metadata access network'
        # is removed  (with the network) if this the last subnet
        # on the router
        self._handle_metadata_access_network(context, router_id)

        # Fetch info needed by the driver from the database
        subnet = self._get_subnet(context, info['subnet_id'])
        router = self._get_router(context, router_id)

        # NOTE(salvatore-orlando): If we fail here, there is nothing
        # to restore at the quantum db level, since the logical switch
        # port connected with the router has been removed anyway.
        # For this reason we won't have an exception handler.
        # However, the driver should ensure best effort to remove
        # all sorts of 'rubbish' in the backend.
        self.driver.remove_router_interface(
            context, router, {'id': info['port_id']}, subnet)

        return info

    def _remove_floatingip_address(self, context, fip_db):
        # Remove floating IP address from logical router port
        # Fetch logical port of router's external gateway
        router_id = fip_db.router_id
        nvp_gw_port_id = nvplib.find_router_gw_port(
            context, self.cluster, router_id)['uuid']
        ext_quantum_port_db = self._get_port(context.elevated(),
                                             fip_db.floating_port_id)
        nvp_floating_ips = self._build_ip_address_list(
            context.elevated(), ext_quantum_port_db['fixed_ips'])
        nvplib.update_lrouter_port_ips(self.cluster,
                                       router_id,
                                       nvp_gw_port_id,
                                       ips_to_add=[],
                                       ips_to_remove=nvp_floating_ips)

    def _update_fip_assoc(self, context, fip, floatingip_db, external_port):
        rollback_data = dict(floatingip_db).copy()
        super(NvpPluginV2, self)._update_fip_assoc(
            context, fip, floatingip_db, external_port)
        # router_id must be set if there's an association
        if not floatingip_db.router_id:
            return
        floating_ips = self._build_ip_address_list(
            context.elevated(), external_port['fixed_ips'])
        # Invoke Nvp driver
        # Re-create NAT rules only if a port id is specified
        if floatingip_db['fixed_port_id']:
            # Invoke association driver function
            self.driver.associate_floating_ip(
                context, floatingip_db, floating_ips, rollback_data)
        else:
            # Invoke disassociation driver function
            self.driver.disassociate_floating_ip(
                context, floatingip_db, floating_ips, rollback_data)

    def _disassociate_floating_ip(self, context, port_id, rollback_data):
        try:
            fip_qry = context.session.query(l3_db.FloatingIP)
            fip_db = fip_qry.filter_by(fixed_port_id=port_id).one()
            ext_quantum_port_db = self._get_port(
                context.elevated(), fip_db.floating_port_id)
            floating_ips = self._build_ip_address_list(
                context.elevated(), ext_quantum_port_db['fixed_ips'])
            self.driver.disassociate_floating_ip(
                context, fip_db, floating_ips, rollback_data)
        except sa_exc.NoResultFound:
            LOG.debug(_("The port '%s' is not associated "
                        "with any floating IP"), port_id)

    def delete_floatingip(self, context, id):
        fip_db = self._get_floatingip(context, id)
        fixed_port_id = fip_db.fixed_port_id
        super(NvpPluginV2, self).delete_floatingip(context, id)
        if not fixed_port_id:
            return
        self._disassociate_floating_ip(context, fip_db.fixed_port_id, fip_db)

    def disassociate_floatingips(self, context, port_id):
        try:
            fip_qry = context.session.query(l3_db.FloatingIP)
            rollback_data = fip_qry.filter_by(fixed_port_id=port_id).one()
        except sa_exc.NoResultFound:
            return
        except sa_exc.MultipleResultsFound:
            # should never happen
            raise Exception(_('Multiple floating IPs found for port %s')
                            % port_id)
        super(NvpPluginV2, self).disassociate_floatingips(context, port_id)
        self._disassociate_floating_ip(context, port_id, rollback_data)

    def create_network_gateway(self, context, network_gateway):
        """Create a layer-2 network gateway.

        Create the gateway service on NVP platform and corresponding data
        structures in Quantum datase.
        """
        # Ensure the default gateway in the config file is in sync with the db
        self._ensure_default_network_gateway()
        # Need to re-do authZ checks here in order to avoid creation on NVP
        gw_data = network_gateway[networkgw.RESOURCE_NAME.replace('-', '_')]
        tenant_id = self._get_tenant_id_for_create(context, gw_data)
        devices = gw_data['devices']
        # Populate default physical network where not specified
        for device in devices:
            if not device.get('interface_name'):
                device['interface_name'] = self.cluster.default_interface_name
        try:
            nvp_res = nvplib.create_l2_gw_service(self.cluster, tenant_id,
                                                  gw_data['name'], devices)
            nvp_uuid = nvp_res.get('uuid')
        except Exception:
            raise nvp_exc.NvpPluginException(
                err_msg=_("Create_l2_gw_service did not "
                          "return an uuid for the newly "
                          "created resource:%s") % nvp_res)
        gw_data['id'] = nvp_uuid
        return super(NvpPluginV2, self).create_network_gateway(context,
                                                               network_gateway)

    def delete_network_gateway(self, context, id):
        """Remove a layer-2 network gateway.

        Remove the gateway service from NVP platform and corresponding data
        structures in Quantum datase.
        """
        # Ensure the default gateway in the config file is in sync with the db
        self._ensure_default_network_gateway()
        with context.session.begin(subtransactions=True):
            try:
                super(NvpPluginV2, self).delete_network_gateway(context, id)
                nvplib.delete_l2_gw_service(self.cluster, id)
            except NvpApiClient.ResourceNotFound:
                # Do not cause a 500 to be returned to the user if
                # the corresponding NVP resource does not exist
                LOG.exception(_("Unable to remove gateway service from "
                                "NVP plaform - the resource was not found"))

    def _ensure_tenant_on_net_gateway(self, context, net_gateway):
        if not net_gateway['tenant_id']:
            net_gateway['tenant_id'] = context.tenant_id
        return net_gateway

    def get_network_gateway(self, context, id, fields=None):
        # Ensure the default gateway in the config file is in sync with the db
        self._ensure_default_network_gateway()
        # Ensure the tenant_id attribute is populated on the returned gateway
        #return self._ensure_tenant_on_net_gateway(
        #    context, super(NvpPluginV2, self).get_network_gateway(
        #        context, id, fields))
        return super(NvpPluginV2, self).get_network_gateway(context,
                                                            id, fields)

    def get_network_gateways(self, context, filters=None, fields=None):
        # Ensure the default gateway in the config file is in sync with the db
        self._ensure_default_network_gateway()
        # Ensure the tenant_id attribute is populated on returned gateways
        net_gateways = super(NvpPluginV2,
                             self).get_network_gateways(context,
                                                        filters,
                                                        fields)
        return net_gateways

    def update_network_gateway(self, context, id, network_gateway):
        # Ensure the default gateway in the config file is in sync with the db
        self._ensure_default_network_gateway()
        return super(NvpPluginV2, self).update_network_gateway(
            context, id, network_gateway)

    def connect_network(self, context, network_gateway_id,
                        network_mapping_info):
        # Ensure the default gateway in the config file is in sync with the db
        self._ensure_default_network_gateway()
        return super(NvpPluginV2, self).connect_network(
            context, network_gateway_id, network_mapping_info)

    def disconnect_network(self, context, network_gateway_id,
                           network_mapping_info):
        # Ensure the default gateway in the config file is in sync with the db
        self._ensure_default_network_gateway()
        return super(NvpPluginV2, self).disconnect_network(
            context, network_gateway_id, network_mapping_info)

    def get_plugin_version(self):
        return PLUGIN_VERSION

    def create_security_group(self, context, security_group, default_sg=False):
        """Create security group.

        If default_sg is true that means a we are creating a default security
        group and we don't need to check if one exists.
        """
        s = security_group.get('security_group')

        tenant_id = self._get_tenant_id_for_create(context, s)
        if not default_sg:
            self._ensure_default_security_group(context, tenant_id)

        nvp_secgroup = nvplib.create_security_profile(self.cluster,
                                                      tenant_id, s)
        security_group['security_group']['id'] = nvp_secgroup['uuid']
        return super(NvpPluginV2, self).create_security_group(
            context, security_group, default_sg)

    def delete_security_group(self, context, security_group_id):
        """Delete a security group.

        :param security_group_id: security group rule to remove.
        """
        with context.session.begin(subtransactions=True):
            security_group = super(NvpPluginV2, self).get_security_group(
                context, security_group_id)
            if not security_group:
                raise ext_sg.SecurityGroupNotFound(id=security_group_id)

            if security_group['name'] == 'default' and not context.is_admin:
                raise ext_sg.SecurityGroupCannotRemoveDefault()

            filters = {'security_group_id': [security_group['id']]}
            if super(NvpPluginV2, self)._get_port_security_group_bindings(
                context, filters):
                raise ext_sg.SecurityGroupInUse(id=security_group['id'])
            nvplib.delete_security_profile(self.cluster,
                                           security_group['id'])
            return super(NvpPluginV2, self).delete_security_group(
                context, security_group_id)

    def create_security_group_rule(self, context, security_group_rule):
        """Create a single security group rule."""
        bulk_rule = {'security_group_rules': [security_group_rule]}
        return self.create_security_group_rule_bulk(context, bulk_rule)[0]

    def create_security_group_rule_bulk(self, context, security_group_rule):
        """Create security group rules.

        :param security_group_rule: list of rules to create
        """
        s = security_group_rule.get('security_group_rules')
        tenant_id = self._get_tenant_id_for_create(context, s)

        # TODO(arosen) is there anyway we could avoid having the update of
        # the security group rules in nvp outside of this transaction?
        with context.session.begin(subtransactions=True):
            self._ensure_default_security_group(context, tenant_id)
            security_group_id = self._validate_security_group_rules(
                context, security_group_rule)

            # Check to make sure security group exists
            security_group = super(NvpPluginV2, self).get_security_group(
                context, security_group_id)

            if not security_group:
                raise ext_sg.SecurityGroupNotFound(id=security_group_id)
            # Check for duplicate rules
            self._check_for_duplicate_rules(context, s)
            # gather all the existing security group rules since we need all
            # of them to PUT to NVP.
            combined_rules = self._merge_security_group_rules_with_current(
                context, s, security_group['id'])
            nvplib.update_security_group_rules(self.cluster,
                                               security_group['id'],
                                               combined_rules)
            return super(
                NvpPluginV2, self).create_security_group_rule_bulk_native(
                    context, security_group_rule)

    def delete_security_group_rule(self, context, sgrid):
        """Delete a security group rule
        :param sgrid: security group id to remove.
        """
        with context.session.begin(subtransactions=True):
            # determine security profile id
            security_group_rule = (
                super(NvpPluginV2, self).get_security_group_rule(
                    context, sgrid))
            if not security_group_rule:
                raise ext_sg.SecurityGroupRuleNotFound(id=sgrid)

            sgid = security_group_rule['security_group_id']
            current_rules = self._get_security_group_rules_nvp_format(
                context, sgid, True)

            self._remove_security_group_with_id_and_id_field(
                current_rules, sgrid)
            nvplib.update_security_group_rules(
                self.cluster, sgid, current_rules)
            return super(NvpPluginV2, self).delete_security_group_rule(context,
                                                                       sgrid)

    def create_qos_queue(self, context, qos_queue, check_policy=True):
        q = qos_queue.get('qos_queue')
        self._validate_qos_queue(context, q)
        q['id'] = nvplib.create_lqueue(self.cluster,
                                       self._nvp_lqueue(q))
        return super(NvpPluginV2, self).create_qos_queue(context, qos_queue)

    def delete_qos_queue(self, context, id, raise_in_use=True):
        filters = {'queue_id': [id]}
        queues = self._get_port_queue_bindings(context, filters)
        if queues:
            if raise_in_use:
                raise ext_qos.QueueInUseByPort()
            else:
                return
        nvplib.delete_lqueue(self.cluster, id)
        return super(NvpPluginV2, self).delete_qos_queue(context, id)
