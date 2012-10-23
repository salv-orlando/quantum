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
import os
import traceback


# TODO Fix relative imports
from common import config
from nvp_plugin_version import PLUGIN_VERSION
from quantum.common import constants
from quantum.common import exceptions as exception
from quantum.common import topics
from quantum.db import api as db
from quantum.db import db_base_plugin_v2
from quantum.db import dhcp_rpc_base
from quantum.db import models_v2
from quantum.db import securitygroups_db
from quantum.extensions import securitygroup as ext_sg
from quantum.openstack.common.rpc import dispatcher
from quantum.openstack.common import cfg
from quantum.openstack.common import context
from quantum.openstack.common import rpc
import NvpApiClient
import nvplib


CONFIG_FILE = "nvp.ini"
CONFIG_FILE_PATHS = []
if os.environ.get('QUANTUM_HOME', None):
    CONFIG_FILE_PATHS.append('%s/etc' % os.environ['QUANTUM_HOME'])
CONFIG_FILE_PATHS.append("/etc/quantum/plugins/nicira")
LOG = logging.getLogger("QuantumPlugin")


def parse_config():
    """Parse the supplied plugin configuration.

    :param config: a ConfigParser() object encapsulating nvp.ini.
    :returns: A tuple: (clusters, plugin_config). 'clusters' is a list of
        NVPCluster objects, 'plugin_config' is a dictionary with plugin
        parameters (currently only 'max_lp_per_bridged_ls').
    """
    db_options = {"sql_connection": cfg.CONF.DATABASE.sql_connection}
    db_options.update({'base': models_v2.model_base.BASEV2})
    sql_max_retries = cfg.CONF.DATABASE.sql_max_retries
    db_options.update({"sql_max_retries": sql_max_retries})
    reconnect_interval = cfg.CONF.DATABASE.reconnect_interval
    db_options.update({"reconnect_interval": reconnect_interval})
    nvp_options = {'max_lp_per_bridged_ls': cfg.CONF.NVP.max_lp_per_bridged_ls}
    nvp_options.update({'failover_time': cfg.CONF.NVP.failover_time})
    nvp_options.update({'concurrent_connections':
                        cfg.CONF.NVP.concurrent_connections})

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
             nvp_conf[cluster_name].nvp_controller_connection, })
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


class NVPCluster(object):
    """Encapsulates controller connection and api_client for a cluster.

    Accessed within the NvpPluginV2 class.

    Each element in the self.controllers list is a dictionary that
    contains the following keys:
        ip, port, user, password, default_tz_uuid, uuid, zone

    There may be some redundancy here, but that has been done to provide
    future flexibility.
    """
    def __init__(self, name):
        self._name = name
        self.controllers = []
        self.api_client = None

    def __repr__(self):
        ss = ['{ "NVPCluster": [']
        ss.append('{ "name" : "%s" }' % self.name)
        ss.append(',')
        for c in self.controllers:
            ss.append(str(c))
            ss.append(',')
        ss.append('] }')
        return ''.join(ss)

    def add_controller(self, ip, port, user, password, request_timeout,
                       http_timeout, retries, redirects,
                       default_tz_uuid, uuid=None, zone=None):
        """Add a new set of controller parameters.

        :param ip: IP address of controller.
        :param port: port controller is listening on.
        :param user: user name.
        :param password: user password.
        :param request_timeout: timeout for an entire API request.
        :param http_timeout: timeout for a connect to a controller.
        :param retries: maximum number of request retries.
        :param redirects: maximum number of server redirect responses to
            follow.
        :param default_tz_uuid: default transport zone uuid.
        :param uuid: UUID of this cluster (used in MDI configs).
        :param zone: Zone of this cluster (used in MDI configs).
        """

        keys = [
            'ip', 'user', 'password', 'default_tz_uuid', 'uuid', 'zone']
        controller_dict = dict([(k, locals()[k]) for k in keys])

        int_keys = [
            'port', 'request_timeout', 'http_timeout', 'retries', 'redirects']
        for k in int_keys:
            controller_dict[k] = int(locals()[k])

        self.controllers.append(controller_dict)

    def get_controller(self, idx):
        return self.controllers[idx]

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, val=None):
        self._name = val

    @property
    def host(self):
        return self.controllers[0]['ip']

    @property
    def port(self):
        return self.controllers[0]['port']

    @property
    def user(self):
        return self.controllers[0]['user']

    @property
    def password(self):
        return self.controllers[0]['password']

    @property
    def request_timeout(self):
        return self.controllers[0]['request_timeout']

    @property
    def http_timeout(self):
        return self.controllers[0]['http_timeout']

    @property
    def retries(self):
        return self.controllers[0]['retries']

    @property
    def redirects(self):
        return self.controllers[0]['redirects']

    @property
    def default_tz_uuid(self):
        return self.controllers[0]['default_tz_uuid']

    @property
    def zone(self):
        return self.controllers[0]['zone']

    @property
    def uuid(self):
        return self.controllers[0]['uuid']


class NvpPluginV2(db_base_plugin_v2.QuantumDbPluginV2,
                  securitygroups_db.SecurityGroupDbMixin):

    """
    NvpPluginV2 is a Quantum plugin that provides L2 Virtual Network
    functionality using NVP.
    """

    __native_bulk_support = True

    supported_extension_aliases = ["security-group"]
    sg_supported_protocols = ['tcp', 'udp', 'icmp']
    sg_supported_ethertypes = ['IPv4', 'IPv6']

    def __init__(self, loglevel=None):
        if loglevel:
            logging.basicConfig(level=loglevel)
            nvplib.LOG.setLevel(loglevel)
            NvpApiClient.LOG.setLevel(loglevel)

        self.db_opts, self.nvp_opts, self.clusters_opts = parse_config()
        self.clusters = []
        for c_opts in self.clusters_opts:
            # Password is guaranteed to be the same across all controllers
            # in the same NVP cluster.
            cluster = NVPCluster(c_opts['name'])
            for controller_connection in c_opts['nvp_controller_connection']:
                args = controller_connection.split(':')
                try:
                    args.extend([c_opts['default_tz_uuid'],
                                 c_opts['nvp_cluster_uuid'],
                                 c_opts['nova_zone_id']])
                    cluster.add_controller(*args)
                except Exception:
                    LOG.exception("Invalid connection parameters for "
                                  "controller %s in cluster %s",
                                  controller_connection,
                                  c_opts['name'])
                    raise

            api_providers = [(x['ip'], x['port'], True)
                             for x in cluster.controllers]
            cluster.api_client = NvpApiClient.NVPApiHelper(
                api_providers, cluster.user, cluster.password,
                request_timeout=cluster.request_timeout,
                http_timeout=cluster.http_timeout,
                retries=cluster.retries,
                redirects=cluster.redirects,
                failover_time=self.nvp_opts['failover_time'],
                concurrent_connections=self.nvp_opts['concurrent_connections'])

            # TODO(salvatore-orlando): do login at first request,
            # not when plugin, is instantiated
            cluster.api_client.login()

            # TODO(pjb): What if the cluster isn't reachable this
            # instant?  It isn't good to fall back to invalid cluster
            # strings.
            # Default for future-versions
            self.clusters.append(cluster)

        # Connect and configure ovs_quantum db
        options = {
            'sql_connection': self.db_opts['sql_connection'],
            'sql_max_retries': self.db_opts['sql_max_retries'],
            'reconnect_interval': self.db_opts['reconnect_interval'],
            'base': models_v2.model_base.BASEV2,
        }
        db.configure_db(options)
        self.setup_rpc()

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

    def clear_state(self):
        nvplib.clear_state(self.clusters[0])

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
        nvp_secgroup = nvplib.create_security_profile(self.clusters[0],
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

    def _remove_none_values(self, rules):
        """Remove none values or NVP will complain about them.
        """
        delete_if_present = ['source_group_id', 'source_ip_prefix',
                             'port_range_min', 'port_range_max', 'protocol']
        for key in delete_if_present:
            for rule in rules['logical_port_ingress_rules']:
                if key in rule:
                    del rule[key]

            for rule in rules['logical_port_egress_rules']:
                if key in rule:
                    del rule[key]

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
        current_rules = self._remove_none_values(
            self._get_security_group_rules_by_nvp_id(context, nvp_id))

        # combine old rules with new rules
        for r in s:
            rule = r['security_group_rule']
            rule['security_group_id'] = nvp_id
            if rule['source_group_id']:
                rule['profile_uuid'] = self._get_profile_uuid(
                    context, rule['source_group_id'])
            if rule['direction'] == 'egress':
                current_rules['logical_port_egress_rules'].append(
                    self._convert_to_nvp_rule(rule))
            elif rule['direction'] == 'ingress':
                current_rules['logical_port_ingress_rules'].append(
                    self._convert_to_nvp_rule(rule))

        nvplib.create_security_group_rules(self.clusters[0], tenant_id, nvp_id,
                                           current_rules, security_group_id)
        return super(NvpPluginV2, self).create_security_group_rule_bulk_native(
            context, security_group_rule)

    def _get_security_group_rules_by_nvp_id(self, context, nvp_id,
                                            want_id=False):
        """Query quantum db for security group rules. If external_id is
        provided the external_id will also be returned.
        """
        fields = {'source_ip_prefix': None,
                  'profile_uuid': None,
                  'protocol': None,
                  'port_range_min': None,
                  'port_range_max': None,
                  'protocol': None,
                  'ethertype': None}

        if want_id:
            fields['id'] = None

        filters = {'security_group_id': [nvp_id], 'direction': ['ingress']}
        ingress_rules = super(NvpPluginV2, self).get_security_group_rules(
            context, filters, fields)
        filters = {'security_group_id': [nvp_id], 'direction': ['egress']}
        egress_rules = super(NvpPluginV2, self).get_security_group_rules(
            context, filters, fields)
        return {'logical_port_ingress_rules': ingress_rules,
                'logical_port_egress_rules': egress_rules}

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
        self._remove_none_values(current_rules)
        nvplib.update_security_group_rules(self.clusters[0], nvp_id,
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
        nvplib.delete_security_profile(self.clusters[0], nvp_id)

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
        # FIXME(arosen) implement admin_state_up = False in NVP
        if network['network']['admin_state_up'] is False:
            LOG.warning("Network with admin_state_up=False are not yet "
                        "supported by this plugin. Ignoring setting for "
                        "network %s",
                        network['network'].get('name', '<unknown>'))

        # TODO(salvatore-orlando): if the network is shared this should be
        # probably stored into the lswitch with a tag
        # TODO(salvatore-orlando): Important - provider networks support
        # (might require a bridged TZ)
        net = nvplib.create_network(tenant_id,
                                    network['network']['name'],
                                    clusters=self.clusters)

        network['network']['id'] = net['net-id']
        return super(NvpPluginV2, self).create_network(context, network)

    def delete_network(self, context, id):
        """
        Deletes the network with the specified network identifier
        belonging to the specified tenant.

        :returns: None
        :raises: exception.NetworkInUse
        :raises: exception.NetworkNotFound
        """

        super(NvpPluginV2, self).delete_network(context, id)
        pairs = self._get_lswitch_cluster_pairs(id, context.tenant_id)
        for (cluster, switches) in pairs:
            nvplib.delete_networks(cluster, id, switches)

        LOG.debug("delete_network() completed for tenant: %s" %
                  context.tenant_id)

    def _get_lswitch_cluster_pairs(self, netw_id, tenant_id):
        """Figure out the set of lswitches on each cluster that maps to this
           network id"""
        pairs = []
        for c in self.clusters:
            lswitches = []
            try:
                ls = nvplib.get_network(c, netw_id)
                lswitches.append(ls['uuid'])
            except exception.NetworkNotFound:
                continue
            pairs.append((c, lswitches))
        if len(pairs) == 0:
            raise exception.NetworkNotFound(net_id=netw_id)
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
        result = {}
        lswitch_query = "&uuid=%s" % id
        # always look for the tenant_id in the resource itself rather than
        # the context, as with shared networks context.tenant_id and
        # network['tenant_id'] might differ on GETs
        # goto to the plugin DB and fecth the network
        network = self._get_network(context, id)
        # TODO(salvatore-orlando): verify whether the query on os_tid is
        # redundant or not.
        if context.is_admin is False:
            tenant_query = ("&tag=%s&tag_scope=os_tid"
                            % network['tenant_id'])
        else:
            tenant_query = ""
        # Then fetch the correspondiong logical switch in NVP as well
        # TODO(salvatore-orlando): verify whether the step on NVP
        # can be completely avoided
        lswitch_url_path = (
            "/ws.v1/lswitch?"
            "fields=uuid,display_name%s%s"
            % (tenant_query, lswitch_query))
        try:
            for c in self.clusters:
                lswitch_results = nvplib.get_all_query_pages(
                    lswitch_url_path, c)
                if lswitch_results:
                    result['lswitch-display-name'] = (
                        lswitch_results[0]['display_name'])
                    break
        except Exception:
            LOG.error("Unable to get switches: %s" % traceback.format_exc())
            raise exception.QuantumException()

        if 'lswitch-display-name' not in result:
            raise exception.NetworkNotFound(net_id=id)

        d = {'id': id,
             'name': result['lswitch-display-name'],
             'tenant_id': network['tenant_id'],
             'admin_state_up': True,
             'status': constants.NET_STATUS_ACTIVE,
             'shared': network['shared'],
             'subnets': []}

        LOG.debug("get_network() completed for tenant %s: %s" % (
                  context.tenant_id, d))
        return d

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

        if context.is_admin and not filters.get("tenant_id"):
            tenant_filter = ""
        elif filters.get("tenant_id"):
            tenant_filter = ""
            for tenant in filters.get("tenant_id"):
                tenant_filter += "&tag=%s&tag_scope=os_tid" % tenant
        else:
            tenant_filter = "&tag=%s&tag_scope=os_tid" % context.tenant_id

        lswitch_filters = "uuid,display_name,fabric_status"
        lswitch_url_path = (
            "/ws.v1/lswitch?fields=%s&relations=LogicalSwitchStatus%s"
            % (lswitch_filters, tenant_filter))
        try:
            for c in self.clusters:
                res = nvplib.get_all_query_pages(
                    lswitch_url_path, c)

                nvp_lswitches.extend(res)
        except Exception:
            LOG.error("Unable to get switches: %s" % traceback.format_exc())
            raise exception.QuantumException()

        # TODO (Aaron) This can be optimized
        if filters.get("id"):
            filtered_lswitches = []
            for nvp_lswitch in nvp_lswitches:
                for id in filters.get("id"):
                    if id == nvp_lswitch['uuid']:
                        filtered_lswitches.append(nvp_lswitch)
            nvp_lswitches = filtered_lswitches

        for quantum_lswitch in quantum_lswitches:
            Found = False
            for nvp_lswitch in nvp_lswitches:
                if nvp_lswitch["uuid"] == quantum_lswitch["id"]:
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
                raise Exception("Quantum and NVP Databases are out of Sync!")
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
                raise exception.NotImplementedError("admin_state_up=False "
                                                    "networks are not "
                                                    "supported.")
        params = {}
        params["network"] = network["network"]
        pairs = self._get_lswitch_cluster_pairs(id, context.tenant_id)

        #Only field to update in NVP is name
        if network['network'].get("name"):
            for (cluster, switches) in pairs:
                for switch in switches:
                    nvplib.update_network(cluster, switch, **params)

        LOG.debug("update_network() completed for tenant: %s" %
                  context.tenant_id)
        return super(NvpPluginV2, self).update_network(context, id, network)

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
            for c in self.clusters:
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
            LOG.error("Unable to get ports: %s" % traceback.format_exc())
            raise exception.QuantumException()

        lports = []
        for quantum_lport in quantum_lports:
            try:
                quantum_lport["admin_state_up"] = (
                    nvp_lports[quantum_lport["id"]]["admin_status_enabled"])

                quantum_lport["name"] = (
                    nvp_lports[quantum_lport["id"]]["display_name"])

                self._extend_port_dict_security_group(context, quantum_lport)
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
                raise Exception("Quantum and NVP Databases are out of Sync!")
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
                   (limit values to "ACTIVE", "DOWN", "BUILD", and
                   "ERROR"?)
         "fixed_ips": list of subnet ID's and IP addresses to be used on
                      this port
         "device_id": identifies the device (e.g., virtual server) using
                      this port.
        }

        :raises: exception.NetworkNotFound
        :raises: exception.StateInvalid
        """
        p = port['port']
        tenant_id = self._get_tenant_id_for_create(context, p)
        default_sg = self._ensure_default_security_group(context, tenant_id)
        self._validate_security_groups_on_port(context, port)
        if not p.get(ext_sg.SECURITYGROUP):
            # For now let's not apply security groups to dhcp ports
            if p.get('device_owner') == 'network:dhcp' and context.is_admin:
                pass
            elif not cfg.CONF.SECURITYGROUP.proxy_mode:
                port['port'][ext_sg.SECURITYGROUP] = [default_sg]
        # Set admin_state_up False since not created in NVP set
        port["port"]["admin_state_up"] = False
        # First we allocate port in quantum database
        try:
            quantum_db = super(NvpPluginV2, self).create_port(context, port)
        except Exception as e:
            raise e

        # Update fields obtained from quantum db
        port["port"].update(quantum_db)

        # We want port to be up in NVP
        port["port"]["admin_state_up"] = True
        params = {}
        params["max_lp_per_bridged_ls"] = \
            self.nvp_opts["max_lp_per_bridged_ls"]
        params["port"] = port["port"]
        params["clusters"] = self.clusters

        try:
            port["port"], nvp_port_id = nvplib.create_port(tenant_id,
                                                           **params)
            nvplib.plug_interface(self.clusters, port["port"]["network_id"],
                                  nvp_port_id, "VifAttachment",
                                  port["port"]["id"])
        except Exception as e:
            # failed to create port in NVP delete port from quantum_db
            super(NvpPluginV2, self).delete_port(context, port["port"]["id"])
            raise e

        d = {"port-id": port["port"]["id"],
             "port-op-status": port["port"]["status"]}

        # Saves the security group that port is on.
        if p.get('device_owner') != 'network:dhcp' and context.is_admin:
            self._process_port_create_security_group(context, p['id'],
                                                     p[ext_sg.SECURITYGROUP])

        LOG.debug("create_port() completed for tenant %s: %s" %
                  (tenant_id, d))

        # update port with admin_state_up True
        port_update = {"port": {"admin_state_up": True}}
        port = super(NvpPluginV2, self).update_port(context,
                                                    port["port"]["id"],
                                                    port_update)
        self._extend_port_dict_security_group(context, port)
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
        # update in base class to leverage ip/subnetting update
        ret_port = super(NvpPluginV2, self).update_port(context, id, port)

        # Copy of addition fields we want to update but
        # are not in the _make_port-dict
        ret_port.update(port['port'])

        port_nvp, cluster = (
            nvplib.get_port_by_quantum_tag(self.clusters,
                                           ret_port["network_id"], id))

        # security groups
        ret_port[ext_sg.SECURITYGROUP] = (
            self._validate_security_groups_on_port(context, port))

        params["cluster"] = cluster
        ret_port["port_security"] = (ret_port.get('port_security',
                                     nvplib.port_security_info(port_nvp)))

        params["port"] = ret_port
        LOG.debug("Update port request: %s" % (params))
        nvplib.update_port(ret_port["network_id"],
                           port_nvp["uuid"], **params)
        LOG.debug("update_port() completed for tenant: %s" % context.tenant_id)

        # delete the port binding and read it with the new rules.
        self._delete_port_security_group_bindings(context, id)
        self._process_port_create_security_group(context, id,
                                                 ret_port.get(
                                                 ext_sg.SECURITYGROUP))
        self._extend_port_dict_security_group(context, ret_port)
        return ret_port

    def delete_port(self, context, id):
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

        port, cluster = nvplib.get_port_by_quantum_tag(self.clusters,
                                                       '*', id)
        if port is None:
            raise exception.PortNotFound(port_id=id)
        # TODO(bgh): if this is a bridged network and the lswitch we just got
        # back will have zero ports after the delete we should garbage collect
        # the lswitch.
        nvplib.delete_port(cluster, port)

        self._delete_port_security_group_bindings(context, id)

        LOG.debug("delete_port() completed for tenant: %s" % context.tenant_id)
        return  super(NvpPluginV2, self).delete_port(context, id)

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

        quantum_db = super(NvpPluginV2, self).get_port(context, id, fields)

        port, cluster = (
            nvplib.get_port_by_quantum_tag(self.clusters,
                                           quantum_db["network_id"], id))

        quantum_db["admin_state_up"] = port["admin_status_enabled"]
        if port["_relations"]["LogicalPortStatus"]["fabric_status_up"]:
            quantum_db["status"] = constants.PORT_STATUS_ACTIVE
        else:
            quantum_db["status"] = constants.PORT_STATUS_DOWN

        LOG.debug("Port details for tenant %s: %s" %
                  (context.tenant_id, quantum_db))
        return quantum_db

    def get_plugin_version(self):
        return PLUGIN_VERSION
