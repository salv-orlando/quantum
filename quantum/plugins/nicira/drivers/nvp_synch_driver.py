# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Openstack Foundation
# All Rights Reserved.
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
#
import collections
import sys

from oslo.config import cfg

from quantum.api.v2 import attributes
from quantum.common import constants
from quantum.db import l3_db
from quantum.extensions import l3
from quantum.extensions import portsecurity as ext_psec
from quantum.extensions import providernet as pnet
from quantum.extensions import securitygroup as ext_sg
from quantum.openstack.common import excutils
from quantum.openstack.common import log as logging
from quantum.plugins.nicira.common import exceptions as nvp_exc
from quantum.plugins.nicira.drivers import base_driver
from quantum.plugins.nicira.extensions import nvp_qos as ext_qos
from quantum.plugins.nicira import nicira_db
from quantum.plugins.nicira import NvpApiClient
from quantum.plugins.nicira import nvplib

LOG = logging.getLogger(__name__)
NVP_NOSNAT_RULES_ORDER = 10
NVP_FLOATINGIP_NAT_RULES_ORDER = 224
NVP_EXTGW_NAT_RULES_ORDER = 255


nvp_to_quantum_net_status_dict = {
    None: constants.NET_STATUS_ERROR,
    False: constants.NET_STATUS_DOWN,
    True: constants.NET_STATUS_ACTIVE
}


def _tags_to_dict(tags):
    """Utility function to convert a tag list into a dict."""
    # Assume scope is never repeated
    return dict((item['scope'], item['tag']) for item in tags)


def _set_network_status(statuses, lswitch):
    """Helper function to retrieve the status of a quantum network."""
    tag_dict = _tags_to_dict(lswitch.get('tags', []))
    quantum_net_id = tag_dict.get(nvplib.TAG_QUANTUM_NET_ID)
    # if tag is not found, use uuid as quantum network id
    if not quantum_net_id:
        quantum_net_id = lswitch['uuid']
    # If a network has multiple lswitches, do an and
    # of fabric_status values for each lswitch
    ls_status = lswitch['_relations']['LogicalSwitchStatus']['fabric_status']
    net_status = statuses.get(quantum_net_id, True) and ls_status
    statuses[quantum_net_id] = net_status


class NvpSynchDriver(base_driver.BaseDriver):
    """NVP synchronous driver"""

    def __init__(self, cluster, response_handlers,
                 exception_handlers):
        self.cluster = cluster
        # Routines for managing logical ports
        _port_drivers = {
            'create': {l3_db.DEVICE_OWNER_ROUTER_GW:
                       self._nvp_create_ext_gw_port,
                       l3_db.DEVICE_OWNER_ROUTER_INTF:
                       self._nvp_create_port},
            'delete': {l3_db.DEVICE_OWNER_ROUTER_GW:
                       self._nvp_delete_ext_gw_port,
                       l3_db.DEVICE_OWNER_ROUTER_INTF:
                       self._nvp_delete_port}
        }

        def get_default_create_port_driver():
            return self._nvp_create_port

        def get_default_delete_port_driver():
            return self._nvp_delete_port

        def get_default_response_handler():
            return self._default_response_handler

        def get_default_exception_handler():
            return self._default_exception_handler

        self._create_port_drivers = collections.defaultdict(
            get_default_create_port_driver, _port_drivers['create'])
        self._delete_port_drivers = collections.defaultdict(
            get_default_delete_port_driver, _port_drivers['delete'])

        self.response_handlers = collections.defaultdict(
            get_default_response_handler, response_handlers)
        self.exception_handlers = collections.defaultdict(
            get_default_exception_handler, exception_handlers)
        super(NvpSynchDriver, self).__init__()

    def _default_response_handler(self, context, resource, **kwargs):
        """Noop response handler."""

    def _default_exception_handler(self, context, resource,
                                   exception, **kwargs):
        """Noop exception handler."""

    def _nvp_get_port_id(self, context, cluster, port_id, network_id):
        """Return the NVP port uuid for a given quantum port.

        First, look up the Quantum database. If not found, execute
        a query on NVP platform as the mapping might be missing because
        the port was created before upgrading to grizzly.
        """
        nvp_port_id = nicira_db.get_nvp_port_id(
            context.session, port_id)
        if nvp_port_id:
            return nvp_port_id
        # Perform a query to NVP and then update the DB
        nvp_port = nvplib.get_port_by_quantum_tag(
            cluster, network_id, port_id)
        nicira_db.add_quantum_nvp_port_mapping(
            context.session, port_id, nvp_port['uuid'])
        return nvp_port['uuid']

    def _nvp_get_lswitch_for_port(self, port_data):
        ports = nvplib.query_lswitch_lports(
            self.cluster, '*',
            filters={'tag': port_data['id'],
                     'tag_scope': 'q_port_id'},
            relations='LogicalSwitchConfig')
        # FUUUUUUUUUUUUUUUUUU
        if ports:
            return ports[0]

    def _nvp_get_router_id(self, context, cluster, router_id):
        """Return the NVP router uuid for a given quantum router.

        First, look up the Quantum database. If not found, execute
        a query on NVP platform as the mapping might be missing because
        the router was created before upgrading to grizzly.
        """
        nvp_router_id = nicira_db.get_nvp_router_id(
            context.session, router_id)
        if nvp_router_id:
            return nvp_router_id
        # Perform a query to NVP and then update the DB
        try:
            nvp_router = nvplib.get_router_by_quantum_tag(cluster, router_id)
            nicira_db.add_quantum_nvp_router_mapping(
                context.session, router_id, nvp_router['uuid'])
        except nvp_exc.NvpInvalidQuantumIdTag:
            # Check for lrouter with uuid = router_id for bw compatibility
            LOG.debug(_("Unable to find router:%s by tag, looking by uuid"),
                      router_id)
            nvp_router = nvplib.get_lrouter(self.cluster, router_id)
        return nvp_router['uuid']

    def _handle_lswitch_selection(self, cluster, network,
                                  network_binding, max_ports,
                                  allow_extra_lswitches):
        lswitches = nvplib.get_lswitches(cluster, network.id)
        if not lswitches:
            LOG.warning(_("No logical switch was found for quantum "
                          "network:%s"), network.id)
            return
        try:
            return [ls for ls in lswitches
                    if (ls['_relations']['LogicalSwitchStatus']
                        ['lport_count'] < max_ports)].pop(0)
        except IndexError:
            # Too bad, no switch available
            LOG.debug(_("No switch has available ports (%d checked)"),
                      len(lswitches))
        if allow_extra_lswitches:
            selected_lswitch = nvplib.create_lswitch(
                cluster, network.tenant_id,
                "%s-ext-%s" % (network.name, len(lswitches)),
                transport_type=network_binding.binding_type,
                transport_zone_uuid=network_binding.phy_uuid,
                vlan_id=network_binding.vlan_id,
                quantum_net_id=network.id)
            return selected_lswitch
        else:
            LOG.error(_("Maximum number of logical ports reached for "
                        "logical network %s"), network.id)
            raise nvp_exc.NvpNoMorePortsException(network=network.id)

    def _nvp_find_lswitch_for_port(self, context, port_data, network):
        # TODO(salvatore-orlando): Do multiple bridges only if
        # NVP version < 3.0
        network_binding = nicira_db.get_network_binding(
            context.session, port_data['network_id'])
        max_ports = cfg.CONF.NVP.max_lp_per_overlay_ls
        allow_extra_lswitches = False
        if (network_binding and
            network_binding.binding_type in ('flat', 'vlan')):
            max_ports = cfg.CONF.NVP.max_lp_per_bridged_ls
            allow_extra_lswitches = True
        return self._handle_lswitch_selection(self.cluster, network,
                                              network_binding, max_ports,
                                              allow_extra_lswitches)

    def _nvp_create_port_helper(self, cluster, ls_uuid, port_data):
        lport = nvplib.create_lport(cluster, ls_uuid, port_data['tenant_id'],
                                    port_data['id'], port_data['name'],
                                    port_data['device_id'],
                                    port_data['admin_state_up'],
                                    port_data['mac_address'],
                                    port_data['fixed_ips'],
                                    port_data[ext_psec.PORTSECURITY],
                                    port_data[ext_sg.SECURITYGROUPS],
                                    port_data[ext_qos.QUEUE])
        nvplib.plug_interface(self.cluster, ls_uuid, lport['uuid'],
                              "VifAttachment", port_data['id'])
        return lport

    def _nvp_create_port(self, context, port_data, network):
        """Driver for creating a logical switch port on NVP platform."""
        selected_lswitch = self._nvp_find_lswitch_for_port(
            context, port_data, network)
        if not selected_lswitch:
            # NVP logical switch not found
            return
        lport = self._nvp_create_port_helper(
            self.cluster, selected_lswitch['uuid'], port_data)
        LOG.debug(_("_nvp_create_port completed for port %(name)s "
                    "on network %(network_id)s. The new port id is "
                    "%(id)s."), port_data)
        return lport

    def _nvp_delete_port(self, context, port_data):
        nvp_port_id = self._nvp_get_port_id(context, self.cluster,
                                            port_data['id'],
                                            port_data['network_id'])
        if not nvp_port_id:
            LOG.debug(_("Port '%s' was already deleted on NVP platform"), id)
            return
        # TODO(bgh): if this is a bridged network and the lswitch we just got
        # back will have zero ports after the delete we should garbage collect
        # the lswitch.
        # TODO(salv-orlando): We should really include lswitch uuid in the
        # port mapping

        nvplib.delete_port(self.cluster,
                           port_data['network_id'],
                           nvp_port_id)
        LOG.debug(_("_nvp_delete_port completed for port %(port_id)s "
                    "on network %(net_id)s"),
                  {'port_id': port_data['id'],
                   'net_id': port_data['network_id']})

    def _nvp_create_router_port(self, context, port_data, network):
        """Driver for creating a switch port to be connected to a router."""
        # No router ports on external networks!
        if network.get(l3.EXTERNAL):
            raise nvp_exc.NvpPluginException(
                err_msg=(_("It is not allowed to create router interface "
                           "ports on external networks as '%s'") %
                         port_data['network_id']))
        selected_lswitch = self._nvp_find_lswitch_for_port(context,
                                                           port_data)
        lport = self._nvp_create_port_helper(self.cluster,
                                             selected_lswitch['uuid'],
                                             port_data)
        LOG.debug(_("_nvp_create_port completed for port %(name)s on "
                    "network %(network_id)s. The new port id is %(id)s."),
                  port_data)
        return lport

    def _nvp_delete_router_port(self, context, port_data):
        # Delete logical router port
        nvp_port_id = self._nvp_get_port_id(context, self.cluster,
                                            port_data)
        lrouter_id = self._nvp_get_router_id(
            context, self.cluster, port_data['device_id'])
        nvplib.delete_peer_router_lport(self.cluster,
                                        lrouter_id,
                                        port_data['network_id'],
                                        nvp_port_id)
        # Delete logical switch port
        self._nvp_delete_port(context, port_data)

    def _nvp_find_router_gw_port(self, context, port_data):
        """Retrieves the UUID of a NVP L3 gateway port.

        This method accepts in input a port structure.
        This port should be a Quantum external gateway port,
        and its device_id attribute should be set to the uuid
        of the quantum router for which the NVP L3 gateway
        port is being sought.
        """
        # TODO(help with info in cache)
        gw_port_id = nicira_db.get_nvp_router_gw_portid(
            context.session, port_data['device_id'])
        # Go to NVP, fetch router and its port, and store mapping
        lrouter = nvplib.get_router_by_quantum_tag(
            self.cluster, port_data['device_id'])
        lr_port = nvplib.find_router_gw_port(
            self.cluster, lrouter['uuid'])
        if not lr_port:
            # TODO(salv-orlando): Resynchronize quantum router
            raise nvp_exc.NvpPluginException(
                err_msg=(_("The gateway port for the router %s "
                           "was not found on the NVP backend")
                         % port_data['device_id']))
        if not gw_port_id:
            nicira_db.add_quantum_nvp_router_mapping(
                context.session, port_data['device_id'],
                lrouter['uuid'], lr_port['uuid'])
        return lr_port

    def _nvp_create_ext_gw_port(self, context, port_data, network):
        """Driver for creating an external gateway port on NVP platform."""
        lr_port = self._nvp_find_router_gw_port(context, port_data)
        # This operation actually always updates a NVP logical port
        # instead of creating one. This is because the gateway port
        # is created at the same time as the NVP logical router, otherwise
        # the fabric status of the NVP router will be down.
        # admin_status should always be up for the gateway port
        # regardless of what the user specifies in quantum
        ip_addresses = port_data['ip_addresses']
        router_id = port_data['device_id']
        nvp_router_id = self._nvp_get_router_id(
            context, self.cluster, router_id)
        nvplib.update_router_lport(self.cluster,
                                   nvp_router_id,
                                   lr_port['uuid'],
                                   port_data['tenant_id'],
                                   port_data['id'],
                                   port_data['name'],
                                   True,
                                   ip_addresses)
        if network.get(pnet.NETWORK_TYPE) == 'l3_ext':
            # Update attachment
            self._nvp_set_router_port_attachment(
                context, router_id, port_data, lr_port['uuid'],
                "L3GatewayAttachment",
                network[pnet.PHYSICAL_NETWORK],
                network[pnet.SEGMENTATION_ID])
        # TODO(salv-orlando): If a previous clear gw operation failed,
        # or if somebody fiddled with NVP, this operation might fail because
        # of conflicts. In this case existing NAT rules should be
        # destroyed and overwritten
        # Set the SNAT rule for each subnet (only first IP)
        for cidr in port_data['subnet_cidrs']:
            cidr_prefix = int(cidr.split('/')[1])
            nvplib.create_lrouter_snat_rule(
                self.cluster, router_id,
                ip_addresses[0].split('/')[0],
                ip_addresses[0].split('/')[0],
                order=NVP_EXTGW_NAT_RULES_ORDER - cidr_prefix,
                match_criteria={'source_ip_addresses': cidr})
        LOG.debug(_("_nvp_create_ext_gw_port completed on external network "
                    "%(ext_net_id)s, attached to router:%(router_id)s. "
                    "NVP port id is %(nvp_port_id)s"),
                  {'ext_net_id': port_data['network_id'],
                   'router_id': router_id,
                   'nvp_port_id': lr_port['uuid']})

    def _nvp_delete_ext_gw_port(self, context, port_data):
        lr_port = self._nvp_find_router_gw_port(context, port_data)
        # Delete is actually never a real delete, otherwise the NVP
        # logical router will stop working
        router_id = self._nvp_get_router_id(
            context, self.cluster, port_data['device_id'])
        nvplib.update_router_lport(self.cluster,
                                   router_id,
                                   lr_port['uuid'],
                                   port_data['tenant_id'],
                                   port_data['id'],
                                   port_data['name'],
                                   True,
                                   ['0.0.0.0/31'])
        # Delete the SNAT rule for each subnet
        for cidr in port_data['subnet_cidrs']:
            nvplib.delete_nat_rules_by_match(
                self.cluster, router_id, "SourceNatRule",
                max_num_expected=1, min_num_expected=1,
                source_ip_addresses=cidr)
        # Reset attachment
        self._nvp_set_router_port_attachment(
            context, router_id, port_data,
            lr_port['uuid'], "L3GatewayAttachment",
            self.cluster.default_l3_gw_service_uuid)
        LOG.debug(_("_nvp_delete_ext_gw_port completed on external network "
                    "%(ext_net_id)s, attached to router:%(router_id)s"),
                  {'ext_net_id': port_data['network_id'],
                   'router_id': router_id})

    def get_network_status(self, network_id):
        super(NvpSynchDriver, self).get_network_status(network_id)
        statuses = {}
        for lswitch in nvplib.query_lswitches_status(
                self.cluster, network_id=network_id):
            _set_network_status(statuses, lswitch)
        # We expect a single element in statuses
        return nvp_to_quantum_net_status_dict[statuses.get(network_id)]

    def _nvp_set_router_port_attachment(self, context, lrouter_uuid,
                                        port_data, lport_uuid,
                                        attachment_type, attachment,
                                        attachment_vlan=None):
        try:
            nvplib.plug_router_port_attachment(
                self.cluster, lrouter_uuid, lport_uuid,
                attachment, attachment_type, attachment_vlan)
            LOG.debug(_("Attached %(att)s to NVP router port %(port)s"),
                      {'att': attachment, 'port': lport_uuid})
        except NvpApiClient.NvpApiException:
            # NVP logical router port should be removed
            nvplib.delete_router_lport(self.cluster, lrouter_uuid, lport_uuid)
            LOG.exception(_("Unable to plug attachment in NVP logical "
                            "router port %(r_port_id)s, associated with "
                            "Quantum %(q_port_id)s, on router %(r_id)s. "
                            "The logical router port has been deleted"),
                          {'r_port_id': lport_uuid,
                           'r_id': lrouter_uuid,
                           'q_port_id': port_data.get('id')})
            raise

    def _nvp_create_and_attach_router_port(self, context, lrouter_uuid,
                                           port_data, attachment_type,
                                           attachment, attachment_vlan=None,
                                           subnet_ids=None):
        # Use a fake IP address if gateway port is not 'real'
        ip_addresses = (port_data.get('fake_ext_gw') and
                        ['0.0.0.0/31'] or port_data['ip_addresses'])
        try:
            lrouter_port = nvplib.create_router_lport(
                self.cluster, lrouter_uuid,
                port_data.get('tenant_id', 'fake'),
                port_data.get('id', 'fake'),
                port_data.get('name', 'fake'),
                port_data.get('admin_state_up', True),
                ip_addresses)
            LOG.debug(_("Created NVP router port:%(lport)s "
                        "for router:%(lrouter)s"),
                      {'lport': lrouter_port['uuid'],
                       'lrouter': lrouter_uuid})
        except NvpApiClient.NvpApiException:
            LOG.exception(_("Unable to create port on NVP logical router %s"),
                          lrouter_uuid)
            raise
        self._nvp_set_router_port_attachment(
            context, lrouter_uuid, port_data, lrouter_port['uuid'],
            attachment_type, attachment, attachment_vlan)
        return lrouter_port

    def get_port_status(self, context, port_id, network_id):
        super(NvpSynchDriver, self).get_port_status(
            context, port_id, network_id)
        try:
            nvp_id = self._nvp_get_port_id(context, self.cluster,
                                           port_id, network_id)

            # TODO(salv-orlando): We should cache the lswitch binding
            # too as long as we allow for multiple lswitches
            # TODO(salv-orlando): This routine has room for improvements!
            lswitches = nvplib.get_lswitches(self.cluster, network_id)
            # Unfortunately the port could be on any switch
            for lswitch in lswitches:
                try:
                    port = nvplib.get_logical_port_status(
                        self.cluster, lswitch['uuid'], nvp_id)
                    # IS THIS WRONG?
                    if port["link_status_up"]:
                        return constants.PORT_STATUS_ACTIVE
                    else:
                        return constants.PORT_STATUS_DOWN
                except NvpApiClient.ResourceNotFound:
                    # Try with next lswitch
                    LOG.debug(_("Logical port %(lport_id)s not found "
                                "on logical switch %(lswitch_id)s"),
                              {'lport_id': nvp_id,
                               'lswitch_id': lswitch['uuid']})
                # If we hit this line, no switch was found for the port
                return constants.PORT_STATUS_ERROR
        except NvpApiClient.ResourceNotFound:
            #TODO(salv-orlando): Remove mappings
            return constants.PORT_STATUS_ERROR
        except NvpApiClient.NvpApiException:
            #TODO(salv-orlando): Log available details (lport, lswitch)
            LOG.exception(_("An unexpected error occurred while "
                            "retrieving logical port status"))
            return constants.PORT_STATUS_ERROR

    def get_router_status(self, context, router_id):
        # TODO(salv-orlando): simplify everything with a mapping
        # between NVP routers and Quantum routers
        super(NvpSynchDriver, self).get_router_status(context, router_id)
        try:
            nvp_id = self._nvp_get_router_id(context, self.cluster,
                                             router_id)
            status = nvplib.get_lrouter_status(self.cluster, nvp_id)
            if status.get('fabric_status'):
                return constants.NET_STATUS_ACTIVE
            else:
                return constants.NET_STATUS_DOWN
        except NvpApiClient.ResourceNotFound:
            # TODO(salv-orlando): Remove mappings
            return constants.NET_STATUS_ERROR
        except NvpApiClient.NvpApiException:
            # TODO(salv-orlando): Log available details (lport, lswitch)
            LOG.exception(_("An unexpected error occurred while "
                            "retrieving logical port status"))
            return constants.NET_STATUS_ERROR

    def get_networks_status(self, context, filters=None):
        super(NvpSynchDriver, self).get_networks_status(
            self, context, filters)
        # [None] will trigger a NVP query without tenant filter
        if context.is_admin:
            tenant_ids = (filters and filters.get('tenant_id', [None])
                          or [None])
        else:
            tenant_ids = [context.tenant_id]

        # Get networks for each tenant in tenant_ids
        statuses = {}
        for tenant_id in tenant_ids:
            for lswitch in nvplib.query_lswitches_status(
                    self.cluster, tenant_id=tenant_id):
                _set_network_status(statuses, lswitch)
        # Get status for shared networks regardless of context
        for lswitch in nvplib.query_lswitches_status(
            self.cluster, shared=True):
            _set_network_status(statuses, lswitch)
        return dict((network_id, nvp_to_quantum_net_status_dict[status])
                    for (network_id, status) in statuses.iteritems())

    def create_network(self, context, tenant_id, network_data):
        """Post DB commit operations."""
        super(NvpSynchDriver, self).create_network(
            context, tenant_id, network_data)
        # TODO(salv-orlando): Define NVP semantics for network admin state
        # and implement support in NVP
        if network_data['admin_state_up'] is False:
            LOG.warning(_("Network with admin_state_up=False are not yet "
                          "supported by this plugin. Ignoring setting for "
                          "network %s"),
                        network_data.get('name', '<unknown>'))
        external = network_data.get(l3.EXTERNAL)
        if attributes.is_attr_set(external) and external:
            # Nothing to do on NVP
            return
        nvp_binding_type = network_data.get(pnet.NETWORK_TYPE)
        if nvp_binding_type in ('flat', 'vlan'):
            nvp_binding_type = 'bridge'
        try:
            lswitch = nvplib.create_lswitch(
                self.cluster, tenant_id,
                network_data.get('name'),
                nvp_binding_type,
                network_data.get(pnet.PHYSICAL_NETWORK),
                network_data.get(pnet.SEGMENTATION_ID),
                quantum_net_id=network_data['id'],
                shared=network_data.get(attributes.SHARED))
            self.response_handlers['create_network'](
                context, network_data, lswitch)
            return lswitch['uuid']
        except Exception:
            # Let the exception handler deal with the Exception
            with excutils.save_and_reraise_exception():
                self.exception_handlers.get['create_network'](
                    context, network_data, sys.exc_info())

    def delete_network(self, context, network_data,
                       ports_to_delete=None):
        """Post DB commit operations."""
        super(NvpSynchDriver, self).delete_network(
            context, network_data)
        # Do not go to NVP for external networks
        if network_data.get(l3.EXTERNAL):
            # Do not go to NVP for external network
            return
        try:
            lswitch_ids = [ls['uuid'] for ls in
                           nvplib.get_lswitches(self.cluster,
                                                network_data['id'])]
            nvplib.delete_networks(self.cluster, id, lswitch_ids)
            # Do not use list comprehension to avoid 2 iterations
            for port in ports_to_delete:
                if (port['device_owner'] != l3_db.DEVICE_OWNER_ROUTER_INTF):
                    continue
                try:
                    nvp_port_id = self._nvp_get_port_id(
                        context, self.cluster, port)
                    nvplib.delete_peer_router_lport(self.cluster,
                                                    port['device_id'],
                                                    port['network_id'],
                                                    nvp_port_id)
                except (NvpApiClient.NvpApiException,
                        NvpApiClient.ResourceNotFound):
                    # Do not raise because the router might have already
                    # been deleted, so there would be nothing to do here
                    LOG.info(_("Ignoring exception as the peer for port"
                               "'%s' has already been deleted."),
                             nvp_port_id)
            self.response_handlers['delete_network'](context, network_data,
                                                     ports_to_delete)
        except NvpApiClient.ResourceNotFound:
            LOG.info(_("The network %s was already removed in the "
                       "NVP backend"), network_data['id'])
        except Exception:
            with excutils.save_and_reraise_exception():
                self.exception_handlers['delete_network'](
                    context, network_data, sys.exc_info())

    def create_port(self, context, port_data, network):
        super(NvpSynchDriver, self).create_port(
            context, port_data, network)
        try:
            lport = None
            if not network[l3.EXTERNAL]:
                port_func = (
                    self._create_port_drivers[port_data['device_owner']])
                lport = port_func(context, port_data, network)
            self.response_handlers['create_port'](context, port_data, lport)
            # lport might be None if logical switch was not found
            return lport and lport['uuid']
        except Exception:
            # Let the exception handler deal with the Exception
            with excutils.save_and_reraise_exception():
                self.exception_handlers['create_port'](
                    context, port_data, sys.exc_info())

    def update_port(self, context, port_data):
        try:
            nvp_port_id = self._nvp_get_port_id(
                context, self.cluster,
                port_data['id'], port_data['network_id'])
            # TODO(salv-orlando): We should cache the lswitch binding
            # too as long as we allow for multiple lswitches
            # TODO(salv-orlando): This routine has room for improvements!
            lswitches = nvplib.get_lswitches(self.cluster,
                                             port_data['network_id'])
            # Unfortunately the port could be on any switch
            for lswitch in lswitches:
                try:
                    nvplib.update_port(self.cluster,
                                       lswitch['uuid'],
                                       nvp_port_id,
                                       port_data['id'],
                                       port_data['tenant_id'],
                                       port_data['name'],
                                       port_data['device_id'],
                                       port_data['admin_state_up'],
                                       port_data['mac_address'],
                                       port_data['fixed_ips'],
                                       port_data[ext_psec.PORTSECURITY],
                                       port_data[ext_sg.SECURITYGROUPS],
                                       port_data[ext_qos.QUEUE])
                    self.response_handlers['update_port'](context, port_data)
                    break
                except NvpApiClient.ResourceNotFound:
                    # Skip this logical switch, look for the next one
                    LOG.debug(_("Logical port %(port_id)s was not "
                                "found on logical switch %(lswitch_id)s"),
                              {'lport_id': nvp_port_id,
                               'lswitch_id': lswitch['uuid']})
            else:
                # NOTE(salv-orlando): as nvp_get_port_id returned successfully
                # we should never hit these lines
                # Put the port in error state but do not bubble up the error
                self.exception_handlers['update_port'](
                    context, port_data, None)
        except NvpApiClient.ResourceNotFound:
            LOG.warning(_("NVP logical port:%s not found"), nvp_port_id)
            # Put the port in error state but do not bubble up the error
            self.exception_handlers['update_port'](context, port_data, None)
        except Exception:
            # Let the exception handler deal with the Exception
            with excutils.save_and_reraise_exception():
                self.exception_handlers['update_port'](context, port_data,
                                                       sys.exc_info())

    def delete_port(self, context, port_data, net):
        super(NvpSynchDriver, self).delete_port(context, port_data)
        try:
            if not net[l3.EXTERNAL]:
                port_func = self._delete_port_drivers[port_data['device_owner']]
                port_func(context, port_data)
            self.response_handlers['delete_port'](context, port_data)
        except NvpApiClient.ResourceNotFound:
            LOG.info(_("The port %s was already removed in the NVP backend"),
                     port_data['id'])
            # Invoke the success response handler, which will remove
            # the port from the database
            self.response_handlers['delete_port'](context, port_data)
        except Exception:
            # Let the exception handler deal with the Exception
            with excutils.save_and_reraise_exception():
                self.exception_handlers['delete_port'](context, port_data,
                                                       sys.exc_info())

    def create_router(self, context, tenant_id, router_data, ext_subnet=None):
        super(NvpSynchDriver, self).create_router(
            context, tenant_id, router_data)
        try:
            # Use a 'fake' nexthop if the external gateway is not set
            nexthop = ext_subnet and ext_subnet.get('gateway_ip') or '1.1.1.1'
            lrouter = nvplib.create_lrouter(
                self.cluster, tenant_id, router_data['name'],
                nexthop, router_data['id'])
            # Create the port here - and update it later if we have gw_info
            # NOTE(salv-orlando): Check whether this step is still necessary
            lrouter_gw_port = self._nvp_create_and_attach_router_port(
                context, lrouter['uuid'], {'fake_ext_gw': True},
                "L3GatewayAttachment", self.cluster.default_l3_gw_service_uuid)
            lrouter['gw_port_uuid'] = lrouter_gw_port
            self.response_handlers['create_router'](
                context, router_data, lrouter)
        except Exception:
            # Let the exception handler deal with the Exception
            with excutils.save_and_reraise_exception():
                self.exception_handlers['create_router'](context, router_data,
                                                         sys.exc_info())

    def delete_router(self, context, router_data):
        super(NvpSynchDriver, self).delete_router(context, router_data)
        try:
            lrouter_id = self._nvp_get_router_id(
                context, self.cluster, router_data['id'])
            nvplib.delete_lrouter(self.cluster, lrouter_id)
            self.response_handlers['delete_router'](context, router_data)
        except NvpApiClient.ResourceNotFound:
            LOG.info(_("The router %s was already removed in "
                       "the NVP backend"), router_data['id'])
            # Invoke the success response handler, which will remove
            # the router from the database
            self.response_handlers['delete_router'](context, router_data)
        except Exception:
            # Let the exception handler deal with the Exception
            with excutils.save_and_reraise_exception():
                self.exception_handlers['delete_router'](
                    context, router_data, sys.exc_info())

    def add_router_interface(self, context, router_data,
                             port_data, subnet_data):
        super(NvpSynchDriver, self).add_router_interface(
            context, router_data, port_data, subnet_data)
        # Add port to the logical router as well
        # The owner of the router port is always the same as the owner of the
        # router. Use tenant_id from the port instead of fetching more records
        # from the Quantum database
        # Find the NVP port corresponding to quantum port_id
        results = nvplib.query_lswitch_lports(
            self.cluster, '*',
            filters={'tag': port_data['id'],
                     'tag_scope': 'q_port_id'})
        if results:
            ls_port = results[0]
        else:
            self.exception_handlers['add_router_interface'](
                context, port_data, None)
            raise nvp_exc.NvpPluginException(
                err_msg=(_("The port %(port_id)s, connected to the router "
                           "%(router_id)s was not found on the NVP "
                           "backend.") % {'port_id': port_data['id'],
                                          'router_id': router_data['id']}))
        try:
            # Create logical router port and patch attachment
            nvp_router_id = self._nvp_get_router_id(
                context, self.cluster, router_data['id'])
            self._nvp_create_and_attach_router_port(
                context, nvp_router_id,
                port_data,
                "PatchAttachment", ls_port['uuid'],
                subnet_ids=[subnet_data['id']])
            # If there is an external gateway we need to
            # configure the SNAT rule.
            gw_port = router_data['gw_port']
            if gw_port:
                # gw_port might have multiple IPs
                # In that case we will consider only the first one
                if gw_port.get('fixed_ips'):
                    snat_ip = gw_port['fixed_ips'][0]['ip_address']
                    cidr_prefix = int(subnet_data['cidr'].split('/')[1])
                    nvplib.create_lrouter_snat_rule(
                        self.cluster, nvp_router_id, snat_ip, snat_ip,
                        order=NVP_EXTGW_NAT_RULES_ORDER - cidr_prefix,
                        match_criteria={'source_ip_addresses':
                                        subnet_data['cidr']})
                    nvplib.create_lrouter_nosnat_rule(
                        self.cluster, nvp_router_id,
                        order=NVP_NOSNAT_RULES_ORDER,
                        match_criteria={'destination_ip_addresses':
                                        subnet_data['cidr']})
            self.response_handlers['add_router_interface'](
                context, port_data)
        except Exception:
            # TODO(salv-orlando): remove NVP entities which have been
            # successfull created
            # Let the exception handler deal with the Exception
            with excutils.save_and_reraise_exception():
                self.exception_handlers['add_router_interface'](
                    context, port_data, sys.exc_info())

    def remove_router_interface(self, context, router_data,
                                port_data, subnet_data):
        super(NvpSynchDriver, self).remove_router_interface(
            context, router_data, port_data, subnet_data)

        results = nvplib.query_lswitch_lports(
            self.cluster, '*', relations="LogicalPortAttachment",
            filters={'tag': port_data['id'], 'tag_scope': 'q_port_id'})
        lrouter_port_id = None
        if results:
            lport = results[0]
            attachment_data = lport['_relations'].get('LogicalPortAttachment')
            lrouter_port_id = (attachment_data and
                               attachment_data.get('peer_port_uuid'))
        else:
            LOG.warning(_("The port %(port_id)s, connected to the router "
                          "%(router_id)s was not found on the NVP backend"),
                        {'port_id': port_data['id'],
                         'router_id': router_data['id']})
        # Destroy router port (no need to unplug the attachment)
        # FIXME(salvatore-orlando): In case of failures in the Quantum plugin
        # this migth leave a dangling port. We perform the operation here
        # to leverage validation performed in the base class
        if not lrouter_port_id:
            LOG.warning(_("Unable to find NVP logical router port for "
                          "Quantum port id:%s. Was this port ever paired "
                          "with a logical router?"), port_data['id'])
        try:
            nvp_router_id = self._nvp_get_router_id(
                context, self.cluster, router_data['id'])
            # Remove SNAT rule if external gateway is configured
            if router_data['gw_port']:
                nvplib.delete_nat_rules_by_match(
                    self.cluster, nvp_router_id, "SourceNatRule",
                    max_num_expected=1, min_num_expected=1,
                    source_ip_addresses=subnet_data['cidr'])
            # Relax the minimum rule number constraint as the nosnat
            # rules do not exist in 2.x deployments
            nvplib.delete_nat_rules_by_match(
                self.cluster, nvp_router_id, "NoSourceNatRule",
                max_num_expected=1, min_num_expected=0,
                destination_ip_addresses=subnet_data['cidr'])
            if lrouter_port_id:
                nvplib.delete_router_lport(
                    self.cluster, nvp_router_id, lrouter_port_id)
            self.response_handlers['remove_router_interface'](
                context, port_data)
        except Exception:
            with excutils.save_and_reraise_exception():
                self.exception_handlers['add_router_interface'](
                    context, port_data, sys.exc_info())

    def _retrieve_and_delete_nat_rules(self, context,
                                       floating_ip_address,
                                       internal_ip, nvp_router_id,
                                       min_num_rules_expected=0):
        try:
            nvplib.delete_nat_rules_by_match(
                self.cluster, nvp_router_id, "DestinationNatRule",
                max_num_expected=1,
                min_num_expected=min_num_rules_expected,
                destination_ip_addresses=floating_ip_address)
            # Remove SNAT rule associated with the single fixed_ip
            # to floating ip
            nvplib.delete_nat_rules_by_match(
                self.cluster, nvp_router_id, "SourceNatRule",
                max_num_expected=1,
                min_num_expected=min_num_rules_expected,
                source_ip_addresses=internal_ip)
        except nvp_exc.NvpNatRuleMismatch:
            # Do not surface to the user
            LOG.warning(_("An incorrect number of matching NAT rules "
                          "was found on the NVP platform"))

    def associate_floating_ip(self, context, floatingip_data,
                              floating_ips, rollback_data):
        floating_ip = floatingip_data['floating_ip_address']
        internal_ip = floatingip_data['fixed_ip_address']
        router_id = floatingip_data['router_id']
        try:
            nvp_router_id = self._nvp_get_router_id(
                context, self.cluster, router_id)
            # Retrieve previous NAT rules, if they exist
            self._retrieve_and_delete_nat_rules(
                context, floating_ip, internal_ip, nvp_router_id)
            # Fetch logical port of router's external gateway
            nvp_gw_port_id = nvplib.find_router_gw_port(
                self.cluster, nvp_router_id)['uuid']
            LOG.debug(_("Address list for NVP logical router "
                        "port:%s"), floating_ips)
            # Create new NAT rules
            nvplib.create_lrouter_dnat_rule(
                self.cluster, nvp_router_id, internal_ip,
                order=NVP_FLOATINGIP_NAT_RULES_ORDER,
                match_criteria={'destination_ip_addresses':
                                floating_ip})
            # setup snat rule such that src ip of a IP packet when
            #  using floating is the floating ip itself.
            nvplib.create_lrouter_snat_rule(
                self.cluster, nvp_router_id, floating_ip, floating_ip,
                order=NVP_FLOATINGIP_NAT_RULES_ORDER,
                match_criteria={'source_ip_addresses': internal_ip})
            # Add Floating IP address to router_port
            nvplib.update_lrouter_port_ips(self.cluster,
                                           nvp_router_id,
                                           nvp_gw_port_id,
                                           ips_to_add=floating_ips,
                                           ips_to_remove=[])
            self.response_handlers['associate_floating_ip'](
                context, floatingip_data)
        except Exception:
            LOG.exception(_("An error occurred while creating NAT "
                            "rules on the NVP platform for floating "
                            "ip:%(floating_ip)s mapped to "
                            "internal ip:%(internal_ip)s"),
                          {'floating_ip': floating_ip,
                           'internal_ip': internal_ip})
            with excutils.save_and_reraise_exception():
                self.exception_handlers['associate_floating_ip'](
                    context, floatingip_data, rollback_data, sys.exc_info())

    def disassociate_floating_ip(self, context, floatingip_data,
                                 floating_ips, rollback_data):
        floating_ip = rollback_data['floating_ip_address']
        internal_ip = rollback_data['fixed_ip_address']
        router_id = rollback_data['router_id']
        try:
            nvp_router_id = self._nvp_get_router_id(
                context, self.cluster, router_id)
            # Retrieve and delete previous NAT rules, if they exist
            self._retrieve_and_delete_nat_rules(
                context, floating_ip, internal_ip, nvp_router_id)
            # Fetch logical port of router's external gateway
            nvp_gw_port_id = nvplib.find_router_gw_port(
                self.cluster, nvp_router_id)['uuid']
            # Remove floating IP address from logical router port
            nvplib.update_lrouter_port_ips(self.cluster,
                                           nvp_router_id,
                                           nvp_gw_port_id,
                                           ips_to_add=[],
                                           ips_to_remove=floating_ips)
            self.response_handlers['disassociate_floating_ip'](
                context, floatingip_data)
        except Exception:
            LOG.exception(_("An error occurred while creating NAT "
                            "rules on the NVP platform for floating "
                            "ip:%(floating_ip)s mapped to "
                            "internal ip:%(internal_ip)s"),
                          {'floating_ip': floating_ip,
                           'internal_ip': internal_ip})
            with excutils.save_and_reraise_exception():
                self.exception_handlers['disassociate_floating_ip'](
                    context, floatingip_data, rollback_data, sys.exc_info())
