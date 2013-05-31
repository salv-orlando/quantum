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
            'create': {},
            'delete': {}
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
        nvplib.delete_port(self.cluster,
                           port_data['network_id'],
                           nvp_port_id)
        LOG.debug(_("_nvp_delete_port completed for port %(port_id)s "
                    "on network %(net_id)s"),
                  {'port_id': port_data['id'],
                   'net_id': port_data['network_id']})

    def get_network_status(self, network_id):
        super(NvpSynchDriver, self).get_network_status(network_id)
        statuses = {}
        for lswitch in nvplib.query_lswitches_status(
                self.cluster, network_id=network_id):
            _set_network_status(statuses, lswitch)
        # We expect a single element in statuses
        return nvp_to_quantum_net_status_dict[statuses.get(network_id)]

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
            port_func = self._create_port_drivers[port_data['device_owner']]
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
            nvplib.update_port(self.cluster,
                               port_data['network_id'],
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
        except NvpApiClient.ResourceNotFound:
            LOG.warning(_("NVP logical port:%s not found"), nvp_port_id)
            # Put the port in error state but do not bubble up the error
            self.exception_handlers['update_port'](context, port_data, None)
        except Exception:
            # Let the exception handler deal with the Exception
            with excutils.save_and_reraise_exception():
                self.exception_handlers['update_port'](context, port_data,
                                                       sys.exc_info())

    def delete_port(self, context, port_data):
        super(NvpSynchDriver, self).delete_port(context, port_data)
        try:
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
