# Copyright (c) 2012 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from oslo.config import cfg

from quantum.api.v2 import attributes
from quantum.common import constants
from quantum.common import utils
from quantum import manager
from quantum.openstack.common import log as logging


LOG = logging.getLogger(__name__)


class DhcpRpcCallbackMixin(object):
    """A mix-in that enable DHCP agent support in plugin implementations."""

    def get_active_networks(self, context, **kwargs):
        """Retrieve and return a list of the active network ids."""
        host = kwargs.get('host')
        LOG.debug(_('Network list requested from %s'), host)
        plugin = manager.QuantumManager.get_plugin()
        if utils.is_extension_supported(
            plugin, constants.AGENT_SCHEDULER_EXT_ALIAS):
            if cfg.CONF.network_auto_schedule:
                plugin.auto_schedule_networks(context, host)
            nets = plugin.list_active_networks_on_active_dhcp_agent(
                context, host)
        else:
            filters = dict(admin_state_up=[True])
            nets = plugin.get_networks(context, filters=filters)
        return [net['id'] for net in nets]

    def get_all_network_info(self, context, **kwargs):
        """Returns all the networks/subnets/ports in system."""
        host = kwargs.get('host')
        LOG.debug(_('get_all_network_info from %s') % host)
        network_to_ports_map = {}
        network_to_subnets_map = {}
        plugin = manager.QuantumManager.get_plugin()
        networks = plugin.get_networks(context)
        subnets = plugin.get_subnets(context)
        ports = plugin.get_ports(context)
        for subnet in subnets:
            network_to_subnets_map.setdefault(
                subnet['network_id'], []).append(subnet)

        for port in ports:
            network_to_ports_map.setdefault(
                port['network_id'], []).append(port)

        for network in networks:
            network['subnets'] = network_to_subnets_map.get(network['id'], [])
            network['ports'] = network_to_ports_map.get(network['id'], [])

        return networks

    def get_network_info(self, context, **kwargs):
        """Retrieve and return a extended information about a network."""
        network_id = kwargs.get('network_id')
        host = kwargs.get('host')
        LOG.debug(_('Network %(network_id)s requested from '
                    '%(host)s'), {'network_id': network_id,
                                  'host': host})
        plugin = manager.QuantumManager.get_plugin()
        network = plugin.get_network(context, network_id)

        filters = dict(network_id=[network_id])
        network['subnets'] = plugin.get_subnets(context, filters=filters)
        network['ports'] = plugin.get_ports(context, filters=filters)
        return network

    def release_dhcp_port(self, context, **kwargs):
        """Release the port currently being used by a DHCP agent."""
        host = kwargs.get('host')
        network_id = kwargs.get('network_id')
        device_id = kwargs.get('device_id')

        LOG.debug(_('DHCP port deletion for %(network_id)s request from '
                    '%(host)s'), locals())
        plugin = manager.QuantumManager.get_plugin()
        filters = dict(network_id=[network_id], device_id=[device_id])
        ports = plugin.get_ports(context, filters=filters)

        if len(ports):
            plugin.delete_port(context, ports[0]['id'])

    def release_port_fixed_ip(self, context, **kwargs):
        """Release the fixed_ip associated the subnet on a port."""
        host = kwargs.get('host')
        network_id = kwargs.get('network_id')
        device_id = kwargs.get('device_id')
        subnet_id = kwargs.get('subnet_id')

        LOG.debug(_('DHCP port remove fixed_ip for %(subnet_id)s request '
                    'from %(host)s'), locals())
        plugin = manager.QuantumManager.get_plugin()
        filters = dict(network_id=[network_id], device_id=[device_id])
        ports = plugin.get_ports(context, filters=filters)

        if len(ports):
            port = ports[0]

            fixed_ips = port.get('fixed_ips', [])
            for i in range(len(fixed_ips)):
                if fixed_ips[i]['subnet_id'] == subnet_id:
                    del fixed_ips[i]
                    break
            plugin.update_port(context, port['id'], dict(port=port))

    def update_lease_expiration(self, context, **kwargs):
        """Release the fixed_ip associated the subnet on a port."""
        host = kwargs.get('host')
        network_id = kwargs.get('network_id')
        ip_address = kwargs.get('ip_address')
        lease_remaining = kwargs.get('lease_remaining')

        LOG.debug(_('Updating lease expiration for %(ip_address)s on network '
                    '%(network_id)s from %(host)s.'), locals())
        plugin = manager.QuantumManager.get_plugin()

        plugin.update_fixed_ip_lease_expiration(context, network_id,
                                                ip_address, lease_remaining)

    def create_dhcp_port(self, context, **kwargs):
        """Create the dhcp port."""
        host = kwargs.get('host')
        port = kwargs.get('port')
        LOG.debug(_('Create dhcp port  %(port)s '
                    'from %(host)s.'),
                  {'port': port,
                   'host': host})

        if 'mac_address' not in port['port']:
            port['port']['mac_address'] = attributes.ATTR_NOT_SPECIFIED
        plugin = manager.QuantumManager.get_plugin()
        return plugin.create_port(context, port)

    def update_dhcp_port(self, context, **kwargs):
        """Update the dhcp port."""
        host = kwargs.get('host')
        port_id = kwargs.get('port_id')
        port = kwargs.get('port')
        LOG.debug(_('Create dhcp port  %(port)s '
                    'from %(host)s.'),
                  {'port': port,
                   'host': host})
        plugin = manager.QuantumManager.get_plugin()
        return plugin.update_port(context, port_id, port)
