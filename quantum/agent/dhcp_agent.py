# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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
#    under the License.

import logging
import socket
import sys
import uuid

import eventlet
import netaddr

from quantum.agent import rpc as agent_rpc
from quantum.agent.common import config
from quantum.agent.linux import dhcp
from quantum.agent.linux import interface
from quantum.agent.linux import ip_lib
from quantum.common import exceptions
from quantum.common import topics
from quantum.openstack.common import cfg
from quantum.openstack.common import context
from quantum.openstack.common import importutils
from quantum.openstack.common.rpc import proxy
from quantum.version import version_string

LOG = logging.getLogger(__name__)


class DhcpAgent(object):
    OPTS = [
        cfg.StrOpt('root_helper', default='sudo'),
        cfg.StrOpt('dhcp_driver',
                   default='quantum.agent.linux.dhcp.Dnsmasq',
                   help="The driver used to manage the DHCP server."),
        cfg.BoolOpt('use_namespaces', default=True,
                    help="Allow overlapping IP.")
    ]

    def __init__(self, conf):
        self.conf = conf
        self.cache = NetworkCache()

        self.dhcp_driver_cls = importutils.import_class(conf.dhcp_driver)
        ctx = context.RequestContext('quantum', 'quantum', is_admin=True)
        self.plugin_rpc = DhcpPluginApi(topics.PLUGIN, ctx)

        self.device_manager = DeviceManager(self.conf, self.plugin_rpc)
        self.notifications = agent_rpc.NotificationDispatcher()

    def run(self):
        """Activate the DHCP agent."""
        # enable DHCP for current networks
        for network_id in self.plugin_rpc.get_active_networks():
            self.enable_dhcp_helper(network_id)

        self.notifications.run_dispatch(self)

    def call_driver(self, action, network):
        """Invoke an action on a DHCP driver instance."""
        try:
            # the Driver expects something that is duck typed similar to
            # the base models.
            driver = self.dhcp_driver_cls(self.conf,
                                          network,
                                          self.conf.root_helper,
                                          self.device_manager)
            getattr(driver, action)()

        except Exception, e:
            LOG.warn('Unable to %s dhcp. Exception: %s' % (action, e))

    def enable_dhcp_helper(self, network_id):
        """Enable DHCP for a network that meets enabling criteria."""
        network = self.plugin_rpc.get_network_info(network_id)
        for subnet in network.subnets:
            if subnet.enable_dhcp:
                if network.admin_state_up:
                    self.call_driver('enable', network)
                    self.cache.put(network)
                break

    def disable_dhcp_helper(self, network_id):
        """Disable DHCP for a network known to the agent."""
        network = self.cache.get_network_by_id(network_id)
        if network:
            self.call_driver('disable', network)
            self.cache.remove(network)

    def refresh_dhcp_helper(self, network_id):
        """Refresh or disable DHCP for a network depending on the current state
        of the network.

        """
        if not self.cache.get_network_by_id(network_id):
            # DHCP current not running for network.
            self.enable_dhcp_helper(network_id)

        network = self.plugin_rpc.get_network_info(network_id)
        for subnet in network.subnets:
            if subnet.enable_dhcp:
                self.cache.put(network)
                self.call_driver('update_l3', network)
                break
        else:
            self.disable_dhcp_helper(network.id)

    def network_create_end(self, payload):
        """Handle the network.create.end notification event."""
        network_id = payload['network']['id']
        self.enable_dhcp_helper(network_id)

    def network_update_end(self, payload):
        """Handle the network.update.end notification event."""
        network_id = payload['network']['id']
        if payload['network']['admin_state_up']:
            self.enable_dhcp_helper(network_id)
        else:
            self.disable_dhcp_helper(network_id)

    def network_delete_start(self, payload):
        """Handle the network.detete.start notification event."""
        self.disable_dhcp_helper(payload['network_id'])

    def subnet_delete_start(self, payload):
        """Handle the subnet.detete.start notification event."""
        subnet_id = payload['subnet_id']
        network = self.cache.get_network_by_subnet_id(subnet_id)
        if network:
            device_id = self.device_manager.get_device_id(network)
            self.plugin_rpc.release_port_fixed_ip(network.id, device_id,
                                                  subnet_id)

    def subnet_update_end(self, payload):
        """Handle the subnet.update.end notification event."""
        network_id = payload['subnet']['network_id']
        self.refresh_dhcp_helper(network_id)

    # Use the update handler for the subnet create event.
    subnet_create_end = subnet_update_end

    def subnet_delete_end(self, payload):
        """Handle the subnet.delete.end notification event."""
        subnet_id = payload['subnet_id']
        network = self.cache.get_network_by_subnet_id(subnet_id)
        if network:
            self.refresh_dhcp_helper(network.id)

    def port_update_end(self, payload):
        """Handle the port.update.end notification event."""
        port = DictModel(payload['port'])
        network = self.cache.get_network_by_id(port.network_id)
        if network:
            self.cache.put_port(port)
            self.call_driver('reload_allocations', network)

    # Use the update handler for the port create event.
    port_create_end = port_update_end

    def port_delete_end(self, payload):
        """Handle the port.delete.end notification event."""
        port = self.cache.get_port_by_id(payload['port_id'])
        if port:
            network = self.cache.get_network_by_id(port.network_id)
            self.cache.remove_port(port)
            self.call_driver('reload_allocations', network)


class DhcpPluginApi(proxy.RpcProxy):
    """Agent side of the dhcp rpc API.

    API version history:
        1.0 - Initial version.

    """

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic, context):
        super(DhcpPluginApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.context = context
        self.host = socket.gethostname()

    def get_active_networks(self):
        """Make a remote process call to retrieve the active networks."""
        return self.call(self.context,
                         self.make_msg('get_active_networks', host=self.host),
                         topic=self.topic)

    def get_network_info(self, network_id):
        """Make a remote process call to retrieve network info."""
        return DictModel(self.call(self.context,
                                   self.make_msg('get_network_info',
                                                 network_id=network_id,
                                                 host=self.host),
                                   topic=self.topic))

    def get_dhcp_port(self, network_id, device_id):
        """Make a remote process call to create the dhcp port."""
        return DictModel(self.call(self.context,
                                   self.make_msg('get_dhcp_port',
                                                 network_id=network_id,
                                                 device_id=device_id,
                                                 host=self.host),
                                   topic=self.topic))

    def release_dhcp_port(self, network_id, device_id):
        """Make a remote process call to release the dhcp port."""
        return self.call(self.context,
                         self.make_msg('release_dhcp_port',
                                       network_id=network_id,
                                       device_id=device_id,
                                       host=self.host),
                         topic=self.topic)

    def release_port_fixed_ip(self, network_id, device_id, subnet_id):
        """Make a remote process call to release a fixed_ip on the port."""
        return self.call(self.context,
                         self.make_msg('release_port_fixed_ip',
                                       network_id=network_id,
                                       subnet_id=subnet_id,
                                       device_id=device_id,
                                       host=self.host),
                         topic=self.topic)


class NetworkCache(object):
    """Agent cache of the current network state."""
    def __init__(self):
        self.cache = {}
        self.subnet_lookup = {}
        self.port_lookup = {}

    def get_network_by_id(self, network_id):
        return self.cache.get(network_id)

    def get_network_by_subnet_id(self, subnet_id):
        return self.cache.get(self.subnet_lookup.get(subnet_id))

    def get_network_by_port_id(self, port_id):
        return self.cache.get(self.port_lookup.get(port_id))

    def put(self, network):
        if network.id in self.cache:
            self.remove(self.cache[network.id])

        self.cache[network.id] = network

        for subnet in network.subnets:
            self.subnet_lookup[subnet.id] = network.id

        for port in network.ports:
            self.port_lookup[port.id] = network.id

    def remove(self, network):
        del self.cache[network.id]

        for subnet in network.subnets:
            del self.subnet_lookup[subnet.id]

        for port in network.ports:
            del self.port_lookup[port.id]

    def put_port(self, port):
        network = self.get_network_by_id(port.network_id)
        for index in range(len(network.ports)):
            if network.ports[index].id == port.id:
                network.ports[index] = port
                break
        else:
            network.ports.append(port)

        self.port_lookup[port.id] = network.id

    def remove_port(self, port):
        network = self.get_network_by_port_id(port.id)

        for index in range(len(network.ports)):
            if network.ports[index] == port:
                del network.ports[index]
                del self.port_lookup[port.id]
                break

    def get_port_by_id(self, port_id):
        network = self.get_network_by_port_id(port_id)
        if network:
            for port in network.ports:
                if port.id == port_id:
                    return port


class DeviceManager(object):
    OPTS = [
        cfg.StrOpt('admin_user'),
        cfg.StrOpt('admin_password'),
        cfg.StrOpt('admin_tenant_name'),
        cfg.StrOpt('auth_url'),
        cfg.StrOpt('auth_strategy', default='keystone'),
        cfg.StrOpt('auth_region'),
        cfg.StrOpt('interface_driver',
                   help="The driver used to manage the virtual interface.")
    ]

    def __init__(self, conf, plugin):
        self.conf = conf
        self.plugin = plugin
        if not conf.interface_driver:
            LOG.error(_('You must specify an interface driver'))
        self.driver = importutils.import_object(conf.interface_driver, conf)

    def get_interface_name(self, network, port=None):
        """Return interface(device) name for use by the DHCP process."""
        if not port:
            device_id = self.get_device_id(network)
            port = self.plugin.get_dhcp_port(network.id, device_id)
        return self.driver.get_device_name(port)

    def get_device_id(self, network):
        """Return a unique DHCP device ID for this host on the network."""
        # There could be more than one dhcp server per network, so create
        # a device id that combines host and network ids

        host_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, socket.gethostname())
        return 'dhcp%s-%s' % (host_uuid, network.id)

    def setup(self, network, reuse_existing=False):
        """Create and initialize a device for network's DHCP on this host."""
        device_id = self.get_device_id(network)
        port = self.plugin.get_dhcp_port(network.id, device_id)

        interface_name = self.get_interface_name(network, port)

        if self.conf.use_namespaces:
            namespace = network.id
        else:
            namespace = None

        if  ip_lib.device_exists(interface_name,
                                 self.conf.root_helper,
                                 namespace):
            if not reuse_existing:
                raise exceptions.PreexistingDeviceFailure(
                    dev_name=interface_name)

            LOG.debug(_('Reusing existing device: %s.') % interface_name)
        else:
            self.driver.plug(network.id,
                             port.id,
                             interface_name,
                             port.mac_address,
                             namespace=namespace)
        ip_cidrs = []
        for fixed_ip in port.fixed_ips:
            subnet = fixed_ip.subnet
            net = netaddr.IPNetwork(subnet.cidr)
            ip_cidr = '%s/%s' % (fixed_ip.ip_address, net.prefixlen)
            ip_cidrs.append(ip_cidr)

        self.driver.init_l3(interface_name, ip_cidrs,
                            namespace=namespace)

    def destroy(self, network):
        """Destroy the device used for the network's DHCP on this host."""
        if self.conf.use_namespaces:
            namespace = network.id
        else:
            namespace = None

        self.driver.unplug(self.get_interface_name(network),
                           namespace=namespace)
        self.plugin.release_dhcp_port(network.id, self.get_device_id(network))

    def update_l3(self, network):
        """Update the L3 attributes for the current network's DHCP device."""
        self.setup(network, reuse_existing=True)


class DictModel(object):
    """Convert dict into an object that provides attribute access to values."""
    def __init__(self, d):
        for key, value in d.iteritems():
            if isinstance(value, list):
                value = [DictModel(item) if isinstance(item, dict) else item
                         for item in value]
            elif isinstance(value, dict):
                value = DictModel(value)

            setattr(self, key, value)


def main():
    eventlet.monkey_patch()
    cfg.CONF.register_opts(DhcpAgent.OPTS)
    cfg.CONF.register_opts(DeviceManager.OPTS)
    cfg.CONF.register_opts(dhcp.OPTS)
    cfg.CONF.register_opts(interface.OPTS)
    cfg.CONF(args=sys.argv, project='quantum')
    config.setup_logging(cfg.CONF)

    mgr = DhcpAgent(cfg.CONF)
    mgr.run()


if __name__ == '__main__':
    main()
