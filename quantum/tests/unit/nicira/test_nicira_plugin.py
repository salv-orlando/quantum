# Copyright (c) 2012 OpenStack, LLC.
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
import contextlib
import logging
import os

import mock
import webob.exc

from quantum.common import exceptions as q_exc
import quantum.common.test_lib as test_lib
from quantum import context
from quantum.extensions import nvp_qos
from quantum.extensions import providernet as pnet
from quantum import manager
from quantum.openstack.common import cfg
import quantum.plugins.nicira.nicira_nvp_plugin as nvp_plugin
from quantum.plugins.nicira.nicira_nvp_plugin import nvplib
from quantum.tests.unit.nicira import fake_nvpapiclient
import quantum.tests.unit.nicira.test_networkgw as test_l2_gw
import quantum.tests.unit.test_db_plugin as test_plugin
import quantum.tests.unit.test_extension_security_group as ext_sg
import quantum.tests.unit.test_l3_plugin as test_l3_plugin
import quantum.tests.unit.test_extension_port_security as psec
from quantum.tests.unit import test_extensions

LOG = logging.getLogger(__name__)
NICIRA_PKG_PATH = nvp_plugin.__name__


class NiciraPluginV2TestCase(test_plugin.QuantumDbPluginV2TestCase):

    _plugin_name = ('%s.QuantumPlugin.NvpPluginV2' % NICIRA_PKG_PATH)

    def _create_network(self, fmt, name, admin_status_up,
                        arg_list=None, providernet_args=None, **kwargs):
        data = {'network': {'name': name,
                            'admin_state_up': admin_status_up,
                            'tenant_id': self._tenant_id}}
        attributes = kwargs
        if providernet_args:
            attributes.update(providernet_args)
        for arg in (('admin_state_up', 'tenant_id', 'shared') +
                    (arg_list or ())):
            # Arg must be present and not empty
            if arg in kwargs and kwargs[arg]:
                data['network'][arg] = kwargs[arg]
        network_req = self.new_create_request('networks', data, fmt)
        if (kwargs.get('set_context') and 'tenant_id' in kwargs):
            # create a specific auth context for this request
            network_req.environ['quantum.context'] = context.Context(
                '', kwargs['tenant_id'])
        return network_req.get_response(self.api)

    def setUp(self):
        etc_path = os.path.join(os.path.dirname(__file__), 'etc')
        test_lib.test_config['config_files'] = [os.path.join(etc_path,
                                                             'nvp.ini.test')]
        # mock nvp api client
        self.fc = fake_nvpapiclient.FakeClient(etc_path)
        self.mock_nvpapi = mock.patch('%s.NvpApiClient.NVPApiHelper'
                                      % NICIRA_PKG_PATH, autospec=True)
        instance = self.mock_nvpapi.start()

        def _fake_request(*args, **kwargs):
            return self.fc.fake_request(*args, **kwargs)

        # Emulate tests against NVP 2.x
        instance.return_value.get_nvp_version.return_value = "2.999"
        instance.return_value.request.side_effect = _fake_request
        super(NiciraPluginV2TestCase, self).setUp(self._plugin_name)

    def tearDown(self):
        self.fc.reset_all()
        super(NiciraPluginV2TestCase, self).tearDown()
        self.mock_nvpapi.stop()
        del test_lib.test_config['config_files']


class NvpQoSTestExtensionManager(object):

    def get_resources(self):
        return nvp_qos.Nvp_qos.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class TestNiciraQoSQueue(NiciraPluginV2TestCase):

    def setUp(self, plugin=None):
        ext_mgr = NvpQoSTestExtensionManager()
        test_lib.test_config['extension_manager'] = ext_mgr
        super(TestNiciraQoSQueue, self).setUp()

    def _create_qos_queue(self, fmt, body):
        qos_queue = self.new_create_request('qos-queues', body)
        return qos_queue.get_response(self.ext_api)

    @contextlib.contextmanager
    def qos_queue(self, name='foo', min='0', max=None,
                  qos_marking=None, dscp='0', default=None, no_delete=False):

        body = {'qos_queue': {'tenant_id': 'tenant',
                              'name': name,
                              'min': min}}

        if max:
            body['qos_queue']['max'] = max
        if qos_marking:
            body['qos_queue']['qos_marking'] = qos_marking
        if dscp:
            body['qos_queue']['dscp'] = dscp
        if default:
            body['qos_queue']['default'] = default

        res = self._create_qos_queue('json', body)
        qos_queue = self.deserialize('json', res)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        yield qos_queue
        if not no_delete:
            self._delete('qos-queues',
                         qos_queue['qos_queue']['id'])

    def test_create_qos_queue(self):
        with self.qos_queue(name='fake_lqueue', min=34, max=44,
                            qos_marking='untrusted', default=False) as q:
            self.assertEquals(q['qos_queue']['name'], 'fake_lqueue')
            self.assertEquals(q['qos_queue']['min'], 34)
            self.assertEquals(q['qos_queue']['max'], 44)
            self.assertEquals(q['qos_queue']['qos_marking'], 'untrusted')
            self.assertEquals(q['qos_queue']['default'], False)

    def test_create_qos_queue_default(self):
        with self.qos_queue(default=True) as q:
            self.assertEquals(q['qos_queue']['default'], True)

    def test_create_qos_queue_two_default_queues_fail(self):
        with self.qos_queue(default=True):
            body = {'qos_queue': {'tenant_id': 'tenant',
                                  'name': 'second_default_queue',
                                  'default': True}}
            res = self._create_qos_queue('json', body)
            self.assertEquals(res.status_int, 409)

    def test_create_port_with_queue(self):
        with self.qos_queue(default=True) as q1:
            res = self._create_network('json', 'net1', True,
                                       arg_list=(nvp_qos.QUEUE,),
                                       queue_id=q1['qos_queue']['id'])
            net1 = self.deserialize('json', res)
            self.assertEquals(net1['network'][nvp_qos.QUEUE],
                              q1['qos_queue']['id'])
            device_id = "00fff4d0-e4a8-4a3a-8906-4c4cdafb59f1"
            with self.port(device_id=device_id) as p:
                self.assertEquals(len(p['port'][nvp_qos.QUEUE]), 36)

    def test_create_shared_queue_networks(self):
        with self.qos_queue(default=True, no_delete=True) as q1:
            res = self._create_network('json', 'net1', True,
                                       arg_list=(nvp_qos.QUEUE,),
                                       queue_id=q1['qos_queue']['id'])
            net1 = self.deserialize('json', res)
            self.assertEquals(net1['network'][nvp_qos.QUEUE],
                              q1['qos_queue']['id'])
            res = self._create_network('json', 'net2', True,
                                       arg_list=(nvp_qos.QUEUE,),
                                       queue_id=q1['qos_queue']['id'])
            net2 = self.deserialize('json', res)
            self.assertEquals(net1['network'][nvp_qos.QUEUE],
                              q1['qos_queue']['id'])
            device_id = "00fff4d0-e4a8-4a3a-8906-4c4cdafb59f1"
            res = self._create_port('json', net1['network']['id'],
                                    device_id=device_id)
            port1 = self.deserialize('json', res)
            res = self._create_port('json', net2['network']['id'],
                                    device_id=device_id)
            port2 = self.deserialize('json', res)
            self.assertEquals(port1['port'][nvp_qos.QUEUE],
                              port2['port'][nvp_qos.QUEUE])

            self._delete('ports', port1['port']['id'])
            self._delete('ports', port2['port']['id'])

    def test_remove_queue_in_use_fail(self):
        with self.qos_queue(no_delete=True) as q1:
            res = self._create_network('json', 'net1', True,
                                       arg_list=(nvp_qos.QUEUE,),
                                       queue_id=q1['qos_queue']['id'])
            net1 = self.deserialize('json', res)
            device_id = "00fff4d0-e4a8-4a3a-8906-4c4cdafb59f1"
            res = self._create_port('json', net1['network']['id'],
                                    device_id=device_id)
            port = self.deserialize('json', res)
            self._delete('qos-queues', port['port'][nvp_qos.QUEUE], 409)

    def test_update_network_new_queue(self):
        with self.qos_queue() as q1:
            res = self._create_network('json', 'net1', True,
                                       arg_list=(nvp_qos.QUEUE,),
                                       queue_id=q1['qos_queue']['id'])
            net1 = self.deserialize('json', res)
            with self.qos_queue() as new_q:
                data = {'network': {nvp_qos.QUEUE: new_q['qos_queue']['id']}}
                req = self.new_update_request('networks', data,
                                              net1['network']['id'])
                res = req.get_response(self.api)
                net1 = self.deserialize('json', res)
                self.assertEquals(net1['network'][nvp_qos.QUEUE],
                                  new_q['qos_queue']['id'])

    def test_update_port_adding_device_id(self):
        with self.qos_queue(no_delete=True) as q1:
            res = self._create_network('json', 'net1', True,
                                       arg_list=(nvp_qos.QUEUE,),
                                       queue_id=q1['qos_queue']['id'])
            net1 = self.deserialize('json', res)
            device_id = "00fff4d0-e4a8-4a3a-8906-4c4cdafb59f1"
            res = self._create_port('json', net1['network']['id'])
            port = self.deserialize('json', res)
            self.assertEquals(port['port'][nvp_qos.QUEUE], None)

            data = {'port': {'device_id': device_id}}
            req = self.new_update_request('ports', data,
                                          port['port']['id'])

            res = req.get_response(self.api)
            port = self.deserialize('json', res)
            self.assertEquals(len(port['port'][nvp_qos.QUEUE]), 36)


class TestNiciraBasicGet(test_plugin.TestBasicGet, NiciraPluginV2TestCase):
    pass


class TestNiciraV2HTTPResponse(test_plugin.TestV2HTTPResponse,
                               NiciraPluginV2TestCase):
    pass


class TestNiciraPortsV2(test_plugin.TestPortsV2, NiciraPluginV2TestCase):

    def test_exhaust_ports_overlay_network(self):
        cfg.CONF.set_override('max_lp_per_overlay_ls', 1, group='NVP')
        with self.network(name='testnet',
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.PHYSICAL_NETWORK,
                                    pnet.SEGMENTATION_ID)) as net:
            with self.subnet(network=net) as sub:
                with self.port(subnet=sub):
                    # creating another port should see an exception
                    self._create_port('json', net['network']['id'], 400)

    def test_exhaust_ports_bridged_network(self):
        cfg.CONF.set_override('max_lp_per_bridged_ls', 1, group="NVP")
        providernet_args = {pnet.NETWORK_TYPE: 'flat',
                            pnet.PHYSICAL_NETWORK: 'tzuuid'}
        with self.network(name='testnet',
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.PHYSICAL_NETWORK,
                                    pnet.SEGMENTATION_ID)) as net:
            with self.subnet(network=net) as sub:
                with self.port(subnet=sub):
                    with self.port(subnet=sub):
                        plugin = manager.QuantumManager.get_plugin()
                        ls = nvplib.get_lswitches(plugin.default_cluster,
                                                  net['network']['id'])
                        self.assertEqual(len(ls), 2)

    def test_create_port_name_exceeds_40_chars(self):
        name = 'port0123456net0123456net0123456net0123456net0123456'
        keys = [('admin_state_up', True), ('status', 'ACTIVE')]
        with self.port(name=name) as port:
            for k, v in keys:
                self.assertEquals(port['port'][k], v)
            self.assertTrue('mac_address' in port['port'])
            ips = port['port']['fixed_ips']
            self.assertEquals(len(ips), 1)
            self.assertEquals(ips[0]['ip_address'], '10.0.0.2')
            self.assertEquals(name, port['port']['name'])


class TestNiciraNetworksV2(test_plugin.TestNetworksV2,
                           NiciraPluginV2TestCase):

    def test_create_network_name_exceeds_40_chars(self):
        name = 'net0123456net0123456net0123456net0123456net0123456'
        keys = [('subnets', []), ('name', name), ('admin_state_up', True),
                ('status', 'ACTIVE'), ('shared', False)]
        with self.network(name=name) as net:
            for k, v in keys:
                self.assertEquals(net['network'][k], v)

    def test_create_network_name_is_none_returns_400(self):
        with self.assertRaises(webob.exc.HTTPClientError) as ctx_manager:
            with self.network(name=None):
                pass
        self.assertEquals(ctx_manager.exception.code, 400)

    def _test_create_bridge_network(self, vlan_id=None):
        net_type = vlan_id and 'vlan' or 'flat'
        name = 'bridge_net'
        keys = [('subnets', []), ('name', name), ('admin_state_up', True),
                ('status', 'ACTIVE'), ('shared', False),
                (pnet.NETWORK_TYPE, net_type),
                (pnet.PHYSICAL_NETWORK, 'tzuuid'),
                (pnet.SEGMENTATION_ID, vlan_id)]
        providernet_args = {pnet.NETWORK_TYPE: net_type,
                            pnet.PHYSICAL_NETWORK: 'tzuuid'}
        if vlan_id:
            providernet_args[pnet.SEGMENTATION_ID] = vlan_id
        with self.network(name=name,
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.PHYSICAL_NETWORK,
                                    pnet.SEGMENTATION_ID)) as net:
            for k, v in keys:
                self.assertEquals(net['network'][k], v)

    def test_create_bridge_network(self):
        self._test_create_bridge_network()

    def test_create_bridge_vlan_network(self):
        self._test_create_bridge_network(vlan_id=123)

    def test_create_bridge_vlan_network_outofrange_returns_400(self):
        with self.assertRaises(webob.exc.HTTPClientError) as ctx_manager:
            self._test_create_bridge_network(vlan_id=5000)
        self.assertEquals(ctx_manager.exception.code, 400)

    def test_create_bridge_vlan_network_idinuse_returns_409(self):
        vlan_id = 123
        self._test_create_bridge_network(vlan_id=vlan_id)
        with self.assertRaises(webob.exc.HTTPClientError) as ctx_manager:
            self._test_create_bridge_network(vlan_id=vlan_id)
        self.assertEquals(ctx_manager.exception.code, 409)

    def test_delete_network_after_removing_subet(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        fmt = 'json'
        # Create new network
        res = self._create_network(fmt=fmt, name='net',
                                   admin_status_up=True)
        network = self.deserialize(fmt, res)
        subnet = self._make_subnet(fmt, network, gateway_ip,
                                   cidr, ip_version=4)
        req = self.new_delete_request('subnets', subnet['subnet']['id'])
        sub_del_res = req.get_response(self.api)
        self.assertEqual(sub_del_res.status_int, 204)
        req = self.new_delete_request('networks', network['network']['id'])
        net_del_res = req.get_response(self.api)
        self.assertEqual(net_del_res.status_int, 204)

    def test_list_networks_with_shared(self):
        with self.network(name='net1') as net1:
            with self.network(name='net2', shared=True) as net2:
                req = self.new_list_request('networks')
                res = self.deserialize('json', req.get_response(self.api))
                self.assertEqual(len(res['networks']), 2)
                req_2 = self.new_list_request('networks')
                req_2.environ['quantum.context'] = context.Context('',
                                                                   'somebody')
                res = self.deserialize('json', req_2.get_response(self.api))
                # tenant must see a single network
                self.assertEqual(len(res['networks']), 1)


class TestNiciraSecurityGroup(ext_sg.TestSecurityGroupsDB,
                              NiciraPluginV2TestCase):
    pass


class TestNiciraPortSecurity(psec.TestPortSecurityDB,
                             NiciraPluginV2TestCase):
    pass


class TestNiciraL3NatTestCase(test_l3_plugin.L3NatDBTestCase,
                              NiciraPluginV2TestCase):

    def test_floatingip_with_assoc_fails(self):
        fmt = 'json'
        with self.subnet(cidr='200.0.0.1/24') as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            with self.port() as private_port:
                with self.router() as r:
                    sid = private_port['port']['fixed_ips'][0]['subnet_id']
                    private_sub = {'subnet': {'id': sid}}
                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        public_sub['subnet']['network_id'])
                    self._router_interface_action('add', r['router']['id'],
                                                  private_sub['subnet']['id'],
                                                  None)
                    PLUGIN_CLASS = ('quantum.plugins.nicira.nicira_nvp_plugin.'
                                    'QuantumPlugin.NvpPluginV2')
                    METHOD = PLUGIN_CLASS + '._update_fip_assoc'
                    with mock.patch(METHOD) as pl:
                        pl.side_effect = q_exc.BadRequest(
                            resource='floatingip',
                            msg='fake_error')
                        res = self._create_floatingip(
                            fmt,
                            public_sub['subnet']['network_id'],
                            port_id=private_port['port']['id'])
                        self.assertEqual(res.status_int, 400)

                    for p in self._list('ports')['ports']:
                        if p['device_owner'] == 'network:floatingip':
                            self.fail('garbage port is not deleted')

                    self._remove_external_gateway_from_router(
                        r['router']['id'],
                        public_sub['subnet']['network_id'])
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  private_sub['subnet']['id'],
                                                  None)


class TestNiciraNetworkGatewayTestCase(test_l2_gw.NetworkGatewayDbTestCase,
                                       NiciraPluginV2TestCase):
    pass
