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

import logging
import os

import mock
import webob.exc

from quantum.common import exceptions as q_exc
import quantum.common.test_lib as test_lib
from quantum import context
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
import quantum.tests.unit.test_extension_nvp_qos as test_nvp_qos
import quantum.tests.unit.test_extension_port_security as psec

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
        instance.return_value.login.return_value = "the_cookie"

        def _fake_request(*args, **kwargs):
            return self.fc.fake_request(*args, **kwargs)

        instance.return_value.request.side_effect = _fake_request
        super(NiciraPluginV2TestCase, self).setUp(self._plugin_name)

    def tearDown(self):
        self.fc.reset_all()
        super(NiciraPluginV2TestCase, self).tearDown()
        self.mock_nvpapi.stop()


class NiciraQoSQueueTestCase(test_nvp_qos.NvpQoSTestCase):

    _plugin_name = ('%s.QuantumPlugin.NvpPluginV2' % NICIRA_PKG_PATH)

    def setUp(self):
        etc_path = os.path.join(os.path.dirname(__file__), 'etc')
        test_lib.test_config['config_files'] = [os.path.join(etc_path,
                                                             'nvp.ini.test')]
        # mock nvp api client
        fc = fake_nvpapiclient.FakeClient(etc_path)
        self.mock_nvpapi = mock.patch('%s.NvpApiClient.NVPApiHelper'
                                      % NICIRA_PKG_PATH, autospec=True)
        instance = self.mock_nvpapi.start()
        instance.return_value.login.return_value = "the_cookie"

        def _fake_request(*args, **kwargs):
            return fc.fake_request(*args, **kwargs)

        instance.return_value.request.side_effect = _fake_request
        super(NiciraQoSQueueTestCase, self).setUp(self._plugin_name)

    def tearDown(self):
        super(NiciraQoSQueueTestCase, self).tearDown()
        self.mock_nvpapi.stop()


class NiciraSecurityGroupsTestCase(ext_sg.SecurityGroupsTestCase):

    _plugin_name = ('%s.QuantumPlugin.NvpPluginV2' % NICIRA_PKG_PATH)

    def setUp(self):
        etc_path = os.path.join(os.path.dirname(__file__), 'etc')
        test_lib.test_config['config_files'] = [os.path.join(etc_path,
                                                             'nvp.ini.test')]
        # mock nvp api client
        fc = fake_nvpapiclient.FakeClient(etc_path)
        self.mock_nvpapi = mock.patch('%s.NvpApiClient.NVPApiHelper'
                                      % NICIRA_PKG_PATH, autospec=True)
        instance = self.mock_nvpapi.start()
        instance.return_value.login.return_value = "the_cookie"

        def _fake_request(*args, **kwargs):
            return fc.fake_request(*args, **kwargs)

        instance.return_value.request.side_effect = _fake_request
        super(NiciraSecurityGroupsTestCase, self).setUp(self._plugin_name)

    def tearDown(self):
        super(NiciraSecurityGroupsTestCase, self).tearDown()
        self.mock_nvpapi.stop()


class NiciraPortSecurityTestCase(psec.PortSecurityTestCase):

    _plugin_name = ('%s.QuantumPlugin.NvpPluginV2' % NICIRA_PKG_PATH)

    def setUp(self):
        etc_path = os.path.join(os.path.dirname(__file__), 'etc')
        test_lib.test_config['config_files'] = [os.path.join(etc_path,
                                                             'nvp.ini.test')]
        # mock nvp api client
        fc = fake_nvpapiclient.FakeClient(etc_path)
        self.mock_nvpapi = mock.patch('%s.NvpApiClient.NVPApiHelper'
                                      % NICIRA_PKG_PATH, autospec=True)
        instance = self.mock_nvpapi.start()
        instance.return_value.login.return_value = "the_cookie"

        def _fake_request(*args, **kwargs):
            return fc.fake_request(*args, **kwargs)

        instance.return_value.request.side_effect = _fake_request
        super(NiciraPortSecurityTestCase, self).setUp(self._plugin_name)

    def tearDown(self):
        super(NiciraPortSecurityTestCase, self).tearDown()
        self.mock_nvpapi.stop()


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


class TestNiciraNetworksV2(test_plugin.TestNetworksV2,
                           NiciraPluginV2TestCase):

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


class TestNiciraSecurityGroup(ext_sg.TestSecurityGroups,
                              NiciraSecurityGroupsTestCase):
    pass


class TestNiciraPortSecurity(psec.TestPortSecurity,
                             NiciraPortSecurityTestCase):
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


class TestNiciraQoSQueue(test_nvp_qos.TestNvpQoS,
                         NiciraQoSQueueTestCase):
    pass


class TestNiciraNetworkGatewayTestCase(test_l2_gw.NetworkGatewayDbTestCase,
                                       NiciraPluginV2TestCase):
    pass
