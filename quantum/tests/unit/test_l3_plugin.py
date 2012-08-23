"""
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Nicira Networks, Inc.  All rights reserved.
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
# @author: Dan Wendlandt, Nicira, Inc
#
"""

import contextlib
import copy
import logging
import unittest

import mock
import webtest
from webob import exc

from quantum.api.v2 import attributes
from quantum.common import config
from quantum.common.test_lib import test_config
from quantum.db import db_base_plugin_v2
from quantum.db import l3_db
from quantum.extensions import extensions
from quantum.extensions import l3
from quantum import manager
from quantum.openstack.common import cfg
from quantum.tests.unit import test_api_v2
from quantum.tests.unit import test_extensions
from quantum.tests.unit import test_db_plugin

LOG = logging.getLogger(__name__)

_uuid = test_api_v2._uuid
_get_path = test_api_v2._get_path


class L3TestExtensionManager(object):

    def get_resources(self):
        return l3.L3.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class L3NatExtensionTestCase(unittest.TestCase):

    def setUp(self):

        plugin = 'quantum.extensions.l3.RouterPluginBase'

        # Ensure 'stale' patched copies of the plugin are never returned
        manager.QuantumManager._instance = None

        # Ensure existing ExtensionManager is not used
        extensions.PluginAwareExtensionManager._instance = None

        # Save the global RESOURCE_ATTRIBUTE_MAP
        self.saved_attr_map = {}
        for resource, attrs in attributes.RESOURCE_ATTRIBUTE_MAP.iteritems():
            self.saved_attr_map[resource] = attrs.copy()

        # Create the default configurations
        args = ['--config-file', test_api_v2.etcdir('quantum.conf.test')]
        config.parse(args=args)

        # Update the plugin and extensions path
        cfg.CONF.set_override('core_plugin', plugin)

        self._plugin_patcher = mock.patch(plugin, autospec=True)
        self.plugin = self._plugin_patcher.start()

        # Instantiate mock plugin and enable the os-quantum-router  extension
        manager.QuantumManager.get_plugin().supported_extension_aliases = (
            ["os-quantum-router"])

        ext_mgr = L3TestExtensionManager()
        self.ext_mdw = test_extensions.setup_extensions_middleware(ext_mgr)
        self.api = webtest.TestApp(self.ext_mdw)

    def tearDown(self):
        self._plugin_patcher.stop()
        self.api = None
        self.plugin = None
        cfg.CONF.reset()

        # Restore the global RESOURCE_ATTRIBUTE_MAP
        attributes.RESOURCE_ATTRIBUTE_MAP = self.saved_attr_map

    def test_router_create(self):
        router_id = _uuid()
        data = {'router': {'name': 'router1', 'admin_state_up': True,
                           'tenant_id': _uuid(),
                           'external_gateway_info': None}}
        return_value = copy.deepcopy(data['router'])
        return_value.update({'status': "ACTIVE", 'id': router_id})

        instance = self.plugin.return_value
        instance.create_router.return_value = return_value

        res = self.api.post_json(_get_path('routers'), data)

        instance.create_router.assert_called_with(mock.ANY,
                                                  router=data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        self.assertTrue('router' in res.json)
        router = res.json['router']
        self.assertEqual(router['id'], router_id)
        self.assertEqual(router['status'], "ACTIVE")
        self.assertEqual(router['admin_state_up'], True)

    def test_router_list(self):
        router_id = _uuid()
        return_value = [{'router': {'name': 'router1', 'admin_state_up': True,
                                    'tenant_id': _uuid(), 'id': router_id}}]

        instance = self.plugin.return_value
        instance.get_routers.return_value = return_value

        res = self.api.get(_get_path('routers'))

        instance.get_routers.assert_called_with(mock.ANY, fields=mock.ANY,
                                                verbose=mock.ANY,
                                                filters=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_router_update(self):
        router_id = _uuid()
        update_data = {'router': {'admin_state_up': False}}
        return_value = {'name': 'router1', 'admin_state_up': False,
                        'tenant_id': _uuid(),
                        'status': "ACTIVE", 'id': router_id}

        instance = self.plugin.return_value
        instance.update_router.return_value = return_value

        res = self.api.put_json(_get_path('routers', id=router_id),
                                update_data)

        instance.update_router.assert_called_with(mock.ANY, router_id,
                                                  router=update_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        self.assertTrue('router' in res.json)
        router = res.json['router']
        self.assertEqual(router['id'], router_id)
        self.assertEqual(router['status'], "ACTIVE")
        self.assertEqual(router['admin_state_up'], False)

    def test_router_get(self):
        router_id = _uuid()
        return_value = {'name': 'router1', 'admin_state_up': False,
                        'tenant_id': _uuid(),
                        'status': "ACTIVE", 'id': router_id}

        instance = self.plugin.return_value
        instance.get_router.return_value = return_value

        res = self.api.get(_get_path('routers', id=router_id))

        instance.get_router.assert_called_with(mock.ANY, router_id,
                                               fields=mock.ANY,
                                               verbose=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        self.assertTrue('router' in res.json)
        router = res.json['router']
        self.assertEqual(router['id'], router_id)
        self.assertEqual(router['status'], "ACTIVE")
        self.assertEqual(router['admin_state_up'], False)

    def test_router_delete(self):
        router_id = _uuid()

        res = self.api.delete(_get_path('routers', id=router_id))

        instance = self.plugin.return_value
        instance.delete_router.assert_called_with(mock.ANY, router_id)
        self.assertEqual(res.status_int, exc.HTTPNoContent.code)

    def test_router_add_interface(self):
        router_id = _uuid()
        subnet_id = _uuid()
        port_id = _uuid()

        interface_data = {'subnet_id': subnet_id}
        return_value = copy.deepcopy(interface_data)
        return_value['port_id'] = port_id

        instance = self.plugin.return_value
        instance.add_router_interface.return_value = return_value

        path = _get_path('routers', id=router_id,
                         action="add_router_interface")
        res = self.api.put_json(path, interface_data)

        instance.add_router_interface.assert_called_with(mock.ANY, router_id,
                                                         interface_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        self.assertTrue('port_id' in res.json)
        self.assertEqual(res.json['port_id'], port_id)
        self.assertEqual(res.json['subnet_id'], subnet_id)


# This plugin class is just for testing
class TestL3NatPlugin(db_base_plugin_v2.QuantumDbPluginV2,
                      l3_db.L3_NAT_db_mixin):
    supported_extension_aliases = ["os-quantum-router"]

    def delete_port(self, context, id):
        self.disassociate_floatingips(context, id)
        return super(TestL3NatPlugin, self).delete_port(context, id)


class L3NatDBTestCase(test_db_plugin.QuantumDbPluginV2TestCase):

    def setUp(self):
        test_config['plugin_name_v2'] = (
            'quantum.tests.unit.test_l3_plugin.TestL3NatPlugin')
        ext_mgr = L3TestExtensionManager()
        test_config['extension_manager'] = ext_mgr
        super(L3NatDBTestCase, self).setUp()

    def _create_router(self, fmt, tenant_id, name=None, admin_state_up=None):
        data = {'router': {'tenant_id': tenant_id}}
        if name:
            data['router']['name'] = name
        if admin_state_up:
            data['router']['admin_state_up'] = admin_state_up
        router_req = self.new_create_request('routers', data, fmt)
        return router_req.get_response(self.ext_api)

    def _add_external_gateway_to_router(self, router_id, network_id,
                                        expected_code=exc.HTTPOk.code):
        return self._update('routers', router_id,
                            {'router': {'external_gateway_info':
                                        {'network_id': network_id}}},
                            expected_code=expected_code)

    def _remove_external_gateway_from_router(self, router_id, network_id,
                                             expected_code=exc.HTTPOk.code):
        return self._update('routers', router_id,
                            {'router': {'external_gateway_info':
                                       {}}},
                            expected_code=expected_code)

    def _router_interface_action(self, action, router_id, subnet_id, port_id,
                                 expected_code=exc.HTTPOk.code):
        interface_data = {}
        if subnet_id:
            interface_data.update({'subnet_id': subnet_id})
        if port_id and (action != 'add' or not subnet_id):
            interface_data.update({'port_id': port_id})

        req = self.new_action_request('routers', interface_data, router_id,
                                      "%s_router_interface" % action)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, expected_code)
        return self.deserialize('json', res)

    @contextlib.contextmanager
    def router(self, name='router1', admin_status_up=True, fmt='json'):
        res = self._create_router(fmt, _uuid(), name=name,
                                  admin_state_up=admin_status_up)
        router = self.deserialize(fmt, res)
        yield router
        self._delete('routers', router['router']['id'])

    def test_router_crd_ops(self):
        with self.router() as r:
            body = self._list('routers')
            self.assertEquals(len(body['routers']), 1)
            self.assertEquals(body['routers'][0]['id'], r['router']['id'])

            body = self._show('routers', r['router']['id'])
            self.assertEquals(body['router']['id'], r['router']['id'])
            self.assertEquals(body['router']['external_gateway_info'], None)

        # post-delete, check that it is really gone
        body = self._list('routers')
        self.assertEquals(len(body['routers']), 0)

        body = self._show('routers', r['router']['id'],
                          expected_code=exc.HTTPNotFound.code)

    def test_router_update(self):
        rname1 = "yourrouter"
        rname2 = "nachorouter"
        with self.router(name=rname1) as r:
            body = self._show('routers', r['router']['id'])
            self.assertEquals(body['router']['name'], rname1)

            body = self._update('routers', r['router']['id'],
                                {'router': {'name': rname2}})

            body = self._show('routers', r['router']['id'])
            self.assertEquals(body['router']['name'], rname2)

    def test_router_add_interface_subnet(self):
        with self.router() as r:
            with self.subnet() as s:
                body = self._router_interface_action('add',
                                                     r['router']['id'],
                                                     s['subnet']['id'],
                                                     None)
                self.assertTrue('port_id' in body)

                # fetch port and confirm device_id
                r_port_id = body['port_id']
                body = self._show('ports', r_port_id)
                self.assertEquals(body['port']['device_id'], r['router']['id'])

                body = self._router_interface_action('remove',
                                                     r['router']['id'],
                                                     s['subnet']['id'],
                                                     None)
                body = self._show('ports', r_port_id,
                                  expected_code=exc.HTTPNotFound.code)

    def test_router_add_interface_port(self):
        with self.router() as r:
            with self.port() as p:
                body = self._router_interface_action('add',
                                                     r['router']['id'],
                                                     None,
                                                     p['port']['id'])
                self.assertTrue('port_id' in body)
                self.assertEquals(body['port_id'], p['port']['id'])

                # fetch port and confirm device_id
                body = self._show('ports', p['port']['id'])
                self.assertEquals(body['port']['device_id'], r['router']['id'])

    def test_router_add_interface_dup_subnet1(self):
        with self.router() as r:
            with self.subnet() as s:
                body = self._router_interface_action('add',
                                                     r['router']['id'],
                                                     s['subnet']['id'],
                                                     None)
                body = self._router_interface_action('add',
                                                     r['router']['id'],
                                                     s['subnet']['id'],
                                                     None,
                                                     expected_code=
                                                     exc.HTTPBadRequest.code)
                body = self._router_interface_action('remove',
                                                     r['router']['id'],
                                                     s['subnet']['id'],
                                                     None)

    def test_router_add_interface_dup_subnet2(self):
        with self.router() as r:
            with self.subnet() as s:
                with self.port(subnet=s) as p1:
                    with self.port(subnet=s) as p2:
                        self._router_interface_action('add',
                                                      r['router']['id'],
                                                      None,
                                                      p1['port']['id'])
                        self._router_interface_action('add',
                                                      r['router']['id'],
                                                      None,
                                                      p2['port']['id'],
                                                      expected_code=
                                                      exc.HTTPBadRequest.code)

    def test_router_add_interface_no_data(self):
        with self.router() as r:
            body = self._router_interface_action('add',
                                                 r['router']['id'],
                                                 None,
                                                 None,
                                                 expected_code=
                                                 exc.HTTPBadRequest.code)

    def test_router_add_gateway(self):
        with self.router() as r:
            with self.subnet() as s:
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    s['subnet']['network_id'])
                body = self._show('routers', r['router']['id'])
                net_id = body['router']['external_gateway_info']['network_id']
                self.assertEquals(net_id, s['subnet']['network_id'])
                self._remove_external_gateway_from_router(
                    r['router']['id'],
                    s['subnet']['network_id'])
                body = self._show('routers', r['router']['id'])
                gw_info = body['router']['external_gateway_info']
                self.assertEquals(gw_info, None)

    def test_router_add_gateway_invalid_network(self):
        with self.router() as r:
            self._add_external_gateway_to_router(
                r['router']['id'],
                "foobar", expected_code=exc.HTTPNotFound.code)

    def test_router_add_gateway_no_subnet(self):
        with self.router() as r:
            with self.network() as n:
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    n['network']['id'], expected_code=exc.HTTPBadRequest.code)

    def test_router_delete_inuse_interface(self):
        with self.router() as r:
            with self.subnet() as s:
                self._router_interface_action('add',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None)
                self._delete('routers', r['router']['id'],
                             expected_code=exc.HTTPConflict.code)

                # remove interface so test can exit without errors
                self._router_interface_action('remove',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None)

    def test_router_remove_router_interface_wrong_subnet_returns_409(self):
        with self.router() as r:
            with self.subnet() as s:
                with self.port() as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  s['subnet']['id'],
                                                  p['port']['id'],
                                                  exc.HTTPConflict.code)

    def test_router_remove_router_interface_wrong_port_returns_409(self):
        with self.router() as r:
            with self.subnet() as s:
                with self.port() as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])
                    # create another port for testing failure case
                    res = self._create_port('json', p['port']['network_id'])
                    p2 = self.deserialize('json', res)
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p2['port']['id'],
                                                  exc.HTTPConflict.code)
                    # remove extra port created
                    self._delete('ports', p2['port']['id'])

    def _create_floatingip(self, fmt, network_id, port_id=None,
                           fixed_ip=None):
        data = {'floatingip': {'floating_network_id': network_id,
                               'tenant_id': self._tenant_id}}
        if port_id:
            data['floatingip']['port_id'] = port_id
            if fixed_ip:
                data['floatingip']['fixed_ip'] = fixed_ip
        floatingip_req = self.new_create_request('floatingips', data, fmt)
        return floatingip_req.get_response(self.ext_api)

    def _validate_floating_ip(self, fip):
        body = self._list('floatingips')
        self.assertEquals(len(body['floatingips']), 1)
        self.assertEquals(body['floatingips'][0]['id'],
                          fip['floatingip']['id'])

        body = self._show('floatingips', fip['floatingip']['id'])
        self.assertEquals(body['floatingip']['id'],
                          fip['floatingip']['id'])

    @contextlib.contextmanager
    def floatingip_with_assoc(self, port_id=None, fmt='json'):
        with self.subnet() as public_sub:
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

                    res = self._create_floatingip(
                        fmt,
                        public_sub['subnet']['network_id'],
                        port_id=private_port['port']['id'])
                    self.assertEqual(res.status_int, exc.HTTPCreated.code)
                    floatingip = self.deserialize(fmt, res)
                    yield floatingip
                    self._delete('floatingips', floatingip['floatingip']['id'])
                    self._remove_external_gateway_from_router(
                        r['router']['id'],
                        public_sub['subnet']['network_id'])
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  private_sub['subnet']['id'],
                                                  None)

    @contextlib.contextmanager
    def floatingip_no_assoc(self, private_sub, fmt='json'):
        with self.subnet() as public_sub:
            with self.router() as r:
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    public_sub['subnet']['network_id'])
                self._router_interface_action('add', r['router']['id'],
                                              private_sub['subnet']['id'],
                                              None)

                res = self._create_floatingip(
                    fmt,
                    public_sub['subnet']['network_id'])
                self.assertEqual(res.status_int, exc.HTTPCreated.code)
                floatingip = self.deserialize(fmt, res)
                yield floatingip
                self._delete('floatingips', floatingip['floatingip']['id'])
                self._remove_external_gateway_from_router(
                    r['router']['id'],
                    public_sub['subnet']['network_id'])
                self._router_interface_action('remove', r['router']['id'],
                                              private_sub['subnet']['id'],
                                              None)

    def test_floatingip_crd_ops(self):
        with self.floatingip_with_assoc() as fip:
            self._validate_floating_ip(fip)

        # post-delete, check that it is really gone
        body = self._list('floatingips')
        self.assertEquals(len(body['floatingips']), 0)

        self._show('floatingips', fip['floatingip']['id'],
                   expected_code=exc.HTTPNotFound.code)

    def test_floatingip_update(self):
        with self.port() as p:
            private_sub = {'subnet': {'id':
                                      p['port']['fixed_ips'][0]['subnet_id']}}
            with self.floatingip_no_assoc(private_sub) as fip:
                body = self._show('floatingips', fip['floatingip']['id'])
                self.assertEquals(body['floatingip']['port_id'], None)
                self.assertEquals(body['floatingip']['fixed_ip_address'], None)

                port_id = p['port']['id']
                ip_address = p['port']['fixed_ips'][0]['ip_address']
                fixed_ip = p['port']['fixed_ips'][0]['ip_address']
                body = self._update('floatingips', fip['floatingip']['id'],
                                    {'floatingip': {'port_id': port_id}})
                self.assertEquals(body['floatingip']['port_id'], port_id)
                self.assertEquals(body['floatingip']['fixed_ip_address'],
                                  ip_address)

    def test_floatingip_with_assoc(self):
        with self.floatingip_with_assoc() as fip:
            body = self._show('floatingips', fip['floatingip']['id'])
            self.assertEquals(body['floatingip']['id'],
                              fip['floatingip']['id'])
            self.assertEquals(body['floatingip']['port_id'],
                              fip['floatingip']['port_id'])
            self.assertTrue(body['floatingip']['fixed_ip_address'] is not None)
            self.assertTrue(body['floatingip']['router_id'] is not None)

    def test_floatingip_port_delete(self):
        with self.subnet() as private_sub:
            with self.floatingip_no_assoc(private_sub) as fip:
                with self.port(subnet=private_sub) as p:
                    body = self._update('floatingips', fip['floatingip']['id'],
                                        {'floatingip':
                                         {'port_id': p['port']['id']}})
                # note: once this port goes out of scope, the port will be
                # deleted, which is what we want to test. We want to confirm
                # that the fields are set back to None
                body = self._show('floatingips', fip['floatingip']['id'])
                self.assertEquals(body['floatingip']['id'],
                                  fip['floatingip']['id'])
                self.assertEquals(body['floatingip']['port_id'], None)
                self.assertEquals(body['floatingip']['fixed_ip_address'], None)
                self.assertEquals(body['floatingip']['router_id'], None)

    def test_double_floating_assoc(self):
        with self.floatingip_with_assoc() as fip1:
            with self.subnet() as s:
                with self.floatingip_no_assoc(s) as fip2:
                    port_id = fip1['floatingip']['port_id']
                    body = self._update('floatingips',
                                        fip2['floatingip']['id'],
                                        {'floatingip':
                                         {'port_id': port_id}},
                                        expected_code=exc.HTTPConflict.code)

    def test_create_floatingip_no_ext_gateway_return_404(self):
        with self.subnet() as public_sub:
            with self.port() as private_port:
                with self.router() as r:
                    res = self._create_floatingip(
                        'json',
                        public_sub['subnet']['network_id'],
                        port_id=private_port['port']['id'])
                    # this should be some kind of error
                    self.assertEqual(res.status_int, exc.HTTPNotFound.code)

    def test_create_floatingip_no_public_subnet_returns_400(self):
        with self.network() as public_network:
            with self.port() as private_port:
                with self.router() as r:
                    sid = private_port['port']['fixed_ips'][0]['subnet_id']
                    private_sub = {'subnet': {'id': sid}}
                    self._router_interface_action('add', r['router']['id'],
                                                  private_sub['subnet']['id'],
                                                  None)

                    res = self._create_floatingip(
                        'json',
                        public_network['network']['id'],
                        port_id=private_port['port']['id'])
                    self.assertEqual(res.status_int, exc.HTTPBadRequest.code)
                    # cleanup
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  private_sub['subnet']['id'],
                                                  None)
