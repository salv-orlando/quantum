# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2012 OpenStack Foundation.
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
#
#    @author: Salvatore Orlando, VMware
#

import logging

import mock
from oslo.config import cfg
import webob.exc as webexc
import webtest

from quantum.api import extensions
from quantum.common import exceptions as q_exc
from quantum import context
from quantum.db import api as db_api
from quantum.db import servicetype_db as st_db
from quantum.extensions import servicetype
from quantum import manager
from quantum.plugins.common import constants
from quantum.tests import base
from quantum.tests.unit import dummy_plugin as dp
from quantum.tests.unit import test_api_v2
from quantum.tests.unit import test_db_plugin
from quantum.tests.unit import test_extensions
from quantum.tests.unit import testlib_api


LOG = logging.getLogger(__name__)
DEFAULT_SERVICE_DEFS = [{'service_class': constants.DUMMY,
                         'plugin': dp.DUMMY_PLUGIN_NAME}]

_uuid = test_api_v2._uuid
_get_path = test_api_v2._get_path


class ParseServiceProviderConfigurationTestCase(base.BaseTestCase):
    def test_default_service_provider_configuration(self):
        providers = cfg.CONF.service_providers.service_provider
        self.assertEqual(providers, [])

    def test_parse_single_service_provider_opt(self):
        cfg.CONF.set_override('service_provider',
                              [constants.LOADBALANCER +
                               ':lbaas:driver_path'],
                              'service_providers')
        expected = {'service_type': constants.LOADBALANCER,
                    'name': 'lbaas',
                    'driver': 'driver_path',
                    'default': False}
        res = st_db.parse_service_provider_opt()
        self.assertEqual(len(res), 1)
        self.assertEqual(res, [expected])

    def test_parse_single_default_service_provider_opt(self):
        cfg.CONF.set_override('service_provider',
                              [constants.LOADBALANCER +
                               ':lbaas:driver_path:default'],
                              'service_providers')
        expected = {'service_type': constants.LOADBALANCER,
                    'name': 'lbaas',
                    'driver': 'driver_path',
                    'default': True}
        res = st_db.parse_service_provider_opt()
        self.assertEqual(len(res), 1)
        self.assertEqual(res, [expected])

    def test_parse_multi_service_provider_opt(self):
        cfg.CONF.set_override('service_provider',
                              [constants.LOADBALANCER +
                               ':lbaas:driver_path',
                               constants.LOADBALANCER + ':name1:path1',
                               constants.LOADBALANCER +
                               ':name2:path2:default'],
                              'service_providers')
        expected = {'service_type': constants.LOADBALANCER,
                    'name': 'lbaas',
                    'driver': 'driver_path',
                    'default': False}
        res = st_db.parse_service_provider_opt()
        self.assertEqual(len(res), 3)
        self.assertEqual(res, [expected,
                               {'service_type': constants.LOADBALANCER,
                                'name': 'name1',
                                'driver': 'path1',
                                'default': False},
                               {'service_type': constants.LOADBALANCER,
                                'name': 'name2',
                                'driver': 'path2',
                                'default': True}])

    def test_parse_service_provider_opt_not_allowed_raises(self):
        cfg.CONF.set_override('service_provider',
                              [constants.LOADBALANCER +
                               ':lbaas:driver_path',
                               'svc_type:name1:path1'],
                              'service_providers')
        self.assertRaises(q_exc.Invalid, st_db.parse_service_provider_opt)


class ServiceTypeDbTestCase(base.BaseTestCase):
    def setUp(self):
        super(ServiceTypeDbTestCase, self).setUp()
        st_db.ServiceTypeManager._instance = None
        self.manager = st_db.ServiceTypeManager.get_instance()
        self.ctx = context.get_admin_context()

    def tearDown(self):
        super(ServiceTypeDbTestCase, self).tearDown()
        self._db_cleanup()
        cfg.CONF.reset()

    def _db_cleanup(self):
        self.ctx.session.query(st_db.ServiceProvider).delete()

    def test_sync_with_db_single_provider(self):
        cfg.CONF.set_override('service_provider',
                              [constants.LOADBALANCER +
                               ':lbaas:driver_path'],
                              'service_providers')
        self.manager._sync_conf_with_db()
        qry = self.ctx.session.query(st_db.ServiceProvider)
        self.assertEqual(qry.count(), 1)

    def test_sync_with_db_update_existing(self):
        cfg.CONF.set_override('service_provider',
                              [constants.LOADBALANCER +
                               ':lbaas:driver_path',
                               constants.DUMMY + ':dummy:dummy_dr'],
                              'service_providers')
        ctx = context.get_admin_context()
        self.manager._sync_conf_with_db()
        # the next call will work as update existing
        cfg.CONF.set_override('service_provider',
                              [constants.LOADBALANCER +
                               ':lbaas:driver_path',
                               constants.DUMMY + ':dummy:dummy_dr1'],
                              'service_providers')
        self.manager._sync_conf_with_db()
        qry = ctx.session.query(st_db.ServiceProvider)
        self.assertEqual(qry.count(), 2)
        prov_count = (ctx.session.query(st_db.ServiceProvider).
                      filter_by(driver='dummy_dr1').count())
        self.assertEqual(prov_count, 1)

    def test_add_service_provider_driver_not_unique(self):
        cfg.CONF.set_override('service_provider',
                              [constants.LOADBALANCER +
                               ':lbaas:driver'],
                              'service_providers')
        prov = {'service_type': constants.LOADBALANCER,
                'name': 'name2',
                'driver': 'driver',
                'default': False}
        self.manager._sync_conf_with_db()
        ctx = context.get_admin_context()
        self.assertRaises(
            q_exc.Invalid,
            self.manager._add_service_provider,
            ctx, prov
        )

    def test_update_service_provider_driver_not_unique(self):
        cfg.CONF.set_override('service_provider',
                              [constants.LOADBALANCER +
                               ':lbaas:driver',
                               constants.LOADBALANCER +
                               ':lbaas1:driver1'],
                              'service_providers')
        prov = {'service_type': constants.LOADBALANCER,
                'name': 'lbaas1',
                'driver': 'driver',
                'default': False}
        self.manager._sync_conf_with_db()
        ctx = context.get_admin_context()
        self.assertRaises(
            q_exc.Invalid,
            self.manager._add_service_provider,
            ctx, prov
        )

    def test_sync_with_db_update_remove_absent(self):
        # Tests that providers which are not present in conf
        # are not deleted
        cfg.CONF.set_override('service_provider',
                              [constants.LOADBALANCER +
                               ':lbaas:driver_path',
                               constants.DUMMY + ':dummy:dummy_dr'],
                              'service_providers')
        self.manager._sync_conf_with_db()
        ctx = context.get_admin_context()
        qry = ctx.session.query(st_db.ServiceProvider)
        self.assertEqual(qry.count(), 2)

        cfg.CONF.set_override('service_provider',
                              [constants.LOADBALANCER +
                               ':lbaas:driver_path'],
                              'service_providers')
        self.manager._sync_conf_with_db()
        qry = ctx.session.query(st_db.ServiceProvider)
        self.assertEqual(qry.count(), 1)

    def test_get_service_providers(self):
        cfg.CONF.set_override('service_provider',
                              [constants.LOADBALANCER +
                               ':lbaas:driver_path',
                               constants.DUMMY + ':dummy:dummy_dr'],
                              'service_providers')
        ctx = context.get_admin_context()
        st_db.parse_service_provider_opt()
        self.manager._sync_conf_with_db()
        res = self.manager.get_service_providers(ctx)
        self.assertEqual(len(res), 2)

        res = self.manager.get_service_providers(
            ctx,
            filters=dict(service_type=[constants.DUMMY])
        )
        self.assertEqual(len(res), 1)

        res = self.manager.get_service_providers(
            ctx,
            filters=dict(service_type=[constants.LOADBALANCER])
        )
        self.assertEqual(len(res), 1)

    def test_get_service_provider(self):
        cfg.CONF.set_override('service_provider',
                              [constants.LOADBALANCER +
                               ':lbaas:driver_path'],
                              'service_providers')
        self.manager._sync_conf_with_db()
        qry = self.ctx.session.query(st_db.ServiceProvider)
        prov = qry.one()

        res = self.manager.get_service_provider(self.ctx, prov['id'])
        self.assertEqual(res, {'id': prov['id'],
                               'service_type': prov['service_type'],
                               'name': prov['name'],
                               'driver': prov['driver'],
                               'default': False})

    def test_get_service_provider_wrong_id(self):
        cfg.CONF.set_override('service_provider',
                              [constants.LOADBALANCER +
                               ':lbaas:driver_path'],
                              'service_providers')
        self.manager._sync_conf_with_db()
        self.assertRaises(st_db.ServiceProviderNotFound,
                          self.manager.get_service_provider, self.ctx, "123")

    def test_add_provider_resource_association(self):
        cfg.CONF.set_override('service_provider',
                              [constants.LOADBALANCER +
                               ':lbaas:driver_path'],
                              'service_providers')
        self.manager._sync_conf_with_db()
        prov = self.ctx.session.query(st_db.ServiceProvider).one()
        self.manager.add_resource_association(self.ctx, prov['id'], "123")
        assoc = self.ctx.session.query(st_db.ProviderResourceAssociation).one()
        self.assertEqual(assoc['provider_id'], prov['id'])
        self.assertEqual(assoc['resource_id'], "123")

    def test_multiple_default_providers_specified_for_service(self):
        cfg.CONF.set_override('service_provider',
                              [constants.LOADBALANCER +
                               ':lbaas1:driver_path:default',
                               constants.LOADBALANCER +
                               ':lbaas2:driver_path:default'],
                              'service_providers')
        self.assertRaises(q_exc.Invalid, self.manager._sync_conf_with_db)


class TestServiceTypeExtensionManager(object):
    """Mock extensions manager."""
    def get_resources(self):
        return (servicetype.Servicetype.get_resources() +
                dp.Dummy.get_resources())

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class ServiceTypeExtensionTestCaseBase(testlib_api.WebTestCase):
    fmt = 'json'

    def setUp(self):
        # This is needed because otherwise a failure will occur due to
        # nonexisting core_plugin
        cfg.CONF.set_override('core_plugin', test_db_plugin.DB_PLUGIN_KLASS)

        cfg.CONF.set_override('service_plugins',
                              ["%s.%s" % (dp.__name__,
                                          dp.DummyServicePlugin.__name__)])
        self.addCleanup(cfg.CONF.reset)
        # Make sure at each test a new instance of the plugin is returned
        manager.QuantumManager._instance = None
        # Ensure existing ExtensionManager is not used
        extensions.PluginAwareExtensionManager._instance = None
        ext_mgr = TestServiceTypeExtensionManager()
        self.ext_mdw = test_extensions.setup_extensions_middleware(ext_mgr)
        self.api = webtest.TestApp(self.ext_mdw)
        self.resource_name = servicetype.RESOURCE_NAME.replace('-', '_')
        super(ServiceTypeExtensionTestCaseBase, self).setUp()


class ServiceTypeExtensionTestCase(ServiceTypeExtensionTestCaseBase):

    def setUp(self):
        self._patcher = mock.patch(
            "%s.%s" % (st_db.__name__,
                       st_db.ServiceTypeManager.__name__),
            autospec=True)
        self.addCleanup(self._patcher.stop)
        self.mock_mgr = self._patcher.start()
        self.mock_mgr.get_instance.return_value = self.mock_mgr.return_value
        super(ServiceTypeExtensionTestCase, self).setUp()

    def test_service_provider_get(self):
        svcprov_id = _uuid()
        return_value = {self.resource_name: {'name': 'test',
                                             'id': svcprov_id}}

        instance = self.mock_mgr.return_value
        instance.get_service_provider.return_value = return_value

        res = self.api.get(_get_path('service-providers/%s' % svcprov_id,
                                     fmt=self.fmt))

        instance.get_service_provider.assert_called_with(mock.ANY,
                                                         svcprov_id,
                                                         fields=mock.ANY)
        self.assertEqual(res.status_int, webexc.HTTPOk.code)

    def test_service_provider_list(self):
        instance = self.mock_mgr.return_value

        res = self.api.get(_get_path('service-providers', fmt=self.fmt))

        instance.get_service_providers.assert_called_with(mock.ANY,
                                                          filters={},
                                                          fields=[])

        self.assertEqual(res.status_int, webexc.HTTPOk.code)


class ServiceTypeExtensionTestCaseXML(ServiceTypeExtensionTestCase):
    fmt = 'xml'


class ServiceTypeManagerTestCase(ServiceTypeExtensionTestCaseBase):

    def setUp(self):
        # Blank out service type manager instance
        st_db.ServiceTypeManager._instance = None
        cfg.CONF.set_override('service_provider',
                              [constants.LOADBALANCER +
                               ':lbaas:driver_path',
                               constants.DUMMY + ':dummy:dummy_dr'],
                              'service_providers')
        self.addCleanup(db_api.clear_db)
        super(ServiceTypeManagerTestCase, self).setUp()

    def _list_service_providers(self):
        return self.api.get(_get_path('service-providers', fmt=self.fmt))

    def _show_service_provider(self, svctype_id, expect_errors=False):
        return self.api.get(_get_path('service-providers/%s' % str(svctype_id),
                                      fmt=self.fmt),
                            expect_errors=expect_errors)

    def test_list_service_providers(self):
        res = self._list_service_providers()
        self.assertEqual(res.status_int, webexc.HTTPOk.code)
        data = self.deserialize(res)
        self.assertTrue('service_providers' in data)
        # it must be 3 because we have the default service type too!
        self.assertEqual(len(data['service_providers']), 2)

    def test_get_service_provider(self):
        res = self._list_service_providers()
        data = self.deserialize(res)
        prov = data['service_providers'][0]
        prov_id = prov['id']
        res = self._show_service_provider(prov_id)
        res_data = self.deserialize(res)
        self.assertEqual(res.status_int, webexc.HTTPOk.code)
        self.assertEqual(res_data,
                         {'service_provider':
                          {'id': prov_id,
                           'name': prov['name'],
                           'service_type': constants.LOADBALANCER,
                           'default': False
                           # driver is not visible
                           }})


class ServiceTypeManagerTestCaseXML(ServiceTypeManagerTestCase):
    fmt = 'xml'
