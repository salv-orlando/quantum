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
import itertools
import mock
import os
import unittest2

import webob.exc

from quantum.api.v2 import attributes
from quantum.api.v2.router import APIRouter
from quantum.common.test_lib import test_config
from quantum.common import config
from quantum.db import api as db
from quantum.db import db_base_plugin_v2
from quantum.db import securitygroups_db
from quantum.extensions.extensions import PluginAwareExtensionManager
from quantum.extensions import securitygroup as ext_sg
from quantum.manager import QuantumManager
from quantum.openstack.common import cfg
from quantum.tests.unit import test_db_plugin
from quantum.tests.unit import test_extensions
from quantum.wsgi import JSONDeserializer

DB_PLUGIN_KLASS = ('quantum.tests.unit.test_extension_securitygroup.'
                   'SecurityGroupTestPlugin')
ROOTDIR = os.path.dirname(os.path.dirname(__file__))
ETCDIR = os.path.join(ROOTDIR, 'etc')


def etcdir(*p):
    return os.path.join(ETCDIR, *p)


class SecurityGroupTestExtensionManager(object):

    def get_resources(self):
        return ext_sg.Securitygroup.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class SecurityGroupsTestCase(test_db_plugin.QuantumDbPluginV2TestCase,
                             unittest2.TestCase):
    def setUp(self, plugin=None):
        super(SecurityGroupsTestCase, self).setUp()
        db._ENGINE = None
        db._MAKER = None
        # Make sure at each test a new instance of the plugin is returned
        QuantumManager._instance = None
        # Make sure at each test according extensions for the plugin is loaded
        PluginAwareExtensionManager._instance = None
        # Save the attributes map in case the plugin will alter it
        # loading extensions
        # Note(salvatore-orlando): shallow copy is not good enough in
        # this case, but copy.deepcopy does not seem to work, since it
        # causes test failures
        self._attribute_map_bk = {}
        for item in attributes.RESOURCE_ATTRIBUTE_MAP:
            self._attribute_map_bk[item] = (attributes.
                                            RESOURCE_ATTRIBUTE_MAP[item].
                                            copy())
        self._tenant_id = 'tenant_id'

        json_deserializer = JSONDeserializer()
        self._deserializers = {
            'application/json': json_deserializer,
        }

        if not plugin:
            plugin = test_config.get('plugin_name_v2', DB_PLUGIN_KLASS)

        # Create the default configurations
        args = ['--config-file', etcdir('quantum.conf.test')]
        # If test_config specifies some config-file, use it, as well
        for config_file in test_config.get('config_files', []):
            args.extend(['--config-file', config_file])
        config.parse(args=args)
        # Update the plugin
        cfg.CONF.set_override('core_plugin', plugin)
        self.api = APIRouter()

        def _is_native_bulk_supported():
            plugin_obj = QuantumManager.get_plugin()
            native_bulk_attr_name = ("_%s__native_bulk_support"
                                     % plugin_obj.__class__.__name__)
            return getattr(plugin_obj, native_bulk_attr_name, False)

        self._skip_native_bulk = not _is_native_bulk_supported()

        QuantumManager.get_plugin().supported_extension_aliases = (
            ["securitygroups"])
        ext_mgr = SecurityGroupTestExtensionManager()
        if ext_mgr:
            self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)

    def tearDown(self):
        super(SecurityGroupsTestCase, self).tearDown()
        db._ENGINE = None
        db._MAKER = None
        cfg.CONF.reset()
        # Restore the original attribute map
        attributes.RESOURCE_ATTRIBUTE_MAP = self._attribute_map_bk

    def _create_securitygroup(self, fmt, name, description, external_id,
                              arg_list=None):

        data = {'securitygroup': {'name': name,
                                  'tenant_id': self._tenant_id,
                                  'description': description}}
        if external_id:
            data['securitygroup']['external_id'] = external_id
        securitygroup_req = self.new_create_request('securitygroups', data,
                                                    fmt)

        return securitygroup_req.get_response(self.ext_api)

    def _build_securitygrouprule(self, parent_group_id, direction,
                                  protocol, port_range_min, port_range_max,
                                  ip_prefix=None, group_id=None,
                                  external_id=None):

        data = {'securitygrouprule': {'parent_group_id': parent_group_id,
                                      'direction': direction,
                                      'protocol': protocol,
                                      'port_range_min': port_range_min,
                                      'port_range_max': port_range_max,
                                      'tenant_id': self._tenant_id}}
        if external_id:
            data['securitygrouprule']['external_id'] = external_id

        if ip_prefix:
            data['securitygrouprule']['ip_prefix'] = ip_prefix

        if group_id:
            data['securitygrouprule']['group_id'] = group_id

        return data

    def _create_securitygrouprule(self, fmt, rules):
        securitygrouprule_req = self.new_create_request('securitygrouprules',
                                                        rules, fmt)

        return securitygrouprule_req.get_response(self.ext_api)

    @contextlib.contextmanager
    def securitygroup(self, name='webservers', description='webservers',
                      external_id=None, fmt='json', no_delete=False):
        res = self._create_securitygroup(fmt, name, description,
                                         external_id)
        securitygroup = self.deserialize(fmt, res)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        yield securitygroup
        if not no_delete:
            self._delete('securitygroups',
                         securitygroup['securitygroup']['id'])

    @contextlib.contextmanager
    def securitygrouprule(self,
            parent_group_id='4cd70774-cc67-4a87-9b39-7d1db38eb087',
            direction='ingress', protocol='6', port_range_min='22',
            port_range_max='22', ip_prefix=None, group_id=None,
            external_id=None, fmt='json', no_delete=False):

        rule = self._build_securitygrouprule(parent_group_id, direction,
            protocol, port_range_min, port_range_max, ip_prefix,
            group_id, external_id)
        res = self._create_securitygrouprule('json', rule)
        securitygrouprule = self.deserialize(fmt, res)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        yield securitygrouprule
        if not no_delete:
            self._delete('securitygrouprules',
                         securitygrouprule['securitygrouprule']['id'])

    def _create_port(self, fmt, net_id, expected_res_status=None, **kwargs):
        """ Override the routine for allowing the securitygroup:external
        attribute
        """
        # attributes containing a colon should be passed with
        # a double underscore
        new_args = dict(itertools.izip(map(lambda x: x.replace('__', ':'),
                                           kwargs),
                                       kwargs.values()))
        arg_list = (ext_sg.EXTERNAL,)
        return super(SecurityGroupsTestCase, self)._create_port(fmt, net_id,
            expected_res_status, arg_list=arg_list, **new_args)


class SecurityGroupTestPlugin(db_base_plugin_v2.QuantumDbPluginV2,
                              securitygroups_db.SecurityGroup_db_mixin):
    """ Test plugin that implements necessary calls on create/delete port for
    associating ports with securitygroups.
    """

    supported_extension_aliases = ["securitygroup"]

    def create_port(self, context, port):
        session = context.session
        with session.begin(subtransactions=True):
            sgids = port['port'].get(ext_sg.EXTERNAL)
            port = super(SecurityGroupTestPlugin, self).create_port(context,
                                                                    port)
            self._process_port_create_securitygroup(context, port['id'], sgids)
            self._extend_port_dict_securitygroup(context, port)
        return port

    def update_port(self, context, id, port):
        session = context.session
        with session.begin(subtransactions=True):
            # delete the port binding and read it with the new rules
            self.delete_port_securitygroup_binding(context, id)
            self._process_port_create_securitygroup(context, id,
                port['port'].get(ext_sg.EXTERNAL))
            port = super(SecurityGroupTestPlugin, self).update_port(
                context, id, port)
            self._extend_port_dict_securitygroup(context, port)
        return port

    def delete_port(self, context, id):
        session = context.session
        with session.begin(subtransactions=True):
            super(SecurityGroupTestPlugin, self).delete_port(context, id)
            self.delete_port_securitygroup_binding(context, id)


class SecurityGroupDBTestCase(SecurityGroupsTestCase):
    def setUp(self, plugin=None):
        test_config['plugin_name_v2'] = DB_PLUGIN_KLASS
        ext_mgr = SecurityGroupTestExtensionManager()
        test_config['extension_manager'] = ext_mgr
        super(SecurityGroupDBTestCase, self).setUp()


class TestSecurityGroups(SecurityGroupDBTestCase):
    def test_create_securitygroup(self):
        name = 'webservers'
        description = 'my webservers'
        keys = [('name', name,), ('description', description)]
        with self.securitygroup(name, description) as securitygroup:
            for k, v, in keys:
                self.assertEquals(securitygroup['securitygroup'][k], v)

    def test_create_securitygroup_external_id(self):
        name = 'webservers'
        description = 'my webservers'
        external_id = 10
        keys = [('name', name,), ('description', description),
                ('external_id', external_id)]
        with self.securitygroup(name, description, external_id) as sg:
            for k, v, in keys:
                self.assertEquals(sg['securitygroup'][k], v)

    def test_create_securitygroup_duplicate_external_id(self):
        name = 'webservers'
        description = 'my webservers'
        external_id = 1
        with self.securitygroup(name, description, external_id):
            res = self._create_securitygroup('json', name, description,
                                              external_id)
            self.deserialize('json', res)
            self.assertEquals(res.status_int, 409)

    def test_list_securitygroups(self):
        name = 'webservers'
        description = 'my webservers'
        with self.securitygroup(name, description):
            res = self.new_list_request('securitygroups')
            groups = self.deserialize('json', res.get_response(self.ext_api))
            self.assertEquals(len(groups['securitygroups']), 1)

    def test_get_securitygroup(self):
        name = 'webservers'
        description = 'my webservers'
        with self.securitygroup(name, description) as sg:
            group_id = sg['securitygroup']['id']
            res = self.new_show_request('securitygroups', group_id)
            group = self.deserialize('json', res.get_response(self.ext_api))
            self.assertEquals(group['securitygroup']['id'], group_id)

    def test_delete_securitygroup(self):
        name = 'webservers'
        description = 'my webservers'
        with self.securitygroup(name, description) as sg:
            group_id = sg['securitygroup']['id']
        req = self.new_show_request('securitygroups', 'json', group_id)
        res = req.get_response(self.ext_api)
        self.assertEquals(res.status_int, 404)

    def test_createsecuritygrouprule_ip_prefix(self):
        name = 'webservers'
        description = 'my webservers'
        with self.securitygroup(name, description) as sg:
            parent_group_id = sg['securitygroup']['id']
            direction = "ingress"
            ip_prefix = "10.0.0.0/24"
            protocol = 6
            port_range_min = 22
            port_range_max = 22
            keys = [('ip_prefix', ip_prefix),
                    ('parent_group_id', parent_group_id),
                    ('direction', direction),
                    ('protocol', protocol),
                    ('port_range_min', port_range_min),
                    ('port_range_max', port_range_max)]
            with self.securitygrouprule(parent_group_id, direction,
                protocol, port_range_min, port_range_max, ip_prefix) as rule:
                for k, v, in keys:
                    self.assertEquals(rule['securitygrouprule'][k], v)

    def test_createsecuritygrouprule_group_id(self):
        name = 'webservers'
        description = 'my webservers'
        with self.securitygroup(name, description) as sg:
            with self.securitygroup(name, description) as sg2:
                parent_group_id = sg['securitygroup']['id']
                direction = "ingress"
                group_id = sg2['securitygroup']['id']
                protocol = 6
                port_range_min = 22
                port_range_max = 22
                keys = [('group_id', group_id),
                        ('parent_group_id', parent_group_id),
                        ('direction', direction),
                        ('protocol', protocol),
                        ('port_range_min', port_range_min),
                        ('port_range_max', port_range_max)]
                with self.securitygrouprule(parent_group_id, direction,
                    protocol, port_range_min, port_range_max,
                    group_id=group_id) as rule:
                    for k, v, in keys:
                        self.assertEquals(rule['securitygrouprule'][k], v)

    def test_createsecuritygrouprule_bad_parent_group(self):
        parent_group_id = "4cd70774-cc67-4a87-9b39-7d1db38eb087"
        direction = "ingress"
        ip_prefix = "10.0.0.0/24"
        protocol = 6
        port_range_min = 22
        port_range_max = 22
        rule = self._build_securitygrouprule(parent_group_id,
            direction, protocol, port_range_min, port_range_max, ip_prefix)
        res = self._create_securitygrouprule('json', rule)
        self.deserialize('json', res)
        self.assertEquals(res.status_int, 404)

    def test_createsecuritygrouprule_bad_group_id(self):
        name = 'webservers'
        description = 'my webservers'
        with self.securitygroup(name, description) as sg:
            parent_group_id = sg['securitygroup']['id']
            group_id = "4cd70774-cc67-4a87-9b39-7d1db38eb087"
            direction = "ingress"
            protocol = 6
            port_range_min = 22
            port_range_max = 22
        rule = self._build_securitygrouprule(parent_group_id,
            direction, protocol, port_range_min, port_range_max,
            group_id=group_id)
        res = self._create_securitygrouprule('json', rule)
        self.deserialize('json', res)
        self.assertEquals(res.status_int, 404)

    def test_createsecuritygrouprule_duplicate_rules(self):
        name = 'webservers'
        description = 'my webservers'
        with self.securitygroup(name, description) as sg:
            parent_group_id = sg['securitygroup']['id']
            with self.securitygrouprule(parent_group_id):
                rule = self._build_securitygrouprule(
                    sg['securitygroup']['id'], 'ingress', '6', '22', '22')
                self._create_securitygrouprule('json', rule)
                res = self._create_securitygrouprule('json', rule)
                self.deserialize('json', res)
                self.assertEquals(res.status_int, 409)

    def test_update_port_with_securitygroup(self):
        with self.network() as n:
            with self.subnet(n):
                with self.securitygroup() as sg:
                    res = self._create_port('json', n['network']['id'])
                    port = self.deserialize('json', res)

                    data = {'port': {'fixed_ips': port['port']['fixed_ips'],
                                     'name': port['port']['name'],
                                     ext_sg.EXTERNAL:
                                        [sg['securitygroup']['id']]}}

                    req = self.new_update_request('ports', data,
                        port['port']['id'])
                    res = self.deserialize('json', req.get_response(self.api))
                    self.assertEquals(res['port'][ext_sg.EXTERNAL][0],
                                      sg['securitygroup']['id'])
                    self._delete('ports', port['port']['id'])

    def test_update_port_remove_securitygroup(self):
        with self.network() as n:
            with self.subnet(n):
                with self.securitygroup() as sg:
                    res = self._create_port('json', n['network']['id'],
                                    securitygroups=[sg['securitygroup']['id']])
                    port = self.deserialize('json', res)

                    data = {'port': {'fixed_ips': port['port']['fixed_ips'],
                                     'name': port['port']['name']}}

                    req = self.new_update_request('ports', data,
                        port['port']['id'])
                    res = self.deserialize('json', req.get_response(self.api))
                    self.assertEquals(res['port'][ext_sg.EXTERNAL], [])
                    self._delete('ports', port['port']['id'])

    def test_create_delete_securitygroup_port_in_use(self):
        with self.network() as n:
            with self.subnet(n):
                with self.securitygroup() as sg:
                    res = self._create_port('json', n['network']['id'],
                        securitygroup__sg=[sg['securitygroup']['id']])
                    port = self.deserialize('json', res)
                    self.assertEquals(port['port'][ext_sg.EXTERNAL][0],
                                  sg['securitygroup']['id'])
                    # try to delete security group that's in use
                    res = self._delete('securitygroups',
                                       sg['securitygroup']['id'], 409)
                    # delete the blocking port
                    self._delete('ports', port['port']['id'])

    def test_createsecuritygrouprule_bulk_native(self):
        if self._skip_native_bulk:
            self.skipTest("Plugin does not support native bulk "
                          "securitygrouprule create")
        with self.securitygroup() as sg:
            rule1 = self._build_securitygrouprule(sg['securitygroup']['id'],
                'ingress', '6', '22', '22', '10.0.0.1/24')
            rule2 = self._build_securitygrouprule(sg['securitygroup']['id'],
                'ingress', '6', '23', '23', '10.0.0.1/24')
            rules = {'securitygrouprules': [rule1['securitygrouprule'],
                                            rule2['securitygrouprule']]}
            res = self._create_securitygrouprule('json', rules)
            self.deserialize('json', res)
            self.assertEquals(res.status_int, 201)

    def test_create_securitygrouprule_bulk_emulated(self):
        real_has_attr = hasattr

        #ensures the API choose the emulation code path
        def fakehasattr(item, attr):
            if attr.endswith('__native_bulk_support'):
                return False
            return real_has_attr(item, attr)

        with mock.patch('__builtin__.hasattr',
                        new=fakehasattr):
            with self.securitygroup() as sg:
                rule1 = self._build_securitygrouprule(
                    sg['securitygroup']['id'], 'ingress', '6', '22', '22',
                        '10.0.0.1/24')
                rule2 = self._build_securitygrouprule(
                    sg['securitygroup']['id'], 'ingress', '6', '23', '23',
                    '10.0.0.1/24')
                rules = {'securitygrouprules': [rule1['securitygrouprule'],
                                            rule2['securitygrouprule']]}
                res = self._create_securitygrouprule('json', rules)
                self.deserialize('json', res)
                self.assertEquals(res.status_int, 201)

    def test_createsecuritygrouprule_duplicate_rule_in_post(self):
        if self._skip_native_bulk:
            self.skipTest("Plugin does not support native bulk "
                          "securitygrouprule create")
        with self.securitygroup() as sg:
            rule = self._build_securitygrouprule(sg['securitygroup']['id'],
                'ingress', '6', '22', '22', '10.0.0.1/24')
            rules = {'securitygrouprules': [rule['securitygrouprule'],
                                            rule['securitygrouprule']]}
            res = self._create_securitygrouprule('json', rules)
            rule = self.deserialize('json', res)
            self.assertEquals(res.status_int, 409)

    def test_createsecuritygrouprule_duplicate_rule_in_post_emulated(self):
        real_has_attr = hasattr

        #ensures the API choose the emulation code path
        def fakehasattr(item, attr):
            if attr.endswith('__native_bulk_support'):
                return False
            return real_has_attr(item, attr)

        with mock.patch('__builtin__.hasattr',
                        new=fakehasattr):

            with self.securitygroup() as sg:
                rule = self._build_securitygrouprule(
                    sg['securitygroup']['id'], 'ingress', '6', '22', '22',
                    '10.0.0.1/24')
                rules = {'securitygrouprules': [rule['securitygrouprule'],
                                               rule['securitygrouprule']]}
                res = self._create_securitygrouprule('json', rules)
                rule = self.deserialize('json', res)
                self.assertEquals(res.status_int, 409)

    def test_createsecuritygrouprule_duplicate_rule_db(self):
        if self._skip_native_bulk:
            self.skipTest("Plugin does not support native bulk "
                          "securitygrouprule create")
        with self.securitygroup() as sg:
            rule = self._build_securitygrouprule(sg['securitygroup']['id'],
                'ingress', '6', '22', '22', '10.0.0.1/24')
            rules = {'securitygrouprules': [rule]}
            self._create_securitygrouprule('json', rules)
            res = self._create_securitygrouprule('json', rules)
            rule = self.deserialize('json', res)
            self.assertEquals(res.status_int, 409)

    def test_createsecuritygrouprule_duplicate_rule_db_emulated(self):
        real_has_attr = hasattr

        #ensures the API choose the emulation code path
        def fakehasattr(item, attr):
            if attr.endswith('__native_bulk_support'):
                return False
            return real_has_attr(item, attr)

        with mock.patch('__builtin__.hasattr',
                        new=fakehasattr):

            with self.securitygroup() as sg:
                rule = self._build_securitygrouprule(
                    sg['securitygroup']['id'], 'ingress', '6', '22', '22',
                    '10.0.0.1/24')
                rules = {'securitygrouprules': [rule]}
                self._create_securitygrouprule('json', rules)
                res = self._create_securitygrouprule('json', rule)
                self.deserialize('json', res)
                self.assertEquals(res.status_int, 409)
