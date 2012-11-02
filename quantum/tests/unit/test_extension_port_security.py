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
import os

import mock
import unittest2
import webob.exc

from quantum.api.v2 import attributes
from quantum.api.v2.router import APIRouter
from quantum import context
from quantum.common.test_lib import test_config
from quantum.common import config
from quantum.db import api as db
from quantum.db import db_base_plugin_v2
from quantum.db import securitygroups_db
from quantum.db import portsecurity_db
from quantum.extensions.extensions import PluginAwareExtensionManager
from quantum.extensions import securitygroup as ext_sg
from quantum.extensions import portsecurity as psec
from quantum.manager import QuantumManager
from quantum.openstack.common import cfg
from quantum.tests.unit import test_db_plugin
from quantum.tests.unit import test_extensions
from quantum.tests.unit import test_extension_security_group
from quantum.wsgi import JSONDeserializer

DB_PLUGIN_KLASS = ('quantum.tests.unit.test_extension_port_security.'
                   'PortSecurityTestPlugin')
ROOTDIR = os.path.dirname(os.path.dirname(__file__))
ETCDIR = os.path.join(ROOTDIR, 'etc')


def etcdir(*p):
    return os.path.join(ETCDIR, *p)


class PortSecurityTestCase(
    test_extension_security_group.SecurityGroupsTestCase,
    test_db_plugin.QuantumDbPluginV2TestCase,
    unittest2.TestCase):
    def setUp(self, plugin=None):
        super(PortSecurityTestCase, self).setUp()
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
            ["port-security"])

    def tearDown(self):
        super(PortSecurityTestCase, self).tearDown()
        db._ENGINE = None
        db._MAKER = None
        cfg.CONF.reset()
        # Restore the original attribute map
        attributes.RESOURCE_ATTRIBUTE_MAP = self._attribute_map_bk


class PortSecurityTestPlugin(db_base_plugin_v2.QuantumDbPluginV2,
                             securitygroups_db.SecurityGroupDbMixin,
                             portsecurity_db.PortSecurityDbMixin):

    """ Test plugin that implements necessary calls on create/delete port for
    associating ports with security groups and port security.
    """

    supported_extension_aliases = ["security-group", "port-security"]

    def create_port(self, context, port):
        self._validate_security_groups_on_port(context, port)
        session = context.session
        with session.begin(subtransactions=True):
            quantum_db = super(PortSecurityTestPlugin, self).create_port(
                context, port)
            port['port'].update(quantum_db)
            p = port['port']
            tenant_id = self._get_tenant_id_for_create(context, p)
            default_sg = self._ensure_default_security_group(
                context, tenant_id)

            port_security = self._validate_port_security(context, p)
            p[psec.PORTSECURITY] = port_security

            if (not p.get(ext_sg.SECURITYGROUP) and
                port_security == 'mac_ip'):
                if (p.get('device_owner') == 'network:dhcp' and
                    context.is_admin):
                    pass
                else:
                    p[ext_sg.SECURITYGROUP] = [default_sg]

            if (p.get(ext_sg.SECURITYGROUP) and
                p[psec.PORTSECURITY] == 'mac_ip'):
                self._process_port_create_security_group(
                    context, p['id'], p[ext_sg.SECURITYGROUP])
            self._process_port_security_create(context, p)

        self._extend_port_dict_security_group(context, p)
        self._extend_port_dict_port_security(context, p)

        return port['port']

    def update_port(self, context, id, port):
        session = context.session
        # If value is not passed in it gets assigned False
        if psec.PORTSECURITY in port['port']:
            update_port_security = port['port'].get(psec.PORTSECURITY)
        else:
            update_port_security = False

        if ext_sg.SECURITYGROUP in port['port']:
            update_security_groups = port['port'].get(ext_sg.SECURITYGROUP)
            if (update_security_groups == [] or
                update_security_groups == "None"):
                update_security_groups = None
        else:
            update_security_groups = False

        with session.begin(subtransactions=True):
            ret_port = super(PortSecurityTestPlugin, self).update_port(
                context, id, port)
            ret_port.update(port['port'])
            # validate the update remove_ip/port_security
            if update_port_security:
                ret_port[psec.PORTSECURITY] = update_port_security
            else:
                ret_port[psec.PORTSECURITY] = (
                    self._get_port_security_binding(context, ret_port['id']))

            ret_port[psec.PORTSECURITY] = self._validate_port_security(
                context, ret_port)

        # validate security groups with port security type
        if ret_port[psec.PORTSECURITY] != 'mac_ip':
            if (update_security_groups is False):
                filters = {'port_id': [id]}
                security_groups = (super(PortSecurityTestPlugin, self).
                                   _get_port_security_group_bindings(
                                   context, filters))
                if security_groups:
                    raise ext_sg.SecurityGroupNoIpMacPortUpdate()
            elif update_security_groups:
                raise ext_sg.SecurityGroupNoIpMacPortUpdate()

        # Request to set port security is mac or off
        if (ret_port[psec.PORTSECURITY] in ['mac', 'off']):
            # update_security_groups will be set to None if we are removing
            # them from a port. if update_security_groups == False there are
            # no updates for the the security groups but since the request
            # turns port_security to mac/off we need to confirm there are
            # not any security_groups on the port because security groups
            # require port_security mac_ip
            if (update_security_groups is False):
                filters = {'port_id': [id]}
                security_groups = (super(PortSecurityTestPlugin, self).
                                   _get_port_security_group_bindings(
                                   context, filters))
                if security_groups:
                    raise psec.SecurityGroupsOnPortCannotRemovePortSecurity()
            elif update_security_groups:
                raise psec.SecurityGroupsOnPortCannotRemovePortSecurity()

        # adding security groups
        if update_security_groups:
            # get the port_security type on port if not in update
            if ret_port[psec.PORTSECURITY] != 'mac_ip':
                raise psec.PortSecurityNotEnabled()
            ret_port[ext_sg.SECURITYGROUP] = (
                self._validate_security_groups_on_port(context, port))
        # didn't modify
        elif update_security_groups is False:
            filters = {'port_id': [id]}
            security_groups = (super(PortSecurityTestPlugin, self).
                               _get_port_security_group_bindings(
                               context, filters))
            ret_port[ext_sg.SECURITYGROUP] = security_groups
        # delete security group on port
        else:
            ret_port[ext_sg.SECURITYGROUP] = None

        if (update_security_groups is not False):
            # delete the port binding and read it with the new rules.
            self._delete_port_security_group_bindings(context, id)
            self._process_port_create_security_group(context, id,
                                                     ret_port.get(
                                                     ext_sg.SECURITYGROUP))

        if update_port_security is not False:
            self._delete_port_security_bindings(context, id)
            self._process_port_security_create(context, ret_port)

        self._extend_port_dict_port_security(context, ret_port)
        self._extend_port_dict_security_group(context, ret_port)

        return ret_port

    def delete_port(self, context, id):
        session = context.session
        with session.begin(subtransactions=True):
            super(PortSecurityTestPlugin, self).delete_port(context, id)
            self._delete_port_security_group_bindings(context, id)

    def create_network(self, context, network):
        tenant_id = self._get_tenant_id_for_create(context, network['network'])
        self._ensure_default_security_group(context, tenant_id)
        return super(PortSecurityTestPlugin, self).create_network(context,
                                                                  network)


class PortSecurityDBTestCase(PortSecurityTestCase):
    def setUp(self, plugin=None):
        test_config['plugin_name_v2'] = DB_PLUGIN_KLASS
        super(PortSecurityDBTestCase, self).setUp()


class TestPortSecurity(PortSecurityDBTestCase):
    def test_create_port_security_mac_ip(self):
        with self.network() as n:
            with self.subnet(n):
                res = self._create_port('json', n['network']['id'],
                                        port_security='mac_ip')

                port = self.deserialize('json', res)
                self.assertEquals(len(port['port']['fixed_ips']), 1)
                self.assertEquals(len(port['port']['security_groups']), 1)
                self.assertEquals(port['port']['port_security'], 'mac_ip')
                self._delete('ports', port['port']['id'])

    def test_create_port_security_mac(self):
        with self.network() as n:
            res = self._create_port('json', n['network']['id'],
                                    port_security='mac')

            port = self.deserialize('json', res)
            self.assertEquals(port['port']['fixed_ips'], [])
            self.assertEquals(port['port']['security_groups'], [])
            self.assertEquals(port['port']['port_security'], 'mac')
            self._delete('ports', port['port']['id'])

    def test_create_port_security_off(self):
        with self.network() as n:
            with self.subnet(n):
                res = self._create_port('json', n['network']['id'],
                                        port_security='off')

                port = self.deserialize('json', res)
                self.assertEquals(port['port']['security_groups'], [])
                self.assertEquals(port['port']['port_security'], 'off')
                self._delete('ports', port['port']['id'])

    def test_create_port_security_mac_ip_with_no_subnet(self):
        with self.network() as n:
            res = self._create_port('json', n['network']['id'],
                                    port_security='mac_ip')

            port = self.deserialize('json', res)
            self.assertEquals(res.status_int, 400)

    def test_create_port_security_mac_with_subnet(self):
        with self.network() as n:
            with self.subnet(n):
                res = self._create_port('json', n['network']['id'],
                                        port_security='mac')

                port = self.deserialize('json', res)
                self.assertEquals(len(port['port']['fixed_ips']), 1)
                self.assertEquals(port['port']['security_groups'], [])
                self.assertEquals(port['port']['port_security'], 'mac')
                self._delete('ports', port['port']['id'])

    def test_create_port_security_mac_ip_with_subnet(self):
        with self.network() as n:
            with self.subnet(n):
                res = self._create_port('json', n['network']['id'],
                                        port_security='mac_ip')

                port = self.deserialize('json', res)
                self.assertEquals(len(port['port']['fixed_ips']), 1)
                self.assertEquals(len(port['port']['security_groups']), 1)
                self.assertEquals(port['port']['port_security'], 'mac_ip')
                self._delete('ports', port['port']['id'])

    def test_create_port_security_remove_mac_ip_and_security_group(self):
        with self.network() as n:
            with self.subnet(n):
                res = self._create_port('json', n['network']['id'],
                                        port_security='mac_ip')

                port = self.deserialize('json', res)
                self.assertEquals(len(port['port']['fixed_ips']), 1)
                self.assertEquals(len(port['port']['security_groups']), 1)
                self.assertEquals(port['port']['port_security'], 'mac_ip')
                data = {'port': {'fixed_ips': port['port']['fixed_ips'],
                                 'name': port['port']['name'],
                                 psec.PORTSECURITY: 'off',
                                 ext_sg.SECURITYGROUP: []}}

                req = self.new_update_request('ports', data,
                                              port['port']['id'])

                res = req.get_response(self.api)
                self.assertEquals(res.status_int, 200)
                self._delete('ports', port['port']['id'])

    def test_create_port_security_remove_mac_ip_security_group_fail(self):
        with self.network() as n:
            with self.subnet(n):
                res = self._create_port('json', n['network']['id'],
                                        port_security='mac_ip')

                port = self.deserialize('json', res)
                self.assertEquals(len(port['port']['fixed_ips']), 1)
                self.assertEquals(len(port['port']['security_groups']), 1)
                self.assertEquals(port['port']['port_security'], 'mac_ip')
                data = {'port': {'fixed_ips': port['port']['fixed_ips'],
                                 'name': port['port']['name'],
                                 psec.PORTSECURITY: 'off'}}

                req = self.new_update_request('ports', data,
                                              port['port']['id'])

                res = req.get_response(self.api)
                self.assertEquals(res.status_int, 400)
                self._delete('ports', port['port']['id'])

    def test_create_port_off_security_add_security_group(self):
        with self.network() as n:
            with self.security_group() as sg:
                res = self._create_port('json', n['network']['id'],
                                        port_security='off')

                port = self.deserialize('json', res)
                data = {'port': {'fixed_ips': port['port']['fixed_ips'],
                        'name': port['port']['name'],
                        ext_sg.SECURITYGROUP: [sg['security_group']['id']]}}

                req = self.new_update_request('ports', data,
                                              port['port']['id'])

                res = req.get_response(self.api)
                self.assertEquals(res.status_int, 400)
                self._delete('ports', port['port']['id'])

    def test_create_port_mac_security_add_security_group(self):
        with self.network() as n:
            with self.security_group() as sg:
                res = self._create_port('json', n['network']['id'],
                                        port_security='mac')

                port = self.deserialize('json', res)
                data = {'port': {'fixed_ips': port['port']['fixed_ips'],
                        'name': port['port']['name'],
                        ext_sg.SECURITYGROUP: [sg['security_group']['id']]}}

                req = self.new_update_request('ports', data,
                                              port['port']['id'])

                res = req.get_response(self.api)
                self.assertEquals(res.status_int, 400)
                self._delete('ports', port['port']['id'])

    def test_create_port_mac_ip_security_add_security_group(self):
        with self.network() as n:
            with self.subnet(n) as s:
                with self.security_group() as sg:
                    res = self._create_port('json', n['network']['id'],
                                            port_security='mac_ip')

                    port = self.deserialize('json', res)
                    data = {'port': {'fixed_ips': port['port']['fixed_ips'],
                            'name': port['port']['name'],
                            psec.PORTSECURITY: port['port'][psec.PORTSECURITY],
                            ext_sg.SECURITYGROUP: (
                                [sg['security_group']['id']])}}

                    req = self.new_update_request('ports', data,
                                                  port['port']['id'])

                    res = req.get_response(self.api)
                    self.assertEquals(res.status_int, 200)
                    self._delete('ports', port['port']['id'])

    def test_create_port_no_sec_add_security_group(self):
        with self.network() as n:
            with self.subnet(n) as s:
                with self.security_group() as sg:
                    res = self._create_port('json', n['network']['id'])

                    port = self.deserialize('json', res)
                    data = {'port': {'fixed_ips': port['port']['fixed_ips'],
                            'name': port['port']['name'],
                            psec.PORTSECURITY: port['port'][psec.PORTSECURITY],
                            ext_sg.SECURITYGROUP: (
                                [sg['security_group']['id']])}}

                    req = self.new_update_request('ports', data,
                                                  port['port']['id'])

                    res = req.get_response(self.api)
                    self.assertEquals(res.status_int, 400)
                    self._delete('ports', port['port']['id'])

    def test_create_port_no_sec_add_security_group_and_mac_ip(self):
        with self.network() as n:
            with self.subnet(n) as s:
                with self.security_group() as sg:
                    res = self._create_port('json', n['network']['id'])

                    port = self.deserialize('json', res)
                    data = {'port': {'fixed_ips': port['port']['fixed_ips'],
                            'name': port['port']['name'],
                            psec.PORTSECURITY: 'mac_ip',
                            ext_sg.SECURITYGROUP: (
                                [sg['security_group']['id']])}}

                    req = self.new_update_request('ports', data,
                                                  port['port']['id'])

                    res = req.get_response(self.api)
                    self.assertEquals(res.status_int, 200)
                    self._delete('ports', port['port']['id'])

    def test_create_port_security_private(self):
        cfg.CONF.PORTSECURITY.require_port_security = 'private'
        with self.network() as n:
            res = self._create_port('json', n['network']['id'],
                                    port_security='mac')
            port = self.deserialize('json', res)
            self.assertEquals(res.status_int, 400)

    def test_update_port_remove_ip_require_ip(self):
        cfg.CONF.PORTSECURITY.require_port_security = 'both'
        with self.network() as n:
            with self.subnet(n):
                res = self._create_port('json', n['network']['id'],
                                        port_security='mac_ip')
                port = self.deserialize('json', res)
                data = {'port': {'fixed_ips': [],
                        'name': port['port']['name']}}

                req = self.new_update_request('ports', data,
                                              port['port']['id'])

                res = req.get_response(self.api)
                self.assertEquals(res.status_int, 400)
                self._delete('ports', port['port']['id'])

    def test_create_port_shared_network_private_only(self):
        cfg.CONF.PORTSECURITY.require_port_security = 'private'
        with self.network(shared=True) as n:
            with self.subnet(n):
                res = self._create_port('json', n['network']['id'])
                port = self.deserialize('json', res)
                self.assertEquals(res.status_int, 201)
                self._delete('ports', port['port']['id'])

    def test_create_port_shared_network_shared_only(self):
        cfg.CONF.PORTSECURITY.require_port_security = 'shared'
        with self.network(shared=True) as n:
            with self.subnet(n):
                res = self._create_port('json', n['network']['id'])
                port = self.deserialize('json', res)
                self.assertEquals(res.status_int, 400)

    def test_create_port_shared_network_both(self):
        cfg.CONF.PORTSECURITY.require_port_security = 'both'
        with self.network(shared=True) as n:
            with self.subnet(n):
                res = self._create_port('json', n['network']['id'])
                port = self.deserialize('json', res)
                self.assertEquals(res.status_int, 400)

    def test_create_port_private_network_both(self):
        cfg.CONF.PORTSECURITY.require_port_security = 'both'
        with self.network() as n:
            with self.subnet(n):
                res = self._create_port('json', n['network']['id'])
                port = self.deserialize('json', res)
                self.assertEquals(res.status_int, 400)
