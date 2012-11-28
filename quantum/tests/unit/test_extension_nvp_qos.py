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

import unittest2
import webob.exc

from quantum.api.v2 import attributes
from quantum.api.v2.router import APIRouter
from quantum.common.test_lib import test_config
from quantum.common import config
from quantum.db import api as db
from quantum.extensions.extensions import PluginAwareExtensionManager
from quantum.extensions import nvp_qos as ext_qos
from quantum.manager import QuantumManager
from quantum.openstack.common import cfg
from quantum.tests.unit import test_db_plugin
from quantum.tests.unit import test_extensions
from quantum.wsgi import JSONDeserializer

ROOTDIR = os.path.dirname(os.path.dirname(__file__))
ETCDIR = os.path.join(ROOTDIR, 'etc')


def etcdir(*p):
    return os.path.join(ETCDIR, *p)


class NvpQoSTestExtensionManager(object):

    def get_resources(self):
        return ext_qos.Nvp_qos.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class NvpQoSTestCase(test_db_plugin.QuantumDbPluginV2TestCase,
                     unittest2.TestCase):
    def setUp(self, plugin=None):
        super(NvpQoSTestCase, self).setUp()
        if plugin is None:
            self.skipTest("This is only for NVP")
        db._ENGINE = None
        db._MAKER = None
        QuantumManager._instance = None
        PluginAwareExtensionManager._instance = None
        # Create the default configurations
        args = ['--config-file', etcdir('quantum.conf.test')]
        # If test_config specifies some config-file, use it, as well
        for config_file in test_config.get('config_files', []):
            args.extend(['--config-file', config_file])
        config.parse(args=args)
        # Update the plugin
        cfg.CONF.set_override('core_plugin', plugin)
        self.api = APIRouter()

        QuantumManager.get_plugin().supported_extension_aliases = (
            ["nvp-qos"])
        ext_mgr = NvpQoSTestExtensionManager()
        if ext_mgr:
            self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)

    def tearDown(self):
        super(NvpQoSTestCase, self).tearDown()
        db._ENGINE = None
        db._MAKER = None
        cfg.CONF.reset()
        # Restore the original attribute map
        attributes.RESOURCE_ATTRIBUTE_MAP = self._attribute_map_bk

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


class TestNvpQoS(NvpQoSTestCase):
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
                                       arg_list=(ext_qos.QUEUE,),
                                       queue_id=q1['qos_queue']['id'])
            net1 = self.deserialize('json', res)
            self.assertEquals(net1['network'][ext_qos.QUEUE],
                              q1['qos_queue']['id'])
            device_id = "00fff4d0-e4a8-4a3a-8906-4c4cdafb59f1"
            with self.port(device_id=device_id) as p:
                self.assertEquals(len(p['port'][ext_qos.QUEUE]), 36)

    def test_create_shared_queue_networks(self):
        with self.qos_queue(default=True, no_delete=True) as q1:
            res = self._create_network('json', 'net1', True,
                                       arg_list=(ext_qos.QUEUE,),
                                       queue_id=q1['qos_queue']['id'])
            net1 = self.deserialize('json', res)
            self.assertEquals(net1['network'][ext_qos.QUEUE],
                              q1['qos_queue']['id'])
            res = self._create_network('json', 'net2', True,
                                       arg_list=(ext_qos.QUEUE,),
                                       queue_id=q1['qos_queue']['id'])
            net2 = self.deserialize('json', res)
            self.assertEquals(net1['network'][ext_qos.QUEUE],
                              q1['qos_queue']['id'])
            device_id = "00fff4d0-e4a8-4a3a-8906-4c4cdafb59f1"
            res = self._create_port('json', net1['network']['id'],
                                    device_id=device_id)
            port1 = self.deserialize('json', res)
            res = self._create_port('json', net2['network']['id'],
                                    device_id=device_id)
            port2 = self.deserialize('json', res)
            self.assertEquals(port1['port'][ext_qos.QUEUE],
                              port2['port'][ext_qos.QUEUE])

            self._delete('ports', port1['port']['id'])
            self._delete('ports', port2['port']['id'])

    def test_remove_queue_in_use_fail(self):
        with self.qos_queue(no_delete=True) as q1:
            res = self._create_network('json', 'net1', True,
                                       arg_list=(ext_qos.QUEUE,),
                                       queue_id=q1['qos_queue']['id'])
            net1 = self.deserialize('json', res)
            device_id = "00fff4d0-e4a8-4a3a-8906-4c4cdafb59f1"
            res = self._create_port('json', net1['network']['id'],
                                    device_id=device_id)
            port = self.deserialize('json', res)
            self._delete('qos-queues', port['port'][ext_qos.QUEUE], 409)

    def test_update_network_new_queue(self):
        with self.qos_queue() as q1:
            res = self._create_network('json', 'net1', True,
                                       arg_list=(ext_qos.QUEUE,),
                                       queue_id=q1['qos_queue']['id'])
            net1 = self.deserialize('json', res)
            with self.qos_queue() as new_q:
                data = {'network': {ext_qos.QUEUE: new_q['qos_queue']['id']}}
                req = self.new_update_request('networks', data,
                                              net1['network']['id'])
                res = req.get_response(self.api)
                net1 = self.deserialize('json', res)
                self.assertEquals(net1['network'][ext_qos.QUEUE],
                                  new_q['qos_queue']['id'])

    def test_update_port_adding_device_id(self):
        with self.qos_queue(no_delete=True) as q1:
            res = self._create_network('json', 'net1', True,
                                       arg_list=(ext_qos.QUEUE,),
                                       queue_id=q1['qos_queue']['id'])
            net1 = self.deserialize('json', res)
            device_id = "00fff4d0-e4a8-4a3a-8906-4c4cdafb59f1"
            res = self._create_port('json', net1['network']['id'])
            port = self.deserialize('json', res)
            self.assertEquals(port['port'][ext_qos.QUEUE], None)

            data = {'port': {'device_id': device_id}}
            req = self.new_update_request('ports', data,
                                          port['port']['id'])

            res = req.get_response(self.api)
            port = self.deserialize('json', res)
            self.assertEquals(len(port['port'][ext_qos.QUEUE]), 36)
