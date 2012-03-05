# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2011 OpenStack LLC.
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
import mox
import quantum.tests.unit.extensions
import json
import unittest
import routes

from quantum import wsgi
from quantum.common import config
from quantum.extensions import extensions
from quantum.extensions.extensions import PluginAwareExtensionManager
from quantum.extensions.extensions import ExtensionMiddleware
from quantum.manager import QuantumManager
from quantum.tests.unit.extension_stubs import StubBaseAppController
from webtest import TestApp
from webob import exc
from xml.etree.ElementTree import tostring

import pprint
pp = pprint.PrettyPrinter()

LOG = logging.getLogger('test_extensions')
test_conf_file = config.find_config_file({}, None, "quantum.conf.sg")
extensions_path = ':'.join(quantum.extensions.__path__)

SG_CREATE_ID = 'sg_create_id'

SECURITY_GROUP_1_XML = '''<securitygroup id="uuid_sg_1_xml" \
name="test_security_group_1_xml"><securityrules><securityrule id="uuid_sr_1" \
direction="ingress" ip_prefix="1.1.1.1/32" securitygroup_id="uuid_sg_1" \
ethertype="IPv4" protocol="6" port_range_min="0" port_range_max="1000"/>\
<securityrule id="uuid_sr_2" direction="egress" ip_prefix="2.1.1.1/32" \
securitygroup_id="uuid_sg_1" ethertype="IPv4" protocol="6" port_range_min="0" \
port_range_max="1000"/></securityrules><ports><port id="uuid_port_1"></port>\
<port id="uuid_port_2"></port></ports></securitygroup>'''

SECURITY_GROUP_1_JSON = dict(
    securitygroup=dict(
        id="uuid_sg_1_json",
        name="test_security_group_1_json",
        securityrules=[
            dict(
                securityrule=dict(
                    id="uuid_sr_1",
                    direction="ingress",
                    ip_prefix="1.1.1.1/32",
                    securitygroup_id="uuid_sg_1",
                    ethertype="IPv4",
                    protocol="6",
                    port_range_min="0",
                    port_range_max="1000"
                )
            ),
            dict(
                securityrule=dict(
                    dict(
                        id="uuid_sr_2",
                        direction="egress",
                        ip_prefix="2.1.1.1/32",
                        securitygroup_id="uuid_sg_1",
                        ethertype="IPv4",
                        protocol="6",
                        port_range_min="0",
                        port_range_max="1000"
                    )
                )
            )
        ],
        ports=[
            dict(port=dict(id="uuid_port_1")),
            dict(port=dict(id="uuid_port_2"))
        ]
    )
)
SECURITY_GROUP_1_JSON_XML_STR = '''<securitygroup id="uuid_sg_1_json" \
name="test_security_group_1_json"><securityrules><securityrule \
direction="ingress" ethertype="IPv4" id="uuid_sr_1" ip_prefix="1.1.1.1/32" \
port_range_max="1000" port_range_min="0" protocol="6" \
securitygroup_id="uuid_sg_1"/><securityrule direction="egress" \
ethertype="IPv4" id="uuid_sr_2" ip_prefix="2.1.1.1/32" port_range_max="1000" \
port_range_min="0" protocol="6" securitygroup_id="uuid_sg_1"/></securityrules>\
<ports><port id="uuid_port_1"/><port id="uuid_port_2"/></ports>\
</securitygroup>'''

SECURITY_GROUP_1_JSON_JSON_STR = '''{"securitygroup": {"name": \
"test_security_group_1_json", "id": "uuid_sg_1_json", "securityrules": \
[{"securityrule": {"direction": "ingress", "ip_prefix": "1.1.1.1/32", \
"protocol": "6", "ethertype": "IPv4", "port_range_max": "1000", \
"port_range_min": "0", "securitygroup_id": "uuid_sg_1", "id": "uuid_sr_1"}}, \
{"securityrule": {"direction": "egress", "ip_prefix": "2.1.1.1/32", \
"protocol": "6", "ethertype": "IPv4", "port_range_max": "1000", \
"port_range_min": "0", "securitygroup_id": "uuid_sg_1", "id": "uuid_sr_2"}}], \
"ports": [{"port": {"id": "uuid_port_1"}}, {"port": {"id": "uuid_port_2"}}]}}\
'''

SECURITY_GROUP_1 = dict(
    id="uuid_sg_1",
    name="test_security_group_1",
    securityrules=[
        dict(
            id="uuid_sr_1",
            direction="ingress",
            ip_prefix="1.1.1.1/32",
            securitygroup_id="uuid_sg_1",
            ethertype="IPv4",
            protocol="6",
            port_range_min="0",
            port_range_max="1000"
        ),
        dict(
            id="uuid_sr_2",
            direction="egress",
            ip_prefix="2.1.1.1/32",
            securitygroup_id="uuid_sg_1",
            ethertype="IPv4",
            protocol="6",
            port_range_min="0",
            port_range_max="1000"
        )
    ],
    ports=[
        dict(id="uuid_port_1"),
        dict(id="uuid_port_2")
    ]
)

SECURITY_GROUP_2 = dict(
    id="uuid_sg_2",
    name="test_security_group_2",
    securityrules=[
        dict(
            id="uuid_sr_1",
            direction="ingress",
            ip_prefix="1.1.1.1/32",
            securitygroup_id="uuid_sg_1",
            ethertype="IPv4",
            protocol="6",
            port_range_min="0",
            port_range_max="1000"
        ),
        dict(
            id="uuid_sr_2",
            direction="egress",
            ip_prefix="2.1.1.1/32",
            securitygroup_id="uuid_sg_1",
            ethertype="IPv4",
            protocol="6",
            port_range_min="0",
            port_range_max="1000"
        )
    ],
    ports=[
        dict(id="uuid_port_1"),
        dict(id="uuid_port_2")
    ]
)

SECURITY_GROUP_IDS_XML = '''<securitygroups><securitygroup id="uuid_sg_1" />\
<securitygroup id="uuid_sg_2" /></securitygroups>'''

SECURITY_GROUP_IDS_JSON = {
    u'securitygroups': [
        {u'securitygroup': {
            u'id': u'uuid_sg_1'}},
         {u'securitygroup': {
            u'id': u'uuid_sg_2'}}]}


def get_plugin(self):
    return FakeNvpPlugin()


class FakeNvpPlugin(object):
    """Fake plugin for testing.

    Based off QuantumEchoPlugin."""

    def get_plugin_interface(self):
        return None

    def get_num_clusters(self):
        return 1

    #--------------------------------------------------------------------------
    # BEGIN Security group functionality.
    #--------------------------------------------------------------------------
    def get_security_groups(self, tenant_id, port_id, ext_sgid):
        return [SECURITY_GROUP_1, SECURITY_GROUP_2]

    def get_security_group_details(self, tenant_id, id, ext_sgid):
        # raise quantum.common.exceptions.SecurityGroupNotFound
        return SECURITY_GROUP_1

    def create_security_group(self, tenant_id, ext_sgid, **kwargs):
        LOG.info('kwargs: %s' % kwargs)
        return dict(id=SG_CREATE_ID, name=kwargs['name'],
                    securityrules=[sr['securityrule']
                                   for sr in kwargs['securityrules']],
                    ports=[p['port'] for p in kwargs['ports']])

    def update_security_group(self, tenant_id, id, ext_sgid, **kwargs):
        # raise quantum.common.exceptions.SecurityGroupNotFound
        print("update_security_group() called\n")
        LOG.info('kwargs: %s' % kwargs)
        return dict(id=SG_CREATE_ID, name=kwargs.get('name', ''),
                    securityrules=[sr['securityrule']
                                   for sr in kwargs['securityrules']],
                    ports=[p['port'] for p in kwargs['ports']])

    def delete_security_group(self, tenant_id, id, ext_sgid):
        # raise quantum.common.exceptions.SecurityGroupNotFound
        # raise quantum.common.exceptions.SecurityGroupInUse
        pass

    def associate_port_security_group(self, tenant_id, security_group_id,
                                      port_id, ext_sgid):
        # raise quantum.common.exceptions.SecurityGroupNotFound
        # raise quantum.common.exceptions.PortNotFound
        # raise quantum.common.exceptions.SecurityAssociatonExists
        return None

    def dissociate_port_security_group(self, tenant_id, security_group_id,
                                       port_id, ext_sgid):
        # raise quantum.common.exceptions.SecurityGroupNotFound
        # raise quantum.common.exceptions.PortNotFound
        # raise quantum.common.exceptions.NoSecurityAssociatonExists
        return None

    supported_extension_aliases = ["securitygroups"]


class ExtensionsTestApp(wsgi.Router):

    def __init__(self, options={}):
        mapper = routes.Mapper()
        controller = StubBaseAppController()
        mapper.resource("dummy_resource", "/dummy_resources",
                        controller=controller)
        super(ExtensionsTestApp, self).__init__(mapper)


class BaseSecurityGroupResourceExtensionTest(unittest.TestCase):
    '''Test basic URL mapping.'''

    class ResourceExtensionController(wsgi.Controller):

        def index(self, request):
            return "resource index"

        def show(self, request, id):
            return {'data': {'id': id}}

        def create(self, request):
            LOG.info('request.body: %s' % request.body)
            return dict(sg={'id': '112233', 'name': 'test_sg'})

        def delete(self, request, id):
            return exc.HTTPOk()

    def test_sg_extension(self):
        res_ext = extensions.ResourceExtension(
            'sg', self.ResourceExtensionController())
        test_app = setup_extensions_test_app(SimpleExtensionManager(res_ext))
        index_response = test_app.get("/sg")
        self.assertEqual(200, index_response.status_int)
        self.assertEqual("resource index", index_response.body)

        show_response = test_app.get("/sg/25266")
        self.assertEqual({'data': {'id': "25266"}}, show_response.json)

        delete_response = test_app.delete("/sg/25266")
        self.assertEqual(200, delete_response.status_int)

        create_response = test_app.post("/sg", {'name': 'test_sg'})
        self.assertEqual({'sg': {'id': "112233", 'name': 'test_sg'}},
                         create_response.json)
        self.assertEqual(200, create_response.status_int)


class CustomSecurityGroupResourceExtensionTest(unittest.TestCase):
    '''Test mapping with custom actions.'''

    class ResourceExtensionController(wsgi.Controller):

        def index(self, request, tenant_id):
            return "resource index"

        def show(self, request, tenant_id, id):
            return {'data': {'id': id, 'tenant_id': tenant_id}}

        def create(self, request, tenant_id):
            LOG.info('request.body: %s' % request.body)
            return dict(securitygroups={'id': '112233', 'name': 'test_sg',
                            'tenant_id': tenant_id})

        def update(self, request, tenant_id, id=None):
            return dict(securitygroups={'id': id, 'tenant_id': tenant_id,
                                        'name': request.params['name']})

        def delete(self, request, tenant_id, id):
            return exc.HTTPOk()

    #--------------------------------------------------------------------------
    # BEGIN Tests.
    #--------------------------------------------------------------------------
    def test_sg_extension(self):
        member = {'show_detail': "GET"}
        collections = {'index_detail': "GET"}
        res_ext = extensions.ResourceExtension(
            'securitygroups', self.ResourceExtensionController(),
            member_actions=member,
            collection_actions=collections,
            parent={'member_name': 'tenant',
                    'collection_name': 'extensions/sg/tenants'})

        test_app = setup_extensions_test_app(SimpleExtensionManager(res_ext))
        index_response = test_app.get(
            "/extensions/sg/tenants/XYZ/securitygroups")
        self.assertEqual(200, index_response.status_int)
        self.assertEqual("resource index", index_response.body)

        show_response = test_app.get(
            "/extensions/sg/tenants/XYZ/securitygroups/25266")
        self.assertEqual({'data': {'id': "25266", 'tenant_id': 'XYZ'}},
                         show_response.json)

        delete_response = test_app.delete(
            "/extensions/sg/tenants/XYZ/securitygroups/25266")
        self.assertEqual(200, delete_response.status_int)

        create_response = test_app.post(
            "/extensions/sg/tenants/XYZ/securitygroups", {'name': 'test_sg'})
        self.assertEqual({'securitygroups': {'id': "112233", 'name': 'test_sg',
                                 'tenant_id': 'XYZ'}},
                         create_response.json)
        self.assertEqual(200, create_response.status_int)

        update_response = test_app.put(
            "/extensions/sg/tenants/XYZ/securitygroups/112233",
            {'name': 'test_sg'})
        self.assertEqual({'securitygroups': {'id': "112233", 'name': 'test_sg',
                         'tenant_id': 'XYZ'}}, update_response.json)
        self.assertEqual(200, update_response.status_int)
        LOG.info('***** update_response: %s' %
                 pp.pformat(update_response.__dict__))


class SecurityGroupExtensionControllerTest(unittest.TestCase):
    def setUp(self):
        super(SecurityGroupExtensionControllerTest, self).setUp()
        self.mox = mox.Mox()
        self.orig_method = QuantumManager.get_plugin
        static_stub = staticmethod(lambda *args, **kwargs: FakeNvpPlugin())
        QuantumManager.get_plugin = static_stub
        self.mox.ReplayAll()
        self.test_app = setup_extensions_test_app()

    def tearDown(self):
        self.mox.VerifyAll()
        self.mox.UnsetStubs()
        QuantumManager.get_plugin = self.orig_method

    def test_index_gets_all_registered_extensions(self):
        response = self.test_app.get("/extensions")
        self.assertTrue(len(response.json["extensions"]) > 0)

        found_sg_extension = False
        for e in response.json["extensions"]:
            if e["alias"] == "securitygroups":
                found_sg_extension = True
                break

        self.assertTrue(found_sg_extension)

    def test_index(self):
        index_response = self.test_app.get(
            "/extensions/sg/tenants/XYZ/securitygroups")
        self.assertEqual(200, index_response.status_int)
        LOG.info('***** index_response: %s' %
                 pp.pformat(index_response.__dict__))

    def test_index_xml(self):
        index_response = self.test_app.get(
            "/extensions/sg/tenants/XYZ/securitygroups.xml")
        self.assertEqual(200, index_response.status_int)
        LOG.info('***** index_response_xml: %s' %
                 tostring(index_response.xml))

    def test_index_json(self):
        index_response = self.test_app.get(
            "/extensions/sg/tenants/XYZ/securitygroups.json")
        self.assertEqual(200, index_response.status_int)
        LOG.debug("index_response_json: %s" % index_response.json)
        sgs = index_response.json["securitygroups"]
        self.assertTrue(sgs[0]["securitygroup"]["id"] == "uuid_sg_1")
        self.assertTrue(sgs[1]["securitygroup"]["id"] == "uuid_sg_2")

    def test_show(self):
        show_response = self.test_app.get(
            "/extensions/sg/tenants/XYZ/securitygroups/UUU")
        self.assertEqual(200, show_response.status_int)
        LOG.debug('show_response: %s' % pp.pformat(show_response.__dict__))

    def test_show_xml(self):
        show_response = self.test_app.get(
            "/extensions/sg/tenants/XYZ/securitygroups/UUU.xml")
        self.assertEqual(200, show_response.status_int)
        LOG.debug('show_response_xml: %s' % tostring(show_response.xml))

    def test_show_json(self):
        show_response = self.test_app.get(
            "/extensions/sg/tenants/XYZ/securitygroups/UUU.json")
        self.assertEqual(200, show_response.status_int)
        LOG.debug('show_response_json: %s' % show_response.json)
        sg = show_response.json['securitygroup']
        sr = sg['securityrules'][0]['securityrule']
        self.assertTrue(sg['id'] == 'uuid_sg_1')
        self.assertTrue(sg['name'] == 'test_security_group_1')
        self.assertTrue(sr['id'] == 'uuid_sr_1')
        self.assertTrue(sr['direction'] == 'ingress')
        self.assertTrue(sr['ip_prefix'] == '1.1.1.1/32')
        self.assertTrue(sr['securitygroup_id'] == 'uuid_sg_1')
        self.assertTrue(sr['ethertype'] == 'IPv4')
        self.assertTrue(sr['protocol'] == '6')
        self.assertTrue(sr['port_range_min'] == '0')
        self.assertTrue(sr['port_range_max'] == '1000')
        self.assertTrue(len(sg['securityrules']) == 2)

    def test_create_json(self):
        create_response = self.test_app.post(
            "/extensions/sg/tenants/XYZ/securitygroups",
            json.dumps(SECURITY_GROUP_1_JSON),
            [('Content-Type', 'application/json')])

        # TODO(del): add tenant_id to securitygroup?
        self.assertEqual(200, create_response.status_int)
        received = create_response.json['securitygroup']
        received = create_response.json['securitygroup']
        self.assertTrue(received['id'] == SG_CREATE_ID)
        self.assertTrue(received['name'] == 'test_security_group_1_json')

        securityrules = received['securityrules']
        securityrule = securityrules[0]['securityrule']
        self.assertTrue(securityrule['id'] == 'uuid_sr_1')
        self.assertTrue(securityrule['direction'] == 'ingress')
        self.assertTrue(securityrule['securitygroup_id'] == 'uuid_sg_1')
        self.assertTrue(securityrule['ethertype'] == 'IPv4')
        self.assertTrue(securityrule['protocol'] == '6')
        self.assertTrue(securityrule['port_range_min'] == '0')
        self.assertTrue(securityrule['port_range_max'] == '1000')
        self.assertTrue(len(list(securityrules)) == 2)

        ports = received["ports"]
        port = ports[0]['port']
        self.assertTrue(port['id'] == 'uuid_port_1')
        self.assertTrue(len(list(ports)) == 2)

    def test_create_xml(self):
        create_response = self.test_app.post(
            "/extensions/sg/tenants/XYZ/securitygroups",
            SECURITY_GROUP_1_XML,
            [('Content-Type', 'application/xml')])

        # TODO(del): add tenant_id to securitygroup?
        self.assertEqual(200, create_response.status_int)
        sg_atts = create_response.xml.attrib
        self.assertTrue(sg_atts['id'] == SG_CREATE_ID)
        self.assertTrue(sg_atts['name'] == 'test_security_group_1_xml')

        securityrules = create_response.xml.find('securityrules')
        securityrule = securityrules.find('securityrule')
        self.assertTrue(securityrule.attrib['id'] == 'uuid_sr_1')
        self.assertTrue(securityrule.attrib['direction'] == 'ingress')
        self.assertTrue(securityrule.attrib['ethertype'] == 'IPv4')
        self.assertTrue(securityrule.attrib['protocol'] == '6')
        self.assertTrue(securityrule.attrib['port_range_min'] == '0')
        self.assertTrue(securityrule.attrib['port_range_max'] == '1000')
        self.assertTrue(len(list(securityrules)) == 2)

        ports = create_response.xml.find("ports")
        port = ports.find('port')
        self.assertTrue(port.attrib['id'] == 'uuid_port_1')
        self.assertTrue(len(list(ports)) == 2)

    def test_update_json(self):
        update_response = self.test_app.put(
            "/extensions/sg/tenants/XYZ/securitygroups/UUU",
            json.dumps(SECURITY_GROUP_1_JSON),
            [('Content-Type', 'application/json')])

        # TODO(del): add tenant_id to securitygroup?
        self.assertEqual(200, update_response.status_int)
        received = update_response.json['securitygroup']
        received = update_response.json['securitygroup']
        self.assertTrue(received['id'] == SG_CREATE_ID)
        self.assertTrue(received['name'] == 'test_security_group_1_json')

        securityrules = received['securityrules']
        securityrule = securityrules[0]['securityrule']
        self.assertTrue(securityrule['id'] == 'uuid_sr_1')
        self.assertTrue(securityrule['direction'] == 'ingress')
        self.assertTrue(securityrule['securitygroup_id'] == 'uuid_sg_1')
        self.assertTrue(securityrule['ethertype'] == 'IPv4')
        self.assertTrue(securityrule['protocol'] == '6')
        self.assertTrue(securityrule['port_range_min'] == '0')
        self.assertTrue(securityrule['port_range_max'] == '1000')
        self.assertTrue(len(list(securityrules)) == 2)

        ports = received["ports"]
        port = ports[0]['port']
        self.assertTrue(port['id'] == 'uuid_port_1')
        self.assertTrue(len(list(ports)) == 2)

    def test_update_xml(self):
        update_response = self.test_app.put(
            "/extensions/sg/tenants/XYZ/securitygroups/UUU",
            SECURITY_GROUP_1_XML,
            [('Content-Type', 'application/xml')])

        # TODO(del): add tenant_id to securitygroup?
        self.assertEqual(200, update_response.status_int)
        sg_atts = update_response.xml.attrib
        self.assertTrue(sg_atts['id'] == SG_CREATE_ID)
        self.assertTrue(sg_atts['name'] == 'test_security_group_1_xml')

        securityrules = update_response.xml.find('securityrules')
        securityrule = securityrules.find('securityrule')
        self.assertTrue(securityrule.attrib['id'] == 'uuid_sr_1')
        self.assertTrue(securityrule.attrib['direction'] == 'ingress')
        self.assertTrue(securityrule.attrib['ethertype'] == 'IPv4')
        self.assertTrue(securityrule.attrib['protocol'] == '6')
        self.assertTrue(securityrule.attrib['port_range_min'] == '0')
        self.assertTrue(securityrule.attrib['port_range_max'] == '1000')
        self.assertTrue(len(list(securityrules)) == 2)

        ports = update_response.xml.find("ports")
        port = ports.find('port')
        self.assertTrue(port.attrib['id'] == 'uuid_port_1')
        self.assertTrue(len(list(ports)) == 2)

    def test_delete(self):
        create_response = self.test_app.delete(
            "/extensions/sg/tenants/XYZ/securitygroups/UUU")
        self.assertEqual(200, create_response.status_int)

    def test_list_for_port_json(self):
        list_response = self.test_app.put(
            "/extensions/sg/tenants/XYZ/securitygroups/list_for_port",
            json.dumps({'port': {'id': 'AAA'}}),
            [('Content-Type', 'application/json')])
        self.assertEqual(200, list_response.status_int)
        self.assertEqual(list_response.json, SECURITY_GROUP_IDS_JSON)

    def test_list_for_port_xml(self):
        list_response = self.test_app.put(
            "/extensions/sg/tenants/XYZ/securitygroups/list_for_port",
            "<port id='AAA'/>",
            [('Content-Type', 'application/xml')])
        self.assertEqual(200, list_response.status_int)
        self.assertEqual(tostring(list_response.xml), SECURITY_GROUP_IDS_XML)

    def test_show_returns_not_found_for_non_existant_extension(self):
        response = self.test_app.get("/extensions/non_existant", status="*")
        self.assertEqual(response.status_int, 404)

    def test_associate_port_json(self):
        associate_response = self.test_app.put(
            "/extensions/sg/tenants/XYZ/securitygroups/UUU/associate_port",
            json.dumps({'port': {'id': 'AAA'}, 'ext_sgid': 'True'}),
            [('Content-Type', 'application/json')])
        self.assertEqual(200, associate_response.status_int)

    def test_dissociate_port_xml(self):
        associate_response = self.test_app.put(
            "/extensions/sg/tenants/XYZ/securitygroups/UUU/dissociate_port",
            "<port id='AAA'/>",
            [('Content-Type', 'application/xml')])
        self.assertEqual(200, associate_response.status_int)


def app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return ExtensionsTestApp(conf)


def setup_extensions_middleware(extension_manager=None):
    extension_manager = (extension_manager or
                         PluginAwareExtensionManager(extensions_path,
                                                     FakeNvpPlugin()))
    LOG.info('extension_manager: %s' % pp.pformat(extension_manager.__dict__))
    options = {'config_file': test_conf_file}
    conf, app = config.load_paste_app('extensions_test_app', options, None)
    return ExtensionMiddleware(app, conf, ext_mgr=extension_manager)


class SerializationTest(unittest.TestCase):

    _common_serialization_metadata = {
            "plurals": {
                "securitygroups": "securitygroup", "ports": "port",
                "securityrules": "securityrule"
            },
            "attributes": {
                "securitygroup": [
                    "id", "name"
                ],
                "securityrule": [
                    "id", "direction", "ip_prefix", "securitygroup_id",
                    "ethertype", "protocol", "port_range_min",
                    "port_range_max"
                ],
                "port": ["id"]
            }
    }

    _serialization_metadata = {
        "application/xml": _common_serialization_metadata,
        "application/json": _common_serialization_metadata,
    }
    _serialization_metadata.update(_common_serialization_metadata)

    def test_serialize_xml(self):
        s = wsgi.SecurityGroupSerializer(
            SerializationTest._serialization_metadata)
        sd = s.serialize(SECURITY_GROUP_1_JSON, 'application/xml')
        self.assertEqual(sd, SECURITY_GROUP_1_JSON_XML_STR)

        sd = s.serialize(SECURITY_GROUP_1_JSON, 'application/json')
        self.assertEqual(sd, SECURITY_GROUP_1_JSON_JSON_STR)

    def test_deserialize_xml(self):
        s = wsgi.SecurityGroupSerializer(
            SerializationTest._serialization_metadata)
        sd = s.deserialize(SECURITY_GROUP_1_JSON_XML_STR, 'application/xml')
        # self.assertEqual(sd, SECURITY_GROUP_1_JSON)
        LOG.info('ds from XML %s' % sd)

        sd = s.deserialize(SECURITY_GROUP_1_JSON_JSON_STR, 'application/json')
        # self.assertEqual(sd, SECURITY_GROUP_1_JSON)
        LOG.info('ds from JSON %s' % sd)


def setup_extensions_test_app(extension_manager=None):
    return TestApp(setup_extensions_middleware(extension_manager))


class SimpleExtensionManager(object):

    def __init__(self, resource_ext=None, action_ext=None, request_ext=None):
        self.resource_ext = resource_ext
        self.action_ext = action_ext
        self.request_ext = request_ext

    def get_resources(self):
        resource_exts = []
        if self.resource_ext:
            resource_exts.append(self.resource_ext)
        return resource_exts

    def get_actions(self):
        action_exts = []
        if self.action_ext:
            action_exts.append(self.action_ext)
        return action_exts

    def get_request_extensions(self):
        request_extensions = []
        if self.request_ext:
            request_extensions.append(self.request_ext)
        return request_extensions
