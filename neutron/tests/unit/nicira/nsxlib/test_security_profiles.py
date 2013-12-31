# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 VMware, Inc.
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

import copy
import json
import mock

from neutron.common import constants
from neutron.plugins.nicira import nsxlib
from neutron.plugins.nicira.nsxlib import security_profiles as sp_lib
from neutron.plugins.nicira import NvpApiClient
from neutron.tests import base


class SecurityProfilesTestCase(base.BaseTestCase):

    default_ingress_rules = [
        {'ethertype': 'IPv4'},
        {'ethertype': 'IPv6'}]
    default_egress_rules = [
        {'ethertype': 'IPv4',
            'protocol': constants.PROTO_NUM_UDP,
            'port_range_min': constants.DHCP_RESPONSE_PORT,
            'port_range_max': constants.DHCP_RESPONSE_PORT,
            'ip_prefix': '0.0.0.0/0'}]
    request_body_template = {
        'tags': [
            {'scope': 'q_sec_group_id', 'tag': 'neutron_id'},
            {'scope': 'os_tid', 'tag': 'tenant_id'},
            {'scope': 'quantum', 'tag': nsxlib.NEUTRON_VERSION}],
        'display_name': '%(display_name)s',
        'logical_port_ingress_rules': default_ingress_rules,
        'logical_port_egress_rules': default_egress_rules
    }
    request_body_template_json = json.dumps(request_body_template)

    def setUp(self):
        super(SecurityProfilesTestCase, self).setUp()
        self.mock_request_p = mock.patch.object(nsxlib, 'do_request')
        self.mock_request = self.mock_request_p.start()
        self.cluster = mock.Mock()
        self.addCleanup(self.mock_request_p.stop)

    def test_create_and_get_security_profile(self):
        exp_req_body = (self.request_body_template_json %
                        {'display_name': 'test'})

        sp_lib.create_security_profile(self.cluster, 'tenant_id',
                                       'neutron_id', {'name': 'test'})

        self.mock_request.assert_called_once_with(
            nsxlib.HTTP_POST, '/ws.v1/security-profile',
            exp_req_body, cluster=mock.ANY)

    def test_create_and_get_default_security_profile(self):
        exp_req_body = (self.request_body_template_json %
                        {'display_name': 'default'})
        self.mock_request.return_value = json.loads(exp_req_body)
        self.mock_request.return_value['uuid'] = 'sec_prof_uuid'
        # the 2nd request should have only rules in the body
        membership_rules = [
            {'ethertype': 'IPv4', 'profile_uuid': 'sec_prof_uuid'},
            {'ethertype': 'IPv6', 'profile_uuid': 'sec_prof_uuid'}]
        exp_req_body_2 = {
            'logical_port_ingress_rules': self.default_ingress_rules,
            'logical_port_egress_rules': (membership_rules +
                                          self.default_egress_rules)}

        sp_lib.create_security_profile(self.cluster, 'tenant_id',
                                       'neutron_id', {'name': 'default'})

        self.mock_request.assert_has_calls(
            [mock.call(nsxlib.HTTP_POST,
                       '/ws.v1/security-profile',
                       exp_req_body,
                       cluster=mock.ANY),
             mock.call(nsxlib.HTTP_PUT,
                       '/ws.v1/security-profile/sec_prof_uuid',
                       json.dumps(exp_req_body_2),
                       cluster=mock.ANY)])

    def test_update_security_profile_rules(self):
        ingress_rule = {'ethertype': 'IPv4'}
        egress_rule = {'ethertype': 'IPv4', 'profile_uuid': 'xyz'}
        new_rules = {'logical_port_egress_rules': [egress_rule],
                     'logical_port_ingress_rules': [ingress_rule]}
        exp_rules = copy.deepcopy(new_rules)
        exp_rules['logical_port_egress_rules'].extend(
            self.default_egress_rules)

        sp_lib.update_security_profile_rules(self.cluster,
                                             'sec_prof_uuid',
                                             new_rules)

        self.mock_request.assert_called_once_with(
            nsxlib.HTTP_PUT,
            '/ws.v1/security-profile/sec_prof_uuid',
            json.dumps(exp_rules),
            cluster=mock.ANY)

    def test_update_security_profile_rules_noingress(self):
        hidden_ingress_rule = {'ethertype': 'IPv4',
                               'ip_prefix': '127.0.0.1/32'}
        egress_rule = {'ethertype': 'IPv4', 'profile_uuid': 'xyz'}
        new_rules = {'logical_port_egress_rules': [egress_rule],
                     'logical_port_ingress_rules': []}
        exp_rules = copy.deepcopy(new_rules)
        exp_rules['logical_port_ingress_rules'].extend([hidden_ingress_rule])
        exp_rules['logical_port_egress_rules'].extend(
            self.default_egress_rules)

        sp_lib.update_security_profile_rules(self.cluster,
                                             'sec_prof_uuid',
                                             new_rules)

        self.mock_request.assert_called_once_with(
            nsxlib.HTTP_PUT,
            '/ws.v1/security-profile/sec_prof_uuid',
            json.dumps(exp_rules),
            cluster=mock.ANY)

    def test_update_non_existing_security_profile_raises(self):
        self.mock_request.side_effect = NvpApiClient.ResourceNotFound
        self.assertRaises(NvpApiClient.ResourceNotFound,
                          sp_lib.update_security_profile_rules,
                          self.cluster, 'whatever',
                          {'logical_port_egress_rules': [],
                           'logical_port_ingress_rules': []})

    def test_delete_security_profile(self):
        sp_lib.delete_security_profile(self.cluster, 'sec_prof_uuid')
        self.mock_request.assert_called_once_with(
            nsxlib.HTTP_DELETE,
            '/ws.v1/security-profile/sec_prof_uuid',
            cluster=mock.ANY)

    def test_delete_non_existing_security_profile_raises(self):
        self.mock_request.side_effect = NvpApiClient.ResourceNotFound
        self.assertRaises(NvpApiClient.ResourceNotFound,
                          sp_lib.delete_security_profile,
                          self.cluster, 'whatever')

    def test_query_security_profiles(self):
        fields = "whatever,whatever_else"
        filters = {'whatever': 'xxx'}
        # simulate a single page of results
        self.mock_request.return_value = {
            'results': [{'xxx': 'yyy'}]}
        sp_lib.query_security_profiles(self.cluster, fields, filters)
        self.mock_request.assert_called_once_with(
            nsxlib.HTTP_GET,
            '/ws.v1/security-profile?fields=whatever,whatever_else&'
            'whatever=xxx&_page_length=1000&tag_scope=quantum',
            cluster=mock.ANY)
