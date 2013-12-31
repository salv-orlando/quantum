# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 VMware, Inc.
# All Rights Reserved
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

from neutron.common import constants
from neutron.openstack.common import log
from neutron.plugins.nicira.common import utils
from neutron.plugins.nicira import nsxlib

LOG = log.getLogger(__name__)
SECPROF_RESOURCE = "security-profile"


def create_security_profile(cluster, tenant_id,
                            neutron_id, security_profile):
    """Create a security profile on the NSX backend.

    :param cluster: a NSX cluster object reference
    :param tenant_id: identifier of the Neutron tenant
    :param neutron_id: neutron security group identifier
    :param security_profile: dictionary with data for
    configuring the NSX security profile.
    """
    path = nsxlib._build_uri_path(SECPROF_RESOURCE)
    # Allow all dhcp responses and all ingress traffic
    hidden_rules = {'logical_port_egress_rules':
                    [{'ethertype': 'IPv4',
                      'protocol': constants.PROTO_NUM_UDP,
                      'port_range_min': constants.DHCP_RESPONSE_PORT,
                      'port_range_max': constants.DHCP_RESPONSE_PORT,
                      'ip_prefix': '0.0.0.0/0'}],
                    'logical_port_ingress_rules':
                    [{'ethertype': 'IPv4'},
                     {'ethertype': 'IPv6'}]}
    # NOTE(salv-orlando): neutron-id tags are prepended with 'q' for
    # historical reasons
    tags = [dict(scope='q_sec_group_id', tag=neutron_id),
            dict(scope='os_tid', tag=tenant_id),
            dict(scope='quantum', tag=nsxlib.NEUTRON_VERSION)]
    display_name = utils.check_and_truncate(security_profile.get('name'))
    body = nsxlib.mk_body(
        tags=tags, display_name=display_name,
        logical_port_ingress_rules=(
            hidden_rules['logical_port_ingress_rules']),
        logical_port_egress_rules=hidden_rules['logical_port_egress_rules']
    )
    res = nsxlib.do_request(nsxlib.HTTP_POST, path, body, cluster=cluster)
    if security_profile.get('name') == 'default':
        # If security group is default allow ip traffic between
        # members of the same security profile is allowed and ingress traffic
        # from the switch
        rules = {'logical_port_egress_rules': [{'ethertype': 'IPv4',
                                                'profile_uuid': res['uuid']},
                                               {'ethertype': 'IPv6',
                                                'profile_uuid': res['uuid']}],
                 'logical_port_ingress_rules': [{'ethertype': 'IPv4'},
                                                {'ethertype': 'IPv6'}]}

        update_security_profile_rules(cluster, res['uuid'], rules)
    LOG.debug(_("Created NSX Security Profile: %(nsx_id)s for "
                "Neutron security group: %(neutron_id)s"),
              {'nsx_id': res['uuid'],
               'neutron_id': neutron_id})
    return res


def update_security_profile_rules(cluster, sp_id, rules):
    path = nsxlib._build_uri_path(SECPROF_RESOURCE, resource_id=sp_id)
    # Allow all dhcp responses in
    rules['logical_port_egress_rules'].append(
        {'ethertype': 'IPv4', 'protocol': constants.PROTO_NUM_UDP,
         'port_range_min': constants.DHCP_RESPONSE_PORT,
         'port_range_max': constants.DHCP_RESPONSE_PORT,
         'ip_prefix': '0.0.0.0/0'})
    # If there are no ingress rules add bunk rule to drop all ingress traffic
    if not rules['logical_port_ingress_rules']:
        rules['logical_port_ingress_rules'].append(
            {'ethertype': 'IPv4', 'ip_prefix': '127.0.0.1/32'})
    body = nsxlib.mk_body(
        logical_port_ingress_rules=rules['logical_port_ingress_rules'],
        logical_port_egress_rules=rules['logical_port_egress_rules'])
    res = nsxlib.do_request(
        nsxlib.HTTP_PUT, path, body, cluster=cluster)
    LOG.debug(_("Updated rules for security Profile: %s"), sp_id)
    return res


def delete_security_profile(cluster, sp_id):
    path = nsxlib._build_uri_path(SECPROF_RESOURCE, resource_id=sp_id)
    nsxlib.do_request(nsxlib.HTTP_DELETE, path, cluster=cluster)


def get_security_profile(cluster, sp_id):
    path = nsxlib._build_uri_path(SECPROF_RESOURCE, resource_id=sp_id)
    res = nsxlib.do_request(nsxlib.HTTP_GET, path, cluster=cluster)
    LOG.debug(_("Retrieved security profile: %s from NSX backend"), sp_id)
    return res


def query_security_profiles(cluster, fields=None, filters=None):
    return nsxlib.get_all_query_pages(
        nsxlib._build_uri_path(
            SECPROF_RESOURCE,
            fields=fields,
            filters=filters),
        cluster)
