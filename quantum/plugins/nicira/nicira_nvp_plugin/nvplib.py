# Copyright 2012 Nicira Networks, Inc.
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
#
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# @author: Brad Hall, Nicira Networks, Inc.
# @author: Dave Lapsley, Nicira Networks, Inc.
# @author: Aaron Rosen, Nicira Networks, Inc.


# TODO(bgh): We should break this into separate files.  It will just keep
# growing as we add more features :)

from copy import copy
import itertools
import json
import hashlib
import logging

import NvpApiClient

#FIXME(danwent): I'd like this file to get to the point where it has
# no quantum-specific logic in it
from quantum.common import constants
from quantum.common import exceptions as exception
from quantum.extensions import securitygroup as ext_sg

# HTTP METHODS CONSTANTS
HTTP_GET = "GET"
HTTP_POST = "POST"
# Default transport type for logical switches
DEF_TRANSPORT_TYPE = "stt"
# Prefix to be used for all NVP API calls
URI_PREFIX = "/ws.v1"
# Resources exposed by NVP API
LSWITCH_RESOURCE = "lswitch"
LPORT_RESOURCE = "lport"

LOCAL_LOGGING = False
if LOCAL_LOGGING:
    from logging.handlers import SysLogHandler
    FORMAT = ("|%(levelname)s|%(filename)s|%(funcName)s|%(lineno)s"
              "|%(message)s")
    LOG = logging.getLogger(__name__)
    formatter = logging.Formatter(FORMAT)
    syslog = SysLogHandler(address="/dev/log")
    syslog.setFormatter(formatter)
    LOG.addHandler(syslog)
    LOG.setLevel(logging.DEBUG)
else:
    LOG = logging.getLogger("nvplib")
    LOG.setLevel(logging.DEBUG)

# TODO(bgh): it would be more efficient to use a bitmap
taken_context_ids = []

_net_type_cache = {}  # cache of {net_id: network_type}
# XXX Only cache default for now
_lqueue_cache = {}
PORT_SECURITY_DEFAULT = True


def _build_uri_path(resource,
                    resource_id=None,
                    parent_resource_id=None,
                    fields=None,
                    relations=None, filters=None):
    # TODO(salvatore-orlando): This is ugly. do something more clever
    # and aovid the if statement
    if resource == LPORT_RESOURCE:
        res_path = ("%s/%s/%s" % (LSWITCH_RESOURCE,
                                  parent_resource_id,
                                  resource) +
                    (resource_id and "/%s" % resource_id or ''))
    else:
        res_path = resource + (resource_id and
                               "/%s" % resource_id or '')

    params = []
    params.append(fields and "fields=%s" % fields)
    params.append(relations and "relations=%s" % relations)
    if filters:
        params.extend(['%s=%s' % (k, v) for (k, v) in filters.iteritems()])
    uri_path = "%s/%s" % (URI_PREFIX, res_path)
    query_string = reduce(lambda x, y: "%s&%s" % (x, y),
                          itertools.ifilter(lambda x: x is not None, params),
                          "")
    if query_string:
        uri_path += "?%s" % query_string
    return uri_path


def get_cluster_version(cluster):
    """Return major/minor version #"""
    # Get control-cluster nodes
    uri = "/ws.v1/control-cluster/node?_page_length=1&fields=uuid"
    try:
        res = do_single_request(HTTP_GET, uri, cluster=cluster)
        res = json.loads(res)
    except NvpApiClient.NvpApiException:
        raise exception.QuantumException()
    if res["result_count"] == 0:
        return None
    node_uuid = res["results"][0]["uuid"]
    # Get control-cluster node status.  It's unsupported to have controllers
    # running different version so we just need the first node version.
    uri = "/ws.v1/control-cluster/node/%s/status" % node_uuid
    try:
        res = do_single_request(HTTP_GET, uri, cluster=cluster)
        res = json.loads(res)
    except NvpApiClient.NvpApiException:
        raise exception.QuantumException()
    version_parts = res["version"].split(".")
    version = "%s.%s" % tuple(version_parts[:2])
    LOG.info("NVP controller cluster version: %s" % version)
    return version


def get_all_query_pages(path, c):
    need_more_results = True
    result_list = []
    page_cursor = None
    query_marker = "&" if (path.find("?") != -1) else "?"
    while need_more_results:
        page_cursor_str = (
            "_page_cursor=%s" % page_cursor if page_cursor else "")
        res = do_single_request(HTTP_GET, "%s%s%s" %
                                (path, query_marker, page_cursor_str),
                                cluster=c)
        body = json.loads(res)
        page_cursor = body.get('page_cursor')
        if not page_cursor:
            need_more_results = False
        result_list.extend(body['results'])
    return result_list


def do_single_request(*args, **kwargs):
    """Issue a request to a specified cluster if specified via kwargs
       (cluster=<cluster>)."""
    cluster = kwargs["cluster"]
    return cluster.api_client.request(*args)


def do_multi_request(*args, **kwargs):
    """Issue a request to all clusters"""
    results = []
    clusters = kwargs["clusters"]
    for x in clusters:
        LOG.debug("Issuing request to cluster: %s" % x.name)
        rv = x.api_client.request(*args)
        results.append(rv)
    return results


# -------------------------------------------------------------------
# Network functions
# -------------------------------------------------------------------
def find_port_and_cluster(clusters, port_id):
    """Return (url, cluster_id) of port or (None, None) if port does not exist.
    """
    for c in clusters:
        query = "/ws.v1/lswitch/*/lport?uuid=%s&fields=*" % port_id
        LOG.debug("Looking for lswitch with port id \"%s\" on: %s"
                  % (port_id, c))
        try:
            res = do_single_request('GET', query, cluster=c)
        except Exception as e:
            LOG.error("get_port_cluster_and_url, exception: %s" % str(e))
            continue
        res = json.loads(res)
        if len(res["results"]) == 1:
            return (res["results"][0], c)
    return (None, None)


def find_lswitch_by_portid(clusters, port_id):
    port, cluster = find_port_and_cluster(clusters, port_id)
    if port and cluster:
        href = port["_href"].split('/')
        return (href[3], cluster)
    return (None, None)


def get_lswitches(cluster, quantum_net_id):
    lswitch_uri_path = _build_uri_path(LSWITCH_RESOURCE, quantum_net_id,
                                       relations="LogicalSwitchStatus")
    results = []
    try:
        resp_obj = do_single_request(HTTP_GET,
                                     lswitch_uri_path,
                                     cluster=cluster)
        ls = json.loads(resp_obj)
        results.append(ls)
        for tag in ls['tags']:
            if (tag['scope'] == "quantum_multi_lswitch" and
                tag['tag'] == "True"):
                # Fetch extra logical switches
                extra_lswitch_uri_path = _build_uri_path(
                    LSWITCH_RESOURCE,
                    fields="uuid,display_name,tags,lport_count",
                    relations="LogicalSwitchStatus",
                    filters={'tag': quantum_net_id,
                             'tag_scope': 'quantum_net_id'})
                extra_switches = get_all_query_pages(extra_lswitch_uri_path,
                                                     cluster)
                results.extend(extra_switches)
        return results
    except NvpApiClient.NvpApiException:
        # TODO(salvatore-olrando): Do a better exception handling
        # and re-raising
        LOG.exception("An error occured while fetching logical switches "
                      "for Quantum network %s", quantum_net_id)
        raise exception.QuantumException()


def create_lswitch(cluster, tenant_id, display_name,
                   transport_type=None,
                   transport_zone_uuid=None,
                   vlan_id=None,
                   quantum_net_id=None,
                   **kwargs):

    transport_zone_config = {"zone_uuid": (transport_zone_uuid or
                                           cluster.default_tz_uuid),
                             "transport_type": (transport_type or
                                                DEF_TRANSPORT_TYPE)}
    lswitch_obj = {"display_name": display_name,
                   "transport_zones": [transport_zone_config],
                   "tags": [{"tag": tenant_id, "scope": "os_tid"}]}
    if transport_type == 'bridge' and vlan_id:
        transport_zone_config["binding_config"] = {"vlan_translation":
                                                   [{"transport": vlan_id}]}
    if quantum_net_id:
        lswitch_obj["tags"].append({"tag": quantum_net_id,
                                    "scope": "quantum_net_id"})
    if "tags" in kwargs:
        lswitch_obj["tags"].extend(kwargs["tags"])
    uri = _build_uri_path(LSWITCH_RESOURCE)
    try:
        lswitch_res = do_single_request(HTTP_POST, uri,
                                        json.dumps(lswitch_obj),
                                        cluster=cluster)
    except NvpApiClient.NvpApiException:
        raise exception.QuantumException()
    lswitch = json.loads(lswitch_res)
    LOG.debug("Created logical switch: %s" % lswitch['uuid'])
    return lswitch


def update_lswitch(cluster, lswitch, display_name, tenant_id=None, **kwargs):
    uri = _build_uri_path(LSWITCH_RESOURCE, resource_id=lswitch)
    # TODO(salvatore-orlando): Make sure this operation does not remove
    # any other important tag set on the lswtich object
    lswitch_obj = {"display_name": display_name,
                   "tags": [{"tag": tenant_id, "scope": "os_tid"}]}
    if "tags" in kwargs:
        lswitch_obj["tags"].extend(kwargs["tags"])
    try:
        resp_obj = do_single_request("PUT", uri, json.dumps(lswitch_obj),
                                     cluster=cluster)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Network not found, Error: %s" % str(e))
        raise exception.NetworkNotFound(net_id=lswitch)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()

    obj = json.loads(resp_obj)
    return obj


def get_all_networks(cluster, tenant_id, networks):
    """Append the quantum network uuids we can find in the given cluster to
       "networks"
       """
    uri = "/ws.v1/lswitch?fields=*&tag=%s&tag_scope=os_tid" % tenant_id
    try:
        resp_obj = do_single_request("GET", uri, cluster=cluster)
    except NvpApiClient.NvpApiException:
        raise exception.QuantumException()
    if not resp_obj:
        return []
    networks_result = copy(networks)
    return networks_result


def query_networks(cluster, tenant_id, fields="*", tags=None):
    uri = "/ws.v1/lswitch?fields=%s" % fields
    if tags:
        for t in tags:
            uri += "&tag=%s&tag_scope=%s" % (t[0], t[1])
    try:
        resp_obj = do_single_request("GET", uri, cluster=cluster)
    except NvpApiClient.NvpApiException:
        raise exception.QuantumException()
    if not resp_obj:
        return []
    lswitches = json.loads(resp_obj)["results"]
    nets = [{'net-id': lswitch["uuid"], 'net-name': lswitch["display_name"]}
            for lswitch in lswitches]
    return nets


def delete_network(cluster, net_id, lswitch_id):
    delete_networks(cluster, net_id, [lswitch_id])


def delete_networks(cluster, net_id, lswitch_ids):
    if net_id in _net_type_cache:
        del _net_type_cache[net_id]
    for ls_id in lswitch_ids:
        path = "/ws.v1/lswitch/%s" % ls_id

        try:
            do_single_request("DELETE", path, cluster=cluster)
        except NvpApiClient.ResourceNotFound as e:
            LOG.error("Network not found, Error: %s" % str(e))
            raise exception.NetworkNotFound(net_id=ls_id)
        except NvpApiClient.NvpApiException as e:
            raise exception.QuantumException()


def query_ports(cluster, network, relations=None, fields="*", filters=None):
    uri = "/ws.v1/lswitch/" + network + "/lport?"
    if relations:
        uri += "relations=%s" % relations
    uri += "&fields=%s" % fields
    if filters and "attachment" in filters:
        uri += "&attachment_vif_uuid=%s" % filters["attachment"]
    try:
        resp_obj = do_single_request("GET", uri, cluster=cluster)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Network not found, Error: %s" % str(e))
        raise exception.NetworkNotFound(net_id=network)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()
    return json.loads(resp_obj)["results"]


def delete_port(cluster, switch, port):
    uri = "/ws.v1/lswitch/" + switch + "/lport/" + port
    try:
        do_single_request("DELETE", uri, cluster=cluster)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Port or Network not found, Error: %s" % str(e))
        raise exception.PortNotFound(port_id=port['uuid'])
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()


def get_logical_port_status(cluster, switch, port):
    query = ("/ws.v1/lswitch/" + switch + "/lport/"
             + port + "?relations=LogicalPortStatus")
    try:
        res_obj = do_single_request('GET', query, cluster=cluster)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Port or Network not found, Error: %s" % str(e))
        raise exception.PortNotFound(port_id=port, net_id=switch)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()
    res = json.loads(res_obj)
    # copy over admin_status_enabled
    res["_relations"]["LogicalPortStatus"]["admin_status_enabled"] = (
        res["admin_status_enabled"])
    return res["_relations"]["LogicalPortStatus"]


def get_port_by_display_name(clusters, lswitch, display_name):
    """Return (url, cluster_id) of port or raises ResourceNotFound
    """
    query = ("/ws.v1/lswitch/%s/lport?display_name=%s&fields=*" %
             (lswitch, display_name))
    LOG.debug("Looking for port with display_name \"%s\" on: %s"
              % (display_name, lswitch))
    for c in clusters:
        try:
            res_obj = do_single_request('GET', query, cluster=c)
        except Exception:
            continue
        res = json.loads(res_obj)
        if len(res["results"]) == 1:
            return (res["results"][0], c)

    LOG.error("Port or Network not found, Error: %s" % str(e))
    raise exception.PortNotFound(port_id=display_name, net_id=lswitch)


def get_port(cluster, network, port, relations=None):
    LOG.info("get_port() %s %s" % (network, port))
    uri = "/ws.v1/lswitch/" + network + "/lport/" + port + "?"
    if relations:
        uri += "relations=%s" % relations
    try:
        resp_obj = do_single_request("GET", uri, cluster=cluster)
        port = json.loads(resp_obj)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Port or Network not found, Error: %s" % str(e))
        raise exception.PortNotFound(port_id=port, net_id=network)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()
    return port


def _configure_extensions(lport_obj, port_data):
    if 'security_profiles' in port_data:
        lport_obj["security_profiles"] = port_data.get('security_profiles')
    # Port Security (MAC)
    lport_obj["allowed_address_pairs"] = []
    if port_data["port_security"] == "mac_ip":
        for fixed_ip in port_data["fixed_ips"]:
            ip_address = fixed_ip.get("ip_address")
            if ip_address:
                lport_obj["allowed_address_pairs"].append(
                    {"mac_address": port_data["mac_address"],
                     "ip_address": fixed_ip["ip_address"]})
        # add address pair allowing src_ip 0.0.0.0 to leave
        # this is required for outgoing dhcp request
        lport_obj["allowed_address_pairs"].append(
            {"mac_address": port_data["mac_address"],
             "ip_address": "0.0.0.0"})

    # Port Security (mac/ip)
    elif port_data.get("port_security") == "mac":
        lport_obj["allowed_address_pairs"].append(
            {"mac_address": port_data["mac_address"]})


def update_port(network, port_id, **params):
    cluster = params["cluster"]
    lport_obj = {}

    admin_state_up = params['port'].get('admin_state_up')
    device_id = params['port'].get('device_id')
    name = params["port"].get("name")
    if admin_state_up:
        lport_obj["admin_status_enabled"] = admin_state_up
    if name:
        lport_obj["display_name"] = name

    if device_id:
        # device_id can be longer than 40 so we rehash it
        device_id = hashlib.sha1(device_id).hexdigest()
        lport_obj["tags"] = (
            [dict(scope='os_tid', tag=params["port"].get("tenant_id")),
             dict(scope='q_port_id', tag=params["port"]["id"]),
             dict(scope='vm_id', tag=device_id)])

    port_data = {'id': params["port"]["id"],
                 'mac_address': params["port"]["mac_address"],
                 'fixed_ips': params["port"]["fixed_ips"],
                 'device_id': params["port"]["device_id"],
                 'port_security': params["port"].get("port_security")}
    if 'security_groups' in params["port"]:
        security_groups = params["port"].get(ext_sg.SECURITYGROUP)
        if security_groups:
            port_data['security_profiles'] = security_groups
        else:
            port_data['security_profiles'] = []

    _configure_extensions(lport_obj, port_data)
    uri = "/ws.v1/lswitch/" + network + "/lport/" + port_id
    try:
        resp_obj = do_single_request("PUT", uri, json.dumps(lport_obj),
                                     cluster=cluster)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Port or Network not found, Error: %s" % str(e))
        raise exception.PortNotFound(port_id=port_id, net_id=network)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()

    obj = json.loads(resp_obj)
    obj["port-op-status"] = get_port_status(cluster, network, obj["uuid"])
    return obj


def create_lport(cluster, lswitch_uuid, tenant_id, quantum_port_id,
                 display_name, device_id, admin_status_enabled,
                 mac_address=None, fixed_ips=None, port_security=None,
                 security_profiles=None):
    """ Creates a logical port on the assigned logical switch """
    # device_id can be longer than 40 so we rehash it
    hashed_device_id = hashlib.sha1(device_id).hexdigest()
    lport_obj = dict(
        admin_status_enabled=admin_status_enabled,
        display_name=display_name,
        tags=[dict(scope='os_tid', tag=tenant_id),
              dict(scope='q_port_id', tag=quantum_port_id),
              dict(scope='vm_id', tag=hashed_device_id)],
    )
    port_data = {'id': quantum_port_id,
                 'mac_address': mac_address,
                 'fixed_ips': fixed_ips,
                 'device_id': device_id,
                 'port_security': port_security}
    if security_profiles:
        port_data['security_profiles'] = security_profiles
    _configure_extensions(lport_obj, port_data)
    path = _build_uri_path(LPORT_RESOURCE, parent_resource_id=lswitch_uuid)
    try:
        resp_obj = do_single_request("POST", path,
                                     json.dumps(lport_obj),
                                     cluster=cluster)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Logical switch not found, Error: %s" % str(e))
        raise

    result = json.loads(resp_obj)
    LOG.debug("Created logical port %s on logical swtich %s"
              % (result['uuid'], lswitch_uuid))
    return result


def get_port_status(cluster, lswitch_id, port_id):
    """Retrieve the operational status of the port"""
    try:
        r = do_single_request("GET",
                              "/ws.v1/lswitch/%s/lport/%s/status" %
                              (lswitch_id, port_id), cluster=cluster)
        r = json.loads(r)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Port not found, Error: %s" % str(e))
        raise exception.PortNotFound(port_id=port_id, net_id=lswitch_id)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()
    if r['link_status_up'] is True:
        return constants.PORT_STATUS_ACTIVE
    else:
        return constants.PORT_STATUS_DOWN


def plug_interface(cluster, lswitch_id, port, type, attachment=None):
    uri = "/ws.v1/lswitch/" + lswitch_id + "/lport/" + port + "/attachment"
    lport_obj = {}
    if attachment:
        lport_obj["vif_uuid"] = attachment

    lport_obj["type"] = type
    try:
        resp_obj = do_single_request("PUT", uri, json.dumps(lport_obj),
                                     cluster=cluster)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Port or Network not found, Error: %s" % str(e))
        raise exception.PortNotFound(port_id=port, net_id=lswitch_id)
    except NvpApiClient.Conflict as e:
        LOG.error("Conflict while making attachment to port, "
                  "Error: %s" % str(e))
        raise exception.AlreadyAttached(att_id=attachment,
                                        port_id=port,
                                        net_id=lswitch_id,
                                        att_port_id="UNKNOWN")
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()

    result = json.dumps(resp_obj)
    return result

#------------------------------------------------------------------------------
# Security Profile convenience functions.
#------------------------------------------------------------------------------
EXT_SECURITY_PROFILE_ID_SCOPE = 'nova_spid'
TENANT_ID_SCOPE = 'os_tid'


def format_exception(etype, e, locals_, request=None):
    """Consistent formatting for exceptions.
    :param etype: a string describing the exception type.
    :param e: the exception.
    :param request: the request object.
    :param locals_: calling context local variable dict.
    :returns: a formatted string.
    """
    msg = ["Error. %s exception: %s." % (etype, e)]
    if request:
        msg.append("request=[%s]" % request)
        if request.body:
            msg.append("request.body=[%s]" % str(request.body))
    l = dict(locals_)
    if "request" in l:
        l.pop("request")
    msg.append("locals=[%s]" % str(l))
    return ' '.join(msg)


def do_request(*args, **kwargs):
    """Convenience function wraps do_single_request.

    :param args: a list of positional arguments.
    :param kwargs: a list of keyworkds arguments.
    :returns: the result of do_single_request loaded into a python object
        or None."""
    res = do_single_request(*args, **kwargs)
    if res:
        return json.loads(res)
    return res


def mk_body(**kwargs):
    """Convenience function creates and dumps dictionary to string.

    :param kwargs: the key/value pirs to be dumped into a json string.
    :returns: a json string."""
    return unicode(json.dumps(dict(**kwargs)))


def set_tenant_id_tag(tenant_id, taglist=None):
    """Convenience function to add tenant_id tag to taglist.

    :param tenant_id: the tenant_id to set.
    :param taglist: the taglist to append to (or None).
    :returns: a new taglist that includes the old taglist with the new
        tenant_id tag set."""
    new_taglist = []
    if taglist:
        new_taglist = [x for x in taglist if x['scope'] != TENANT_ID_SCOPE]
    new_taglist.append(dict(scope=TENANT_ID_SCOPE, tag=tenant_id))
    return new_taglist


def set_ext_security_profile_id_tag(external_id, taglist=None):
    """Convenience function to add spid tag to taglist.

    :param external_id: the security_profile id from nova
    :param taglist: the taglist to append to (or None).
    :returns: a new taglist that includes the old taglist with the new
        spid tag set."""
    new_taglist = []
    if taglist:
        new_taglist = [x for x in taglist if x['scope'] !=
                       EXT_SECURITY_PROFILE_ID_SCOPE]
    if external_id:
        new_taglist.append(dict(scope=EXT_SECURITY_PROFILE_ID_SCOPE,
                                tag=str(external_id)))
    return new_taglist


# -----------------------------------------------------------------------------
# Security Group API Calls
# -----------------------------------------------------------------------------


def create_security_profile(cluster, tenant_id, security_profile):
    path = "/ws.v1/security-profile"
    tags = set_tenant_id_tag(tenant_id)
    tags = set_ext_security_profile_id_tag(
        security_profile.get('external_id'), tags)
    # Allow all dhcp responses in
    dhcp = {'logical_port_egress_rules': [{'ethertype': 'IPv4',
                                           'protocol': 17,
                                           'port_range_min': 68,
                                           'port_range_max': 68,
                                           'ip_prefix': '0.0.0.0/0'}],
            'logical_port_ingress_rules': []}
    try:
        body = mk_body(
            tags=tags, display_name=security_profile.get('name'),
            logical_port_ingress_rules=dhcp['logical_port_ingress_rules'],
            logical_port_egress_rules=dhcp['logical_port_egress_rules'])
        rsp = do_request("POST", path, body, cluster=cluster)
    except NvpApiClient.NvpApiException as e:
        LOG.error(format_exception("Unknown", e, locals()))
        raise exception.QuantumException()
    if security_profile.get('name') == 'default':
        # If if security group is default allow ip traffic between
        # members of the same security profile.
        rules = {'logical_port_egress_rules': [{'ethertype': 'IPv4',
                                                'profile_uuid': rsp['uuid']},
                                               {'ethertype': 'IPv6',
                                                'profile_uuid': rsp['uuid']}],
                 'logical_port_ingress_rules': []}

        update_security_group_rules(cluster, rsp['uuid'], rules)
    LOG.debug("Created Security Profile: %s" % rsp)
    return rsp


def update_security_group_rules(cluster, spid, rules):
    path = "/ws.v1/security-profile/%s" % spid

    # Allow all dhcp responses in
    rules['logical_port_egress_rules'].append({'ethertype': 'IPv4',
                                               'protocol': 17,
                                               'port_range_min': 68,
                                               'port_range_max': 68,
                                               'ip_prefix': '0.0.0.0/0'})
    try:
        body = mk_body(
            logical_port_ingress_rules=rules['logical_port_ingress_rules'],
            logical_port_egress_rules=rules['logical_port_egress_rules'])
        rsp = do_request("PUT", path, body, cluster=cluster)
    except NvpApiClient.NvpApiException as e:
        LOG.error(format_exception("Unknown", e, locals()))
        raise exception.QuantumException()
    LOG.debug("Updated Security Profile: %s" % rsp)
    return rsp


def delete_security_profile(cluster, spid):
    path = "/ws.v1/security-profile/%s" % spid

    try:
        do_request("DELETE", path, cluster=cluster)
    except NvpApiClient.NvpApiException as e:
        LOG.error(format_exception("Unknown", e, locals()))
        raise exception.QuantumException()
