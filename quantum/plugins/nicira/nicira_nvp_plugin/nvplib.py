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
import json
import hashlib
import logging

import NvpApiClient

#FIXME(danwent): I'd like this file to get to the point where it has
# no quantum-specific logic in it
from quantum.common import constants
from quantum.common import exceptions as exception
from quantum.extensions import securitygroup as ext_sg
from quantum.plugins.nicira.nicira_nvp_plugin.common import (
    exceptions as nvp_exc)

VERSION = '2012.2'
# HTTP METHODS CONSTANTS
HTTP_GET = "GET"
HTTP_POST = "POST"
# Default transport type for logical switches
DEF_TRANSPORT_TYPE = "stt"
# Prefix to be used for all NVP API calls
URI_PREFIX = "/ws.v1"
# Resources exposed by NVP API
LSWITCH_RESOURCE = "lswitch"
LSWITCHPORT_RESOURCE = "lport/%s" % LSWITCH_RESOURCE
LROUTER_RESOURCE = "lrouter"
LQUEUE_RESOURCE = "lqueue"
LROUTERPORT_RESOURCE = "lport/%s" % LROUTER_RESOURCE
LROUTERNAT_RESOURCE = "nat/lrouter"
GWSERVICE_RESOURCE = "gateway-service"

# Constants for NAT rules
MATCH_KEYS = ["destination_ip_addresses", "destination_port_max",
              "destination_port_min", "source_ip_addresses",
              "source_port_max", "source_port_min", "protocol"]

SNAT_KEYS = ["to_src_port_min", "to_src_port_max", "to_src_ip_min",
             "to_src_ip_max"]

DNAT_KEYS = ["to_dst_port", "to_dst_ip_min", "to_dst_ip_max"]


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
                    relations=None,
                    filters=None,
                    types=None,
                    is_attachment=False):
    resources = resource.split('/')
    res_path = resources[0] + (resource_id and "/%s" % resource_id or '')
    if len(resources) > 1:
        # There is also a parent resource to account for in the uri
        res_path = "%s/%s/%s" % (resources[1],
                                 parent_resource_id,
                                 res_path)
    if is_attachment:
        res_path = "%s/attachment" % res_path
    params = []
    params.append(fields and "fields=%s" % fields)
    params.append(relations and "relations=%s" % relations)
    params.append(types and "types=%s" % types)
    if filters:
        params.extend(['%s=%s' % (k, v) for (k, v) in filters.iteritems()])
    uri_path = "%s/%s" % (URI_PREFIX, res_path)
    non_empty_params = [x for x in params if x is not None]
    if len(non_empty_params):
        query_string = reduce(lambda x, y: "%s&%s" % (x, y),
                              non_empty_params)
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
            if (tag.get('scope') == "quantum_multi_lswitch" and
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
                   "tags": [{"tag": tenant_id, "scope": "os_tid"},
                            {"scope": "quantum", 'tag': VERSION}]}
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
    lswitch_obj = {"display_name": display_name}
    tags = kwargs.get('tags', [])
    if tenant_id:
        tags.append({"tag": tenant_id, "scope": "os_tid"})
    if tags:
        lswitch_obj['tags'] = tags

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


def create_l2_gw_service(cluster, tenant_id, display_name, devices):
    """ Create a NVP Layer-2 Network Gateway Service.

        :param cluster: The target NVP cluster
        :param tenant_id: Identifier of the Openstack tenant for which
        the gateway service.
        :param display_name: Descriptive name of this gateway service
        :param devices: List of transport node uuids (and network
        interfaces on them) to use for the network gateway service
        :raise NvpApiException: if there is a problem while communicating
        with the NVP controller
    """
    tags = [{"tag": tenant_id, "scope": "os_tid"},
            {"tag": VERSION, "scope": "quantum"}]
    # NOTE(salvatore-orlando): This is a little confusing, but device_id in
    # NVP is actually the identifier a physical interface on the gateway
    # device, which in the Quantum API is referred as interface_name
    gateways = [{"transport_node_uuid": device['id'],
                 "device_id": device['interface_name'],
                 "type": "L2Gateway"} for device in devices]
    gwservice_obj = {
        "display_name": display_name,
        "tags": tags,
        "gateways": gateways,
        "type": "L2GatewayServiceConfig"
    }
    try:
        return json.loads(do_single_request(
            "POST", _build_uri_path(GWSERVICE_RESOURCE),
            json.dumps(gwservice_obj), cluster=cluster))
    except NvpApiClient.NvpApiException:
        # just log and re-raise - let the caller handle it
        LOG.exception("An exception occured while communicating with "
                      "the NVP controller for cluster:%s", cluster.name)
        raise


def create_lrouter(cluster, tenant_id, display_name, nexthop):
    """ Create a NVP logical router on the specified cluster.

        :param cluster: The target NVP cluster
        :param tenant_id: Identifier of the Openstack tenant for which
        the logical router is being created
        :param display_name: Descriptive name of this logical router
        :param nexthop: External gateway IP address for the logical router
        :raise NvpApiException: if there is a problem while communicating
        with the NVP controller
    """
    tags = [{"tag": tenant_id, "scope": "os_tid", "tag": "quantum"}]
    lrouter_obj = {
        "display_name": display_name,
        "tags": tags,
        "routing_config": {
            "default_route_next_hop": {
                "gateway_ip_address": nexthop,
                "type": "RouterNextHop"
            },
            "type": "SingleDefaultRouteImplicitRoutingConfig"
        },
        "type": "LogicalRouterConfig"
    }
    try:
        return json.loads(do_single_request("POST",
                                            _build_uri_path(LROUTER_RESOURCE),
                                            json.dumps(lrouter_obj),
                                            cluster=cluster))
    except NvpApiClient.NvpApiException:
        # just log and re-raise - let the caller handle it
        LOG.exception("An exception occured while communicating with "
                      "the NVP controller for cluster:%s", cluster.name)
        raise


def delete_lrouter(cluster, lrouter_id):
    try:
        do_single_request("DELETE",
                          _build_uri_path(LROUTER_RESOURCE,
                                          resource_id=lrouter_id),
                          cluster=cluster)
    except NvpApiClient.NvpApiException:
        # just log and re-raise - let the caller handle it
        LOG.exception("An exception occured while communicating with "
                      "the NVP controller for cluster:%s", cluster.name)
        raise


def delete_l2_gw_service(cluster, gateway_id):
    try:
        do_single_request("DELETE",
                          _build_uri_path(GWSERVICE_RESOURCE,
                                          resource_id=gateway_id),
                          cluster=cluster)
    except NvpApiClient.NvpApiException:
        # just log and re-raise - let the caller handle it
        LOG.exception("An exception occured while communicating with "
                      "the NVP controller for cluster:%s", cluster.name)
        raise


def get_lrouter(cluster, lrouter_id):
    try:
        return json.loads(do_single_request("GET",
                          _build_uri_path(LROUTER_RESOURCE,
                                          resource_id=lrouter_id,
                                          relations='LogicalRouterStatus'),
                          cluster=cluster))
    except NvpApiClient.NvpApiException:
        # just log and re-raise - let the caller handle it
        LOG.exception("An exception occured while communicating with "
                      "the NVP controller for cluster:%s", cluster.name)
        raise


def get_l2_gw_service(cluster, gateway_id):
    try:
        return json.loads(do_single_request("GET",
                          _build_uri_path(GWSERVICE_RESOURCE,
                                          resource_id=gateway_id),
                          cluster=cluster))
    except NvpApiClient.NvpApiException:
        # just log and re-raise - let the caller handle it
        LOG.exception("An exception occured while communicating with "
                      "the NVP controller for cluster:%s", cluster.name)
        raise


def get_lrouters(cluster, tenant_id, fields=None, filters=None):
    actual_filters = {}
    if filters:
        actual_filters.update(filters)
    if tenant_id:
        actual_filters['tag'] = tenant_id
        actual_filters['tag_scope'] = 'os_tid'
    lrouter_fields = "uuid,display_name,fabric_status,tags"
    return get_all_query_pages(
        _build_uri_path(LROUTER_RESOURCE,
                        fields=lrouter_fields,
                        relations='LogicalRouterStatus',
                        filters=actual_filters),
        cluster)


def get_l2_gw_services(cluster, tenant_id=None,
                       fields=None, filters=None):
    actual_filters = {}
    if filters:
        actual_filters.update(filters)
    if tenant_id:
        actual_filters['tag'] = tenant_id
        actual_filters['tag_scope'] = 'os_tid'
    return get_all_query_pages(
        _build_uri_path(GWSERVICE_RESOURCE,
                        filters=actual_filters),
        cluster)


def update_l2_gw_service(cluster, gateway_id, display_name):
    # TODO(salvatore-orlando): Allow updates for gateways too
    gwservice_obj = get_l2_gw_service(cluster, gateway_id)
    if not display_name:
        # Nothing to update
        return gwservice_obj
    gwservice_obj["display_name"] = (display_name or
                                     gwservice_obj["display_name"])
    try:
        return json.loads(do_single_request("PUT",
                          _build_uri_path(GWSERVICE_RESOURCE,
                                          resource_id=gateway_id),
                          json.dumps(gwservice_obj),
                          cluster=cluster))
    except NvpApiClient.NvpApiException:
        # just log and re-raise - let the caller handle it
        LOG.exception("An exception occured while communicating with "
                      "the NVP controller for cluster:%s", cluster.name)
        raise


def update_lrouter(cluster, lrouter_id, display_name, nexthop):
    lrouter_obj = get_lrouter(cluster, lrouter_id)
    if not display_name and not nexthop:
        # Nothing to update
        return lrouter_obj
    # It seems that this is faster than the doing an if on display_name
    lrouter_obj["display_name"] = display_name or lrouter_obj["display_name"]
    if nexthop:
        nh_element = lrouter_obj["routing_config"].get(
            "default_route_next_hop")
        if nh_element:
            nh_element["gateway_ip_address"] = nexthop
    try:
        return json.loads(do_single_request("PUT",
                          _build_uri_path(LROUTER_RESOURCE,
                                          resource_id=lrouter_id),
                          json.dumps(lrouter_obj),
                          cluster=cluster))
    except NvpApiClient.NvpApiException:
        # just log and re-raise - let the caller handle it
        LOG.exception("An exception occured while communicating with "
                      "the NVP controller for cluster:%s", cluster.name)
        raise


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


def query_lswitch_lports(cluster, ls_uuid, fields="*",
                         filters=None, relations=None):
    # Fix filter for attachments
    if filters and "attachment" in filters:
        filters['attachment_vif_uuid'] = filters["attachment"]
        del filters['attachment']
    uri = _build_uri_path(LSWITCHPORT_RESOURCE, parent_resource_id=ls_uuid,
                          fields=fields, filters=filters, relations=relations)
    try:
        resp_obj = do_single_request("GET", uri, cluster=cluster)
    except NvpApiClient.ResourceNotFound:
        LOG.exception("Logical switch: %s not found", ls_uuid)
        raise
    except NvpApiClient.NvpApiException:
        LOG.exception("An error occured while querying logical ports on "
                      "the NVP platfom")
        raise
    return json.loads(resp_obj)["results"]


def query_lrouter_lports(cluster, lr_uuid, fields="*",
                         filters=None, relations=None):
    uri = _build_uri_path(LROUTERPORT_RESOURCE, parent_resource_id=lr_uuid,
                          fields=fields, filters=filters, relations=relations)
    try:
        resp_obj = do_single_request("GET", uri, cluster=cluster)
    except NvpApiClient.ResourceNotFound:
        LOG.exception("Logical router: %s not found", lr_uuid)
        raise
    except NvpApiClient.NvpApiException:
        LOG.exception("An error occured while querying logical router "
                      "ports on the NVP platfom")
        raise
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

    LOG.error("Port or Network not found")
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


def _configure_extensions(lport_obj, port_data, do_port_security=True):
    if 'security_profiles' in port_data:
        lport_obj["security_profiles"] = port_data.get('security_profiles')

    if not do_port_security:
        return
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

    # Qos
    if 'queue_id' in port_data:
        lport_obj['queue_uuid'] = port_data.get('queue_id')


def update_port(network, port_id, **params):
    cluster = params["cluster"]
    lport_obj = {}

    device_id = params['port'].get('device_id')
    name = params["port"].get("name")
    if 'admin_state_up' in params['port']:
        lport_obj["admin_status_enabled"] = (
            params['port'].get('admin_state_up'))

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

    if params['port'].get('queue_id'):
        port_data['queue_id'] = params['port']['queue_id']

    _configure_extensions(lport_obj, port_data,
                          params.get('do_port_security', True))
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
                 security_profiles=None, queue_id=None, do_port_security=True):
    """ Creates a logical port on the assigned logical switch """
    # device_id can be longer than 40 so we rehash it
    hashed_device_id = hashlib.sha1(device_id).hexdigest()
    lport_obj = dict(
        admin_status_enabled=admin_status_enabled,
        display_name=display_name,
        tags=[dict(scope='os_tid', tag=tenant_id),
              dict(scope='q_port_id', tag=quantum_port_id),
              dict(scope='vm_id', tag=hashed_device_id),
              dict(scope='quantum', tag=VERSION)]
    )
    port_data = {'id': quantum_port_id,
                 'mac_address': mac_address,
                 'fixed_ips': fixed_ips,
                 'device_id': device_id,
                 'port_security': port_security}
    if security_profiles:
        port_data['security_profiles'] = security_profiles
    if queue_id:
        port_data['queue_id'] = queue_id

    _configure_extensions(lport_obj, port_data, do_port_security)
    path = _build_uri_path(LSWITCHPORT_RESOURCE,
                           parent_resource_id=lswitch_uuid)
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


def create_router_lport(cluster, lrouter_uuid, tenant_id, quantum_port_id,
                        display_name, admin_status_enabled, ip_addresses):
    """ Creates a logical port on the assigned logical router """
    tags = [dict(scope='os_tid', tag=tenant_id),
            dict(scope='q_port_id', tag=quantum_port_id),
            dict(scope='quantum', tag=VERSION)]
    lport_obj = dict(
        admin_status_enabled=admin_status_enabled,
        display_name=display_name,
        tags=tags,
        ip_addresses=ip_addresses,
        type="LogicalRouterPortConfig"
    )
    path = _build_uri_path(LROUTERPORT_RESOURCE,
                           parent_resource_id=lrouter_uuid)
    try:
        resp_obj = do_single_request("POST", path,
                                     json.dumps(lport_obj),
                                     cluster=cluster)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Logical router not found, Error: %s" % str(e))
        raise

    result = json.loads(resp_obj)
    LOG.debug("Created logical port %s on logical router %s"
              % (result['uuid'], lrouter_uuid))
    return result


def update_router_lport(cluster, lrouter_uuid, lrouter_port_uuid,
                        tenant_id, quantum_port_id, display_name,
                        admin_status_enabled, ip_addresses):
    """ Updates a logical port on the assigned logical router """
    lport_obj = dict(
        admin_status_enabled=admin_status_enabled,
        display_name=display_name,
        tags=[dict(scope='os_tid', tag=tenant_id),
              dict(scope='q_port_id', tag=quantum_port_id),
              dict(scope='quantum', tag=VERSION)],
        ip_addresses=ip_addresses,
        type="LogicalRouterPortConfig"
    )
    # Do not pass null items to NVP
    for key in lport_obj.keys():
        if lport_obj[key] is None:
            del lport_obj[key]
    path = _build_uri_path(LROUTERPORT_RESOURCE,
                           lrouter_port_uuid,
                           parent_resource_id=lrouter_uuid)
    try:
        resp_obj = do_single_request("PUT", path,
                                     json.dumps(lport_obj),
                                     cluster=cluster)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Logical router or router port not found, "
                  "Error: %s" % str(e))
        raise

    result = json.loads(resp_obj)
    LOG.debug("Updated logical port %s on logical router %s"
              % (lrouter_port_uuid, lrouter_uuid))
    return result


def delete_router_lport(cluster, lrouter_uuid, lport_uuid):
    """ Creates a logical port on the assigned logical router """
    path = _build_uri_path(LROUTERPORT_RESOURCE, lport_uuid, lrouter_uuid)
    try:
        do_single_request("DELETE", path, cluster=cluster)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Logical router not found, Error: %s" % str(e))
        raise
    LOG.debug("Delete logical router port %s on logical router %s"
              % (lport_uuid, lrouter_uuid))


def delete_peer_router_lport(cluster, lr_uuid, ls_uuid, lp_uuid):
    nvp_port = get_port(cluster, ls_uuid, lp_uuid,
                        relations="LogicalPortAttachment")
    try:
        relations = nvp_port.get('_relations')
        if relations:
            att_data = relations.get('LogicalPortAttachment')
            if att_data:
                lrp_uuid = att_data.get('peer_port_uuid')
                if lrp_uuid:
                    delete_router_lport(cluster, lr_uuid, lrp_uuid)
    except (NvpApiClient.NvpApiException, NvpApiClient.ResourceNotFound):
        LOG.exception(_("Unable to fetch and delete peer logical "
                        "router port for logical switch port:%s"),
                      lp_uuid)
        raise


def find_router_gw_port(context, cluster, router_id):
    """ Retrieves the external gateway port for a NVP logical router """

    # Find the uuid of nvp ext gw logical router port
    # TODO(salvatore-orlando): Consider storing it in Quantum DB
    results = query_lrouter_lports(
        cluster, router_id,
        filters={'attachment_gwsvc_uuid': cluster.default_l3_gw_uuid})
    if len(results):
        # Return logical router port
        return results[0]


def plug_router_port_attachment(cluster, router_id, port_id,
                                attachment_uuid, nvp_attachment_type):
    """Attach a router port to the given attachment.
       Current attachment types:
       - PatchAttachment [-> logical switch port uuid]
       - L3GatewayAttachment [-> L3GatewayService uuid]
    """
    uri = _build_uri_path(LROUTERPORT_RESOURCE, port_id, router_id,
                          is_attachment=True)
    attach_obj = {}
    attach_obj["type"] = nvp_attachment_type
    if nvp_attachment_type == "PatchAttachment":
        attach_obj["peer_port_uuid"] = attachment_uuid
    elif nvp_attachment_type == "L3GatewayAttachment":
        attach_obj["l3_gateway_service_uuid"] = attachment_uuid
    else:
        raise Exception("Invalid NVP attachment type '%s'" %
                        nvp_attachment_type)
    try:
        resp_obj = do_single_request(
            "PUT", uri, json.dumps(attach_obj), cluster=cluster)
    except NvpApiClient.ResourceNotFound as e:
        LOG.exception("Router Port not found, Error: %s" % str(e))
        raise
    except NvpApiClient.Conflict as e:
        LOG.exception("Conflict while setting router port attachment")
        raise
    except NvpApiClient.NvpApiException as e:
        LOG.exception("Unable to plug attachment into logical router port")
        raise
    result = json.loads(resp_obj)
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


def _plug_interface(cluster, lswitch_id, lport_id, att_obj):
    uri = _build_uri_path(LSWITCHPORT_RESOURCE, lport_id, lswitch_id,
                          is_attachment=True)
    try:
        resp_obj = do_single_request("PUT", uri, json.dumps(att_obj),
                                     cluster=cluster)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Port or Network not found, Error: %s" % str(e))
        raise exception.PortNotFound(port_id=lport_id, net_id=lswitch_id)
    except NvpApiClient.Conflict as e:
        LOG.error("Conflict while plugging attachment into port, "
                  "Error: %s" % str(e))
        raise exception.AlreadyAttached(port_id=lport_id,
                                        net_id=lswitch_id,
                                        att_port_id="UNKNOWN")
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()

    result = json.dumps(resp_obj)
    return result


def plug_l2_gw_service(cluster, lswitch_id, lport_id,
                       gateway_id, vlan_id=None):
    """ Plug a Layer-2 Gateway Attachment object in a logical port """
    att_obj = {'type': 'L2GatewayAttachment',
               'l2_gateway_service_uuid': gateway_id}
    if vlan_id:
        att_obj['vlan_id'] = vlan_id
    return _plug_interface(cluster, lswitch_id, lport_id, att_obj)


def plug_interface(cluster, lswitch_id, port, type, attachment=None):
    """ Plug a VIF Attachment object in a logical port """
    lport_obj = {}
    if attachment:
        lport_obj["vif_uuid"] = attachment

    lport_obj["type"] = type
    return _plug_interface(cluster, lswitch_id, port, lport_obj)

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
    tags.append({'scope': 'quantum', 'tag': VERSION})
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


def _create_nat_match_obj(**kwargs):
    nat_match_obj = {"ethertype": "IPv4"}
    for k, v in kwargs.items():
        if k in MATCH_KEYS:
            nat_match_obj[k] = v
            del kwargs[k]
    if kwargs:
        raise Exception("invalid keys for NAT match: %(kwargs)s" % locals())
    return nat_match_obj


def _create_lrouter_nat_rule(cluster, router_id, nat_rule_obj):
    LOG.debug("Creating NAT rule: %s" % nat_rule_obj)
    uri = _build_uri_path(LROUTERNAT_RESOURCE, parent_resource_id=router_id)
    try:
        resp = do_single_request("POST", uri, json.dumps(nat_rule_obj),
                                 cluster=cluster)
    except NvpApiClient.ResourceNotFound:
        LOG.exception("NVP Logical Router %s not found", router_id)
        raise
    except NvpApiClient.NvpApiException:
        LOG.exception("An error occurred while creating the NAT rule "
                      "on the NVP platform")
        raise
    rule = json.loads(resp)
    return rule


def create_lrouter_snat_rule(cluster, router_id,
                             min_src_ip, max_src_ip, **kwargs):

    nat_match_obj = _create_nat_match_obj(**kwargs)
    nat_rule_obj = {
        "to_source_ip_address_min": min_src_ip,
        "to_source_ip_address_max": max_src_ip,
        "type": "SourceNatRule",
        "match": nat_match_obj
    }
    return _create_lrouter_nat_rule(cluster, router_id, nat_rule_obj)


def create_lrouter_dnat_rule(cluster, router_id, to_min_dst_ip,
                             to_max_dst_ip, to_dst_port=None, **kwargs):

    nat_match_obj = _create_nat_match_obj(**kwargs)
    nat_rule_obj = {
        "to_destination_ip_address_min": to_min_dst_ip,
        "to_destination_ip_address_max": to_max_dst_ip,
        "type": "DestinationNatRule",
        "match": nat_match_obj
    }
    if to_dst_port:
        nat_rule_obj['to_destination_port'] = to_dst_port
    return _create_lrouter_nat_rule(cluster, router_id, nat_rule_obj)


def delete_nat_rules_by_match(cluster, router_id, rule_type,
                              max_num_expected,
                              min_num_expected=0,
                              **kwargs):
    # remove nat rules
    nat_rules = query_nat_rules(cluster, router_id)
    to_delete_ids = []
    for r in nat_rules:
        if (r['type'] != rule_type):
            continue

        is_match = True
        for key, value in kwargs.iteritems():
            if not (key in r['match'] and r['match'][key] == value):
                is_match = False
                break
        if is_match:
            to_delete_ids.append(r['uuid'])
    if not (len(to_delete_ids) in
            range(min_num_expected, max_num_expected + 1)):
        raise nvp_exc.NvpNatRuleMismatch(actual_rules=len(to_delete_ids),
                                         min_rules=min_num_expected,
                                         max_rules=max_num_expected)

    for rule_id in to_delete_ids:
        delete_router_nat_rule(cluster, router_id, rule_id)


def delete_router_nat_rule(cluster, router_id, rule_id):
    uri = _build_uri_path(LROUTERNAT_RESOURCE, rule_id, router_id)
    try:
        do_single_request("DELETE", uri, cluster=cluster)
    except NvpApiClient.NvpApiException:
        LOG.exception("An error occurred while removing NAT rule %s "
                      "for logical router %s", rule_id, router_id)
        raise


def get_router_nat_rule(cluster, tenant_id, router_id, rule_id):
    uri = _build_uri_path(LROUTERNAT_RESOURCE, rule_id, router_id)
    try:
        resp = do_single_request("GET", uri, cluster=cluster)
    except NvpApiClient.ResourceNotFound:
        LOG.exception("NAT rule %s not found", rule_id)
        raise
    except NvpApiClient.NvpApiException:
        LOG.exception("An error occured while retrieving NAT rule %s"
                      "from NVP platform", rule_id)
        raise
    res = json.loads(resp)
    return res


def query_nat_rules(cluster, router_id, fields="*", filters=None):
    uri = _build_uri_path(LROUTERNAT_RESOURCE, parent_resource_id=router_id,
                          fields=fields, filters=filters)
    try:
        resp = do_single_request("GET", uri, cluster=cluster)
    except NvpApiClient.ResourceNotFound:
        LOG.exception("NVP Logical Router %s not found", router_id)
        raise
    except NvpApiClient.NvpApiException:
        LOG.exception("An error occured while retrieving NAT rules for "
                      "NVP logical router %s", router_id)
        raise
    res = json.loads(resp)
    LOG.debug("NAT rules retrieved from router %s: %s", router_id, res)
    return res["results"]


# -----------------------------------------------------------------------------
# QOS API Calls
# -----------------------------------------------------------------------------

def create_lqueue(cluster, lqueue):
    uri = _build_uri_path(LQUEUE_RESOURCE)
    lqueue['tags'] = [{'tag': VERSION, 'scope': 'quantum'}]
    try:
        resp_obj = do_single_request("POST", uri, json.dumps(lqueue),
                                     cluster=cluster)
    except NvpApiClient.NvpApiException as e:
        LOG.error("Failed to create logical queue %s" % str(e))
        raise exception.QuantumException()
    return json.loads(resp_obj)['uuid']


def delete_lqueue(cluster, id):
    try:
        do_single_request("DELETE",
                          _build_uri_path(LQUEUE_RESOURCE,
                                          resource_id=id),
                          cluster=cluster)
    except Exception as e:
        LOG.error("Failed to delete logical queue %s" % str(e))
        raise exception.QuantumException()

# -----------------------------------------------------------------------------
# NVP Cluster API Calls
# -----------------------------------------------------------------------------


def check_cluster_connectivity(cluster):
    """Make sure that we can issue a request to each of the cluster nodes"""
    try:
        resp = do_single_request("GET", "/ws.v1/control-cluster",
                                 cluster=cluster)
    except Exception as e:
        msg = "Failed to connect to cluster %s: %s" % (cluster, str(e))
        raise Exception(msg)
    return json.loads(resp)
