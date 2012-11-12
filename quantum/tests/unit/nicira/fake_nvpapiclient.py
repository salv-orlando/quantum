# Copyright 2012 Nicira Networks, Inc.
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

import json
import logging
import urlparse
import uuid

LOG = logging.getLogger("fake_nvpapiclient")
LOG.setLevel(logging.DEBUG)


class FakeClient:

    LSWITCH_RESOURCE = 'lswitch'
    LPORT_RESOURCE = 'lport'
    LROUTER_RESOURCE = 'lrouter'
    SECPROF_RESOURCE = 'securityprofile'
    LSWITCH_STATUS = 'lswitchstatus'
    LROUTER_STATUS = 'lrouterstatus'
    LSWITCH_LPORT_RESOURCE = 'lswitch_lport'
    LROUTER_LPORT_RESOURCE = 'lrouter_lport'
    LSWITCH_LPORT_STATUS = 'lswitch_lportstatus'
    LSWITCH_LPORT_ATT = 'lswitch_lportattachment'
    LROUTER_LPORT_STATUS = 'lrouter_lportstatus'
    LROUTER_LPORT_ATT = 'lrouter_lportattachment'

    RESOURCES = [LSWITCH_RESOURCE, LROUTER_RESOURCE,
                 LPORT_RESOURCE, SECPROF_RESOURCE]

    FAKE_GET_RESPONSES = {
        LSWITCH_RESOURCE: "fake_get_lswitch.json",
        LSWITCH_LPORT_RESOURCE: "fake_get_lswitch_lport.json",
        LSWITCH_LPORT_STATUS: "fake_get_lswitch_lport_status.json",
        LSWITCH_LPORT_ATT: "fake_get_lswitch_lport_att.json",
        LROUTER_RESOURCE: "fake_get_lrouter.json",
        LROUTER_LPORT_RESOURCE: "fake_get_lrouter_lport.json",
        LROUTER_LPORT_STATUS: "fake_get_lrouter_lport_status.json",
        LROUTER_LPORT_ATT: "fake_get_lrouter_lport_att.json",
        LROUTER_STATUS: "fake_get_lrouter_status.json"
    }

    FAKE_POST_RESPONSES = {
        LSWITCH_RESOURCE: "fake_post_lswitch.json",
        LROUTER_RESOURCE: "fake_post_lrouter.json",
        LSWITCH_LPORT_RESOURCE: "fake_post_lswitch_lport.json",
        LROUTER_LPORT_RESOURCE: "fake_post_lrouter_lport.json",
        SECPROF_RESOURCE: "fake_post_security_profile.json"
    }

    FAKE_PUT_RESPONSES = {
        LSWITCH_RESOURCE: "fake_post_lswitch.json",
        LROUTER_RESOURCE: "fake_post_lrouter.json",
        LSWITCH_LPORT_RESOURCE: "fake_post_lswitch_lport.json",
        LROUTER_LPORT_RESOURCE: "fake_post_lrouter_lport.json",
        LSWITCH_LPORT_ATT: "fake_put_lswitch_lport_att.json",
        LROUTER_LPORT_ATT: "fake_put_lrouter_lport_att.json",
        SECPROF_RESOURCE: "fake_post_security_profile.json"
    }

    MANAGED_RELATIONS = {
        LSWITCH_RESOURCE: [],
        LROUTER_RESOURCE: [],
        LSWITCH_LPORT_RESOURCE: ['LogicalPortAttachment'],
        LROUTER_LPORT_RESOURCE: ['LogicalPortAttachment'],
    }

    _fake_lswitch_dict = {}
    _fake_lrouter_dict = {}
    _fake_lswitch_lport_dict = {}
    _fake_lrouter_lport_dict = {}
    _fake_lswitch_lportstatus_dict = {}
    _fake_lrouter_lportstatus_dict = {}
    _fake_securityprofile_dict = {}

    def __init__(self, fake_files_path):
        self.fake_files_path = fake_files_path

    def _get_tag(self, resource, scope):
        tags = [tag['tag'] for tag in resource['tags']
                if tag['scope'] == scope]
        return len(tags) > 0 and tags[0]

    def _get_filters(self, querystring):
        if not querystring:
            return (None, None)
        params = urlparse.parse_qs(querystring)
        tag_filter = None
        attr_filter = None
        if 'tag' in params and 'tag_scope' in params:
            tag_filter = {'scope': params['tag_scope'][0],
                          'tag': params['tag'][0]}
        elif 'uuid' in params:
            attr_filter = {'uuid': params['uuid'][0]}
        return (tag_filter, attr_filter)

    def _add_lswitch(self, body):
        fake_lswitch = json.loads(body)
        fake_lswitch['uuid'] = str(uuid.uuid4())
        self._fake_lswitch_dict[fake_lswitch['uuid']] = fake_lswitch
        # put the tenant_id and the zone_uuid in the main dict
        # for simplyfying templating
        zone_uuid = fake_lswitch['transport_zones'][0]['zone_uuid']
        fake_lswitch['zone_uuid'] = zone_uuid
        fake_lswitch['tenant_id'] = self._get_tag(fake_lswitch, 'os_tid')
        fake_lswitch['lport_count'] = 0
        return fake_lswitch

    def _add_lrouter(self, body):
        fake_lrouter = json.loads(body)
        fake_lrouter['uuid'] = str(uuid.uuid4())
        self._fake_lrouter_dict[fake_lrouter['uuid']] = fake_lrouter
        fake_lrouter['tenant_id'] = self._get_tag(fake_lrouter, 'os_tid')
        fake_lrouter['lport_count'] = 0
        default_nexthop = fake_lrouter['routing_config'].get(
            'default_route_next_hop')
        fake_lrouter['default_next_hop'] = default_nexthop.get(
            'gateway_ip_address', '0.0.0.0')
        return fake_lrouter

    def _add_lswitch_lport(self, body, ls_uuid):
        fake_lport = json.loads(body)
        new_uuid = str(uuid.uuid4())
        fake_lport['uuid'] = new_uuid
        # put the tenant_id and the ls_uuid in the main dict
        # for simplyfying templating
        fake_lport['ls_uuid'] = ls_uuid
        fake_lport['tenant_id'] = self._get_tag(fake_lport, 'os_tid')
        fake_lport['quantum_port_id'] = self._get_tag(fake_lport,
                                                      'q_port_id')
        fake_lport['quantum_device_id'] = self._get_tag(fake_lport, 'vm_id')
        self._fake_lswitch_lport_dict[fake_lport['uuid']] = fake_lport

        fake_lswitch = self._fake_lswitch_dict[ls_uuid]
        fake_lswitch['lport_count'] += 1
        fake_lport_status = fake_lport.copy()
        fake_lport_status['ls_tenant_id'] = fake_lswitch['tenant_id']
        fake_lport_status['ls_uuid'] = fake_lswitch['uuid']
        fake_lport_status['ls_name'] = fake_lswitch['display_name']
        fake_lport_status['ls_zone_uuid'] = fake_lswitch['zone_uuid']
        self._fake_lswitch_lportstatus_dict[new_uuid] = fake_lport_status
        return fake_lport

    def _add_lrouter_lport(self, body, lr_uuid):
        fake_lport = json.loads(body)
        new_uuid = str(uuid.uuid4())
        fake_lport['uuid'] = new_uuid
        # put the tenant_id and the ls_uuid in the main dict
        # for simplyfying templating
        fake_lport['lr_uuid'] = lr_uuid
        fake_lport['tenant_id'] = self._get_tag(fake_lport, 'os_tid')
        fake_lport['quantum_port_id'] = self._get_tag(fake_lport,
                                                      'q_port_id')
        # replace ip_address with its json dump
        if 'ip_addresses' in fake_lport:
            ip_addresses_json = json.dumps(fake_lport['ip_addresses'])
            fake_lport['ip_addresses'] = ip_addresses_json
            fake_lport['ip_addresses_json'] = json.dumps(
                fake_lport['ip_addresses'])
        self._fake_lrouter_lport_dict[fake_lport['uuid']] = fake_lport
        fake_lrouter = self._fake_lrouter_dict[lr_uuid]
        fake_lrouter['lport_count'] += 1
        fake_lport_status = fake_lport.copy()
        fake_lport_status['lr_tenant_id'] = fake_lrouter['tenant_id']
        fake_lport_status['lr_uuid'] = fake_lrouter['uuid']
        fake_lport_status['lr_name'] = fake_lrouter['display_name']
        self._fake_lrouter_lportstatus_dict[new_uuid] = fake_lport_status
        return fake_lport

    def _add_securityprofile(self, body):
        fake_securityprofile = json.loads(body)
        fake_securityprofile['uuid'] = str(uuid.uuid4())
        # put the tenant_id and the nova_spid in the main dict
        # for simplyfying templating
        fake_securityprofile['tenant_id'] = self._get_tag(
            fake_securityprofile, 'os_tid')

        fake_securityprofile['nova_spid'] = self._get_tag(fake_securityprofile,
                                                          'nova_spid')
        self._fake_securityprofile_dict[fake_securityprofile['uuid']] = (
            fake_securityprofile)
        return fake_securityprofile

    def _build_relation(self, src, dst, resource_type, relation):
        if not relation in self.MANAGED_RELATIONS[resource_type]:
            return  # Relation is not desired in output
        if not '_relations' in src or not src['_relations'].get(relation):
            return  # Item does not have relation
        relation_data = src['_relations'].get(relation)
        dst_relations = dst.get('_relations')
        if not dst_relations:
            dst_relations = {}
        dst_relations[relation] = relation_data

    def _fill_attachment(self, att_data, ls_uuid=None,
                         lr_uuid=None, lp_uuid=None):
        new_data = att_data.copy()
        for k in ('ls_uuid', 'lr_uuid', 'lp_uuid'):
            if locals().get(k):
                new_data[k] = locals()[k]

        def populate_field(field_name):
            if field_name in att_data:
                new_data['%s_field' % field_name] = ('"%s" : "%s",'
                                                     % (field_name,
                                                        att_data[field_name]))
                del new_data[field_name]
            else:
                new_data['%s_field' % field_name] = ""

        for field in ['vif_uuid', 'peer_port_href', 'peer_port_uuid']:
            populate_field(field)
        return new_data

    def _get_resource_type(self, path):
        """
        Identifies resource type and relevant uuids in the uri

        /ws.v1/lswitch/xxx
        /ws.v1/lswitch/xxx/status
        /ws.v1/lswitch/xxx/lport/yyy
        /ws.v1/lswitch/xxx/lport/yyy/status
        /ws.v1/lrouter/zzz
        /ws.v1/lrouter/zzz/status
        /ws.v1/lrouter/zzz/lport/www
        /ws.v1/lrouter/zzz/lport/www/status
        """
        # The first element will always be 'ws.v1' - so we just discard it
        uri_split = path.split('/')[1:]
        # parse uri_split backwaeds
        suffix = ""
        idx = len(uri_split) - 1
        if 'status' in uri_split[idx]:
            suffix = "status"
            idx = idx - 1
        elif 'attachment' in uri_split[idx]:
            suffix = "attachment"
            idx = idx - 1
        # then check if we have an uuid
        uuids = []
        if uri_split[idx].replace('-', '') not in self.RESOURCES:
            uuids.append(uri_split[idx])
            idx = idx - 1
        resource_type = "%s%s" % (uri_split[idx], suffix)
        if idx > 1:
            uuids.insert(0, uri_split[idx - 1])
            resource_type = "%s_%s" % (uri_split[idx - 2], resource_type)
        return (resource_type.replace('-', ''), uuids)

    def _list(self, resource_type, response_file,
              parent_uuid=None, query=None, relations=None):
        (tag_filter, attr_filter) = self._get_filters(query)
        with open("%s/%s" % (self.fake_files_path, response_file)) as f:
            response_template = f.read()
            res_dict = getattr(self, '_fake_%s_dict' % resource_type)
            if parent_uuid == "*":
                parent_uuid = None

            def _attr_match(res_uuid):
                if not attr_filter:
                    return True
                item = res_dict[res_uuid]
                for (attr, value) in attr_filter.iteritems():
                    if item.get(attr) != value:
                        return False
                return True

            def _tag_match(res_uuid):
                if not tag_filter:
                    return True
                return any([x['scope'] == tag_filter['scope'] and
                            x['tag'] == tag_filter['tag']
                            for x in res_dict[res_uuid]['tags']])

            def _lswitch_match(res_uuid):
                if (not parent_uuid or
                        res_dict[res_uuid].get('ls_uuid') == parent_uuid):
                    return True
                return False

            def _lrouter_match(res_uuid):
                if (not parent_uuid or
                        res_dict[res_uuid].get('lr_uuid') == parent_uuid):
                    return True
                return False

            def _build_item(resource):
                item = json.loads(response_template % resource)
                if relations:
                    for relation in relations:
                        self._build_relation(resource, item,
                                             resource_type, relation)
                return item

            for item in res_dict.itervalues():
                if 'tags' in item:
                    item['tags_json'] = json.dumps(item['tags'])
            if 'lswitch' in resource_type:
                parent_func = _lswitch_match
            else:
                parent_func = _lrouter_match
            items = [_build_item(res_dict[res_uuid])
                     for res_uuid in res_dict
                     if (parent_func(res_uuid) and
                         _tag_match(res_uuid) and
                         _attr_match(res_uuid))]

            return json.dumps({'results': items,
                               'result_count': len(items)})

    def _show(self, resource_type, response_file,
              uuid1, uuid2=None, relations=None):
        target_uuid = uuid2 or uuid1
        with open("%s/%s" % (self.fake_files_path, response_file)) as f:
            response_template = f.read()
            res_dict = getattr(self, '_fake_%s_dict' % resource_type)
            for item in res_dict.itervalues():
                if 'tags' in item:
                    item['tags_json'] = json.dumps(item['tags'])

            items = [json.loads(response_template % res_dict[res_uuid])
                     for res_uuid in res_dict if res_uuid == target_uuid]
            if items:
                return json.dumps(items[0])
            raise Exception("show: resource %s:%s not found" %
                            (resource_type, target_uuid))

    def handle_get(self, url):
        #TODO(salvatore-orlando): handle field selection
        parsedurl = urlparse.urlparse(url)
        (res_type, uuids) = self._get_resource_type(parsedurl.path)
        relations = urlparse.parse_qs(parsedurl.query).get('relations')
        response_file = self.FAKE_GET_RESPONSES.get(res_type)
        if not response_file:
            raise Exception("resource not found")
        if 'lport' in res_type:
            if len(uuids) > 1:
                return self._show(res_type, response_file, uuids[0],
                                  uuids[1], relations=relations)
            else:
                return self._list(res_type, response_file, uuids[0],
                                  query=parsedurl.query, relations=relations)
        elif 'lswitch' in res_type or 'lrouter' in res_type:
            if len(uuids) > 0:
                return self._show(res_type, response_file, uuids[0],
                                  relations=relations)
            else:
                return self._list(res_type, response_file,
                                  query=parsedurl.query,
                                  relations=relations)
        else:
            raise Exception("unknown resource:%s" % res_type)

    def handle_post(self, url, body):
        parsedurl = urlparse.urlparse(url)
        (res_type, uuids) = self._get_resource_type(parsedurl.path)
        response_file = self.FAKE_POST_RESPONSES.get(res_type)
        if not response_file:
            raise Exception("resource not found")
        with open("%s/%s" % (self.fake_files_path, response_file)) as f:
            response_template = f.read()
            add_resource = getattr(self, '_add_%s' % res_type)
            args = [body]
            if len(uuids):
                args.append(uuids[0])
            response = response_template % add_resource(*args)
            return response

    def handle_put(self, url, body):
        parsedurl = urlparse.urlparse(url)
        (res_type, uuids) = self._get_resource_type(parsedurl.path)
        response_file = self.FAKE_PUT_RESPONSES.get(res_type)
        if not response_file:
            raise Exception("resource not found")
        with open("%s/%s" % (self.fake_files_path, response_file)) as f:
            response_template = f.read()
            # Manage attachment operations
            is_attachment = False
            if res_type.endswith('attachment'):
                is_attachment = True
                res_type = res_type[:res_type.index('attachment')]
            res_dict = getattr(self, '_fake_%s_dict' % res_type)
            resource = res_dict[uuids[-1]]
            if not is_attachment:
                resource.update(json.loads(body))
            else:
                relations = resource.get("_relations")
                if not relations:
                    relations = {}
                relations['LogicalPortAttachment'] = json.loads(body)
                resource['_relations'] = relations
                body_2 = json.loads(body)
                if body_2['type'] == "PatchAttachment":
                    # We need to do a trick here
                    if self.LROUTER_RESOURCE in res_type:
                        res_type_2 = res_type.replace(self.LROUTER_RESOURCE,
                                                      self.LSWITCH_RESOURCE)
                    elif self.LSWITCH_RESOURCE in res_type:
                        res_type_2 = res_type.replace(self.LSWITCH_RESOURCE,
                                                      self.LROUTER_RESOURCE)
                    res_dict_2 = getattr(self, '_fake_%s_dict' % res_type_2)
                    body_2['peer_port_uuid'] = uuids[-1]
                    resource_2 = res_dict_2[json.loads(body)['peer_port_uuid']]
                    relations_2 = resource_2.get("_relations")
                    if not relations_2:
                        relations_2 = {}
                    relations_2['LogicalPortAttachment'] = body_2
                    resource_2['_relations'] = relations_2
                elif body_2['type'] == "L3GatewayAttachment":
                    resource['attachment_gwsvc_uuid'] = (
                        body_2['l3_gateway_service_uuid'])
            if not is_attachment:
                response = response_template % resource
            else:
                if res_type == self.LROUTER_LPORT_RESOURCE:
                    lr_uuid = uuids[0]
                    ls_uuid = None
                elif res_type == self.LSWITCH_LPORT_RESOURCE:
                    ls_uuid = uuids[0]
                    lr_uuid = None
                lp_uuid = uuids[1]
                response = response_template % self._fill_attachment(
                    json.loads(body), ls_uuid, lr_uuid, lp_uuid)
            return response

    def handle_delete(self, url):
        parsedurl = urlparse.urlparse(url)
        (res_type, uuids) = self._get_resource_type(parsedurl.path)
        response_file = self.FAKE_PUT_RESPONSES.get(res_type)
        if not response_file:
            raise Exception("resource not found")
        res_dict = getattr(self, '_fake_%s_dict' % res_type)
        del res_dict[uuids[-1]]
        return ""

    def fake_request(self, *args, **kwargs):
        method = args[0]
        handler = getattr(self, "handle_%s" % method.lower())
        return handler(*args[1:])

    def reset_all(self):
        self._fake_lswitch_dict.clear()
        self._fake_lrouter_dict.clear()
        self._fake_lswitch_lport_dict.clear()
        self._fake_lrouter_lport_dict.clear()
        self._fake_lswitch_lportstatus_dict.clear()
        self._fake_lrouter_lportstatus_dict.clear()
        self._fake_securityprofile_dict.clear()
