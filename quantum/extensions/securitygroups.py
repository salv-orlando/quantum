"""
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Nicira Networks, Inc.  All rights reserved.
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
# @author: Dave Lapsley, Nicira Networks, Inc
#

This module implements Quantum Security Group Extensions.

These extensions expose security group functionality in underlying quantum
plugins. The API is a superset of the current Nova/EC2 security group API.

The following shows the mappings between the extension controller handler
functions and URLs/Operations.

index()
    GET
    /v1.1/extensions/sg/tenants/{tenant_id}/securitygroups
show()
    GET
    /v1.1/extensions/sg/tenants/{tenant_id}/securitygroups/{securitygroup_id}
create()
    POST
    /v1.1/extensions/sg/tenants/{tenant_id}/securitygroups
delete()
    DELETE
    /v1.1/extensions/sg/tenants/{tenant_id}/securitygroups/{securitygroup_id}
list_for_port()
    GET
    /v1.1/extensions/sg/tenants/{tenant_id}/securitygroups/list_for_port
associate_port()
    PUT
    /v1.1/extensions/sg/tenants/{tenant_id}/securitygroups/{securitygroup_id}
    /associate_port
dissociate_port()
    PUT
    /v1.1/extensions/sg/tenants/{tenant_id}/securitygroups/{securitygroup_id}
    /dissociate_port
"""
import logging
from webob import exc
from quantum import wsgi
from quantum.extensions import _securitygroups as securitygroups_view
from quantum.extensions import extensions
from quantum.manager import QuantumManager
from quantum.common import exceptions as qexceptions

from nicira_nvp_plugin.extensions.faults import Quantum11HTTPError
from nicira_nvp_plugin.extensions import exceptions


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
    LOG = logging.getLogger('quantum.api.securitygroups')


EXT_ID_SEPARATOR = ':'
EXT_ID_PREFIX = 'ext'


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


def extract_security_group_id(sgid):
    """Extract security group id from externally supplied URI.
    :param id: the security group id.
    :returns: a tuple (ext_sgid, sgid). ext_sgid is a boolean
        indicating if this is an externally generated sgid. sgid is
        the security group id to use."""
    fields = sgid.split(EXT_ID_SEPARATOR)
    if (len(fields) == 2) and (str(fields[0]) == EXT_ID_PREFIX):
        return True, str(fields[1])
    return False, str(sgid)


class Securitygroups(object):
    """Securitygroup extension file"""
    def __init__(self):
        pass

    @classmethod
    def get_name(cls):
        """ Returns Ext Resource Name """
        return "securitygroups"

    @classmethod
    def get_alias(cls):
        """ Returns Ext Resource Alias """
        return "securitygroups"

    @classmethod
    def get_description(cls):
        """ Returns Ext Resource Description """
        return "The security groups extension."

    @classmethod
    def get_namespace(cls):
        """ Returns Ext Resource Namespace """
        return "http://docs.openstack.org/ext/securitygroups/api/v1.1"

    @classmethod
    def get_updated(cls):
        """ Returns Ext Resource update """
        return "2012-03-07T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """ Returns Ext Resources """
        parent_resource = dict(member_name="tenant",
                               collection_name="extensions/sg/tenants")

        controller = SecurityGroupController(QuantumManager.get_plugin())
        m_actions = {'associate_port': 'PUT', 'dissociate_port': 'PUT',
                     'update': 'PUT'}
        c_actions = {'list_for_port': 'PUT'}
        return [extensions.ResourceExtension(
            'securitygroups', controller, collection_actions=c_actions,
            member_actions=m_actions, parent=parent_resource)]

    @classmethod
    def check_plugin_config(cls, plugin):
        if plugin.get_num_clusters() != 1:
            LOG.info("Invalid number of clusters. Aborting securitygroups.")
            return False
        return True


# Note on Security Group Identifiers.
#
# The ext_sgid parameter is set in the body of incoming requests
# if Quantum and its plugin are using externally generated Security
# Group IDs. If the ext_sgid parameter is not set, then it is assumed
# Quantum is generating the Security Group IDs. The security group
# extension only looks for the "ext_sgid" key in the request body.
# It does not care about the value of the key.
EXT_SGID_KEY = 'ext_sgid'


class SecurityGroupController(wsgi.Controller):
    """SecurityGroup API controller (based on quantum WSGI controller."""

    _items_param_list = [
        {'param-name': 'ext_sgid', 'required': False, 'default-value': None},
    ]

    _create_param_list = [
        {'param-name': 'ext_sgid', 'required': False, 'default-value': None},
        {'param-name': 'id', 'required': False},
        {'param-name': 'name', 'required': True},
        {'param-name': 'ports', 'required': False, 'default-value': []},
        {'param-name': 'securityrules', 'required': False,
         'default-value': []},
    ]

    _update_param_list = [
        {'param-name': 'ext_sgid', 'required': False, 'default-value': None},
        {'param-name': 'name', 'required': True},
        {'param-name': 'ports', 'required': False, 'default-value': []},
        {'param-name': 'securityrules', 'required': False,
         'default-value': []},
    ]

    _list_for_port_param_list = [
        {'param-name': 'ext_sgid', 'required': False, 'default-value': None},
        {'param-name': 'port', 'required': False},
    ]

    _associate_port_param_list = [
        {'param-name': 'id', 'required': True},
    ]

    _dissociate_port_param_list = [
        {'param-name': 'id', 'required': True},
    ]

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
                    "id", "direction", "ip_prefix",
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

    def __init__(self, plugin):
        super(SecurityGroupController, self).__init__()

        self._resource_name = 'securitygroups'
        self._plugin = plugin

    def _serialize(self, data, content_type, default_xmlns):
        """Serialize the given dict to the provided content_type.

        Uses self._serialization_metadata if it exists, which is a dict mapping
        MIME types to information needed to serialize to that type."""
        _metadata = getattr(type(self), '_serialization_metadata', {})
        serializer = wsgi.SecurityGroupSerializer(_metadata, default_xmlns)
        try:
            return serializer.serialize(data, content_type)
        except qexceptions.InvalidContentType:
            raise exc.HTTPNotAcceptable()

    def _deserialize(self, data, content_type):
        """Deserialize the request body to the specefied content type.

        Uses self._serialization_metadata if it exists, which is a dict mapping
        MIME types to information needed to serialize to that type.

        """
        _metadata = getattr(type(self), '_serialization_metadata', {})
        serializer = wsgi.SecurityGroupSerializer(_metadata)
        return serializer.deserialize(data, content_type)

    def _extract_request_body(self, request, resource_name, params):
        """ verifies required parameters are in request body.
            sets default value for missing optional parameters.

            body argument must be the deserialized body
        """
        LOG.debug(str(locals()))
        try:
            body = request.body
            if body is None:
                # Initialize empty resource for setting default value
                body = {resource_name: {}}
            else:
                body = self._deserialize(body,
                                         request.best_match_content_type())
            data = body[resource_name]
        except KeyError:
            # raise if _resource_name is not in req body.
            raise exc.HTTPBadRequest("Unable to find '%s' in request body"
                                     % resource_name)
        for param in params:
            param_name = param['param-name']
            param_value = data.get(param_name)
            # If the parameter wasn't found and it was required, return 400
            if param_value is None and param['required']:
                msg = ("Failed to parse request. Parameter: %s not specified"
                       % param_name)
                LOG.error(msg)
                raise exc.HTTPBadRequest(msg)
            data[param_name] = param_value or param.get('default-value')
        return data

    def index(self, request, tenant_id):
        """Process the List Security Groups API call.

        List Security Groups ids configured in Quantum for the tenant
        identified by tenant_id.

        URI: GET /v1.1/extensions/sg/tenants/{tenant_id}/securitygroups

        :param request: incoming request object.
        :param tenant_id: id of this tenant.
        :raises: Unauthorized(401), Forbidden(403)
        :returns: list of security group ids for this tenant. For example:
            <securitygroups>
                <securitygroup id="8bec1293-16bd-4568-ba75-1f58bec0b4c3"/>
                <securitygroup id="2a39409c-7146-4501-8429-3579e03e9b56"/>
            </securitygroups>"""
        LOG.debug(str(locals()))
        return self._items(request, tenant_id, is_detail=False)

    def _items(self, request, tenant_id, port_id=None, is_detail=False):
        """Returns a list of security group identifiers for the tenant
        and port (if specified).

        :param request: incoming request object.
        :param tenant_id: id of this tenant.
        :param port_id: id of port.
        :param is_detail: boolean indicating whether or not to return
            detailed records.
        :returns: list of security group ids for this tenant. For example:
            <securitygroups>
                <securitygroup id="8bec1293-16bd-4568-ba75-1f58bec0b4c3"/>
                <securitygroup id="2a39409c-7146-4501-8429-3579e03e9b56"/>
            </securitygroups>"""
        LOG.debug(str(locals()))
        ext_sgid = False
        if request.GET.get('ext_sgid'):
            ext_sgid = True

        try:
            securitygroups = self._plugin.get_security_groups(tenant_id,
                                                              port_id,
                                                              ext_sgid)
            builder = securitygroups_view.get_view_builder(request)
            result = [builder.build(securitygroup, is_detail)
                      for securitygroup in securitygroups]
            return dict(securitygroups=result)
        except Exception as e:
            LOG.error(format_exception("Unknown", e, locals(), request))
            return Quantum11HTTPError(e)

    # pylint: disable-msg=E1101
    def show(self, request, tenant_id, id):
        """Process the Show Security Group Detail API call.

        Show detailed information for a specific security group, identified by
        securitygroup_id, for a given tenant, identified by tenant_id.

        URI: GET /v1.1/extensions/sg/tenants/{tenant_id}/securitygroups
                    /{securitygroup_id}

        :param request: incoming request object.
        :param tenant_id: id of this tenant.
        :param id: id of the security group.
        :raises: Unauthorized(401), Forbidden(403), SecurityGroupNotFound()
        :returns: summary of security group identified by securitygroup_id for
            tenant identified by tenant_id. For example:

            <securitygroup
               id="8bec1293-16bd-4568-ba75-1f58bec0b4c3"
               name="test_security_group">
               <securityrules>
                  <securityrule id="134e16bd-4568-ba75-1f58bec0b4c3"
                     ip_prefix="1.1.1.1/32"
                     direction="ingress"
                     ethertype="IPv4"
                     protocol="17"
                     port_range_min="0"
                     port_range_max="1000"
                   />
                  <securityrule id="1642316d-4568-ba75-1f58bec0b4c3"
                     ip_prefix="2.1.1.1/32"
                     direction="egress"
                     ethertype="IPv4"
                     protocol="6"
                     port_range_min="0"
                     port_range_max="1000"
                   />
               </securityrules>
               <ports>
                  <port id="98017ddc-efc8-4c25-a915-774b2a633855"/>
                  <port id="b832be00-6553-4f69-af33-acd554e36d08"/>
               <ports>
            </securitygroup>"""
        LOG.debug(str(locals()))

        try:
            ext_sgid, id = extract_security_group_id(id)
            securitygroup = self._plugin.get_security_group_details(
                tenant_id, id, ext_sgid)
            builder = securitygroups_view.get_view_builder(request)
            return builder.build(securitygroup, True)
        except exceptions.SecurityGroupNotFound as e:
            LOG.error(format_exception("SecurityGroupNotFound", e, locals(),
                                       request))
            return Quantum11HTTPError(e)
        except Exception as e:
            LOG.error(format_exception("Unknown", e, locals(), request))
            return Quantum11HTTPError(e)

    def create(self, request, tenant_id):
        """Process the Create Security Group API call.

        Create a new security group for the tenant identified by tenant_id.

        URI: POST /v1.1/extensions/sg/tenants/{tenant_id}/securitygroups

        :param request: incoming request object.
        :param tenant_id: id of this tenant.
        :raises: Bad Request(400), Unauthorized(401), Forbidden(403)
        :returns: security group id. For example:
            <securitygroup
                id="9bec1293-16bd-4568-ba75-1f58bec0b4c3"
            />"""
        LOG.debug(str(locals()))
        params = self._extract_request_body(
            request, 'securitygroup', type(self)._create_param_list)

        # Marshal keyword args.
        kwargs = dict(
            name=params['name'],
            securityrules=params['securityrules'],
            ports=params['ports'])

        ext_sgid = (params.get('ext_sgid') is not None)
        if ext_sgid:
            kwargs['id'] = params['id']

        try:
            # Create the security group.
            securitygroup = self._plugin.create_security_group(
                tenant_id, ext_sgid, **kwargs)

            builder = securitygroups_view.get_view_builder(request)
            result = builder.build(securitygroup, True)
            LOG.debug('create() result: %s' % result)
            return result
        except exc.HTTPError as e:
            LOG.error(format_exception("Unknown", e, locals(), request))
            return Quantum11HTTPError(e)

    def update(self, request, tenant_id, id):
        """Process the Update Security Group API call.

        Update a security group for the tenant identified by tenant_id.

        URI: PUT /v1.1/extensions/sg/tenants/{tenant_id}/securitygroups

        :param request: incoming request object.
        :param tenant_id: id of this tenant.
        :param id: id of the security group.
        :raises: Bad Request(400), Unauthorized(401), Forbidden(403)
            SecurityGroupNotFound()
        :returns: security group id. For example:
            <securitygroup
                id="8bec1293-16bd-4568-ba75-1f58bec0b4c3"
            />"""
        ext_sgid, id = extract_security_group_id(id)
        params = self._extract_request_body(
            request, 'securitygroup', type(self)._update_param_list)

        # Marshal keyword args.
        kwargs = dict(
            name=params['name'],
            securityrules=params['securityrules'],
            ports=params['ports'])

        LOG.debug(str(locals()))
        try:
            securitygroup = self._plugin.update_security_group(
                tenant_id, id, ext_sgid, **kwargs)
            builder = securitygroups_view.get_view_builder(request)
            result = builder.build(securitygroup, True)
            LOG.info('Result from plugin: %s' % result)
            return result
        except Exception as e:
            LOG.error(format_exception("Unknown", e, locals(), request))
            return Quantum11HTTPError(e)

    def delete(self, request, tenant_id, id):
        """Process the Delete Security Group API call.

        Destroys the security group (and associated rules) identified by
        securitygroup_id for the tenant identified by tenant_id.

        URI: DELETE /v1.1/extensions/sg/tenants/{tenant_id}/securitygroups
                        /{securitygroup_id}

        :param request: incoming request object.
        :param tenant_id: id of this tenant.
        :param id: id of the security group to be deleted.
        :raises: Bad Request(400), Unauthorized(401), Forbidden(403),
            SecurityGroupNotFound(), SecurityGroupInUse().
        :returns: Nothing."""
        LOG.debug(str(locals()))
        try:
            # Are we using externally generated IDs?
            ext_sgid, id = extract_security_group_id(id)
            self._plugin.delete_security_group(tenant_id, id, ext_sgid)
        except exceptions.SecurityGroupNotFound as e:
            return Quantum11HTTPError(e)
        except exceptions.SecurityGroupInUse as e:
            return Quantum11HTTPError(e)

    def list_for_port(self, request, tenant_id):
        """Process the List Security Groups for Port API call.

        Returns a list of identifiers of the security groups associated with
        the port specified in the request body, for the tenant identified by
        tenant_id.

        URI: GET /v1.1/extensions/sa/tenants/{tenant_id}/securitygroups
                    /listforport

        :param request: incoming request object.
        :param tenant_id: id of this tenant.
        :raises: Bad Request(400), Unauthorized(401), Forbidden(403),
            PortNotFound(430), SecurityGroupNotFound().
        :returns: a list of securitygroup ids. For example:
            <securitygroups>
               <securitygroup id="158233b0-ca9a-40b4-8614-54a4a99d47d1"/>
               <securitygroup id="b832be00-6553-4f69-af33-acd554e36d08"/>
            </securitygroups>"""
        ext_sgid = False
        if request.GET.get('ext_sgid'):
            ext_sgid = True
        port_id = request.GET.get('port_id')

        return self._items(request, tenant_id, port_id, is_detail=False)

    def associate_port(self, request, tenant_id, id):
        """Process the Associate Port with Security Group API call.

        Associates the port specified in the request body with the security
        group identified by id, for the tenant identified by tenant_id.

        URI: PUT /v1.1/extensions/sg/tenants/{tenant_id}/securitygroups
                    /{securitygroup_id}/associate_port

        :param request: incoming request object.
        :param tenant_id: id of this tenant.
        :param id: id of the securitygroup to be associated.
        :raises: Bad Request(400), Unauthorized(401), Forbidden(403),
            PortNotFound(430), SecurityGroupNotFound(),
            SecurityAssocationExists().
        :returns: Nothing."""
        LOG.debug(str(locals()))
        ext_sgid, id = extract_security_group_id(id)
        params = self._extract_request_body(request, 'port',
            type(self)._associate_port_param_list)
        port_id = params['id']

        try:
            self._plugin.associate_port_security_group(tenant_id, id, port_id,
                                                       ext_sgid)
        except qexceptions.PortNotFound as e:
            LOG.error(format_exception("PortNotFound", e, locals(), request))
            return Quantum11HTTPError(e)
        except exceptions.SecurityGroupNotFound as e:
            LOG.error(format_exception("SecurityGroupNotFound", e, locals(),
                                       request))
            return Quantum11HTTPError(e)
        except exceptions.SecurityAssociationExists as e:
            LOG.error(format_exception("SecurityAssociationExists", e,
                                       locals(), request))
            return Quantum11HTTPError(e)

    def dissociate_port(self, request, tenant_id, id):
        """Process the Dissociate Port from Security Group API call.

        Dissociates the port specified in the request body from the security
        group identified by securitygroup_id, for the tenant identified by
        tenant_id.

        URI: DELETE /v1.1/extensions/sg/tenants/{tenant_id}/securitygroups
                        /{securitygroup_id}/dissociate_port

        :param tenant_id: id of this tenant.
        :param id: id of the securitygroup to be associated.
        :raises: Bad Request(400), Unauthorized(401), Forbidden(403),
            PortNotFound(430), SecurityGroupNotFound(),
            NoSecurityAssocationExists().
        :returns: Nothing."""
        LOG.debug(str(locals()))
        ext_sgid, id = extract_security_group_id(id)
        params = self._extract_request_body(
            request, 'port', type(self)._dissociate_port_param_list)
        port_id = params['id']

        try:
            self._plugin.dissociate_port_security_group(tenant_id, id,
                                                        port_id, ext_sgid)
        except qexceptions.PortNotFound as e:
            LOG.error(format_exception("SecurityAssociationExists", e,
                                       locals(), request))
            return Quantum11HTTPError(e)
        except exceptions.SecurityGroupNotFound as e:
            LOG.error(format_exception("SecurityAssociationExists", e,
                                       locals(), request))
            return Quantum11HTTPError(e)
        except exceptions.NoSecurityAssociationExists as e:
            LOG.error(format_exception("SecurityAssociationExists", e,
                                       locals(), request))
            return Quantum11HTTPError(e)
