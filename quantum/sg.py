"""
# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Nicira Networks, Inc
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
#
# @author: Dave Lapsley, Nicira Networks, Inc
#
"""

"""Implement NVP Security Group Handler and API.

The nova security_group_handler flag needs to be set to this class
to enable it: quantum.sg.NvpSecurityGroupHandler."""

import httplib
import urllib
import socket
from nova.db import api as db
from nova.network.quantum import sg
from nova.network.quantum import client
from nova.network.quantum.client import api_call
from nova.openstack.common import cfg
from nova import log as logging
from nova import flags


LOG = logging.getLogger('nova.network.api.quantum.sg.nvp-plugin')
FLAGS = flags.FLAGS

# Useful constants.
DEFAULT_DIRECTION = "egress"
DEFAULT_ETHERTYPE = "IPv4"
DEFAULT_SG_NAME = "default"


# Mysql Security Group Schema
#
# mysql> describe security_groups;
# +-------------+--------------+------+-----+---------+----------------+
# | Field       | Type         | Null | Key | Default | Extra          |
# +-------------+--------------+------+-----+---------+----------------+
# | created_at  | datetime     | YES  |     | NULL    |                |
# | updated_at  | datetime     | YES  |     | NULL    |                |
# | deleted_at  | datetime     | YES  |     | NULL    |                |
# | deleted     | tinyint(1)   | YES  |     | NULL    |                |
# | id          | int(11)      | NO   | PRI | NULL    | auto_increment |
# | name        | varchar(255) | YES  |     | NULL    |                |
# | description | varchar(255) | YES  |     | NULL    |                |
# | user_id     | varchar(255) | YES  |     | NULL    |                |
# | project_id  | varchar(255) | YES  |     | NULL    |                |
# +-------------+--------------+------+-----+---------+----------------+
#
# mysql> describe security_group_rules;
# +-----------------+--------------+------+-----+---------+----------------+
# | Field           | Type         | Null | Key | Default | Extra          |
# +-----------------+--------------+------+-----+---------+----------------+
# | created_at      | datetime     | YES  |     | NULL    |                |
# | updated_at      | datetime     | YES  |     | NULL    |                |
# | deleted_at      | datetime     | YES  |     | NULL    |                |
# | deleted         | tinyint(1)   | YES  |     | NULL    |                |
# | id              | int(11)      | NO   | PRI | NULL    | auto_increment |
# | parent_group_id | int(11)      | YES  | MUL | NULL    |                |
# | protocol        | varchar(255) | YES  |     | NULL    |                |
# | from_port       | int(11)      | YES  |     | NULL    |                |
# | to_port         | int(11)      | YES  |     | NULL    |                |
# | cidr            | varchar(255) | YES  |     | NULL    |                |
# | group_id        | int(11)      | YES  | MUL | NULL    |                |
# +-----------------+--------------+------+-----+---------+----------------+

class NvpSecurityGroupQuantumClient(client.Client):

    action_prefix = "/v1.1/extensions/sg/tenants/{tenant_id}"

    """Action query strings"""
    securitygroups_path = "/securitygroups"
    securitygroup_path = "/securitygroups/ext:%s"
    listforport_path = "/securitygroups/list_for_port"
    associateport_path = "/securitygroups/ext:%s/associate_port"
    dissociateport_path = "/securitygroups/ext:%s/dissociate_port"

    # Placed in the body of each call to indicate external id generation.
    ext_sgid_key = 'ext_sgid'

    # Convenience variable.
    ext_sgid_body = '{ "%s": True }' % ext_sgid_key

    def __init__(self, *args, **kwargs):
        """Creates a new client to Quantum service.

        :param host: The host where service resides
        :param port: The port where service resides
        :param use_ssl: True to use SSL, False to use HTTP
        :param tenant: The tenant ID to make requests with
        :param format: The format to query the server with
        :param testing_stub: A class that stubs basic server methods for tests
        :param key_file: The SSL key file to use if use_ssl is true
        :param cert_file: The SSL cert file to use if use_ssl is true
        :param logger: logging object to be used by client library
        """
        super(NvpSecurityGroupQuantumClient, self).__init__(*args, **kwargs)

    # TODO(del): bug in parent class prevents clean inheritance.
    def do_request(self, method, action, body=None,
                   headers=None, params=None):
        """Connects to the server and issues a request.
        Returns the result data, or raises an appropriate exception if
        HTTP status code is not 2xx

        :param method: HTTP method ("GET", "POST", "PUT", etc...)
        :param body: string of data to send, or None (default)
        :param headers: mapping of key/value pairs to add as headers
        :param params: dictionary of key/value pairs to add to append
                             to action
        """
        # Ensure we have a tenant id
        if not self.tenant:
            raise Exception(_("Tenant ID not set"))

        # Add format and tenant_id
        action += ".%s" % self.format
        action = type(self).action_prefix + action
        action = action.replace('{tenant_id}', self.tenant)

        if isinstance(params, dict):
            action += '?' + urllib.urlencode(params)

        try:
            connection_type = self.get_connection_type()
            headers = headers or {"Content-Type":
                                  "application/%s" % self.format}

            # Open connection and send request, handling SSL certs
            certs = {'key_file': self.key_file, 'cert_file': self.cert_file}
            certs = dict((x, certs[x]) for x in certs if certs[x] is not None)

            if self.use_ssl and len(certs):
                c = connection_type(self.host, self.port, **certs)
            else:
                c = connection_type(self.host, self.port)

            if self.logger:
                self.logger.debug(
                    _("Quantum Client Request: %(method)s %(action)s" %
                                    locals()))
                if body:
                    self.logger.debug(body)

            c.request(method, action, body, headers)
            res = c.getresponse()
            status_code = self.get_status_code(res)
            data = res.read()

            if self.logger:
                self.logger.debug("Quantum Client Reply (code = %s) :\n %s" %
                                  (str(status_code), data))

            if status_code in client.NOT_FOUND_CODES:
                raise client.QuantumNotFoundException(
                    _("Quantum entity not found: %s" % data))

            if status_code in (httplib.OK,
                               httplib.CREATED,
                               httplib.ACCEPTED,
                               httplib.NO_CONTENT):
                if data is not None and len(data):
                    return self.deserialize(data, status_code)
            else:
                raise client.QuantumServerException(
                      _("Server %(status_code)s error: %(data)s"
                                        % locals()))

        except (socket.error, IOError), e:
            raise client.QuantumIOException(_("Unable to connect to "
                              "server. Got error: %s" % e))

    @api_call
    def list_security_groups(self, filter_ops=None, **kwargs):
        """Fetches a list of all securitygroups for a tenant"""
        body = self.serialize(dict(ext_sgid="True"))
        return self.do_request("GET", self.securitygroups_path,
                               body=body, params=filter_ops)

    @api_call
    def show_security_group_details(self, sg_id, **kwargs):
        """Fetches the details of a certain securitygroup"""
        return self.do_request("GET", self.securitygroup_path % sg_id,
                               body=self.ext_sgid_body)

    @api_call
    def create_security_group(self, body=None, **kwargs):
        """Creates a new securitygroup"""
        if not body:
            body = {}
        body['ext_sgid'] = "True"
        body = self.serialize(body)
        return self.do_request("POST", self.securitygroups_path, body=body)

    @api_call
    def update_security_group(self, sg_id, body=None, **kwargs):
        """Updates a securitygroup"""
        if not body:
            body = {}
        body['ext_sgid'] = "True"
        body = self.serialize(body)
        return self.do_request("PUT", self.securitygroup_path % sg_id,
                               body=body)

    @api_call
    def delete_security_group(self, sg_id, **kwargs):
        """Deletes the specified securitygroup"""
        return self.do_request("DELETE", self.securitygroup_path % sg_id)

    @api_call
    def list_for_port(self, port_id, **kwargs):
        """List all security groups for a particular port."""
        body = dict(ext_sgid="True", port=dict(id=port_id))
        body = self.serialize(body)
        return self.do_request("PUT", self.listforport_path, body=body)

    @api_call
    def associate_port(self, sg_id, port_id, **kwargs):
        """Associates security group with a port."""
        # TODO(del): default sg handling.
        if sg_id == 1:
            return
        body = dict(ext_sgid="True", port=dict(id=port_id))
        body = self.serialize(body)
        return self.do_request("PUT", self.associateport_path % sg_id,
                               body=body)

    @api_call
    def dissociate_port(self, sg_id, port_id, **kwargs):
        """Dissociates security group from a port."""
        body = dict(ext_sgid="True", port=dict(id=port_id))
        body = self.serialize(body)
        return self.do_request("PUT", self.dissociateport_path % sg_id,
                               body=body)


class NvpSecurityGroupHandler(sg.SecurityGroupHandlerBase):
    """Handle security group events from nova."""

    def __init__(self, client_=None, qclient=None):
        """Constructor.

        :param client: a pre-configured NVP client Security Group Extension
            client for use (most useful for testing).
        :param client: a pre-configured NVP client for use (most useful for
            testing)."""
        if not client_:
            try:
                host = FLAGS.quantum_connection_host
            except cfg.NoSuchOptError:
                host = '127.0.0.1'
            try:
                port = FLAGS.quantum_connection_port
            except cfg.NoSuchOptError:
                port = 9696
            self.client = NvpSecurityGroupQuantumClient(
                host, port, format="json", logger=LOG)
        else:
            self.client = client_

        if not qclient:
            self.qclient = client.Client(host, port, format="json", logger=LOG)
        else:
            self.qclient = qclient

    def get_port_by_attachment(self, tenant_id, net_id, attachment_id):
        """Given a tenant and network, search for the port UUID that
           has the specified interface-id attachment."""
        port_list = []
        try:
            port_list_resdict = self.qclient.list_ports(
                net_id, tenant=tenant_id,
                filter_ops={'attachment': attachment_id})
            port_list = port_list_resdict["ports"]
        except client.QuantumNotFoundException:
            return None

        return port_list[0]['id']

    def _locate_port(self, q_tenant_id, net_id, attachment_id):
        """Find tenant and port ids based on provided information."""
        port_id = self.get_port_by_attachment(q_tenant_id, net_id,
                                              attachment_id)
        if not port_id:
            try:
                q_tenant_id = FLAGS.quantum_default_tenant_id
                port_id = self.get_port_by_attachment(
                    q_tenant_id, net_id, attachment_id)
            except:
                port_id = None
        return q_tenant_id, port_id

    def _locate_vif(self, admin_context, project_id, vif_ref):
        """Find out which tenant/network/port this vif is attached to"""
        q_tenant_id = project_id
        network_ref = db.network_get(admin_context, vif_ref['network_id'])
        net_id = network_ref['uuid']
        q_tenant_id, port_id = self._locate_port(q_tenant_id, net_id,
                                                 vif_ref['uuid'])
        return q_tenant_id, net_id, port_id

#------------------------------------------------------------------------------
# Security group trigger handlers.
#------------------------------------------------------------------------------
    def trigger_security_group_create_refresh(self, context, group):
        '''Called when a security_group is created.

        :param context: the security context.
        :param group: the new group added. group is a dictionary that contains
            the following: user_id, project_id, name, description).'''
        try:
            # Get security group and rules.
            sg = db.security_group_get_by_name(context, group['project_id'],
                                               group['name'])
            srs = db.security_group_rule_get_by_security_group(context, sg.id)

            # Create request body security group.
            sg_dict = mk_security_group_dict(sg, srs)
            body = dict(securitygroup=sg_dict)

            # Send request.
            res = self.client.create_security_group(body,
                                                    tenant=context.project_id)
            LOG.debug('Created security group: %s' % res)
        except Exception as e:
            LOG.error("Error creating security group: %s" % e)

    def trigger_security_group_destroy_refresh(self, context, sg_id):
        '''Called when a security_group is destroyed.

        :param context: the security context.
        :param security_group_id: the security group identifier.'''
        try:
            self.client.delete_security_group(sg_id, tenant=context.project_id)
        except Exception as e:
            LOG.error("Error destrotying security group: %s" % e)

    def trigger_security_group_rule_create_refresh(self, context, rule_ids):
        '''Called when a rule is added to a security_group.

        :param context: the security context.
        :param rule_ids: a list of rule ids that have been affected.'''
        try:
            # Find all the affected security groups (sgs).
            sgs = set()
            for rid in rule_ids:
                r = db.security_group_rule_get(context, rid)
                sgs.add(r.parent_group)

            # Update all of the affected security groups.
            for sg in sgs:
                srs = db.security_group_rule_get_by_security_group(context,
                                                                   sg.id)
                sg_dict = mk_security_group_dict(sg, srs)
                body = dict(securitygroup=sg_dict)

                # Some debugging information.
                LOG.debug('Security group body: %s' % body)

                # Send the request.
                try:
                    self.client.update_security_group(
                        sg.id, body, tenant=context.project_id)
                except Exception as e:
                    msg = _("Error sending update_security_group(): %s")
                    LOG.error(msg % e)
        except Exception as e:
            LOG.error("Error creating rule: %s" % e)

    def trigger_security_group_rule_destroy_refresh(self, context, rule_ids):
        '''Called when a rule is removed from a security_group.

        :param context: the security context.
        :param rule_ids: a list of rule ids that have been affected.'''
        try:
            # Find all the affected security groups (sgs).
            admin_context = context.elevated(read_deleted='yes')
            sgs = set()
            for rid in rule_ids:
                r = db.security_group_rule_get(admin_context, rid)
                sgs.add(r.parent_group)

            # Update all of the affected security groups.
            for sg in sgs:
                srs = db.security_group_rule_get_by_security_group(context,
                                                                   sg.id)
                sg_dict = mk_security_group_dict(sg, srs)
                body = dict(securitygroup=sg_dict)

                # Send the request.
                try:
                    self.client.update_security_group(
                        sg.id, body, tenant=context.project_id)
                except Exception as e:
                    LOG.error("Error sending update_security_group(): %s" % e)
        except Exception as e:
            LOG.error("Error destroying security group rule: error %s" % e)

    def trigger_instance_add_security_group_refresh(self, context, instance_id,
                                                    group_names):
        '''Called when a security group gains a new member.

        :param context: the security context.
        :param instance: the instance to be associated.
        :param group_name: the name of the security group to be associated.'''
        try:
            msg = _("trigger_instance_add_security_group_refresh: "
                    " group_names=%s" % str(group_names))
            LOG.debug(msg)
            project_id = context.project_id

            sgs = db.security_group_get_by_project(context, project_id)
            if not sgs:
                msg = _("Instance %(instance_id) project: %(project_id)s is"
                        " using default security group")
                LOG.info(msg % locals())
                return

            if len(sgs) == 1 and sgs[0].name == DEFAULT_SG_NAME:
                msg = _("Instance %(instance_id) project: %(project_id)s is"
                        " using default security group")
                LOG.info(msg % locals())
                return

            vifs = db.virtual_interface_get_by_instance(context, instance_id)
            for sg in sgs:
                dump_security_group(context, sg)
                for v in vifs:
                    try:
                        tenant_id, net_id, port_id = self._locate_vif(
                            context, project_id, v)
                        self.client.associate_port(sg.id, port_id,
                                                   tenant=project_id)
                    except Exception as e:
                        msg = _("Unable to associate port %(port_id)s for"
                                " tenant %(tenant_id)s on network %(net_id)s."
                                " Error: %(e)s")
                        LOG.error(msg % locals())
        except Exception as e:
            LOG.info("Error adding instance to security group: %s" % e)

    def trigger_instance_remove_security_group_refresh(self, context,
                                                       instance_id,
                                                       group_name):
        '''Called when a security group loses a member.

        :param context: the security context.
        :param instance_id: the instance to be disassociated.
        :param group_name: the name of the security group to be
            disassociated.'''
        try:
            project_id = context.project_id
            if group_name == DEFAULT_SG_NAME:
                msg = _("Instance %(instance_id) project: %(project_id)s is"
                        " using default security group")
                LOG.info(msg % locals())
                return

            vifs = db.virtual_interface_get_by_instance(context, instance_id)
            sg = db.security_group_get_by_name(context, project_id, group_name)
            for v in vifs:
                try:
                    tenant_id, net_id, port_id = self._locate_vif(context,
                                                                  project_id,
                                                                  v)
                    self.client.dissociate_port(sg.id, port_id,
                                                tenant=project_id)
                except Exception as e:
                    msg = _("Unable to dissociate port %(port_id)s for tenant "
                            " %(tenant_id)s on network %(net_id)s. Error:"
                            " %(e)s")
                    LOG.error(msg % locals())
        except Exception as e:
            LOG.error("Error removing instance from security group: %s" % e)

    def trigger_security_group_members_refresh(self, context, group_ids):
        '''Called when a security group gains or loses a member.

        :param context: the security context.
        :param group_ids: a list of security group identifiers.'''
        msg = _("trigger_security_group_members_refresh: group_ids=%s")
        LOG.debug(msg % str(group_ids))


#------------------------------------------------------------------------------
# Convenience functions.
#------------------------------------------------------------------------------
def dump_security_group(context, sg):
    """Convenience function for dumping security groups.

    :param sg: security group object to dump.
    :returns: Nothing."""
    LOG.debug("security_group {")
    LOG.debug("    name = %s" % sg.name)
    LOG.debug("    description = %s" % sg.description)
    LOG.debug("    user_id = %s" % sg.user_id)
    LOG.debug("    project_id = %s" % sg.project_id)
    LOG.debug("    rules {")

    for sgr in db.security_group_rule_get_by_security_group(context, sg.id):
        LOG.debug("    security_group_rule {")
        LOG.debug("        id = %s" % sgr.id)
        LOG.debug("        protocol = %s" % sgr.protocol)
        LOG.debug("        from_port = %s" % sgr.from_port)
        LOG.debug("        to_port = %s" % sgr.to_port)
        LOG.debug("        cidr = %s" % sgr.cidr)
        LOG.debug("        parent_group_id = %s" % sgr.parent_group_id)
        LOG.debug("        group_id = %s" % sgr.group_id)
        LOG.debug("    }")
    LOG.debug("    }")
    LOG.debug("}")


def mk_security_group_dict(sg, srs):
    """Create security group dictionary from a security group
    object and a set of security gorup rules.

    :param sg: the security group.
    :param srs: a list of security group rules.
    :returns: a dictionary object containing the security group rules."""
    sg_dict = {}
    sg_dict["name"] = sg.name
    sg_dict["securityrules"] = []
    sg_dict["id"] = str(sg.id)
    for r in srs:
        sg_dict["securityrules"].append(dict(
            direction=DEFAULT_DIRECTION,
            ip_prefix=r.cidr,
            ethertype=DEFAULT_ETHERTYPE,
            protocol=str(r.protocol),
            port_range_min=str(r.from_port),
            port_range_max=str(r.to_port)
        ))
    return sg_dict
