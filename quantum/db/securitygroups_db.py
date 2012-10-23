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
# @author: Aaron Rosen, Nicira, Inc
#
"""

import re

from sqlalchemy.orm import exc
import sqlalchemy as sa

from quantum.api.v2 import attributes
from quantum.common import utils
from quantum.db import model_base
from quantum.db import models_v2
from quantum.extensions import securitygroup as ext_sg


class SecurityGroup(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a v2 quantum security group."""
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    external_id = sa.Column(sa.Integer, unique=True)


class SecurityGroupPortBinding(model_base.BASEV2):
    """Represents binding between quantum ports and security profiles"""
    port_id = sa.Column(sa.String(36), primary_key=True)
    sgid = sa.Column(sa.String(36), primary_key=True)


class SecurityGroupRule(model_base.BASEV2, models_v2.HasId,
                        models_v2.HasTenant):
    """Represents a v2 quantum security group rule."""
    external_id = sa.Column(sa.Integer)
    parent_group_id = sa.Column(sa.String(36),
        sa.ForeignKey("securitygroups.id", ondelete="CASCADE"), nullable=False)

    group_id = sa.Column(sa.String(36),
            sa.ForeignKey("securitygroups.id", ondelete="CASCADE"),
            nullable=True)

    direction = sa.Column(sa.Enum('ingress', 'egress'))
    ethertype = sa.Column(sa.String(5))  # IPv4, IPv6
    protocol = sa.Column(sa.Integer)
    port_range_min = sa.Column(sa.Integer)
    port_range_max = sa.Column(sa.Integer)
    ip_prefix = sa.Column(sa.String(255))


class SecurityGroup_db_mixin(ext_sg.SecurityGroupPluginBase):
    """Mixin class to add security group to db_plugin_base_v2."""

    __native_bulk_support = True

    def create_securitygroup_bulk(self, context, securitygrouprule):
        return self._create_bulk('securitygroup', context, securitygrouprule)

    def create_securitygroup(self, context, securitygroup):
        s = securitygroup['securitygroup']
        if s.get('external_id') is not None:
            try:
                # Check if security group already exists
                sg = self.get_securitygroup(context, s.get('external_id'))
                if sg:
                    raise ext_sg.SecurityGroupAlreadyExists(
                        name=sg.get('name', ''),
                        external_id=s.get('external_id'))
            except ext_sg.SecurityGroupNotFound:
                pass

        tenant_id = self._get_tenant_id_for_create(context, s)
        with context.session.begin(subtransactions=True):
            security_group_db = SecurityGroup(
                               id=s.get('id') or utils.str_uuid(),
                               description=s['description'],
                               tenant_id=tenant_id,
                               name=s['name'],
                               external_id=s.get('external_id'))
            context.session.add(security_group_db)
        return self._make_security_group_dict(security_group_db)

    def get_securitygroups(self, context, filters=None, fields=None):
        return self._get_collection(context, SecurityGroup,
                                    self._make_security_group_dict,
                                    filters=filters, fields=fields)

    def get_securitygroup(self, context, id, fields=None):
        return self._make_security_group_dict(self._get_securitygroup(
            context, id), fields)

    def _get_securitygroup(self, context, id):
        try:
            query = self._model_query(context, SecurityGroup)
            if not re.match(attributes.UUID_PATTERN, str(id)):
                sg = query.filter(SecurityGroup.external_id == id).one()
            else:
                sg = query.filter(SecurityGroup.id == id).one()

        except exc.NoResultFound:
            raise ext_sg.SecurityGroupNotFound(id=id)
        return sg

    def delete_securitygroup(self, context, id):
        filters = {'sgid': [id]}
        ports = self.get_port_securitygroup_binding(context, filters)
        if ports:
            raise ext_sg.SecurityGroupInUse(id=id)
        # confirm security group exists
        sg = self._get_securitygroup(context, id)

        # delete security group rules then group
        filters = {'parent_group_id': [id]}
        fields = {'id': None}
        with context.session.begin(subtransactions=True):
            context.session.delete(sg)

    def _make_security_group_dict(self, security_group, fields=None):
        res = {'id': security_group['id'],
               'name': security_group['name'],
               'tenant_id': security_group['tenant_id'],
               'description': security_group['description']}
        if security_group.get('external_id'):
            res['external_id'] = security_group['external_id']
        return self._fields(res, fields)

    def _make_securitygroup_binding_dict(self, security_group, fields=None):
        res = {'port_id': security_group['port_id'],
               'sgid': security_group['sgid']}
        return self._fields(res, fields)

    def create_port_securitygroup_binding(self, context, port_id, sgid):
        with context.session.begin(subtransactions=True):
            db = SecurityGroupPortBinding(port_id=port_id,
                                          sgid=sgid)
            context.session.add(db)

    def get_port_securitygroup_binding(self, context,
                                       filters=None, fields=None):
        return self._get_collection(context, SecurityGroupPortBinding,
                                    self._make_securitygroup_binding_dict,
                                    filters=filters, fields=fields)

    def delete_port_securitygroup_binding(self, context, port_id):
        query = self._model_query(context, SecurityGroupPortBinding)
        bindings = query.filter(
            SecurityGroupPortBinding.port_id == port_id)
        with context.session.begin(subtransactions=True):
            for binding in bindings:
                context.session.delete(binding)

    def create_securitygrouprule_bulk(self, context, securitygrouprule):
        return self._create_bulk('securitygrouprule', context,
                                 securitygrouprule)

    def create_securitygrouprule_bulk_native(self, context, securitygrouprule):
        r = securitygrouprule['securitygrouprules']

        parent_group_id = self._confirm_same_parent_group_id(securitygrouprule)
        if not self.get_securitygroup(context, parent_group_id):
            raise ext_sg.SecurityGroupNotFound(id=parent_group_id)

        self._check_for_duplicate_rules(context, r)
        ret = []
        for rule_dict in r:
            rule = rule_dict['securitygrouprule']
            tenant_id = self._get_tenant_id_for_create(context, rule)
            with context.session.begin(subtransactions=True):
                db = SecurityGroupRule(id=utils.str_uuid(),
                               tenant_id=tenant_id,
                               parent_group_id=rule['parent_group_id'],
                               direction=rule['direction'],
                               external_id=rule.get('external_id'),
                               group_id=rule.get('group_id'),
                               ethertype=rule['ethertype'],
                               protocol=rule['protocol'],
                               port_range_min=rule['port_range_min'],
                               port_range_max=rule['port_range_max'],
                               ip_prefix=rule.get('ip_prefix'))
                context.session.add(db)
            ret.append(self._make_security_group_rule_dict(db))
        return ret

    def create_securitygrouprule(self, context, securitygrouprule):
        bulk_rule = {'securitygrouprules': [securitygrouprule]}
        return self.create_securitygrouprule_bulk_native(context, bulk_rule)[0]

    def _confirm_same_parent_group_id(self, securitygrouprule):
        """Check that rules being installed all belong to same security group.
        """
        new_rules = {}
        for rules in securitygrouprule['securitygrouprules']:
            rule = rules.get('securitygrouprule')
            if rule['parent_group_id'] not in new_rules:
                new_rules[rule['parent_group_id']] = []
            new_rules[rule['parent_group_id']].append(rule)

        if len(new_rules.keys()) > 1:
            raise ext_sg.SecurityGroupNotSingleGroupRules()
        else:
            return new_rules.keys()[0]

    def _make_security_group_rule_dict(self, securitygrouprule, fields=None):
        res = {'id': securitygrouprule['id'],
               'tenant_id': securitygrouprule['tenant_id'],
               'parent_group_id': securitygrouprule['parent_group_id'],
               'ethertype': securitygrouprule['ethertype'],
               'direction': securitygrouprule['direction'],
               'protocol': securitygrouprule['protocol'],
               'port_range_min': securitygrouprule['port_range_min'],
               'port_range_max': securitygrouprule['port_range_max'],
               'ip_prefix': securitygrouprule['ip_prefix'],
               'group_id': securitygrouprule['group_id'],
               'external_id': securitygrouprule['external_id']}

        return self._fields(res, fields)

    def _make_security_group_rule_filter_dict(self, securitygrouprule):
        sgr = securitygrouprule['securitygrouprule']
        res = {'tenant_id': [sgr['tenant_id']],
               'parent_group_id': [sgr['parent_group_id']],
               'ethertype': [sgr['ethertype']],
               'direction': [sgr['direction']],
               'protocol': [sgr['protocol']],
               'port_range_min': [sgr['port_range_min']],
               'port_range_max': [sgr['port_range_max']]}

        if sgr.get('ip_prefix'):
            res['ip_prefix'] = [sgr['ip_prefix']]

        if sgr.get('group_id'):
            res['group_id'] = [sgr['group_id']]

        if sgr.get('external_id'):
            res['external_id'] = [sgr['external_id']]

        return res

    def _check_for_duplicate_rules(self, context, securitygrouprules):
        """ Check for duplicate rules
        """
        for i in securitygrouprules:
            found_self = False
            for j in securitygrouprules:
                if i['securitygrouprule'] == j['securitygrouprule']:
                    if found_self:
                        raise ext_sg.DuplicateSecurityGroupRuleInPost(rule=i)
                    found_self = True

            # Check in database if rule exists
            filters = self._make_security_group_rule_filter_dict(i)
            self.get_securitygrouprules(context)
            if self.get_securitygrouprules(context, filters):
                raise ext_sg.SecurityGroupRuleExists(rule=i)

    def get_securitygrouprules(self, context, filters=None, fields=None):
        return  self._get_collection(context, SecurityGroupRule,
                                        self._make_security_group_rule_dict,
                                        filters=filters, fields=fields)

    def get_securitygrouprule(self, context, id, fields=None):
        securitygrouprule = self._get_securitygrouprule(context, id)
        return self._make_security_group_rule_dict(securitygrouprule, fields)

    def _get_securitygrouprule(self, context, id):
        try:
            if not re.match(attributes.UUID_PATTERN, id):
                query = self._model_query(context, SecurityGroupRule)
                sgr = query.filter(SecurityGroupRule.external_id == id).one()
            else:
                query = self._model_query(context, SecurityGroupRule)
                sgr = query.filter(SecurityGroupRule.id == id).one()
        except exc.NoResultFound:
            raise ext_sg.SecurityGroupRuleNotFound(id=id)
        return sgr

    def delete_securitygrouprule(self, context, sgrid):
        with context.session.begin(subtransactions=True):
            rule = self._get_securitygrouprule(context, sgrid)
            context.session.delete(rule)

    def _extend_port_dict_securitygroup(self, context, port):
        filters = {'port_id': [port['id']]}
        fields = {'sgid': None}
        port[ext_sg.EXTERNAL] = []
        sgids = self.get_port_securitygroup_binding(context, filters, fields)
        for sgid in sgids:
            port[ext_sg.EXTERNAL].append(sgid['sgid'])
        return port

    def _process_port_create_securitygroup(self, context, port_id, sgids):
        if not sgids:
            return
        for sgid in sgids:
            self.create_port_securitygroup_binding(context, port_id, sgid)
