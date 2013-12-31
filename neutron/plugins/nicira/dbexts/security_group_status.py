# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2014 VMware, Inc.  All rights reserved.
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

import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron.db import db_base_plugin_v2
from neutron.db import model_base
from neutron.db import securitygroups_db as sg_db
from neutron.openstack.common import log as logging
from neutron.plugins.nicira.extensions import securitygroupstatus as sg_status

LOG = logging.getLogger(__name__)


class SecurityGroupStatus(model_base.BASEV2):

    __tablename__ = "securitygroupstatus"

    security_group_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('securitygroups.id', ondelete="CASCADE"),
        primary_key=True)
    status = sa.Column(sa.String(16), nullable=False)

    # Add a relationship to the Security Group model class using
    # the backref attribute.
    security_group = orm.relationship(
        sg_db.SecurityGroup,
        backref=orm.backref("status_info", lazy='joined',
                            uselist=False, cascade='delete'))


class SecurityGroupStatusDbMixin(object):
    """Mixin class for security group status."""

    def _extend_security_group_status(self, sec_group_res, sec_group_db):
        sec_group_res[sg_status.STATUS] = sec_group_db.status_info.status

    # Register dict extend functions for ports
    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        'security_groups', ['_extend_security_group_status'])

    def _set_security_group_status(self, context, sec_group, new_status):
        try:
            query = self._model_query(context, SecurityGroupStatus)
            status = query.filter(
                SecurityGroupStatus.security_group_id == sec_group['id']).one()
            status.update({sg_status.STATUS: new_status})
        except exc.NoResultFound:
            self._create_security_group_status(
                context, sec_group['id'], new_status)
        sec_group[sg_status.STATUS] = new_status

    def _create_security_group_status(self, context, sg_id, status):
        with context.session.begin(subtransactions=True):
            sg_status = SecurityGroupStatus(security_group_id=sg_id,
                                            status=status)
            context.session.add(sg_status)
