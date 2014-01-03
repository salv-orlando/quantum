# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2014 OpenStack Foundation
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

"""sec_group_status

Revision ID: 2c08f530b0cc
Revises: 1b2580001654
Create Date: 2014-01-03 05:19:30.770377

"""

# revision identifiers, used by Alembic.
revision = '2c08f530b0cc'
down_revision = '1b2580001654'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.plugins.nicira.NeutronPlugin.NvpPluginV2',
    'neutron.plugins.nicira.NeutronServicePlugin.NvpAdvancedPlugin'
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_table(
        'securitygroupstatus',
        sa.Column('security_group_id', sa.String(length=36), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.ForeignKeyConstraint(['security_group_id'], ['securitygroups.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('security_group_id'),
        mysql_engine='InnoDB')


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_table('securitygroupstatus')
