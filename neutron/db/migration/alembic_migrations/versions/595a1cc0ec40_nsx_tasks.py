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

"""nsx_tasks

Revision ID: 595a1cc0ec40
Revises: 2c08f530b0cc
Create Date: 2014-01-24 04:32:38.893830

"""

# revision identifiers, used by Alembic.
revision = '595a1cc0ec40'
down_revision = '2c08f530b0cc'

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
        'nsxasyncsecuritygrouptasks',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('celery_task_id', sa.String(length=36), nullable=True),
        sa.Column('task_counter', sa.Integer(), nullable=True),
        sa.Column('is_create', sa.Boolean(), nullable=False),
        sa.Column('is_delete', sa.Boolean(), nullable=False),
        sa.Column('task_data', sa.String(length=8192), nullable=True),
        sa.Column('neutron_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['neutron_id'],
                                ['securitygroups.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('task_counter'),
        mysql_engine='InnoDB')


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return
    op.drop_table('nsxasyncsecuritygrouptasks')
