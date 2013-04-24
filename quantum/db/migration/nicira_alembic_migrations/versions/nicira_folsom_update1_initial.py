# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 OpenStack LLC
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

"""nw_gw_default

Revision ID: nicira-folsom-update1
Revises: nicira-folsom
Create Date: 2013-02-04 07:28:31.810001

"""

# revision identifiers, used by Alembic.
revision = 'nicira-folsom-update1'
down_revision = 'nicira-folsom'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'quantum.plugins.nicira.nicira_nvp_plugin.QuantumPlugin.NvpPluginV2'
]

from alembic import op
import sqlalchemy as sa

from quantum.db import migration


def upgrade(active_plugin=None, options=None):
    if not migration.should_run(active_plugin, migration_for_plugins):
        return

    op.add_column('networkgateways', sa.Column('default', sa.Boolean(),
                                               nullable=True))
    op.add_column('networkgateways', sa.Column('shared', sa.Boolean(),
                                               nullable=True))
    op.alter_column('networkgateways', u'tenant_id',
                    existing_type=sa.String(length=36),
                    nullable=True)


def downgrade(active_plugin=None, options=None):
    if not migration.should_run(active_plugin, migration_for_plugins):
        return

    op.alter_column('networkgateways', u'tenant_id',
                    existing_type=sa.String(length=36),
                    nullable=False)
    op.drop_column('networkgateways', 'default')
    op.drop_column('networkgateways', 'shared')
