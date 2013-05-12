# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 OpenStack Foundation
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

"""New service types framework (service providers)

Revision ID: 557edfc53098
Revises: 3cabb850f4a5
Create Date: 2013-06-29 21:10:41.283358

"""

# revision identifiers, used by Alembic.
revision = '557edfc53098'
down_revision = '3cabb850f4a5'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = ['*']

from alembic import op
import sqlalchemy as sa


from quantum.db import migration


def upgrade(active_plugin=None, options=None):
    if not migration.should_run(active_plugin, migration_for_plugins):
        return
    # creating new tables
    op.create_table(
        'serviceproviders',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('service_type', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=36), nullable=False),
        sa.Column('driver', sa.String(length=36), nullable=False),
        sa.Column('default', sa.Boolean, nullable=False, default=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('service_type', 'name',
                            name='uniq_serviceproviders0service_type0name'),
        sa.UniqueConstraint('driver', name='uniq_serviceproviders0driver'),
    )

    op.create_table(
        'providerresourceassociations',
        sa.Column('provider_id', sa.String(length=36), nullable=False),
        sa.Column('resource_id', sa.String(length=36), nullable=False),
        sa.UniqueConstraint('provider_id', 'resource_id',
                            name='uniq_providerresourceassociations0'
                            'provider_id0resource_id'),
        sa.ForeignKeyConstraint(['provider_id'], ['serviceproviders.id'], )
    )

    # altering existing relationships to new table
    op.rename_table('routerservicetypebindings',
                    'routerserviceproviderbindings')
    op.drop_column('routerserviceproviderbindings', 'service_type_id')
    op.add_column('routerserviceproviderbindings',
                  sa.Column('service_provider_id',
                            sa.String(length=36),
                            sa.ForeignKey('serviceproviders.id'),
                            nullable=False))
    # dropping unused tables
    op.drop_table('servicedefinitions')
    op.drop_table('servicetypes')


def downgrade(active_plugin=None, options=None):
    if not migration.should_run(active_plugin, migration_for_plugins):
        return
    op.create_table(
        'servicetypes',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255)),
        sa.Column('name', sa.String(255)),
        sa.Column('description', sa.String(255)),
        sa.Column('default', sa.Boolean(), nullable=False, default=False),
        sa.Column('num_instances', sa.Column(sa.Integer(), default=0)),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_table(
        'servicedefinitions',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('service_class', sa.String(255)),
        sa.Column('plugin', sa.String(255)),
        sa.Column('driver', sa.String(255)),
        sa.Column('service_type_id', sa.String(36),
                  sa.ForeignKey('servicetypes.id',
                                ondelete='CASCADE')),
        sa.PrimaryKeyConstraint('id', 'service_class')
    )
    # restoring relationships
    op.drop_column('routerserviceproviderbindings', 'service_provider_id')
    op.add_column('routerserviceproviderbindings',
                  sa.Column('service_type_id',
                            sa.String(length=36),
                            sa.ForeignKey('servicetypes.id'),
                            nullable=False))
    op.rename_table('routerserviceproviderbindings',
                    'routerservicetypebindings')

    op.drop_table('providerresourceassociations')
    op.drop_table('serviceproviders')
