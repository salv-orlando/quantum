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

"""nicira-folsom

Revision ID: 3fbc0174f2a7
Revises: 5a875d0e5c
Create Date: 2013-01-28 10:05:21.270894

"""

# revision identifiers, used by Alembic.
revision = 'nicira-folsom'
down_revision = 'folsom'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'quantum.plugins.nicira.nicira_nvp_plugin.QuantumPlugin.NvpPluginV2'
]

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

from quantum.db import migration


def upgrade(active_plugin=None, options=None):
    if not migration.should_run(active_plugin, migration_for_plugins):
        return

    op.create_table('qosqueues',
                    sa.Column('tenant_id', sa.String(length=255),
                              nullable=True),
                    sa.Column('id', sa.String(length=36), nullable=False),
                    sa.Column('name', sa.String(length=255), nullable=True),
                    sa.Column('default', sa.Boolean(), nullable=True),
                    sa.Column('min', sa.Integer(), nullable=False),
                    sa.Column('max', sa.Integer(), nullable=True),
                    sa.Column('qos_marking', sa.Enum('untrusted', 'trusted'),
                              nullable=True),
                    sa.Column('dscp', sa.Integer(), nullable=True),
                    sa.PrimaryKeyConstraint('id'))
    op.create_table('securitygroups',
                    sa.Column('tenant_id', sa.String(length=255),
                              nullable=True),
                    sa.Column('id', sa.String(length=36), nullable=False),
                    sa.Column('name', sa.String(length=255), nullable=True),
                    sa.Column('description', sa.String(length=255),
                              nullable=True),
                    sa.Column('external_id', sa.Integer(), nullable=True),
                    sa.PrimaryKeyConstraint('id'),
                    sa.UniqueConstraint('external_id'))
    op.create_table('securitygrouprules',
                    sa.Column('tenant_id', sa.String(length=255),
                              nullable=True),
                    sa.Column('id', sa.String(length=36), nullable=False),
                    sa.Column('external_id', sa.Integer(), nullable=True),
                    sa.Column('security_group_id', sa.String(length=36),
                              nullable=False),
                    sa.Column('source_group_id', sa.String(length=36),
                              nullable=True),
                    sa.Column('direction',
                              sa.Enum('ingress', 'egress',
                                      name='securitygrouprules_direction'),
                              nullable=True),
                    sa.Column('ethertype', sa.String(length=40),
                              nullable=True),
                    sa.Column('protocol', sa.String(length=40),
                              nullable=True),
                    sa.Column('port_range_min', sa.Integer(), nullable=True),
                    sa.Column('port_range_max', sa.Integer(), nullable=True),
                    sa.Column('source_ip_prefix', sa.String(length=255),
                              nullable=True),
                    sa.ForeignKeyConstraint(['security_group_id'],
                                            ['securitygroups.id'],
                                            ondelete='CASCADE'),
                    sa.ForeignKeyConstraint(['source_group_id'],
                                            ['securitygroups.id'],
                                            ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('id'))
    op.create_table('securitygroupportbindings',
                    sa.Column('port_id', sa.String(length=36),
                              nullable=False),
                    sa.Column('security_group_id', sa.String(length=36),
                              nullable=False),
                    sa.ForeignKeyConstraint(['port_id'], ['ports.id'], ),
                    sa.ForeignKeyConstraint(['security_group_id'],
                                            ['securitygroups.id'], ),
                    sa.PrimaryKeyConstraint('port_id', 'security_group_id'))
    op.create_table('networkgateways',
                    sa.Column('id', sa.String(length=36), nullable=False),
                    sa.Column('name', sa.String(length=255), nullable=True),
                    sa.Column('tenant_id', sa.String(length=36),
                              nullable=False),
                    sa.PrimaryKeyConstraint('id'))
    op.create_table('networkgatewaydevices',
                    sa.Column('id', sa.String(length=36), nullable=False),
                    sa.Column('network_gateway_id', sa.String(length=36),
                              nullable=True),
                    sa.Column('interface_name', sa.String(length=64),
                              nullable=True),
                    sa.ForeignKeyConstraint(['network_gateway_id'],
                                            ['networkgateways.id'],
                                            ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('id'))
    op.create_table('networkconnections',
                    sa.Column('tenant_id', sa.String(length=255),
                              nullable=True),
                    sa.Column('network_gateway_id', sa.String(length=36),
                              nullable=True),
                    sa.Column('network_id', sa.String(length=36),
                              nullable=True),
                    sa.Column('segmentation_type',
                              sa.Enum('flat', 'vlan',
                                      name="net_conn_seg_type"),
                              nullable=True),
                    sa.Column('segmentation_id', sa.Integer(),
                              nullable=True),
                    sa.Column('port_id', sa.String(length=36),
                              nullable=False),
                    sa.ForeignKeyConstraint(['network_gateway_id'],
                                            ['networkgateways.id'],
                                            ondelete='CASCADE'),
                    sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                            ondelete='CASCADE'),
                    sa.ForeignKeyConstraint(['port_id'], ['ports.id'],
                                            ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('port_id'),
                    sa.UniqueConstraint('network_gateway_id',
                                        'segmentation_type',
                                        'segmentation_id'))
    op.create_table('nvp_network_bindings',
                    sa.Column('network_id', sa.String(length=36),
                              nullable=False),
                    sa.Column('binding_type',
                              sa.Enum('flat', 'vlan', 'stt', 'gre',
                                      name='network_types'),
                              nullable=False),
                    sa.Column('tz_uuid', sa.String(length=36), nullable=True),
                    sa.Column('vlan_id', sa.Integer(), nullable=True),
                    sa.ForeignKeyConstraint(['network_id'],
                                            ['networks.id'],
                                            ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('network_id'))
    op.create_table('quantum_nvp_port_mapping',
                    sa.Column('quantum_id', sa.String(length=36),
                              nullable=False),
                    sa.Column('nvp_id', sa.String(length=36),
                              nullable=True),
                    sa.ForeignKeyConstraint(['quantum_id'], ['ports.id'],
                                            ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('quantum_id'))
    op.create_table('networkqueuemappings',
                    sa.Column('network_id', sa.String(length=36),
                              nullable=False),
                    sa.Column('queue_id', sa.String(length=36),
                              nullable=True),
                    sa.ForeignKeyConstraint(['network_id'],
                                            ['networks.id'],
                                            ondelete='CASCADE'),
                    sa.ForeignKeyConstraint(['queue_id'],
                                            ['qosqueues.id'],
                                            ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('network_id'))
    op.create_table('portsecuritybindings',
                    sa.Column('port_id', sa.String(length=36),
                              nullable=False),
                    sa.Column('security_type', sa.Enum('off', 'mac', 'mac_ip'),
                              nullable=True),
                    sa.ForeignKeyConstraint(['port_id'], ['ports.id'],
                                            ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('port_id'))
    op.create_table('portqueuemappings',
                    sa.Column('port_id', sa.String(length=36),
                              nullable=False),
                    sa.Column('queue_id', sa.String(length=36),
                              nullable=False),
                    sa.ForeignKeyConstraint(['port_id'], ['ports.id'],
                                            ondelete='CASCADE'),
                    sa.ForeignKeyConstraint(['queue_id'], ['qosqueues.id'], ),
                    sa.PrimaryKeyConstraint('port_id', 'queue_id'))


def downgrade(active_plugin=None, options=None):
    if not migration.should_run(active_plugin, migration_for_plugins):
        return

    op.drop_table('networkconnections')
    op.drop_table('securitygroupportbindings')
    op.drop_table('portqueuemappings')
    op.drop_table('quantum_nvp_port_mapping')
    op.drop_table('portsecuritybindings')
    op.drop_table('networkqueuemappings')
    op.drop_table('nvp_network_bindings')
    op.drop_table('networkgatewaydevices')
    op.drop_table('securitygrouprules')
    op.drop_table('securitygroups')
    op.drop_table('networkgateways')
    op.drop_table('qosqueues')