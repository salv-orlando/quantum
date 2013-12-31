# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Nicira, Inc.
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

import json

from sqlalchemy import Boolean, Column, Enum, ForeignKey, Integer, String
from sqlalchemy import orm
from sqlalchemy import types as sa_types

from neutron.db import l3_db
from neutron.db.models_v2 import HasId, model_base
from neutron.db import securitygroups_db as sg_db


class NvpNetworkBinding(model_base.BASEV2):
    """Represents a binding of a virtual network with a transport zone.

    This model class associates a Neutron network with a transport zone;
    optionally a vlan ID might be used if the binding type is 'bridge'
    """
    __tablename__ = 'nvp_network_bindings'

    # TODO(arosen) - it might be worth while refactoring the how this data
    # is stored later so every column does not need to be a primary key.
    network_id = Column(String(36),
                        ForeignKey('networks.id', ondelete="CASCADE"),
                        primary_key=True)
    # 'flat', 'vlan', stt' or 'gre'
    binding_type = Column(Enum('flat', 'vlan', 'stt', 'gre', 'l3_ext',
                               name='nvp_network_bindings_binding_type'),
                          nullable=False, primary_key=True)
    phy_uuid = Column(String(36), primary_key=True, nullable=True)
    vlan_id = Column(Integer, primary_key=True, nullable=True,
                     autoincrement=False)

    def __init__(self, network_id, binding_type, phy_uuid, vlan_id):
        self.network_id = network_id
        self.binding_type = binding_type
        self.phy_uuid = phy_uuid
        self.vlan_id = vlan_id

    def __repr__(self):
        return "<NetworkBinding(%s,%s,%s,%s)>" % (self.network_id,
                                                  self.binding_type,
                                                  self.phy_uuid,
                                                  self.vlan_id)


class NeutronNsxSecurityGroupMapping(model_base.BASEV2):
    """Backend mappings for Neutron Security Group identifiers.

    This class maps a neutron security group identifier to the corresponding
    NSX security profile identifier.
    """

    __tablename__ = 'neutron_nsx_security_group_mappings'
    neutron_id = Column(String(36),
                        ForeignKey('securitygroups.id', ondelete="CASCADE"),
                        primary_key=True)
    nsx_id = Column(String(36))


class NeutronNsxPortMapping(model_base.BASEV2):
    """Represents the mapping between neutron and nvp port uuids."""

    __tablename__ = 'neutron_nsx_port_mappings'
    neutron_id = Column(String(36),
                        ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    nsx_switch_id = Column(String(36))
    nsx_port_id = Column(String(36))

    def __init__(self, neutron_id, nsx_switch_id, nsx_port_id):
        self.neutron_id = neutron_id
        self.nsx_switch_id = nsx_switch_id
        self.nsx_port_id = nsx_port_id


class MultiProviderNetworks(model_base.BASEV2):
    """Networks that were provision through multiprovider extension."""

    __tablename__ = 'nvp_multi_provider_networks'
    network_id = Column(String(36),
                        ForeignKey('networks.id', ondelete="CASCADE"),
                        primary_key=True)

    def __init__(self, network_id):
        self.network_id = network_id


class NSXRouterExtAttributes(model_base.BASEV2):
    """Router attributes managed by Nicira plugin extensions."""
    router_id = Column(String(36),
                       ForeignKey('routers.id', ondelete="CASCADE"),
                       primary_key=True)
    distributed = Column(Boolean, default=False, nullable=False)
    service_router = Column(Boolean, default=False, nullable=False)
    # Add a relationship to the Router model in order to instruct
    # SQLAlchemy to eagerly load this association
    router = orm.relationship(
        l3_db.Router,
        backref=orm.backref("nsx_attributes", lazy='joined',
                            uselist=False, cascade='delete'))


# Model classes for asynchronous task tracking
# Each class must either have an attribute name neutron_id for the neutron
# foreign key or define an attribute mapping in neutron_id_attributes

class JsonEncodedDict(sa_types.TypeDecorator):
    """Represent an immutable structure as a json-encoded string."""

    impl = sa_types.VARCHAR

    def process_bind_param(self, value, dialect):
        if value is not None:
            value = json.dumps(value)

        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = json.loads(value)
        return value


class BaseTask(object):
    """Base class for task info."""
    # Celery's task ID. It's supposed to be unique, but it should be nullable
    # as well. Therefore the unique attribute should not be set as not all
    # backends support multiple NULL entries for a unique column.
    celery_task_id = Column(String(36), nullable=True)
    # Auto increment attribute for ordering queued tasks on a given resource
    task_counter = Column(Integer, unique=True, autoincrement=True)
    is_create = Column(Boolean, default=False, nullable=False)
    is_delete = Column(Boolean, default=False, nullable=False)
    # Up to 8Kb of data for each task
    task_data = Column(JsonEncodedDict(8192))


class NsxAsyncSecurityGroupTask(model_base.BASEV2, HasId, BaseTask):
    """Active tasks for neutron security groups."""
    neutron_id = Column(
        String(36),
        ForeignKey('securitygroups.id', ondelete="CASCADE"))

    security_group = orm.relationship(
        sg_db.SecurityGroup,
        backref=orm.backref("task_info", lazy='joined', cascade='delete'))
