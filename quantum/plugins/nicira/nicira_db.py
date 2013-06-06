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

from sqlalchemy.orm import exc

import quantum.db.api as db
from quantum.openstack.common import log as logging
from quantum.plugins.nicira import nicira_models
from quantum.plugins.nicira import nicira_networkgw_db

LOG = logging.getLogger(__name__)


def get_network_binding(session, network_id):
    session = session or db.get_session()
    try:
        binding = (session.query(nicira_models.NvpNetworkBinding).
                   filter_by(network_id=network_id).
                   one())
        return binding
    except exc.NoResultFound:
        return


def get_network_binding_by_vlanid(session, vlan_id):
    session = session or db.get_session()
    try:
        binding = (session.query(nicira_models.NvpNetworkBinding).
                   filter_by(vlan_id=vlan_id).
                   one())
        return binding
    except exc.NoResultFound:
        return


def get_network_binding_by_vlanid_and_phynet(session, vlan_id,
                                             physical_network):
    session = session or db.get_session()
    try:
        binding = (session.query(nicira_models.NvpNetworkBinding).
                   filter_by(vlan_id=vlan_id, phy_uuid=physical_network).
                   one())
        return binding
    except exc.NoResultFound:
        return


def add_network_binding(session, network_id, binding_type, phy_uuid, vlan_id):
    with session.begin(subtransactions=True):
        binding = nicira_models.NvpNetworkBinding(network_id, binding_type,
                                                  phy_uuid, vlan_id)
        session.add(binding)
    return binding


def _add_quantum_nvp_mapping(session, model, quantum_id, nvp_id):
    with session.begin(subtransactions=True):
        mapping = model()
        mapping.quantum_id = quantum_id
        mapping.nvp_id = nvp_id
        session.add(mapping)
        return mapping


def add_quantum_nvp_port_mapping(session, quantum_id, nvp_id):
    return _add_quantum_nvp_mapping(
        session, nicira_models.QuantumNvpPortMapping, quantum_id, nvp_id)


def add_quantum_nvp_router_mapping(session, quantum_id, nvp_id,
                                   nvp_gw_port_id=None):
    with session.begin(subtransactions=True):
        mapping = _add_quantum_nvp_mapping(
            session, nicira_models.QuantumNvpRouterMapping, quantum_id, nvp_id)
        if nvp_gw_port_id:
            mapping.nvp_gw_port_id = nvp_gw_port_id
    return mapping


def set_quantum_nvp_router_mapping(session, quantum_id,
                                   nvp_id=None, nvp_gw_port_id=None):
    with session.begin(subtransactions=True):
        try:
            mapping = (session.query(nicira_models.QuantumNvpRouterMapping).
                       filter_by(quantum_id=quantum_id).one())
        except exc.NoResultFound:
            LOG.warn(_("No mapping found for router:%s"), quantum_id)
        if nvp_id:
            mapping.nvp_id = nvp_id
        if nvp_gw_port_id:
            mapping.nvp_gw_port_id = nvp_gw_port_id
    return mapping


def _get_nvp_id(session, model, quantum_id, field='nvp_id'):
    try:
        mapping = (session.query(model).
                   filter_by(quantum_id=quantum_id).
                   one())
        return mapping[field]
    except exc.NoResultFound:
        return


def get_nvp_port_id(session, quantum_id):
    return _get_nvp_id(
        session, nicira_models.QuantumNvpPortMapping, quantum_id)


def get_nvp_router_id(session, quantum_id):
    return _get_nvp_id(
        session, nicira_models.QuantumNvpRouterMapping, quantum_id)


def get_nvp_router_gw_portid(session, quantum_id):
    return _get_nvp_id(
        session, nicira_models.QuantumNvpRouterMapping,
        quantum_id, field='nvp_gw_port_id')


def unset_default_network_gateways(session):
    with session.begin(subtransactions=True):
        session.query(nicira_networkgw_db.NetworkGateway).update(
            {nicira_networkgw_db.NetworkGateway.default: False})


def set_default_network_gateway(session, gw_id):
    with session.begin(subtransactions=True):
        gw = (session.query(nicira_networkgw_db.NetworkGateway).
              filter_by(id=gw_id).one())
        gw['default'] = True
