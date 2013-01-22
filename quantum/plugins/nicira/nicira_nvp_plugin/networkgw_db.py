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
# @author: Salvatore Orlando, VMware
#

import logging

import sqlalchemy as sa
from sqlalchemy import exc as sa_exc
from sqlalchemy import orm
from webob import exc as web_exc

from quantum.api.v2 import attributes
from quantum.api.v2 import base
from quantum.common import exceptions
from quantum.common import utils
from quantum.db import db_base_plugin_v2
from quantum.db import model_base
from quantum.db import models_v2
from quantum.extensions import networkgw


LOG = logging.getLogger(__name__)
DEVICE_OWNER_NET_GW_INTF = 'network:gateway-interface'
ALLOWED_CONNECTION_ATTRIBUTES = set(('network_id',
                                     'segmentation_type',
                                     'segmentation_id'))


class GatewayInUse(exceptions.InUse):
    message = _("Network Gateway '%(gateway_id)s' still has active mappings "
                "with one or more quantum networks.")


class NetworkGatewayPortInUse(exceptions.InUse):
    message = _("Port '%(port_id)s' is owned by '%(device_owner)s' and "
                "therefore cannot be deleted directly via the port API.")


class GatewayConnectionInUse(exceptions.InUse):
    message = _("The specified mapping is already in use on network "
                "gateway '%(gateway_id)s'.")


class MultipleGatewayConnections(exceptions.QuantumException):
    message = _("Multiple network connections found on '%(gateway_id)s' "
                "with provided criteria.")


class GatewayConnectionNotFound(exceptions.NotFound):
    message = _("The connection %(network_mapping_info)s was not found on the "
                "network gateway '%(network_gateway_id)s'")


# Add exceptions to HTTP Faults mappings
base.FAULT_MAP.update({GatewayInUse: web_exc.HTTPConflict,
                       NetworkGatewayPortInUse: web_exc.HTTPConflict,
                       GatewayConnectionInUse: web_exc.HTTPConflict,
                       GatewayConnectionNotFound: web_exc.HTTPNotFound,
                       MultipleGatewayConnections: web_exc.HTTPConflict})


class NetworkConnection(model_base.BASEV2, models_v2.HasTenant):
    """ Defines a connection between a network gateway and a network """
    # We use port_id as the primary key as one can connect a gateway
    # to a network in multiple ways (and we cannot use the same port form
    # more than a single gateway)
    network_gateway_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('networkgateways.id',
                                                 ondelete='CASCADE'))
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete='CASCADE'))
    segmentation_type = sa.Column(sa.Enum('flat', 'vlan'))
    segmentation_id = sa.Column(sa.Integer)
    __table_args__ = (sa.UniqueConstraint(network_gateway_id,
                                          segmentation_type,
                                          segmentation_id),)
    # Also, storing port id comes back useful when disconnecting a network
    # from a gateway
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete='CASCADE'),
                        primary_key=True)

    def __init__(self, network_id, segmentation_type, port_id,
                 tenant_id, segmentation_id=None):
        self.network_id = network_id
        self.port_id = port_id
        self.tenant_id = tenant_id
        self.segmentation_type = segmentation_type
        self.segmentation_id = segmentation_id


class NetworkGatewayDevice(model_base.BASEV2, models_v2.HasId):
    network_gateway_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('networkgateways.id',
                                                 ondelete='CASCADE'))
    interface_name = sa.Column(sa.String(64))

    def __init__(self, id, interface_name=None):
        # Do not allow auto-generated ids - they won't make sense
        self.id = id
        self.interface_name = interface_name


class NetworkGateway(model_base.BASEV2, models_v2.HasId,
                     models_v2.HasTenant):
    """ Defines the data model for a network gateway """
    name = sa.Column(sa.String(255))
    tenant_id = sa.Column(sa.String(36), nullable=False)
    devices = orm.relationship(NetworkGatewayDevice,
                               backref='networkgateways',
                               cascade='all,delete')
    network_connections = orm.relationship(NetworkConnection)


class NetworkGatewayMixin(networkgw.NetworkGatewayPluginBase):

    resource = networkgw.RESOURCE_NAME.replace('-', '_')

    def _get_network_gateway(self, context, gw_id):
        return self._get_by_id(context, NetworkGateway, gw_id)

    def _make_network_gateway_dict(self, network_gateway, fields=None):
        device_list = []
        for d in network_gateway.devices:
            device_list.append({'id': d['id'],
                                'interface_name': d['interface_name']})
        res = {'id': network_gateway['id'],
               'name': network_gateway['name'],
               'devices': device_list,
               'tenant_id': network_gateway['tenant_id']}
        # NOTE(salvatore-orlando):perhaps return list of connected networks
        return self._fields(res, fields)

    def _validate_network_mapping_info(self, network_mapping_info):
        network_id = network_mapping_info.get('network_id')
        if not network_id:
            raise exceptions.InvalidInput(
                error_message=_("A network identifier must be specified "
                                "when connecting a network to a network "
                                "gateway. Unable to complete operation"))
        connection_attrs = set(network_mapping_info.keys())
        if not connection_attrs.issubset(ALLOWED_CONNECTION_ATTRIBUTES):
            raise exceptions.InvalidInput(
                error_message=_("Invalid keys found among the ones provided "
                                "in the request body: %(connection_attrs)s."
                                % locals()))
        return network_id

    def prevent_network_gateway_port_deletion(self, context, port_id):
        """ Pre-deletion check.

        Ensures a port will not be deleted if is being used by a network
        gateway. In that case an exception will be raised.
        """
        port_db = self._get_port(context, port_id)
        if port_db['device_owner'] == DEVICE_OWNER_NET_GW_INTF:
            raise NetworkGatewayPortInUse(port_id=port_id,
                                          device_owner=port_db['device_owner'])

    def create_network_gateway(self, context, network_gateway):
        gw_data = network_gateway[self.resource]
        tenant_id = self._get_tenant_id_for_create(context, gw_data)
        with context.session.begin(subtransactions=True):
            gw_db = NetworkGateway(
                id=gw_data.get('id') or utils.str_uuid(),
                tenant_id=tenant_id,
                name=gw_data.get('name'))
            # Create records for gateway devices
            devices = gw_data.get('devices') or []
            for device in devices:
                gw_db.devices.append(
                    NetworkGatewayDevice(**device))
            context.session.add(gw_db)
        LOG.debug(_("Created network gateway with id:%s" % gw_db['id']))
        return self._make_network_gateway_dict(gw_db)

    def update_network_gateway(self, context, id, network_gateway):
        gw_data = network_gateway[self.resource]
        with context.session.begin(subtransactions=True):
            gw_db = self._get_network_gateway(context, id)
            # Ensure there is something to update before doing it
            db_values_set = set([v for (k, v) in gw_db.iteritems()])
            if not set(gw_data.values()).issubset(db_values_set):
                gw_db.update(gw_data)
        LOG.debug(_("Updated network gateway with id:%s" % id))
        return self._make_network_gateway_dict(gw_db)

    def get_network_gateway(self, context, id, fields=None):
        gw_db = self._get_network_gateway(context, id)
        return self._make_network_gateway_dict(gw_db, fields)

    def delete_network_gateway(self, context, id):
        with context.session.begin(subtransactions=True):
            gw_db = self._get_network_gateway(context, id)
            if gw_db.network_connections:
                raise GatewayInUse(gateway_id=id)
            context.session.delete(gw_db)
        LOG.debug(_("Network gateway '%s' was destroyed." % id))

    def get_network_gateways(self, context, filters=None, fields=None):
        return self._get_collection(context, NetworkGateway,
                                    self._make_network_gateway_dict,
                                    filters=filters, fields=fields)

    def connect_network(self, context, network_gateway_id,
                        network_mapping_info):
        network_id = self._validate_network_mapping_info(network_mapping_info)
        LOG.debug(_("Connecting network '%(network_id)s' to gateway "
                    "'%(network_gateway_id)s'" % locals()))
        try:
            with context.session.begin(subtransactions=True):
                gw_db = self._get_network_gateway(context, network_gateway_id)
                tenant_id = self._get_tenant_id_for_create(context, gw_db)
                # TODO(salvatore-orlando): This will give the port a fixed_ip,
                # but we actually do not need any. Instead of wasting an IP we
                # should have a way to say a port shall not be associated with
                # any subnet
                try:
                    # We pass the segmenetation type and id too - the plugin
                    # might find them useful as the network connection object
                    # does not exist yet.
                    # NOTE: they're not extended attributes, just extra data
                    # passed in the port structure to the plugin
                    port = self.create_port(context, {
                        'port':
                        {'tenant_id': tenant_id,
                         'network_id': network_id,
                         'mac_address': attributes.ATTR_NOT_SPECIFIED,
                         'admin_state_up': True,
                         'fixed_ips': attributes.ATTR_NOT_SPECIFIED,
                         'device_id': network_gateway_id,
                         'device_owner': DEVICE_OWNER_NET_GW_INTF,
                         'name': '',
                         'gw:segmentation_type':
                         network_mapping_info.get('segmentation_type'),
                         'gw:segmentation_id':
                         network_mapping_info.get('segmentation_id')}})
                except exceptions.NetworkNotFound:
                    err_msg = _("Requested network '%(network_id)s' not found."
                                "Unable to create network connection on "
                                "gateway '%(network_gateway_id)s" % locals())
                    LOG.error(err_msg)
                    raise exceptions.InvalidInput(error_message=err_msg)
                port_id = port['id']
                LOG.debug(_("Gateway port for '%(network_gateway_id)s' "
                            "created on network '%(network_id)s':%(port_id)s"
                            % locals()))
                # Create NetworkConnection record
                network_mapping_info['port_id'] = port_id
                network_mapping_info['tenant_id'] = tenant_id
                gw_db.network_connections.append(
                    NetworkConnection(**network_mapping_info))
                # now deallocate the ip from the port
                for fixed_ip in port.get('fixed_ips', []):
                    db_base_plugin_v2.QuantumDbPluginV2._delete_ip_allocation(
                        context, network_id,
                        fixed_ip['subnet_id'],
                        fixed_ip['ip_address'])
                LOG.debug(_("Ensured no Ip addresses are configured on port "
                            "'%(port_id)s'" % locals()))
                return {'connection_info':
                        {'network_gateway_id': network_gateway_id,
                         'network_id': network_id,
                         'port_id': port_id}}
        except sa_exc.IntegrityError as e:
            # Verify if it is an error we might expect
            # TODO(salvatore-orlando): come one, you can do better than this!
            if 'columns' in str(e.orig) and 'not unique' in str(e.orig):
                LOG.error(_("Attempted to map network '%(network_id)s' with "
                            "parameters already in use"))
                raise GatewayConnectionInUse(gateway_id=network_gateway_id)
            # Else re-raise
            raise

    def disconnect_network(self, context, network_gateway_id,
                           network_mapping_info):
        network_id = self._validate_network_mapping_info(network_mapping_info)
        LOG.debug(_("Connecting network '%(network_id)s' to gateway "
                    "'%(network_gateway_id)s'" % locals()))
        with context.session.begin(subtransactions=True):
            # Uniquely identify connection, otherwise raise
            filters = {'network_gateway_id': [network_gateway_id]}
            for k, v in network_mapping_info.iteritems():
                if v:
                    filters[k] = [v]
            net_connections = self._get_collection(
                context, NetworkConnection, lambda x, _1: x, filters=filters)
            if not net_connections:
                raise GatewayConnectionNotFound(
                    network_mapping_info=network_mapping_info,
                    network_gateway_id=network_gateway_id)
            if len(net_connections) > 1:
                raise MultipleGatewayConnections(
                    gateway_id=network_gateway_id)
            # Remove gateway port from network
            # FIXME(salvatore-orlando): Ensure state of port in NVP is
            # consistent with outcome of transaction
            self.delete_port(context, net_connections[0]['port_id'],
                             nw_gw_port_check=False)
            # Remove NetworkConnection record
            context.session.delete(net_connections[0])
