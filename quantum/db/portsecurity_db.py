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

import logging

import sqlalchemy as sa
from sqlalchemy.orm import exc

from quantum.api.v2 import attributes
from quantum.db import l3_db
from quantum.db import model_base
from quantum.extensions import portsecurity as psec
from quantum.openstack.common import cfg

LOG = logging.getLogger(__name__)


class PortSecurityBinding(model_base.BASEV2):
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    security_type = sa.Column(sa.Enum(
        'off', 'mac', 'mac_ip', name='portsecuritybindings_security_type'))


class PortSecurityDbMixin(object):
    """Mixin class to add  port security."""

    def _validate_port_security(self, context, port):
        net_info = self._get_network(context, port['network_id'])
        server_policy = cfg.CONF.PORTSECURITY.require_port_security
        has_ip = self._ip_on_port(port)
        has_mac = self._mac_on_port(port)
        port_security = port.get(psec.PORTSECURITY)
        if port_security == attributes.ATTR_NOT_SPECIFIED:
            port_security = 'off'
        # Do not apply port security to DHCP and router ports
        if port.get('device_owner') in ('network:dhcp',
                                        l3_db.DEVICE_OWNER_ROUTER_INTF,
                                        l3_db.DEVICE_OWNER_ROUTER_GW,
                                        l3_db.DEVICE_OWNER_FLOATINGIP):
            return port_security
        if ((server_policy == 'shared' or server_policy == 'both') and
            net_info['shared']):
            if not has_ip:
                raise psec.PortSecurityMissingMacIp()
            elif port_security != 'mac_ip':
                raise psec.PortSecurityRequiredToCreatePortSharedNetwork()

        elif ((server_policy == 'both' or server_policy == 'private') and
              not net_info['shared']):
            if not has_ip:
                raise psec.PortSecurityMissingMacIp()
            elif port_security != 'mac_ip':
                raise psec.PortSecurityRequiredToCreatePort()

        if port_security == 'mac' and not has_mac:
            raise psec.PortSecurityMissingMac()
        elif port_security == 'mac_ip' and not has_ip:
            raise psec.PortSecurityNoMacIp()
        if server_policy is False:
            if (not port_security or
                port_security == attributes.ATTR_NOT_SPECIFIED):
                port_security = 'off'

        return port_security

    def _mac_on_port(self, port):
        if not port.get('mac_address'):
            return False
        else:
            return True

    def _ip_on_port(self, port):
        fixed_ips = port.get('fixed_ips')
        if not fixed_ips:
            return False
        for fixed_ip in fixed_ips:
            if not fixed_ip.get('ip_address'):
                return False
        return True

    def _process_port_security_create(self, context, port):
        with context.session.begin(subtransactions=True):
            port_security_binding = PortSecurityBinding(
                port_id=port['id'],
                security_type=port[psec.PORTSECURITY])
            context.session.add(port_security_binding)
        return self._make_port_security_dict(port_security_binding)

    def _delete_port_security_bindings(self, context, port_id):
        query = self._model_query(context, PortSecurityBinding)
        binding = query.filter(
            PortSecurityBinding.port_id == port_id).one()
        with context.session.begin(subtransactions=True):
            context.session.delete(binding)

    def _make_port_security_dict(self, port, fields=None):
        res = {'port_id': port['port_id'],
               'security_type': port['security_type']}
        return self._fields(res, fields)

    def _extend_port_dict_port_security(self, context, port):
        port[psec.PORTSECURITY] = self._get_port_security_binding(
            context, port['id'])

    def _get_port_security_binding(self, context, port_id):
        try:
            query = self._model_query(context, PortSecurityBinding)
            binding = query.filter(
                PortSecurityBinding.port_id == port_id).one()
        except exc.NoResultFound:
            raise psec.PortSecurityBindingNotFound(port_id=port_id)
        return binding['security_type']
