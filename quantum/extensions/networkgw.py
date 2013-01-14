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

from abc import abstractmethod
import logging

from quantum.api.v2 import attributes
from quantum.api.v2 import base
from quantum.extensions import extensions
from quantum import manager
from quantum.openstack.common import cfg
from quantum import quota

LOG = logging.getLogger(__name__)

RESOURCE_NAME = "network-gateway"
COLLECTION_NAME = "%ss" % RESOURCE_NAME
EXT_ALIAS = RESOURCE_NAME
DEVICE_ID_ATTR = 'id'
IFACE_NAME_ATTR = 'interface_name'

# Attribute Map for Network Gateway Resource
# TODO(salvatore-orlando): add admin state as other quantum resources
RESOURCE_ATTRIBUTE_MAP = {
    COLLECTION_NAME: {
        'id': {'allow_post': False, 'allow_put': False,
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'is_visible': True, 'default': ''},
        'devices': {'allow_post': True, 'allow_put': False,
                    'validate': {'type:device_list': None},
                    'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True}
    }
}


def _validate_device_list(data, valid_values=None):
    """ Validate the list of service definitions. """
    if not data:
        # Devices must be provided
        msg = _("Cannot create a gateway with an empty device list")
        LOG.error(_("%(f_name)s:%(msg)s"),
                  {'f_name': _validate_device_list.__name__,
                   'msg': msg})
        return msg
    try:
        for device in data:
            try:
                # Do a copy of the original object so we can easily
                # pop out stuff from it
                device_copy = device.copy()
                # Validate 'device_id' attribute
                device_id = device_copy.get(DEVICE_ID_ATTR)
                err_msg = attributes._validate_regex(device_id,
                                                     attributes.UUID_PATTERN)
                if err_msg:
                    return(_("%s: %s") % (_validate_device_list.__name__,
                                          err_msg))
            except TypeError:
                LOG.exception(_("Exception while parsing device definition:%s"
                              % device))
                msg = _("Was expecting a dict for device definition, "
                        "found the following: %s") % device
                LOG.error(_("%(f_name)s:%(msg)s"),
                          {'f_name': _validate_device_list.__name__,
                           'msg': msg})
                return msg
    except TypeError:
        return _("%s: provided data are not iterable" %
                 _validate_device_list.__name__)

nw_gw_quota_opts = [
    cfg.IntOpt('quota_network_gateway',
               default=5,
               help='number of network gateways allowed per tenant, '
                    '-1 for unlimited')
]

cfg.CONF.register_opts(nw_gw_quota_opts, 'QUOTAS')

attributes.validators['type:device_list'] = _validate_device_list


class Networkgw(object):
    """ API extension for Layer-2 Gateway support.

    The Layer-2 gateway feature allows for connecting quantum networks
    with external networks at the layer-2 level. No assumption is made on
    the location of the external network, which might not even be directly
    reachable from the hosts where the VMs are deployed.

    This is achieved by instantiating 'network gateways', and then connecting
    Quantum network to them.
    """

    @classmethod
    def get_name(cls):
        return "Quantum-NVP Network Gateway"

    @classmethod
    def get_alias(cls):
        return EXT_ALIAS

    @classmethod
    def get_description(cls):
        return "Connects Quantum networks with external networks at layer 2"

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/quantum/network-gateway/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2012-11-30T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """ Returns Ext Resources """
        plugin = manager.QuantumManager.get_plugin()
        params = RESOURCE_ATTRIBUTE_MAP.get(COLLECTION_NAME, dict())

        member_actions = {'connect_network': 'PUT',
                          'disconnect_network': 'PUT'}

        # register quotas for network gateways
        quota.QUOTAS.register_resource_by_name(RESOURCE_NAME)

        controller = base.create_resource(COLLECTION_NAME,
                                          RESOURCE_NAME,
                                          plugin, params,
                                          member_actions=member_actions)
        return [extensions.ResourceExtension(COLLECTION_NAME,
                                             controller,
                                             member_actions=member_actions)]


class NetworkGatewayPluginBase(object):

    @abstractmethod
    def create_network_gateway(self, context, network_gateway):
        pass

    @abstractmethod
    def update_network_gateway(self, context, id, network_gateway):
        pass

    @abstractmethod
    def get_network_gateway(self, context, id, fields=None):
        pass

    @abstractmethod
    def delete_network_gateway(self, context, id):
        pass

    @abstractmethod
    def get_network_gateways(self, context, filters=None, fields=None):
        pass

    @abstractmethod
    def connect_network(self, context, network_gateway_id,
                        network_mapping_info):
        pass

    @abstractmethod
    def disconnect_network(self, context, network_gateway_id,
                           network_mapping_info):
        pass
