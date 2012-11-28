# Copyright (c) 2012 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from abc import abstractmethod

from quantum.api.v2 import attributes as attr
from quantum.api.v2 import base
from quantum.common import exceptions as qexception
from quantum.extensions import extensions
from quantum import manager


class DefaultQueueCreateNotAdmin(qexception.InUse):
    message = _("Need to be admin in order to create queue called default")


class DefaultQueueAlreadyExists(qexception.InUse):
    message = _("Default queue already exists.")


class QueueUpdateMustBeAdmin(qexception.InvalidInput):
    message = _("Need to be admin in order to update queue")


class QueueInvalidDscp(qexception.InvalidInput):
    message = _("Invalid for dscp %(data)s must be int.")


class QueueMinGreaterMax(qexception.InvalidInput):
    message = _("Invalid bandwidth rate min greater than max.")


class QueueInvalidBandwidth(qexception.InvalidInput):
    message = _("Invalid bandwidth rate %(data)s must be unsigned int.")


class MissingDSCPForTrusted(qexception.InvalidInput):
    message = _("No DSCP field needed when QoS workload marked trusted")


class QueueNotFound(qexception.NotFound):
    message = _("Queue %(id)s does not exist")


class QueueInUseByPort(qexception.InUse):
    message = _("Unable to delete queue attached to port.")


class QueuePortBindingNotFound(qexception.NotFound):
    message = _("Port is not associated with lqueue")


def convert_to_int(val):
    if val is None:
        return 0
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        msg = _("%s is not int") % val
        raise qexception.InvalidInput(error_message=msg)


#TODO Fix base.py so we can tell the user which field
# could not be converted correctly..
def _validate_type_unsigned_int(data, exception_to_raise):
    if data is None:
        return data
    try:
        int(data)
        if data < 0:
            raise ValueError
    except (ValueError, TypeError):
        raise exception_to_raise(data=data)


attr.validators['type:unsigned_int'] = _validate_type_unsigned_int

# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    'qos_queues': {
        'id': {'allow_post': False, 'allow_put': False,
               'is_visible': True},
        'default': {'allow_post': True, 'allow_put': False,
                    'convert_to': attr.convert_to_boolean,
                    'validate': {'type:boolean': None},
                    'is_visible': True, 'default': False},
        'name': {'allow_post': True, 'allow_put': False,
                 'is_visible': True, 'default': ''},
        'min': {'allow_post': True, 'allow_put': False,
                'is_visible': True, 'default': '0',
                'validate': {'type:unsigned_int': QueueInvalidBandwidth},
                'convert_to': convert_to_int},
        'max': {'allow_post': True, 'allow_put': False,
                'is_visible': True, 'default': None,
                'validate': {'type:unsigned_int': QueueInvalidBandwidth},
                'convert_to': convert_to_int},
        'qos_marking': {'allow_post': True, 'allow_put': False,
                        'validate': {'type:values': ['untrusted', 'trusted']},
                        'default': 'untrusted', 'is_visible': True},
        'dscp': {'allow_post': True, 'allow_put': False,
                 'is_visible': True, 'default': 0,
                 'validate': {'type:unsigned_int': QueueInvalidDscp},
                 'convert_to': convert_to_int},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
    },
}


QUEUE = 'queue_id'
EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {QUEUE: {'allow_post': False,
                      'allow_put': False,
                      'is_visible': True,
                      'default': False}},

    'networks': {QUEUE: {'allow_post': True,
                         'allow_put': True,
                         'is_visible': True,
                         'default': False}}

}


class Nvp_qos(object):
    """Port Queue extension"""

    @classmethod
    def get_name(cls):
        return "nvp-qos"

    @classmethod
    def get_alias(cls):
        return "nvp-qos"

    @classmethod
    def get_description(cls):
        return "The NVP Qos extension."

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/nvp-qos/api/v2.0"

    @classmethod
    def get_updated(cls):
        return "2012-10-05T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """ Returns Ext Resources """
        exts = []
        plugin = manager.QuantumManager.get_plugin()
        resource_name = 'qos_queue'
        collection_name = resource_name.replace('_', '-') + "s"
        params = RESOURCE_ATTRIBUTE_MAP.get(resource_name + "s", dict())
        controller = base.create_resource(collection_name,
                                          resource_name,
                                          plugin, params, allow_bulk=False)

        ex = extensions.ResourceExtension(collection_name,
                                          controller)
        exts.append(ex)

        return exts

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}


class QueuePluginBase(object):
    @abstractmethod
    def create_qos_queue(self, context, queue):
        pass

    @abstractmethod
    def delete_qos_queue(self, context, id):
        pass

    @abstractmethod
    def get_qos_queue(self, context, id, fields=None):
        pass

    @abstractmethod
    def get_qos_queues(self, context, filters=None, fields=None):
        pass
