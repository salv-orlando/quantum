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

from quantum.api.v2 import attributes

EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {
        'port_security': {'allow_post': True, 'allow_put': True,
                          'validate': {'type:values': ['off',
                                                       'mac',
                                                       'mac_ip']},
                          'default': attributes.ATTR_NOT_SPECIFIED,
                          'is_visible': True},
    }
}


class Portsecurity(object):
    """Extension class supporting port security
    """

    @classmethod
    def get_name(cls):
        return "Port Security"

    @classmethod
    def get_alias(cls):
        return "port_security"

    @classmethod
    def get_description(cls):
        return "Provides port security"

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/provider/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2012-07-23T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
