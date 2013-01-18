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
from quantum.common import exceptions as qexception
from quantum.openstack.common import cfg


class PortSecurityRequiredToCreatePortSharedNetwork(qexception.InvalidInput):
    message = _("Cannot create port on shared network unless "
                "port_security='mac_ip is passed in.")


class PortSecurityRequiredToCreatePort(qexception.InvalidInput):
    message = _("Cannot create port unless "
                "port_security='mac_ip is passed in.")


class PortSecurityMissingMacIp(qexception.InvalidInput):
    message = _("Must specifiy a mac and a IP on port for this network.")


class PortSecurityMissingMac(qexception.InvalidInput):
    message = _("Port is missing mac address for port_security='mac'.")


class PortSecurityNoMacIp(qexception.InvalidInput):
    message = _("Cannot enable mac_ip port_security without"
                " mac and ip on port.")


class PortSecurityInvalidConfiguration(qexception.InvalidExtenstionEnv):
    message = _("Invalid configuration for Port Security on server.")


class PortSecurityUpdateNotAdmin(qexception.InvalidExtenstionEnv):
    message = _("Most be admin to remove port security on port")


class PortSecurityBindingNotFound(qexception.NotFound):
    message = _("Port Security binding not found for port %(port_id)s")


class PortSecurityNotEnabled(qexception.InvalidInput):
    message = _("Port Security must be enabled on port to add security group")


class PortSecurityIpRequired(qexception.InvalidInput):
    message = _("Port creation requires ip address.")


class PortSecurityMacIPRequired(qexception.InvalidInput):
    message = _("Port Security mac_ip requires ip address on port")


class SecurityGroupsOnPortCannotRemovePortSecurity(qexception.InvalidInput):
    message = _("Port security cannot be disabled as long as there is a"
                " security group configured on the port")


class NoPortSecurityWithSecurityGroups(qexception.InvalidInput):
    message = _("Cannot use security groups without port_security set to "
                "mac_ip")

PORTSECURITY = 'port_security'
EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {
        PORTSECURITY: {'allow_post': True, 'allow_put': True,
                       'validate': {'type:values': ['off',
                                                    'mac',
                                                    'mac_ip']},
                       'default': attributes.ATTR_NOT_SPECIFIED,
                       'is_visible': True},
    }
}

port_security_opts = [
    # require_port_security can be set to the following values:
    # False, private, shared, both. If set to False ports can be created
    # without port_security enabled. If set to private than ports on private
    # networks will be created with port security mac_ip and raise if there
    # is not an ip associated with the port. The same applies for shared and
    # both.
    cfg.StrOpt('require_port_security', default=False),
]
cfg.CONF.register_opts(port_security_opts, 'PORTSECURITY')


class Portsecurity(object):
    """Extension class supporting port security
    """

    @classmethod
    def get_name(cls):
        return "Port Security"

    @classmethod
    def get_alias(cls):
        return "port-security"

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
