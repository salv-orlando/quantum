# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Nicira Networks, Inc
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

""" NVP Plugin exceptions """

from quantum.common import exceptions as q_exc


class NvpPluginException(q_exc.QuantumException):
    message = _("An unexpected error occurred in the NVP Plugin:%(err_desc)s")


class NvpInvalidConnection(NvpPluginException):
    message = _("Invalid NVP connection parameters: %(conn_params)s")


class NvpInvalidNovaZone(NvpPluginException):
    message = _("Unable to find cluster config entry "
                "for nova zone: %(nova_zone)s")


#TODO(salvatore-orlando): Consider moving this exception to quamtum.common
class NvpPortSecurityNoIpException(NvpPluginException):
    messsage = _("No IP configured on port %(port)s for applying "
                 "port security policy")


class NvpNoMorePortsException(NvpPluginException):
    message = _("Unable to create port on network %(network)s. "
                "Maximum number of ports reached")


class NvpOutOfSyncException(NvpPluginException):
    message = _("Quantum and NVP Databases are out of Sync!")


class NvpResourceNotFound(NvpPluginException):
    message = _("The NVP %(nvp_resource_type)s corresponding to the Quantum "
                "%(quantum_resource_type)s:%(quantum_id)s does not exist on "
                "the NVP platform")


class NvpNatRuleMismatch(NvpPluginException):
    message = _("While retrieving NAT rules, %(actual_rules)s where found "
                "whereas rules in the (%(min_rules)s,%(max_rules)s) interval "
                "were expected")
