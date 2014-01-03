# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2014 VMware.  All rights reserved.
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


STATUS = 'status'
EXTENDED_ATTRIBUTES_2_0 = {
    'security_groups': {
        STATUS: {'allow_post': False, 'allow_put': False,
                 'is_visible': True},
    }
}


class Securitygroupstatus(object):
    """Extension class supporting status for security groups."""

    @classmethod
    def get_name(cls):
        return "Security Group Status"

    @classmethod
    def get_alias(cls):
        return "sec-group-status"

    @classmethod
    def get_description(cls):
        return "Provides operational status for security groups"

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/secgroupstatus/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2014-01-02-1T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        return []

    def get_required_extensions(self):
        return ["security-group"]

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
