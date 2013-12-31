# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 VMware, Inc.
# All Rights Reserved
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

from oslo.config import cfg

from neutron.plugins.nicira.nsx_handlers import async_handlers
from neutron.plugins.nicira.nsx_handlers import sync_handlers


class NsxSynchronizationHandlers(object):
    """Handler functions for operations on NSX backend.

    This class provides functions for handling Neutron operations on
    the NSX backend. It is meant to be used by the Neutron plugin once
    the DB operations are successfully completed, or before the DB
    operation takes place. The actual implementation of the handler
    could then be either synchronous or asynchronous, according to
    the value of the configuration parameter NSX_SYNC.enable_async_tasks.

    NOTE: Synchronous operations are still provided for backward
    compatibility with releases up to Havana; however they are scheduled
    for deprecation and removal.
    """

    def __init__(self):
        """Initialize NSX synchronization handlers."""
        if cfg.CONF.NSX_SYNC.enable_async_tasks:
            # TODO(salv-orlando): Verify that there are workers
            # ready to process requests
            self.handle_create_security_group_delegate = (
                async_handlers.create_security_group_handler)
            self.handle_delete_security_group_delegate = (
                async_handlers.delete_security_group_handler)
            self.handle_create_security_group_rules_delegate = (
                async_handlers.create_security_group_rules_handler)
            self.handle_delete_security_group_rule_delegate = (
                async_handlers.delete_security_group_rule_handler)
        else:
            self.handle_create_security_group_delegate = (
                sync_handlers.create_security_group_handler)
            self.handle_delete_security_group_delegate = (
                sync_handlers.delete_security_group_handler)
            self.handle_create_security_group_rules_delegate = (
                sync_handlers.create_security_group_rules_handler)
            self.handle_delete_security_group_rule_delegate = (
                sync_handlers.delete_security_group_rule_handler)

    def handle_create_security_group(self, plugin, context,
                                     security_group_data):
        self.handle_create_security_group_delegate(
            plugin, context, security_group_data)

    def handle_delete_security_group(self, plugin, context,
                                     security_group_id):
        self.handle_delete_security_group_delegate(
            plugin, context, security_group_id)

    def handle_create_security_group_rules(self, plugin, context,
                                           security_group_id, new_rules):
        self.handle_create_security_group_rules_delegate(
            plugin, context, security_group_id, new_rules)

    def handle_delete_security_group_rule(self, plugin, context,
                                          security_group_id, rule_id):
        self.handle_delete_security_group_rule_delegate(
            plugin, context, security_group_id, rule_id)
