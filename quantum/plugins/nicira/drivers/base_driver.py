# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Openstack Foundation
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
#

from quantum.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class BaseDriver(object):
    """Base interface for all Nicira NVP/NSX drivers."""

    def get_network_status(self, network_id):
        LOG.debug(_("Retrieving status for network:%s"), network_id)

    def get_port_status(self, context, port_id, network_id):
        LOG.debug(_("Retrieving status for port:%s"), port_id)

    def get_networks_status(self, tenant_id):
        LOG.debug(_("Retrieving status for networks belonging to :%s"),
                  tenant_id)

    def create_network(self, context, tenant_id, network_data):
        """Post-DB commit operations."""
        LOG.debug(_("Creating network:%s"), network_data['id'])

    def update_network(self, tenant_id, network_data):
        """Post-DB commit operations."""
        LOG.debug(_("Updating network:%s"), network_data['id'])

    def delete_network(self, context, network_data):
        """Post-DB commit operations."""
        LOG.debug(_("Deleting network:%s"), network_data['id'])

    def create_port(self, context, port_data, network):
        """Post-DB commit operations."""
        LOG.debug(_("Creating port:%s"), port_data['id'])

    def delete_port(self, context, port_data):
        LOG.debug(_("Removing port:%s"), port_data['id'])
