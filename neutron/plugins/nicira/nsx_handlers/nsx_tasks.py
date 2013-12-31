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

import time

import celery
from oslo.config import cfg

from neutron.openstack.common import log
from neutron.openstack.common.rpc.impl_kombu import kombu_opts
from neutron.plugins.nicira.common import nsx_utils
from neutron.plugins.nicira import nsx_cluster
from neutron.plugins.nicira.nsxlib import security_profiles
from neutron.plugins.nicira import NvpApiClient


LOG = log.getLogger(__name__)
cfg.CONF.register_opts(kombu_opts)
broker_str = ('amqp://%(user)s:%(password)s@%(host)s:%(port)s' %
              {'user': cfg.CONF.rabbit_userid,
               'password': cfg.CONF.rabbit_password,
               'host': cfg.CONF.rabbit_host,
               'port': cfg.CONF.rabbit_port})
nsx_celery_app = nsx_utils.get_nsx_celery_app(broker_str)


class NsxTask(celery.Task):
    """Base class for NSX Tasks."""

    _cluster = None

    @property
    def cluster(self):
        if not self._cluster:
            self._cluster = nsx_cluster.NSXcluster.get_instance(cfg.CONF)
            if not self._cluster.api_client:
                nsx_utils.configure_nsx_cluster(
                    self._cluster,
                    cfg.CONF.NSX.concurrent_connections,
                    cfg.CONF.NSX_SYNC.nsx_gen_timeout)


@nsx_celery_app.task(base=NsxTask)
def synchronize_security_group(security_group_data,
                               is_create=False, is_delete=False):
    """Synchronizes a security group with the NSX backend.

    @param security_group_data Dict describing the security group
    being synchronized. Security group rules should have already
    been converted in the NSX format.
    @param is_create True if the security group must be created
    @param is_delete True if the security group must be delete

    @return NSX uuid of the synchronized security group
    """
    # Query for security group on backend
    # skip if explicitly instructed to create or delete
    # (I am not sure how safe is to allow the above)
    start = time.time()
    neutron_id = security_group_data.pop('id')
    if not (is_create or is_delete):
        try:
            nsx_uuid = security_group_data['nsx_uuid']
            security_profiles.get_security_profile(
                synchronize_security_group.cluster, nsx_uuid)
        except NvpApiClient.ResourceNotFound:
            # The default policy is to recreate the security
            # profile; chaining on the server side should ensure
            # out of order execution does not produce unexpected
            # results
            is_create = True
    # Create/update security profile
    if is_create:
        # If the neutron id or tenant id are not found we should raise
        tenant_id = security_group_data.pop('tenant_id')
        # The security group data structure has NSX-formatted rules
        nsx_resp = security_profiles.create_security_profile(
            synchronize_security_group.cluster,
            tenant_id,
            neutron_id,
            security_group_data)
        nsx_uuid = nsx_resp['uuid']
    elif is_delete:
        security_profiles.delete_security_profile(
            synchronize_security_group.clster, nsx_uuid)
    else:
        # Must update security group rules
        # Updates must always specify The whole list
        # of security profiles rules.
        # TODO(salv-orlando): support update for other security
        # profiles attributes
        rules = security_group_data.pop('security_group_rules')
        if rules:
            security_profiles.update_security_profile_rules(rules)
    # Always return NSX uuid of security profile
    elapsed = time.time() - start
    LOG.info(_("Task synchronize_security_group for neutron security "
               "group:%(sg_id)s completed in %(elapsed).3f"),
             {'sg_id': neutron_id, 'elapsed': elapsed})
    return nsx_uuid
