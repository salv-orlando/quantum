# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 VMware, Inc.
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

import sys

from kombu import Queue
from oslo.config import cfg

from neutron.common import config
from neutron.openstack.common.rpc.impl_kombu import kombu_opts
from neutron.plugins.nicira.common import config as nicira_config
from neutron.plugins.nicira.common import nsx_utils


def _setup_openstack_conf():
    os_conf = cfg.CONF
    cfg.CONF.register_opts(kombu_opts)
    nicira_config.register_sync_opts()
    os_conf(project='neutron')
    config.setup_logging(os_conf)
    return os_conf

# The command line will contain celery config options which
# should not be passed to the openstack config parser
argv_bk = sys.argv[:]
sys.argv = sys.argv[:1]
os_conf = _setup_openstack_conf()
# Build broker URL from Neutron configuration
broker_str = ('amqp://%(user)s:%(password)s@%(host)s:%(port)s' %
              {'user': os_conf.rabbit_userid,
               'password': os_conf.rabbit_password,
               'host': os_conf.rabbit_host,
               'port': os_conf.rabbit_port})
# Restore sys.argv to allow celery to process command line args
sys.argv = argv_bk
nsx_celery_app = nsx_utils.get_nsx_celery_app(broker_str)


def main():
    # Celery configuration for this app
    nsx_celery_app.conf.update(
        CELERY_TASK_RESULT_EXPIRES=60,
        CELERY_QUEUES=(Queue('nsx_tasks'),),
        CELERY_DEFAULT_EXCHANGE=cfg.CONF.NSX_SYNC.base_exchange_name,
        CELERY_RESULT_EXCHANGE=('%s_results' %
                                cfg.CONF.NSX_SYNC.base_exchange_name),
        CELERY_DEFAULT_QUEUE='nsx_tasks',
        #CELERYBEAT_SCHEDULE={
        #    'synchronize_ports': {
        #        'task': ('neutron.plugins.nicira.nsx_handlers.'
        #                 'nsx_tasks.synchronize_ports'),
        #        'schedule': timedelta(milliseconds=2550), },}
    )
    nsx_celery_app.start()
