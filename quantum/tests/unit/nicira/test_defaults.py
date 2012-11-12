# Copyright 2012 Nicira Networks, Inc.
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

import unittest2 as unittest

from quantum.openstack.common import cfg
from quantum.plugins.nicira.nicira_nvp_plugin.common import config


class ConfigurationTest(unittest.TestCase):

    def test_defaults(self):
        self.assertEqual('sqlite://', cfg.CONF.DATABASE.sql_connection)
        self.assertEqual(-1, cfg.CONF.DATABASE.sql_max_retries)
        self.assertEqual(2, cfg.CONF.DATABASE.reconnect_interval)
        self.assertEqual(64, cfg.CONF.NVP.max_lp_per_bridged_ls)
        self.assertEqual(256, cfg.CONF.NVP.max_lp_per_overlay_ls)
        self.assertEqual(5, cfg.CONF.NVP.concurrent_connections)
        self.assertEqual(240, cfg.CONF.NVP.failover_time)
