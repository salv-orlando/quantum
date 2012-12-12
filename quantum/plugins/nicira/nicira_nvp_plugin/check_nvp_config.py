#!/usr/bin/env python
# Copyright 2012 Nicira, Inc.
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless equired by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# @author: Aaron Rosen, VMware


import sys

from quantum.common import config
import quantum.plugins.nicira.nicira_nvp_plugin.NvpApiClient as NvpApiClient
import quantum.plugins.nicira.nicira_nvp_plugin.nvplib as nvplib
from quantum.plugins.nicira.nicira_nvp_plugin import QuantumPlugin


def help():
    print "Usage ./check_nvp_config path/to/nvp.ini"
    exit(1)


def display_controller_info(controller):
    print "\tCan login: %s" % controller.get('can_login')
    print "\tuser: %s" % controller.get('user')
    print "\tpassword: %s" % controller.get('password')
    print "\tip: %s" % controller.get('ip')
    print "\tport: %s" % controller.get('port')
    print "\trequested_timeout: %s" % controller.get('requested_timeout')
    print "\tretires: %s" % controller.get('retries')
    print "\tredirects: %s" % controller.get('redirects')
    print "\thttp_timeout: %s" % controller.get('http_timeout')


def test_controller(cluster, controller):
    api_providers = [(controller.get('ip'), controller.get('port'), True)]
    api_client = NvpApiClient.NVPApiHelper(
        api_providers, cluster.user, cluster.password,
        controller.get('requested_timeout'),
        controller.get('http_timeout'),
        controller.get('retries'),
        controller.get('redirects'))

    controller['can_login'] = (api_client.login() and True or False)


def main(argv):
    if len(sys.argv) != 2:
        help()
    args = ['--config-file']
    args.append(sys.argv[1])
    config.parse(args)
    db_opts, nvp_opts, clusters_opts = QuantumPlugin.parse_config()
    print "-----------Database Options--------------------"
    print "sql_connection: %s" % db_opts.get('sql_connection')
    print "reconnect_interval: %d" % db_opts.get('reconnect_interval')
    print "sql_max_retries: %d" % db_opts.get('sql_max_retries')
    print "-----------NVP Options--------------------"
    print ("Number of concurrents allow to each controller %d" %
           nvp_opts.concurrent_connections)
    print "NVP Generation Timeout %d" % nvp_opts.nvp_gen_timeout
    print "NVP Default Cluster Name %s" % nvp_opts.default_cluster_name

    print "-----------Cluster Options--------------------"
    if not len(clusters_opts):
        print "No NVP Clusters detected in nvp.ini!"
        exit(1)
    clusters, default_cluster = QuantumPlugin.parse_clusters_opts(
        clusters_opts, nvp_opts.concurrent_connections,
        nvp_opts.nvp_gen_timeout, nvp_opts.default_cluster_name)
    for cluster in clusters.itervalues():
        num_controllers = cluster.get_num_controllers()
        print "\n%d controllers found in cluster [CLUSTER:%s]" % (
            num_controllers, cluster.name)
        if num_controllers == 0:
            print ("Cluster %s has no nvp_controller_connection defined!" %
                   cluster.name)
            exit(1)

        for i in range(0, num_controllers):
            controller = cluster.get_controller(i)
            if i == 0:
                controller.update(nvplib.check_cluster_connectivity(cluster))
                print ("\n\tdefault_tz_uuid: %s" %
                       controller.get('default_tz_uuid'))
                print ("\tapi_redirect_interval: %s" %
                       controller.get('api_redirect_interval'))
                print "\tcluster uuid: %s" % controller.get('uuid')
                print "\tapi_mode: %s" % controller.get('api_mode')
                print ("\tdefault_l3_gw_uuid: %s" %
                       controller.get('default_l3_gw_uuid'))
            print ("\n-----controller %d------\n" % (i + 1))
            test_controller(cluster, controller)
            display_controller_info(controller)
        print "\n"

main(sys.argv)
