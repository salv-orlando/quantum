"""
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Nicira Networks, Inc.  All rights reserved.
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
# @author: Dave Lapsley, Nicira Networks, Inc
#
"""


def get_view_builder(req):
    """Get view builder."""
    base_url = req.application_url
    return ViewBuilder(base_url)


class ViewBuilder(object):
    """
    ViewBuilder for securitygroups. Derived from quantum.views.networks
    """
    def __init__(self, base_url):
        """
        :param base_url: url of the root wsgi application
        """
        self.base_url = base_url

    def build(self, securitygroup_data, is_detail=False):
        """Generic method used to generate a securitygroup entity.

        Only returns data dictionaries (not tagged with to plevel
        security group tag).
        """
        if is_detail:
            return self._build_detail(securitygroup_data)
        return self._build_simple(securitygroup_data)

    def _build_simple(self, securitygroup_data):
        """Return a simple description of a securitygroup"""
        return dict(securitygroup=dict(id=securitygroup_data['id']))

    def _build_detail(self, securitygroup_data):
        """Return detailed view of a securitygroup."""
        rules = [dict(securityrule=r)
                 for r in securitygroup_data.get('securityrules', [])]
        ports = [dict(port=p)
                 for p in securitygroup_data.get('ports', [])]
        return dict(securitygroup=dict(id=securitygroup_data['id'],
                    name=securitygroup_data.get('name'),
                    securityrules=rules,
                    ports=ports))
