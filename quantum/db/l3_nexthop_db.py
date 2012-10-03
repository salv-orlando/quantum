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
"""

import logging
import sqlalchemy as sa
from sqlalchemy.orm import exc

from quantum.api.v2 import attributes
from quantum.db import l3_db
from quantum.db import model_base
from quantum.extensions import l3_nexthop
from quantum import policy

LOG = logging.getLogger(__name__)


class RouterNexthop(model_base.BASEV2):
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id', ondelete="CASCADE"),
                          primary_key=True)
    nexthop = sa.Column(sa.String(64))


class L3NexthopMixin(object):
    """ Utility functions for router nexthop management.

    To be used by classes inheriting from this mixin
    """

    def _check_nexthop_view_auth(self, context, network):
        return policy.check(context,
                            "extension:router_nexthop:view",
                            network)

    def _enforce_nexthop_set_auth(self, context, network):
        return policy.enforce(context,
                              "extension:router_nexthop:set",
                              network)

    def _router_nexthop(self, context, router_id):
        try:
            value = context.session.query(RouterNexthop).filter_by(
                router_id=router_id).one()
            return value.nexthop
        except exc.NoResultFound:
            return None

    def _extend_router_dict_nexthop(self, context, router):
        if self._check_nexthop_view_auth(context, router):
            router[l3_nexthop.NEXTHOP] = self._router_nexthop(
                context, router['id'])

    def _process_nexthop_create(self, context, router_data, router_id):
        nexthop = router_data.get(l3_nexthop.NEXTHOP)
        # TODO(salvatore-orlando): process default settings here!
        if not attributes.is_attr_set(nexthop):
            return
        self._enforce_nexthop_set_auth(context, router_data)
        if nexthop:
            context.session.add(RouterNexthop(router_id=router_id,
                                              nexthop=nexthop))

    def _process_nexthop_update(self, context, router_data, router_id):
        new_value = router_data.get(l3_nexthop.NEXTHOP)
        self._enforce_nexthop_set_auth(context, router_data)
        existing_value = self._router_nexthop(context, router_id)
        if existing_value == new_value:
            return
        if new_value:
            context.session.add(RouterNexthop(router_id=router_id,
                                              nexthop=new_value))
        else:
            # Remove the nexthop information
            context.session.query(RouterNexthop).filter_by(
                router_id=router_id).delete()

    def _filter_nexthop(self, context, routers, filters):
        vals = filters.get(l3_nexthop.NEXTHOP, [])
        if not vals:
            return routers
        query = context.session.query(RouterNexthop)
        negate = False
        if len(vals) > 0 and vals[0] != 'null':
            query = query.filter(RouterNexthop.nexthop.in_(vals))
        else:
            negate = True
        router_ids = set([nh['router_id'] for nh in query.all()])
        return [router for router in routers
                if (router['id'] in router_ids) != negate]
