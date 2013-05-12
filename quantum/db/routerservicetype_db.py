# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 VMware, Inc.  All rights reserved.
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
# @author: Kaiwei Fan, VMware, Inc

import sqlalchemy as sa

from quantum.db import model_base
from quantum.extensions import routerservicetype as rst


class RouterServiceProviderBinding(model_base.BASEV2):
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id', ondelete="CASCADE"),
                          primary_key=True)
    service_provider_id = sa.Column(sa.String(36),
                                    sa.ForeignKey('serviceproviders.id'),
                                    nullable=False)


class RouterServiceTypeDbMixin(object):
    """Mixin class to add service providers to a router."""

    def _process_create_router_service_provider_id(self, context, router):
        with context.session.begin(subtransactions=True):
            db = RouterServiceProviderBinding(
                router_id=router['id'],
                service_provider_id=router[rst.SERVICE_PROVIDER_ID])
            context.session.add(db)
        return self._make_router_service_provider_id_dict(db)

    def _extend_router_service_provider_id_dict(self, context, router):
        rsbind = self._get_router_service_provider_id_binding(
            context, router['id'])
        if rsbind:
            router[rst.SERVICE_PROVIDER_ID] = rsbind['service_provider_id']

    def _get_router_service_provider_id_binding(self, context, router_id):
        query = self._model_query(context, RouterServiceProviderBinding)
        query = query.filter_by(router_id=router_id)
        return query.first()

    def _make_router_service_provider_id_dict(self, router_service_provider):
        res = {
            'router_id': router_service_provider['router_id'],
            'service_provider_id':
            router_service_provider[rst.SERVICE_PROVIDER_ID]
        }
        return self._fields(res, None)
