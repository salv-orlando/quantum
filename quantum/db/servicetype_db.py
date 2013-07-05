# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2013 OpenStack Foundation.
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
#    under the License.
#
#    @author: Salvatore Orlando, VMware
#

from oslo.config import cfg
import sqlalchemy as sa
from sqlalchemy.orm import exc as orm_exc

from quantum.common import exceptions as q_exc
from quantum import context
from quantum.db import api as db
from quantum.db import db_base_plugin_v2 as base_plugin
from quantum.db import model_base
from quantum.db import models_v2
from quantum.openstack.common.db import exception as db_exc
from quantum.openstack.common import log as logging
from quantum.plugins.common import constants

LOG = logging.getLogger(__name__)

serviceprovider_opts = [
    cfg.MultiStrOpt('service_provider', default=[],
                    help=_('Defines providers for advanced services '
                           'using the format: '
                           '<service_type>:<name>:<driver>[:default]'))
]

cfg.CONF.register_opts(serviceprovider_opts, 'service_providers')


def parse_service_provider_opt():
    """Parse service definition opts and returns result."""
    svc_providers_opt = cfg.CONF.service_providers.service_provider
    res = []
    for prov_def in svc_providers_opt:
        split = prov_def.split(':')
        svc_type = split[0]
        name = split[1]
        driver = split[2]
        try:
            default = split[3] == 'default'
        except IndexError:
            default = False
        if svc_type not in constants.ALLOWED_SERVICES:
            msg = _("Service type '%s' is not allowed") % svc_type
            LOG.error(msg)
            raise q_exc.Invalid(msg)
        res.append({'service_type': svc_type,
                    'name': name,
                    'driver': driver,
                    'default': default})
    return res


class ServiceProviderNotFound(q_exc.NotFound):
    message = _("Service provider %(service_prov_id)s could not be found")


class DefaultServiceProviderNotFound(ServiceProviderNotFound):
    message = _("Service type %(service_type)s does not have a default "
                "service provider")


class ServiceProvider(model_base.BASEV2, models_v2.HasId):
    service_type = sa.Column(sa.String(36), nullable=False)
    name = sa.Column(sa.String(36), nullable=False)
    driver = sa.Column(sa.String(255), nullable=False, unique=True)
    default = sa.Column(sa.Boolean, nullable=False, default=False)
    __table_args__ = (sa.UniqueConstraint('service_type', 'name',
                                          name='uniq_serviceproviders0'
                                          'service_type0name'),)


class ProviderResourceAssociation(model_base.BASEV2):
    provider_id = sa.Column(sa.String(36),
                            sa.ForeignKey("serviceproviders.id",
                                          ondelete="CASCADE"),
                            nullable=False, primary_key=True)
    # should be manualy deleted on resource deletion
    resource_id = sa.Column(sa.String(36), nullable=False, primary_key=True)
    __table_args__ = (sa.UniqueConstraint('provider_id', 'resource_id',
                                          name='uniq_provider'
                                          'resourceassociations0'
                                          'provider_id0resource_id'),)


class ServiceTypeManager(base_plugin.CommonDbMixin):
    """Manage service type objects in Quantum database."""

    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self._initialize_db()
        self.sync_svc_provider_conf_with_db()

    def _initialize_db(self):
        db.configure_db()
        # Register models for service type management
        # Note this might have been already done if configure_db also
        # created the engine
        db.register_models(models_v2.model_base.BASEV2)

    def sync_svc_provider_conf_with_db(self, ctx=None):
        """Synchs configuration with the database."""
        # Use getattr as the member might not have been defined yet
        if getattr(self, 'db_synchronized', False):
            return
        LOG.debug(_("Synchronizing service provider "
                    "configuration with database"))
        if not ctx:
            ctx = context.get_admin_context()
        # collect existing entries, excluding reference providers
        existing_qry = ctx.session.query(ServiceProvider.service_type,
                                         ServiceProvider.name)
        existing = [(svc_type, name) for svc_type, name in existing_qry]

        svc_providers = parse_service_provider_opt()
        conf = [(prov_def['service_type'],
                 prov_def['name']) for prov_def in svc_providers]
        # collect entries to delete
        to_delete = [(svc_type, name) for svc_type, name in existing
                     if (svc_type, name) not in conf]

        # add/update existing providers
        with ctx.session.begin(subtransactions=True):
            for prov in svc_providers:
                self._add_service_provider(ctx, prov)

            # deleting entries absent in conf
            for svc_type, name in to_delete:
                prov_db = (ctx.session.query(ServiceProvider).
                           filter_by(service_type=svc_type).
                           filter_by(name=name).one())
                ctx.session.delete(prov_db)
        self.db_synchronized = True

    def _add_service_provider(self, context, prov):
        """Adds or updates service provider in the database."""
        with context.session.begin(subtransactions=True):
            try:
                prov_db = (context.session.query(ServiceProvider).
                           filter_by(name=prov['name']).
                           filter_by(service_type=prov['service_type']).
                           one())
                prov_db.update(prov)
                try:
                    context.session.flush()
                except db_exc.DBDuplicateEntry:
                    msg = (_("Driver %s is not unique across providers") %
                           prov['driver'])
                    LOG.exception(msg)
                    raise q_exc.Invalid(msg)
            except orm_exc.NoResultFound:
                #ensure only one default provider is added for given service
                if prov['default']:
                    exists = (context.session.query(ServiceProvider).
                              filter_by(service_type=prov['service_type']).
                              filter_by(default=True).first())
                    if exists:
                        msg = _("Multiple default providers "
                                "for service %s") % prov['service_type']
                        LOG.exception(msg)
                        raise q_exc.Invalid(msg)
                svc_provider = ServiceProvider(
                    service_type=prov['service_type'],
                    name=prov['name'],
                    driver=prov['driver'],
                    default=prov['default']
                )
                context.session.add(svc_provider)
                try:
                    context.session.flush()
                except db_exc.DBDuplicateEntry:
                    msg = (_("Driver %s is not unique across providers") %
                           prov['driver'])
                    LOG.exception(msg)
                    raise q_exc.Invalid(msg)

    def get_service_providers(self, context, filters=None, fields=None):
        return self._get_collection(context, ServiceProvider,
                                    self._make_svc_provider_dict,
                                    filters, fields)

    def _get_service_provider(self, context, id):
        query = context.session.query(ServiceProvider).filter_by(id=id)
        try:
            return query.one()
        except orm_exc.NoResultFound:
            raise ServiceProviderNotFound(service_prov_id=id)

    def get_service_provider(self, context, id, fields=None):
        return self._make_svc_provider_dict(
            self._get_service_provider(context, id),
            fields
        )

    def get_default_service_provider(self, context, service_type):
        """Return the default provider for a given service type."""
        filters = {'service_type': [service_type],
                   'default': [True]}
        providers = self.get_service_providers(context, filters=filters)
        # By construction we expect at most a single item in provider
        if not providers:
            raise DefaultServiceProviderNotFound(service_type=service_type)
        return providers[0]

    def _make_svc_provider_dict(self, svc_prov, fields=None):
        res = {'id': svc_prov['id'],
               'service_type': svc_prov['service_type'],
               'name': svc_prov['name'],
               'driver': svc_prov['driver'],
               'default': svc_prov['default']
               }
        return self._fields(res, fields)

    def add_resource_association(self, context, prov_id,
                                 resource_id):
        with context.session.begin(subtransactions=True):
            assoc = ProviderResourceAssociation(provider_id=prov_id,
                                                resource_id=resource_id)
            context.session.add(assoc)
