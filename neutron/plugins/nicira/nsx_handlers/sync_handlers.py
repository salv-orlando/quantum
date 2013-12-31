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


from sqlalchemy.orm import exc as sa_orm_exc

from neutron.db import securitygroups_db as sg_db
from neutron.openstack.common import excutils
from neutron.openstack.common import log
from neutron.plugins.nicira.common import constants as nsx_constants
from neutron.plugins.nicira.common import exceptions as nsx_exc
from neutron.plugins.nicira.common import nsx_utils
from neutron.plugins.nicira.common import securitygroups as sg_utils
from neutron.plugins.nicira.dbexts import nicira_db
from neutron.plugins.nicira.nsxlib import security_profiles
from neutron.plugins.nicira import NvpApiClient

LOG = log.getLogger(__name__)


def _delete_security_group(plugin, context, sg_id):
    with context.session.begin(subtransactions=True):
        sg = plugin._get_security_group(context, sg_id)
        context.session.delete(sg)


def _db_rollback_security_group_rules(context, sg_id, original_rules):
    """Db-only routine for restoring rules for a security group."""
    with context.session.begin(subtransactions=True):
        # Ensure security group still exists before proceeding
        try:
            context.session.query(sg_db.SecurityGroup).filter(
                id == sg_id).one()
        except sa_orm_exc.NoResultFound:
            LOG.debug(_("Skipping DB rollback for security group:%s as it"
                        "is not present anymore in neutron DB"), sg_id)
            return
        context.session.query(sg_db.SecurityGroupRule).filter(
            sg_db.SecurityGroupRule.security_group_id == sg_id).delete(
                synchronize_session=False)
        for rule in original_rules:
            rule_db = sg_db.SecurityGroupRule(
                id=rule['id'], tenant_id=rule['tenant_id'],
                security_group_id=rule['security_group_id'],
                direction=rule['direction'],
                remote_group_id=rule.get('remote_group_id'),
                ethertype=rule['ethertype'],
                protocol=rule['protocol'],
                port_range_min=rule['port_range_min'],
                port_range_max=rule['port_range_max'],
                remote_ip_prefix=rule.get('remote_ip_prefix'))
            context.session.add(rule_db)


def create_security_group_handler(plugin, context, security_group_data):
    try:
        nvp_secgroup = security_profiles.create_security_profile(
            plugin.cluster,
            security_group_data['id'],
            security_group_data['tenant_id'],
            security_group_data)
        with context.session.begin(subtransactions=True):
            # Status for security groups immediately
            # transitions to ACTIVE for synchronous handlers
            plugin._set_security_group_status(
                context, security_group_data, nsx_constants.STATUS_ACTIVE)
            # Add mapping between neutron and nsx identifiers
            nicira_db.add_neutron_nsx_security_group_mapping(
                context.session,
                security_group_data['id'],
                nvp_secgroup['uuid'])

    except (NvpApiClient.ResourceNotFound, NvpApiClient.NvpApiException):
        # Security group must be removed from Neutron DB
        # This is a rollback-upon-create operation and therefore
        # there is no need to worry about the security group being the
        # default one or ports bound to it (as it's just been created, and
        # the API call has not yet returned).
        with excutils.save_and_reraise_exception():
            LOG.warn(_("Unable to create security group on NSX backend,"
                       "rolling back security group:%s on Neutron DB"),
                     security_group_data['id'])
            with context.session.begin(subtransactions=True):
                _delete_security_group(plugin,
                                       context,
                                       security_group_data['id'])


def delete_security_group_handler(plugin, context, security_group_id):
    nsx_sec_profile_id = nsx_utils.get_nsx_security_group_id(
        context.session, plugin.cluster, security_group_id)
    if nsx_sec_profile_id:
        plugin._set_security_group_status(
            context, {'id': security_group_id},
            nsx_constants.STATUS_PENDING_DELETE)
        try:
            security_profiles.delete_security_profile(
                plugin.cluster, nsx_sec_profile_id)
            # NSX operation succeeded; record can be safely destroyed
            _delete_security_group(plugin, context, security_group_id)
            # Ensure contents are written to the DB before returning
            context.session.flush()
        except NvpApiClient.ResourceNotFound:
            # The security profile was not found on the backend.
            # Do not fail in this case.
            LOG.warning(_("The NSX security profile %(sec_profile_id)s, "
                        "associated with the Neutron security group "
                        "%(sec_group_id)s was not found on the backend"),
                        {'sec_profile_id': nsx_sec_profile_id,
                            'sec_group_id': security_group_id})
        except NvpApiClient.NvpApiException:
            # Raise and fail the operation, as there is a problem which
            # prevented the sec group from being removed from the backend
            LOG.exception(_("An exception occurred while removing the "
                            "NSX security profile %(sec_profile_id)s, "
                            "associated with Neutron security group "
                            "%(sec_group_id)s"),
                          {'sec_profile_id': nsx_sec_profile_id,
                           'sec_group_id': security_group_id})
            plugin._set_security_group_status(
                context, {'id': security_group_id},
                nsx_constants.STATUS_ERROR)
            raise nsx_exc.NvpPluginException(
                _("Unable to remove security group %s from NSX backend"),
                security_group_id)
    else:
        LOG.info(_("Neutron security group %s was not removed from the "
                   "backend as no corresponding NSX security profile was "
                   "found."), security_group_id)


def _update_nsx_security_profile_safe(plugin, context, security_group_id,
                                      new_rules, existing_rules):
    nsx_sec_profile_id = nsx_utils.get_nsx_security_group_id(
        context.session, plugin.cluster, security_group_id)
    try:
        security_profiles.update_security_profile_rules(
            plugin.cluster, nsx_sec_profile_id, new_rules)
    except (NvpApiClient.ResourceNotFound, NvpApiClient.NvpApiException):
        # Operation on neutron DB must be manually rolled back as the backend
        # operation failed and the previous DB transaction was already
        # committed. As atomicity and isolation do not apply anymore, a
        # concurrent request might have deleted or altered records.
        # The current approach does not handle well updates, which are however
        # not yet supported for security group rules.
        with excutils.save_and_reraise_exception():
            LOG.warn(_("Unable to update security group on NSX backend,"
                       "rolling back security group:%s and its rules on "
                       "Neutron DB"), security_group_id)
            _db_rollback_security_group_rules(
                context,
                security_group_id,
                existing_rules)


def create_security_group_rules_handler(plugin, context, security_group_id,
                                        new_rules):
    # gather all the existing security group rules since we need all
    # of them to PUT to NSX.
    # Neutron's update process currently triggers the backend only
    # for security group rule changes
    existing_rules = plugin.get_security_group_rules(
        context, {'security_group_id': [security_group_id]})
    combined_rules = sg_utils.merge_security_group_rules_with_current(
        context.session, plugin.cluster, new_rules, existing_rules)
    _update_nsx_security_profile_safe(plugin, context, security_group_id,
                                      combined_rules, existing_rules)


def delete_security_group_rule_handler(plugin, context, security_group_id,
                                       rule_id):
    existing_rules = plugin.get_security_group_rules(
        context, {'security_group_id': [security_group_id]})
    updated_rules = sg_utils.get_security_group_rules_nsx_format(
        context.session, plugin.cluster, existing_rules, with_id=True)
    sg_utils.remove_security_group_with_id_and_id_field(
        updated_rules, rule_id)
    _update_nsx_security_profile_safe(plugin, context, security_group_id,
                                      updated_rules, existing_rules)
