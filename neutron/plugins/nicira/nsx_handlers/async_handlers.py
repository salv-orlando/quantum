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

from eventlet import greenthread

from neutron.openstack.common import log
from neutron.plugins.nicira.common import nsx_utils
from neutron.plugins.nicira.common import securitygroups as sg_utils
from neutron.plugins.nicira.dbexts import nicira_db
from neutron.plugins.nicira.dbexts import nicira_models
from neutron.plugins.nicira.nsx_handlers import nsx_tasks
from neutron.plugins.nicira import NvpApiClient

LOG = log.getLogger(__name__)

""" Handlers for aysnchronous NSX operations.

This module contains an implementation of the handlers function definied
in NsxSynchronizationHandlers which dispatch celery tasks and collect
their results upon completion in an asynchronous fashion.

To this aim, this module is peppered with debug log statements which
will be helpful in debugging issues.
And we all know there will be plenty of them.
"""


def _log_task_outcome(task_result):
    """Logs information about a completed task."""
    LOG.debug(_("Task:%(id)s - State:%(state)s"), task_result)
    if task_result.state.lower() == 'success':
        LOG.debug(_("Result:%s"), task_result.result)
    else:
        LOG.debug(_("Traceback:%s"), task_result.traceback)


def enqueue_task(session, model_class, neutron_id,
                 task_data, is_create=False, is_delete=False):
    """Add a task to a queue.

    Tasks are stored in a database in order to allow multiple API
    workers to add them to the same queue.

    @param task_data Task info
    @param is_create True if the task should create a resource
    @param is_delete True if the task should delete a resource
    """
    # Add task id to Neutron Database
    with session.begin(subtransactions=True):
        task = nicira_db.add_task(
            nicira_models.NsxAsyncSecurityGroupTask,
            session,
            neutron_id,
            task_data,
            is_create,
            is_delete)
    # NOTE(salv-orlando): Logging the model class name is a bit ugly but still
    # better than nothing
    LOG.debug(_("Added task:%(task_id)s for neutron %(model_class)s "
                "%(neutron_id)s. Task counter is:%(task_counter)d"),
              {'task_id': task.id,
               'model_class': model_class,
               'neutron_id': neutron_id,
               'task_counter': task.task_counter})
    return task


def launch_task(context, model_class, task, task_info,
                task_callback, plugin):
    """Execute a task."""
    result = task.delay(task_info.task_data,
                        task_info.is_create,
                        task_info.is_delete)
    # Set celery task id in neutron database
    nicira_db.set_celery_task_id(
        model_class,
        context.session,
        task.id,
        result.id)
    LOG.debug(_("Launched task:%(task_id)s for neutron %(model_class)s "
                "%(neutron_id)s. Celery task id is:%(celery_task_id)s"),
              {'task_id': task_info.id,
               'model_class': model_class,
               'neutron_id': task_info.neutron_id,
               'celery_task_id': task_info.celery_task_id})

    # Handle task result in a separate thread
    greenthread.spawn_n(task_callback, plugin, context,
                        task_info.task_data, result)


def process_security_group_sync_task_result(
    plugin, context, security_group_data, task_result):
    # TODO(salv-orlando): consider using a timeout. It is not
    # necessary as long as the backend HTTP client has a timeout
    # mechanism which prevents hangs
    security_group_id = security_group_data['id']
    # Remove task from neutron DB
    nicira_db.remove_task_by_celery_id(
        nicira_models.NsxAsyncSecurityGroupTask,
        context.session,
        task_result.id)
    try:
        LOG.debug(_("Task:%s - Fetching results"), task_result.id)
        sg_sync_result = task_result.get()
        _log_task_outcome(sg_sync_result)
        # Do no update status and mappings if the security group
        # is being deleted and the task completed successfully
        if not security_group_data.get('is_delete'):
            plugin._set_security_group_status(
                context, security_group_data, "ACTIVE")
            # Add mapping between neutron and nsx identifiers
            nicira_db.add_neutron_nsx_security_group_mapping(
                context.session,
                security_group_id,
                sg_sync_result.result['uuid'])
    except NvpApiClient.NvpApiException:
        # Operation failed on backend
        LOG.exception(_("Neutron security group %s not created on NSX "
                        "backend because of an error"), security_group_id)
        # Set the security group in error state
        plugin._set_security_group_status(
            context, security_group_data, "ERROR")
        # TODO(salv-orlando): devise a strategy for fixing resources in error
        # due to transient issues with backend communication
    # Check if the queue is not empty and launch next task
    next_task = nicira_db.get_next_task_to_run(
        nicira_models.NsxAsyncSecurityGroupTask,
        context.session,
        security_group_id)
    if next_task:
        launch_task(context,
                    nicira_models.NsxAsyncSecurityGroupTask,
                    nsx_tasks.synchronize_security_group,
                    next_task,
                    process_security_group_sync_task_result,
                    plugin)


def prepare_security_group_task(plugin, context, security_group_data,
                                is_create=False, is_delete=False):
    # Check if the task queue is empty
    if nicira_db.has_pending_tasks(nicira_models.NsxAsyncSecurityGroupTask,
                                   context.session,
                                   security_group_data['id']):
        # There are still tasks in execution.
        # Enqueue current task and return.
        return enqueue_task(nicira_models.NsxAsyncSecurityGroupTask,
                            context.session,
                            security_group_data['id'],
                            security_group_data,
                            is_create,
                            is_delete)
    # Execute all operations in a transaction.
    # Launching celery tasks within a transaction should not cause troubles
    with context.session.begin(subtrasancations=True):
        # Queue is empty. Add task to DB and launch it
        task = enqueue_task(nicira_models.NsxAsyncSecurityGroupTask,
                            context.session,
                            security_group_data['id'],
                            security_group_data,
                            is_create,
                            is_delete)
        # TODO(salv-orlando): Devise a better coordination strategy
        # Post-Enqueue check to verify no other process has launched a task
        # in the meanwhile. The next stament should not ever raise TypeError
        next_task_counter = nicira_db.get_next_task_to_run(
            nicira_models.NsxAsyncSecurityGroupTask,
            context.session,
            security_group_data['id'])['task_counter']
        if next_task_counter < task.task_counter:
            # Another task was concurrently added and this will have to wait
            return

        # Launch task. Notify the worker that this is a create request
        launch_task(context,
                    nicira_models.NsxAsyncSecurityGroupTask,
                    nsx_tasks.synchronize_security_group,
                    task,
                    process_security_group_sync_task_result,
                    plugin)
    return task


def create_security_group_handler(plugin, context, security_group_data):
    LOG.debug(_("Starting create_security_group_handler for neutron "
                "security group:%s"), security_group_data['id'])
    task = prepare_security_group_task(
        plugin, context, security_group_data, is_create=True)
    LOG.debug(_("create_security_group_handler for neutron security "
                "group :%(security_group_id)s completed. Task "
                "identifier is:%(task_id)s"),
              {'security_group_id': security_group_data['id'],
               'task_id': task.id})


def delete_security_group_handler(plugin, context, security_group_id):
    LOG.debug(_("Starting delete_security_group_handler for neutron "
                "security group:%s"), security_group_id)
    # The worker must be informed that this is a delete request
    security_group_data = {'id': security_group_id}
    task = prepare_security_group_task(
        plugin, context, security_group_data, is_delete=True)
    LOG.debug(_("delete_security_group_handler for neutron security "
                "group :%(security_group_id)s completed. Task "
                "identifier is:%(task_id)s"),
              {'security_group_id': security_group_id,
               'task_id': task.id})


def create_security_group_rules_handler(plugin, context, security_group_id,
                                        new_rules):
    LOG.debug(_("Starting create_security_group_rules_handler for neutron "
                "security group:%s"), security_group_id)
    # In some corner cases the following might trigger a necessary synchronous
    # call to the NSX backend
    # TODO(salv-orlando): Make it a task as well in order to further decouple
    # plugin from backend
    nsx_uuid = nsx_utils.get_nsx_security_group_id(
        context.session, plugin.cluster, security_group_id)
    existing_rules = plugin.get_security_group_rules(
        context, {'security_group_id': [security_group_id]})
    combined_rules = sg_utils.merge_security_group_rules_with_current(
        context.session, plugin.cluster, new_rules, existing_rules)
    security_group_data = {'id': security_group_id,
                           'nsx_uuid': nsx_uuid,
                           'security_group_rules': combined_rules}
    task = prepare_security_group_task(plugin, context, security_group_data)
    LOG.debug(_("create_security_group_rules_handler for neutron security "
                "group :%(security_group_id)s completed. Task "
                "identifier is:%(task_id)s"),
              {'security_group_id': security_group_id,
               'task_id': task.id})


def delete_security_group_rule_handler(plugin, context, security_group_id,
                                       rule_id):
    LOG.debug(_("Starting delete_security_group_rule_handler for neutron "
                "security group:%(sg_id)s and rule:%(rule_id)s"),
              {'sg_id': security_group_id, 'rule_id': rule_id})
    # In some corner cases the following might trigger a necessary synchronous
    # call to the NSX backend
    # TODO(salv-orlando): Make it a task as well in order to further decouple
    # plugin from backend
    nsx_uuid = nsx_utils.get_nsx_security_group_id(
        context.session, plugin.cluster, security_group_id)
    existing_rules = plugin.get_security_group_rules(
        context, {'security_group_id': [security_group_id]})
    updated_rules = sg_utils.get_security_group_rules_nsx_format(
        context.session, plugin.cluster, existing_rules, with_id=True)
    sg_utils.remove_security_group_with_id_and_id_field(
        updated_rules, rule_id)
    security_group_data = {'id': security_group_id,
                           'nsx_uuid': nsx_uuid,
                           'security_group_rules': updated_rules}
    task = prepare_security_group_task(plugin, context, security_group_data)
    LOG.debug(_("delete_security_group_rule_handler for neutron security "
                "group :%(security_group_id)s completed. Task "
                "identifier is:%(task_id)s"),
              {'security_group_id': security_group_id,
               'task_id': task.id})
