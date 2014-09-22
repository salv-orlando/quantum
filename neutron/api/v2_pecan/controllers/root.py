# License header crap

import pecan

from neutron.api.v2_pecan.controllers import core_controllers
from neutron.api.v2_pecan import resources


class BaseResourceController(object):

    def __init__(self, resource_cls, resource_id):
        # TODO: handle not found error
        self.resource = resource_cls.load(resource_id)

    def _view(self, resource):
        # TODO: strip off hidden fields, return requested fields only,
        # and authZ based field filtering
        return resource.as_dict()

    @pecan.expose(generic=True, template='json')
    def index(self):
        return self._view(self.resource)

    @index.when(method='PUT', template='json')
    def do_put(self, **kwargs):
        resource.update_from_dict(pecan.request.body)

    @index.when(method='DELETE', template='json')
    def do_delete(self, **kwargs):
        resource.delete()


class BaseResourceListController(object):

    def __init__(self, resource_cls):
        self.resource_cls = resource_cls

    def _list_view(self, resource_list):
        # TODO: strip off hidden fields, return requested fields only,
        # and authZ based field filtering
        return [resource.as_dict() for resource in resource_list]

    @pecan.expose()
    def _lookup(self, resource_id, *remainder):
        return BaseResourceController(resource_cls, resource_id), remainder

    @pecan.expose(generic=True, template='json')
    def index(self):
        return self._list_view(resource_cls.list())

    @index.when(method='POST', template='json')
    def do_post(self, **kwargs):
        return resource_cls.create(pecan.request.body, kwargs)


class V2Controller(object):
    """Version 2 API controller root."""

    networks = BaseResourceListController(resources.network)
    ports = core_controllers.PortsController()
    subnets = core_controllers.SubnetsController()
    routers = core_controllers.RoutersController()
    floatingips = core_controllers.FloatingIpsController()
    extensions = core_controllers.ExtensionsController()
    # TODO _lookup for extensions


class RootController(object):

    v2 = V2Controller()

    @pecan.expose(generic=True)
    def index(self):
        # FIXME: Return version information
        return dict()
