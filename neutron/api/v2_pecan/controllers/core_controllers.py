# License header crap

import pecan
from pecan import rest

from neutron.api.v2_pecan.controllers import root


class NetworksController(root.BaseResourceListController):

    def __init__(self):
        super(NetworksController, self).__init__(NetworkManager)


class NetworkManager(object):

    @staticmethod
    def load(selfi, network_id):
        pass

    @staticmethod
    def list(self, filters):
        pass

    @staticmethod
    def create(self):
        pass


class PortsController(rest.RestController):

    @pecan.expose('json')
    def get(self, port_id):
        return {'id': port_id, 'name': 'meh_port'}

    @pecan.expose('json')
    def get_all(self):
        return [{'id': '1', 'name': 'blah_port'},
                {'id': '2', 'name': 'gah_port'}]


class SubnetsController(rest.RestController):

    @pecan.expose('json')
    def get(self, subnet_id):
        return {'id': subnet_id, 'name': 'meh_subnet'}

    @pecan.expose('json')
    def get_all(self):
        return [{'id': '1', 'name': 'blah_subnet'},
                {'id': '2', 'name': 'gah_subnet'}]


class RoutersController(rest.RestController):

    @pecan.expose('json')
    def get(self, router_id):
        return {'id': router_id, 'name': 'meh_router'}

    @pecan.expose('json')
    def get_all(self):
        return [{'id': '1', 'name': 'blah_router'},
                {'id': '2', 'name': 'gah_router'}]


class FloatingIpsController(rest.RestController):

    @pecan.expose('json')
    def get(self, floatingip_id):
        return {'id': floatingip_id, 'name': 'meh_fip'}

    @pecan.expose('json')
    def get_all(self):
        return [{'id': '1', 'name': 'blah_fip'},
                {'id': '2', 'name': 'gah_fip'}]

class ExtensionsController(rest.RestController):

    @pecan.expose('json')
    def get(self, ext_name):
        return {'name': 'meh_ext', 'meh': 'meh'}

    @pecan.expose('json')
    def get_all(self):
        return [{'id': '1', 'name': 'blah_ext'},
                {'id': '2', 'name': 'gah_ext'}]

