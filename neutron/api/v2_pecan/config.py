# Server Specific Configurations
server = {
    'port': '9696',
    'host': '0.0.0.0'
}

# Pecan Application Configurations
app = {
    'root': 'neutron.api.v2_pecan.controllers.root.RootController',
    'modules': ['neutron.api.v2_pecan'],
    'debug': True,
}
