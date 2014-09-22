from pecan import hooks
from pecan import make_app


class PluginHook(hooks.PecanHook):

    def before(self, state):
        state.request.plugin = 'cess e soreta'

def setup_app(config):

    app_conf = dict(config.app)
    app_conf['hooks'] = [PluginHook()]
    print "APP_CONF:%s" % app_conf
    return make_app(
        app_conf.pop('root'),
        logging=getattr(config, 'logging', {}),
        hooks=app_conf.pop('hooks'),
        **app_conf
    )
