
from ats.util.options import Option, get_configdict, EnvConfigPrinter


prefix = 'ATSAUTH_'

options = [
    Option('server.listen_address', default='127.0.0.1'),
    Option('server.listen_port', default=8081),
    Option('log.jsonformat', default=False),
    Option('server.jwt_secret'),
    Option('authentication.insecure', default=False, required=False),
    Option('authentication.os_cacert', required=False),
    Option('authentication.os_auth_url'),
    Option('authentication.os_user_tenant_name',
           help='Name of the tenant that contains users to authenticate'),
    Option('db.dsn'),
]


def config_get(environ):
    return get_configdict(prefix=prefix,
                          options=options,
                          environ=environ)


def ConfigPrinter():
    return EnvConfigPrinter(prefix=prefix,
                            options=options)
