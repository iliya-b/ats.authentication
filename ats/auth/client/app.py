
import sys

from cliff.commandmanager import CommandManager

import ats.auth
from ats.client.client import ClientApp


class App(ClientApp):
    default_config_file = 'auth-client.ini'

    def __init__(self):
        super().__init__(
            description='ats-auth',
            version=ats.auth.version,
            command_manager=CommandManager('ats_auth'))


def main(argv=sys.argv[1:]):
    app = App()
    return app.run(argv)
