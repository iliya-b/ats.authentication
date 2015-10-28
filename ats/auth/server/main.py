
import argparse
import asyncio
import os
import sys
import warnings

import structlog

from ats.auth.server.config import config_get, ConfigPrinter
from ats.util.logging import setup_logging, setup_structlog, structlog_middleware

from .app import ATSAuthApp

warnings.filterwarnings('ignore', category=DeprecationWarning)

async def init(*, loop, config, debug=False):
    setup_structlog(config)
    log = structlog.get_logger()

    app = ATSAuthApp(config=config,
                     loop=loop,
                     logger=log,
                     middlewares=[structlog_middleware])
    await app.setup()

    listen_address = app.config['server']['listen_address'].strip()

    if debug:
        import aiohttp_debugtoolbar
        aiohttp_debugtoolbar.setup(app, hosts=[listen_address])
        log.info('Debug toolbar available at /_debugtoolbar')

    listen_port = app.config['server']['listen_port']

    srv = await loop.create_server(app.make_handler(),
                                   listen_address,
                                   listen_port)
    for socket in srv.sockets:
        log.info('Server started at %s', socket.getsockname())
    return srv


def get_parser():
    ap = argparse.ArgumentParser()

    ap.add_argument(
        '--write-config-defaults',
        action=ConfigPrinter(),
        nargs=0,
        help='print default configuration values')

    ap.add_argument(
        '--debug',
        dest='debug',
        action='store_true',
        help='enable debug toolbar')

    ap.add_argument(
        '--no-debug',
        dest='debug',
        action='store_false',
        help='disable debug toolbar')

    ap.set_defaults(debug=False)

    return ap


def main(argv=sys.argv[1:]):
    parser = get_parser()
    args = parser.parse_args(argv)

    config = config_get(environ=os.environ)
    setup_logging(config)

    loop = asyncio.get_event_loop()
    # asyncio debugging
    loop.set_debug(enabled=False)

    loop.run_until_complete(init(loop=loop, config=config, debug=args.debug))

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
