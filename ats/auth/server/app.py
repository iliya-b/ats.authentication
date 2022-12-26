
import datetime
from http import HTTPStatus
import json
import time

from aiohttp import web
import aiopg

import jose.jwt

from ats.auth.server.db import jwt as db_jwt
from ats.util.helpers import authenticated_userid, get_os_session, json_request


class ATSAuthApp(web.Application):
    def __init__(self, config, *args, **kw):
        super().__init__(*args, **kw)
        self.config = config

    async def setup(self):
        await self.setup_db()
        self.setup_routes()

    def setup_routes(self):
        router = self.router
        router.add_route('POST', '/user/login', self.handle_token_create)
        router.add_route('POST', '/user/logout', self.handle_logout)
        router.add_route('POST', '/user/logout_all', self.handle_logout_all)

    async def setup_db(self):
        self.logger.debug('Set up DBMS connection pool...')
        self.dbpool = await aiopg.create_pool(self.config['db']['dsn'])

    async def issue_jwt_token(self, username):
        secret = self.config['server']['jwt_secret']
        ts = time.time()
        claims = {
            'iss': 'ats.auth',         # Issuer
            'sub': username,           # Subject
            'iat': ts,                 # Issued At
            'exp': ts + 24 * 60 * 60,  # Expiration Time
        }
        token = jose.jwt.encode(claims, key=secret, algorithm='HS256')
        await db_jwt.insert_jwt(self,
                                token=token,
                                uid=claims['sub'],
                                issued_at=datetime.datetime.fromtimestamp(claims['iat']),
                                expires_at=datetime.datetime.fromtimestamp(claims['exp']))
        return token

    async def handle_token_create(self, request):
        """
        Returns a JWT token to the user. No need to store it for validation.
        """

        request_schema = {
            'type': 'object',
            'properties': {
                'username': {'type': 'string'},
                'password': {'type': 'string'},
            },
            'required': ['username', 'password']
        }

        js = await json_request(request, schema=request_schema)

        username = js['username']
        password = js['password']

        config_auth = self.config['authentication']

        os_auth_url = config_auth['os_auth_url']
        os_tenant_name = config_auth['os_user_tenant_name']

        auth_payload = {
            'auth': {
                'identity':{
                    'methods':['password']
                },
                'password':{
                    'user':{
                        'domain':{'id':'default'},
                        'name':'aic-' + username,
                        'password': password
                    }
                },
                "scope": {
                    "project": {
                        "domain": {
                            "id": "default"
                        },
                        "name": "aic"
                    }
                }
            }
        }

        session = get_os_session(os_cacert=config_auth.get('os_cacert'),
                                 insecure=config_auth.get('insecure'),
                                 log=self.logger)

        r = await session.post(os_auth_url + '/tokens',
                               data=json.dumps(auth_payload),
                               headers={'Content-Type': 'application/json'})

        js = await r.json()

        if r.status != HTTPStatus.OK:
            # XXX what about status codes != 401 ??
            raise web.HTTPUnauthorized

        payload = {
            'token': await self.issue_jwt_token(username)
        }
        return web.Response(content_type='application/json',
                            text=json.dumps(payload, indent=4))

    async def handle_logout(self, request):
        """
        Revoke the current token.
        """

        auth_header = request.headers.get('Authorization')

        if not auth_header:
            self.logger.warning('No authorization header')

        if not auth_header.startswith('Bearer '):
            self.logger.warning('Authorization header: no Bearer')

        token = auth_header[len('Bearer '):]

        await db_jwt.revoke_jwt(self,
                                token=token)

        self.logger.info('Token revoked: %s', token)

        return web.Response(status=HTTPStatus.NO_CONTENT)

    async def handle_logout_all(self, request):
        """
        Revoke all tokens created by the current user.
        """

        userid = await authenticated_userid(request)

        await db_jwt.revoke_all_jwt(self,
                                    userid=userid)

        return web.Response(status=HTTPStatus.NO_CONTENT)
