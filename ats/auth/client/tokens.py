
import getpass
import os

from cliff.command import Command

import jose.jwt


class Create(Command):
    "Create a JWT (RFC 7519) cryptographic token"

    def get_parser(self, prog_name):
        ap = super().get_parser(prog_name)
        ap.add_argument(
            '--username',
            help='username (will use OS_USERNAME if missing)'
        )
        ap.add_argument(
            '--password',
            help='password (will use OS_PASSWORD if missing, will prompt if OS_PASSWORD is also missing)'
        )
        return ap

    def take_action(self, parsed_args):

        username = parsed_args.username
        if not username:
            if 'OS_USERNAME' in os.environ:
                username = os.environ['OS_USERNAME']
            else:
                raise Exception('Username is mandatory')

        password = parsed_args.password
        if not password:
            if 'OS_PASSWORD' in os.environ:
                password = os.environ['OS_PASSWORD']
            else:
                password = getpass.getpass('Password for user {}: '.format(username))

        config = self.app.config
        self.app.LOG.debug('Requesting new token...')

        payload = {
            'username': username,
            'password': password,
        }

        self.app.LOG.debug('username: %s', username)

        r = self.app.do_post('user', 'login',
                             json=payload)

        js = r.json()
        token = js['token']

        header = jose.jwt.get_unverified_headers(token)
        self.app.LOG.debug('header: {}'.format(header))

        try:
            secret = config['client']['jwt_secret']
        except KeyError:
            claims = jose.jwt.get_unverified_claims(token)
            self.app.LOG.debug('UNVERIFIED claims: {}'.format(claims))
        else:
            if secret:
                claims = jose.jwt.decode(token, secret, algorithms='HS256')
                self.app.LOG.debug('Verified claims: {}'.format(claims))

        print(token)


class Logout(Command):
    "Revoke a token"

    def get_parser(self, prog_name):
        ap = super().get_parser(prog_name)
        ap.add_argument(
            'token',
            help='token to revoke'
        )
        return ap

    def take_action(self, parsed_args):
        signed_token = parsed_args.token

        claims = jose.jwt.get_unverified_claims(signed_token)
        userid = claims['sub']
        self.app.LOG.info('Logging out user %s', userid)

        headers = {
            'Authorization': 'Bearer %s' % signed_token
        }

        self.app.do_post('user', 'logout',
                         headers=headers)

        self.app.LOG.info('Token revoked.')


class LogoutAll(Command):
    "Revoke all tokens created by a user"

    def get_parser(self, prog_name):
        ap = super().get_parser(prog_name)
        self.app.add_auth_options(ap)
        return ap

    def take_action(self, parsed_args):
        self.app.do_post('user', 'logout_all',
                         headers=self.app.auth_header(parsed_args))

        self.app.LOG.info('All tokens revoked.')
