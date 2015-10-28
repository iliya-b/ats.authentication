#!/usr/bin/env python3

import ats.auth

from setuptools import setup, find_packages

PROJECT = 'ats.auth'

try:
    long_description = open('README.rst', 'rt').read()
except IOError:
    long_description = ''

setup(
    name=PROJECT,
    version=ats.auth.version,

    description='AiC Test Services',
    long_description=long_description,

    author='Jenkins',
    author_email='jenkins@rnd.alterway.fr',

    install_requires=[
        'ats.client',

        # server
        'aiohttp',
        'python-jose',
        'aiopg',
        'ats.util',
        'structlog',
    ],

    extras_require={
        'docs': (
            'sphinx',
            'sphinx_rtd_theme',
            'sphinxcontrib-httpdomain',
            'sphinxcontrib-programoutput',
        )},
    namespace_packages=['ats'],
    packages=find_packages(),
    include_package_data=True,

    entry_points={
        'console_scripts': [
            'ats-auth = ats.auth.client.app:main',
            'ats-auth-server = ats.auth.server.main:main',
        ],
        # for Cliff
        'ats_auth': [
            'token create = ats.auth.client.tokens:Create',
            'token revoke = ats.auth.client.tokens:Logout',
            'token revoke-all = ats.auth.client.tokens:LogoutAll',
        ]
    },

    zip_safe=False,
)
