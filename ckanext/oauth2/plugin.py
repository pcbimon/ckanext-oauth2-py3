# -*- coding: utf-8 -*-

# Copyright (c) 2014 CoNWeT Lab., Universidad Politécnica de Madrid
# Copyright (c) 2018 Future Internet Consulting and Development Solutions S.L.

# This file is part of OAuth2 CKAN Extension.

# OAuth2 CKAN Extension is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# OAuth2 CKAN Extension is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with OAuth2 CKAN Extension.  If not, see <http://www.gnu.org/licenses/>.
from functools import partial
import logging
import os

from ckan import plugins
from ckan.common import g,session
import ckan.model as model
from ckan.model.user import User
from ckan.plugins import toolkit
from flask import Blueprint

from ckanext.oauth2.oauth2 import OAuth2Helper
from ckanext.oauth2.controller import OAuth2Controller
import ckan.lib.navl.dictization_functions as df
from ckan.model import (PACKAGE_NAME_MAX_LENGTH)
from ckan.common import _,CKANConfig
from typing import Any, Mapping, Optional
from ckan.types import (
    Context)
import re
Invalid = df.Invalid
Missing = df.Missing
missing = df.missing
# Allow alphanumeric characters, spaces, dashes, and dots
name_match = re.compile('[a-zA-Z0-9_\-\. ]+$') # type: ignore
log = logging.getLogger(__name__)


def _no_permissions(context, msg): # type: ignore
    user = context['user']
    return {'success': False, 'msg': msg.format(user=user)}


@toolkit.auth_sysadmins_check
def user_create(context, data_dict=None): # type: ignore
    log.debug('Checking if the user can be created')
    log.debug('User Request Is Admin? : %s' % (context['auth_user_obj'].sysadmin == True))
    try:
        if not context['auth_user_obj'].sysadmin:
            msg = toolkit._('Only system administrators can create users')
            return _no_permissions(context, msg)
        else:
            return {'success': True}
    except Exception:
        return _no_permissions(context, msg)


@toolkit.auth_sysadmins_check
def user_update(context, data_dict=None): # type: ignore
    log.debug('Checking if the user can be updated')
    log.debug('User Request Is Admin? : %s' % (context['auth_user_obj'].sysadmin == True))
    try:
        if not context['auth_user_obj'].sysadmin:
            msg = toolkit._('Only system administrators can update users')
            return _no_permissions(context, msg)
        else:
            return {'success': True}
    except Exception:
        return _no_permissions(context, msg)
        


@toolkit.auth_sysadmins_check
def user_reset(context, data_dict): # type: ignore
    msg = toolkit._('Users cannot reset passwords.')
    return _no_permissions(context, msg)


@toolkit.auth_sysadmins_check
def request_reset(context, data_dict): # type: ignore
    msg = toolkit._('Users cannot reset passwords.')
    return _no_permissions(context, msg)

def name_validator(value: Any, context: Context) -> Any:
    if not isinstance(value, str):
        raise Invalid(_('Names must be strings'))

    # check basic textual rules
    if value in ['new', 'edit', 'search']:
        raise Invalid(_('That name cannot be used'))
    if len(value) < 2:
        raise Invalid(_('Must be at least %s characters long') % 2)
    if len(value) > PACKAGE_NAME_MAX_LENGTH:
        raise Invalid(_('Name must be a maximum of %i characters long') % \
                      PACKAGE_NAME_MAX_LENGTH)
    if not name_match.match(value):
        raise Invalid(_('Name must be alphanumeric characters, dashes, or dots only'))
    return value

class OAuth2Plugin(plugins.SingletonPlugin):

    plugins.implements(plugins.IAuthenticator, inherit=True)
    plugins.implements(plugins.IAuthFunctions, inherit=True)
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IValidators)

    def __init__(self, name=None): # type: ignore
        '''Store the OAuth 2 client configuration'''
        log.debug('Init OAuth2 extension')

        self.oauth2helper = OAuth2Helper()

    def get_blueprint(self):
        log.debug('Setting up Blueprint rules to redirect to OAuth2 service')
        log.debug('Name: %s' % self.name)
        blueprint = Blueprint(self.name, self.__module__)
        blueprint.template_folder = u'templates'
        controller = OAuth2Controller()

        rules = [
            (u'/user/login/oauth2', u'user_login_oauth2', controller.login),
            (u'/authen-service/OAuthCallback', u'oauth2_callback', controller.callback),
            (u'/user/logout/oauth2', u'user_logout_oauth2', controller.logout),
            (u'/user/not_authorized', u'user_not_authorized', controller.not_authorized),
            (u'/user/update_api_key', u'user_not_authorized', controller.not_authorized)

        ]
        for rule in rules:
            blueprint.add_url_rule(*rule)
        log.debug('Blueprint rules added')
        return blueprint

    def identify(self):
        log.debug('identify')

        def _refresh_and_save_token(user_name:str):
            new_token = self.oauth2helper.refresh_token(user_name)
            if new_token:
                toolkit.c.usertoken = new_token

        environ = toolkit.request.environ
        apikey = toolkit.request.headers.get(self.authorization_header, '')
        user_name = None

        if self.authorization_header == "authorization":
            if apikey.startswith('Bearer '):
                apikey = apikey[7:].strip()
            else:
                apikey = ''

        # This API Key is not the one of CKAN, it's the one provided by the OAuth2 Service
        if apikey:
            try:
                token = {'access_token': apikey}
                user_name = self.oauth2helper.identify(token)
            except Exception:
                pass

        # If the authentication via API fails, we can still log in the user using session.
        if user_name is None and 'repoze.who.identity' in environ:
            user_name = environ['repoze.who.identity']['repoze.who.userid']
            log.info('User %s logged using session' % user_name)

        # If we have been able to log in the user (via API or Session)
        if user_name:
            g.user = user_name
            toolkit.c.user = user_name
            toolkit.c.usertoken = self.oauth2helper.get_stored_token(user_name)
            toolkit.c.usertoken_refresh = partial(_refresh_and_save_token, user_name)
        else:
            g.user = None
            log.warn('The user is not currently logged...')
    def authenticate(self,identity: Mapping[str, Any]) -> Optional[User]:
        log.debug('authenticate')
        user_plugin_extra = identity.get('plugin_extra', {})
        # ckeck user authentication from OAuth2 service
        log.debug(identity)
        # get user from email
        email = identity.get('email', None)
        if email is None:
            return None
        user = model.User.by_email(email)
        # if session "authentication" is "oauth2" and user is not found, return None
        if user is None:
            log.debug('User not found')
            return None
        # if user is found, session "authentication" is "oauth2" and user is not active, return None
        if not user.is_active():
            log.debug('User is not active')
            return None
        # if user is found, session "authentication" is "oauth2" and user is active, return user
        authentication = session.get('authentication', None)
        if authentication == 'oauth2':
            valid_plugin_extra = {'oauth2':True}
            if user_plugin_extra == valid_plugin_extra:
                return user
            return None
        # if session "authentication" is not "oauth2", return user object
        return user
    def get_auth_functions(self): # type: ignore
        # we need to prevent some actions being authorized.
        return {
            'user_create': user_create,
            'user_update': user_update,
            'user_reset': user_reset,
            'request_reset': request_reset
        }

    def update_config(self, config: 'CKANConfig') -> None:
        # Update our configuration
        self.register_url = os.environ.get("CKAN_OAUTH2_REGISTER_URL", config.get('ckan.oauth2.register_url', None))
        self.reset_url = os.environ.get("CKAN_OAUTH2_RESET_URL", config.get('ckan.oauth2.reset_url', None))
        self.edit_url = os.environ.get("CKAN_OAUTH2_EDIT_URL", config.get('ckan.oauth2.edit_url', None))
        self.authorization_header = os.environ.get("CKAN_OAUTH2_AUTHORIZATION_HEADER", config.get('ckan.oauth2.authorization_header', 'Authorization')).lower()
        config['ckan.auth.public_user_details'] = False
        config['ckan.auth.create_user_via_web'] = False
        config['ckan.auth.create_user_via_api']= False
        # Add this plugin's templates dir to CKAN's extra_template_paths, so
        # that CKAN will use this plugin's custom templates.
        plugins.toolkit.add_template_directory(config, 'templates')
        plugins.toolkit.add_public_directory(config, 'public')
    def get_validators(self):
        return {
            'name_validator': name_validator
        }

