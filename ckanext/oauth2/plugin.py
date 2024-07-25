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
from ckan.common import g
from ckan.lib.helpers import helper_functions as h
from ckan.lib import signals
from ckan.model.user import User
from ckan.plugins import toolkit
from ckan.plugins.toolkit import (abort)
from flask import Blueprint

from ckan.types.model import Model
from ckanext.oauth2.oauth2 import OAuth2Helper
from ckanext.oauth2.controller import OAuth2Controller
import ckan.lib.navl.dictization_functions as df
from ckan.model import (PACKAGE_NAME_MAX_LENGTH)
from ckan.common import _,CKANConfig
from typing import Any, Mapping, Optional, Union, cast
from ckan.types import (
    Context)
import re
Invalid = df.Invalid
Missing = df.Missing
missing = df.missing
# Allow alphanumeric characters, spaces, dashes, and dots
name_match = re.compile('[a-zA-Z0-9_\-\. ]+$') # type: ignore
log = logging.getLogger(__name__)
from flask_login import current_user as _cu
current_user = cast(Union["Model.User", "Model.AnonymousUser"], _cu)

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
            (u'/user/oauth2/login', u'user_login_oauth2', controller.login),
            (u'/authen-service/OAuthCallback', u'oauth2_callback', controller.callback),
            (u'/user/oauth2/logout', u'user_logout_oauth2', controller.logout),
            (u'/user/not_authorized', u'user_not_authorized', controller.not_authorized)

        ]
        for rule in rules:
            blueprint.add_url_rule(*rule)
        log.debug('Blueprint rules added')
        return blueprint
    def logout(self):
        log.debug('logout')
        if current_user.is_authenticated:
            user_obj = User.by_name(current_user.name)
            if (user_obj is not None and isinstance(user_obj.plugin_extras, dict) and user_obj.plugin_extras.get('oauth2', None) == True): # type: ignore
                log.debug('go to oauth2 logout')
                return toolkit.redirect_to(controller='OAuth2Plugin', action='user_logout_oauth2')
    def identify(self):
        log.debug('identify')

        def _refresh_and_save_token(user_name:str):
            new_token = self.oauth2helper.refresh_token(user_name)
            if new_token:
                toolkit.c.usertoken = new_token

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
        if current_user.is_authenticated:
            user_name = current_user.name
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
        if not ('login' in identity and 'password' in identity):
            return None
        login = identity['login']
        user_obj = User.by_name(login)
        if not user_obj:
            user_obj = User.by_email(login)
        if user_obj is None:
            log.debug('Login failed - username or email %r not found', login)
        elif not user_obj.is_active:
            log.debug('Login as %r failed - user isn\'t active', login)
        elif not user_obj.validate_password(identity['password']):
            log.debug('Login as %r failed - password not valid', login)
        elif (isinstance(user_obj.plugin_extras, dict) and user_obj.plugin_extras.get('oauth2', None) == True): # type: ignore
            log.debug('User only can be authenticated by oauth2')
            abort(401, _('User only can be authenticated by oauth2'))
        else:
            return user_obj
        signals.failed_login.send(login)
        return None
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

