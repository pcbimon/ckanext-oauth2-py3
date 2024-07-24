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




import base64
import ckan.model as model
from ckan.model.user import User
from . import db
import json
import logging
import os

from base64 import b64encode, b64decode
from ckan.plugins import toolkit
from oauthlib.oauth2 import InsecureTransportError
from oauthlib.oauth2.rfc6749.errors import InsufficientScopeError
import requests
from requests_oauthlib import OAuth2Session
import six
from typing import (
    Any, Optional, cast, Union)
from ckan.types import Model
import jwt

from . import constants
from flask_login import login_user as _login_user, logout_user as _logout_user
from flask_login import current_user as _cu
from ckan.views.user import rotate_token
current_user = cast(Union["Model.User", "Model.AnonymousUser"], _cu)
login_user = _login_user
logout_user = _logout_user

log = logging.getLogger(__name__)


def generate_state(url: str):
    return b64encode(str.encode(json.dumps({constants.CAME_FROM_FIELD: url})))


def get_came_from(state: str):
    return json.loads(b64decode(state)).get(constants.CAME_FROM_FIELD, '/')


REQUIRED_CONF = ("authorization_endpoint", "token_endpoint", "client_id", "client_secret", "profile_api_url", "profile_api_user_field", "profile_api_mail_field")


class OAuth2Helper(object):

    def __init__(self):

        self.verify_https = os.environ.get('OAUTHLIB_INSECURE_TRANSPORT', '') == ""
        if self.verify_https and os.environ.get("REQUESTS_CA_BUNDLE", "").strip() != "":
            self.verify_https = os.environ["REQUESTS_CA_BUNDLE"].strip()

        self.jwt_enable = six.text_type(os.environ.get('CKAN_OAUTH2_JWT_ENABLE', toolkit.config.get('ckan.oauth2.jwt.enable',''))).strip().lower() in ("true", "1", "on")

        self.legacy_idm = six.text_type(os.environ.get('CKAN_OAUTH2_LEGACY_IDM', toolkit.config.get('ckan.oauth2.legacy_idm', ''))).strip().lower() in ("true", "1", "on")
        self.authorization_endpoint = six.text_type(os.environ.get('CKAN_OAUTH2_AUTHORIZATION_ENDPOINT', toolkit.config.get('ckan.oauth2.authorization_endpoint', ''))).strip()
        self.token_endpoint = six.text_type(os.environ.get('CKAN_OAUTH2_TOKEN_ENDPOINT', toolkit.config.get('ckan.oauth2.token_endpoint', ''))).strip()
        self.profile_api_url = six.text_type(os.environ.get('CKAN_OAUTH2_PROFILE_API_URL', toolkit.config.get('ckan.oauth2.profile_api_url', ''))).strip()
        self.client_id = six.text_type(os.environ.get('CKAN_OAUTH2_CLIENT_ID', toolkit.config.get('ckan.oauth2.client_id', ''))).strip()
        self.client_secret = six.text_type(os.environ.get('CKAN_OAUTH2_CLIENT_SECRET', toolkit.config.get('ckan.oauth2.client_secret', ''))).strip()
        self.scope = six.text_type(os.environ.get('CKAN_OAUTH2_SCOPE', toolkit.config.get('ckan.oauth2.scope', ''))).strip()
        self.rememberer_name = six.text_type(os.environ.get('CKAN_OAUTH2_REMEMBER_NAME', toolkit.config.get('ckan.oauth2.rememberer_name', 'auth_tkt'))).strip()
        self.profile_api_user_field = six.text_type(os.environ.get('CKAN_OAUTH2_PROFILE_API_USER_FIELD', toolkit.config.get('ckan.oauth2.profile_api_user_field', ''))).strip()
        self.profile_api_fullname_field = six.text_type(os.environ.get('CKAN_OAUTH2_PROFILE_API_FULLNAME_FIELD', toolkit.config.get('ckan.oauth2.profile_api_fullname_field', ''))).strip()
        self.profile_api_mail_field = six.text_type(os.environ.get('CKAN_OAUTH2_PROFILE_API_MAIL_FIELD', toolkit.config.get('ckan.oauth2.profile_api_mail_field', ''))).strip()
        self.profile_api_groupmembership_field = six.text_type(os.environ.get('CKAN_OAUTH2_PROFILE_API_GROUPMEMBERSHIP_FIELD', toolkit.config.get('ckan.oauth2.profile_api_groupmembership_field', ''))).strip()
        self.sysadmin_group_name = six.text_type(os.environ.get('CKAN_OAUTH2_SYSADMIN_GROUP_NAME', toolkit.config.get('ckan.oauth2.sysadmin_group_name', ''))).strip()

        self.redirect_uri = six.text_type(os.environ.get('CKAN_OAUTH2_REDIRECT_URL', toolkit.config.get('ckan.oauth2.redirect_url', ''))).strip()
        self.logout_redirect = six.text_type(os.environ.get('CKAN_OAUTH2_LOGOUT_REDIRECT', toolkit.config.get('ckan.oauth2.logout_redirect', ''))).strip()
        self.logout_url = six.text_type(os.environ.get('CKAN_OAUTH2_LOGOUT_URL', toolkit.config.get('ckan.oauth2.logout_url', ''))).strip()

        # Init db
        db.init_db(model)

        missing = [key for key in REQUIRED_CONF if getattr(self, key, "") == ""]
        if missing:
            raise ValueError("Missing required oauth2 conf: %s" % ", ".join(missing))
        elif self.scope == "":
            self.scope = None

    def challenge(self, came_from_url: str):
        # This function is called by the log in function when the user is not logged in
        state = generate_state(came_from_url)
        oauth = OAuth2Session(self.client_id, redirect_uri=self.redirect_uri, scope=self.scope, state=state)
        auth_url, _ = oauth.authorization_url(self.authorization_endpoint)
        log.debug('Challenge: Redirecting challenge to page {0}'.format(auth_url))
        # CKAN 2.6 only supports bytes
        return toolkit.redirect_to(auth_url)
    def logout(self):
        user_name = None
        if current_user.is_authenticated:
            log.info('User %s logged using session' % current_user.name)
        if current_user.is_authenticated:
            logout_user()
            log.info('User %s logged out' % user_name)
        # Redirect to the logout URL
        url = self.logout_url+'?post_logout_redirect_uri='+self.logout_redirect
        log.debug('Logout: Redirecting to page {0}'.format(url))
        return toolkit.redirect_to(url)
    def get_token(self):
        oauth = OAuth2Session(self.client_id, redirect_uri=self.redirect_uri, scope=self.scope)

        # Just because of FIWARE Authentication
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        if self.legacy_idm:
            # This is only required for Keyrock v6 and v5
            headers['Authorization'] = 'Basic %s' % base64.urlsafe_b64encode(
                '%s:%s' % (self.client_id, self.client_secret)
            )

        try:
            token = oauth.fetch_token(self.token_endpoint,
                                      headers=headers,
                                      client_secret=self.client_secret,
                                      authorization_response=toolkit.request.url,
                                      verify=self.verify_https)
        except requests.exceptions.SSLError as e:
            # TODO search a better way to detect invalid certificates
            if "verify failed" in six.text_type(e):
                raise InsecureTransportError()
            else:
                raise

        return token

    def identify(self, token: str) -> str:

        if self.jwt_enable:

            access_token = token['access_token']
            user_data = jwt.decode(access_token, verify=False)
            user = self.user_json(user_data)
        else:

            try:
                if self.legacy_idm:
                    profile_response = requests.get(self.profile_api_url + '?access_token=%s' % token['access_token'], verify=self.verify_https)
                else:
                    oauth = OAuth2Session(self.client_id, token=token)
                    profile_response = oauth.get(self.profile_api_url, verify=self.verify_https)

            except requests.exceptions.SSLError as e:
                # TODO search a better way to detect invalid certificates
                if "verify failed" in six.text_type(e):
                    raise InsecureTransportError()
                else:
                    raise

            # Token can be invalid
            if not profile_response.ok:
                error = profile_response.json()
                if error.get('error', '') == 'invalid_token':
                    raise ValueError(error.get('error_description'))
                else:
                    profile_response.raise_for_status()
            else:
                user_data = profile_response.json()
                user = self.user_json(user_data)

        # Save the user in the database
        model.Session.add(user)
        model.Session.commit()
        model.Session.remove()

        return user.name # type: ignore

    def user_json(self, user_data: Any) -> Optional[User]:
        log.debug(f'user_json: {user_data}')
        email = user_data[self.profile_api_mail_field]
        user_name = user_data[self.profile_api_user_field]

        # In CKAN can exists more than one user associated with the same email
        # Some providers, like Google and FIWARE only allows one account per email
        user = model.User.by_email(email)
        if user is None:
            raise InsufficientScopeError('User with email %s does not exist' % email)
        # Now we update his/her user_name with the one provided by the OAuth2 service
        # In the future, users will be obtained based on this field
        user.name = user_name

        # Update fullname
        if self.profile_api_fullname_field != "" and self.profile_api_fullname_field in user_data:
            user.fullname = user_data[self.profile_api_fullname_field]

        # Update sysadmin status
        if self.profile_api_groupmembership_field != "" and self.profile_api_groupmembership_field in user_data:
            user.sysadmin = self.sysadmin_group_name in user_data[self.profile_api_groupmembership_field]

        return user

    def _get_rememberer(self, environ): # type: ignore
        log.debug('Get Current User')
        log.debug(current_user)
        return current_user

    def remember(self, user_name: str):
        '''
        Remember the authenticated identity.

        This method simply delegates to another IIdentifier plugin if configured.
        '''
        log.debug('Repoze OAuth remember')
        user_obj = model.User.by_name(user_name)
        login_user(user_obj)
        rotate_token()
        # for header, value in headers:
        #     toolkit.response.headers.add(header, value)

    def redirect_from_callback(self):
        '''Redirect to the callback URL after a successful authentication.'''
        # state = toolkit.request.params.get('state')
        # came_from = get_came_from(state)
        return toolkit.redirect_to(constants.INITIAL_PAGE)

    def get_stored_token(self, user_name: str): # type: ignore
        user_token = db.UserToken.by_user_name(user_name=user_name)
        if user_token:
            return {
                'access_token': user_token.access_token,
                'refresh_token': user_token.refresh_token,
                'expires_in': user_token.expires_in,
                'token_type': user_token.token_type
            }

    def update_token(self, user_name:str, token:str):

        user_token = db.UserToken.by_user_name(user_name=user_name)
        # Create the user if it does not exist
        if not user_token:
            user_token = db.UserToken()
            user_token.user_name = user_name
        # Save the new token
        user_token.access_token = token['access_token']
        user_token.token_type = token['token_type']
        user_token.refresh_token = token.get('refresh_token')
        if 'expires_in' in token:
            user_token.expires_in = token['expires_in']
        else:
            access_token = jwt.decode(user_token.access_token, verify=False)
            user_token.expires_in = access_token['exp'] - access_token['iat']

        model.Session.add(user_token)
        model.Session.commit()

    def refresh_token(self, user_name:str):
        token = self.get_stored_token(user_name)
        if token:
            client = OAuth2Session(self.client_id, token=token, scope=self.scope)
            try:
                token = client.refresh_token(self.token_endpoint, client_secret=self.client_secret, client_id=self.client_id, verify=self.verify_https)
            except requests.exceptions.SSLError as e:
                # TODO search a better way to detect invalid certificates
                if "verify failed" in six.text_type(e):
                    raise InsecureTransportError()
                else:
                    raise
            self.update_token(user_name, token)
            log.info('Token for user %s has been updated properly' % user_name)
            return token
        else:
            log.warn('User %s has no refresh token' % user_name)
