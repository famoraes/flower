from __future__ import absolute_import

import re
import json
import base64

from rauth import OAuth1Service

import tornado.web
import tornado.auth
from tornado import gen
from tornado.concurrent import return_future
from tornado.escape import json_decode, json_encode

from tornado import httpclient
from tornado import escape

from ..views import BaseHandler


class LoginHandler(BaseHandler, tornado.auth.OAuthMixin):

    # _OAUTH_REQUEST_TOKEN_URL = "https://sandbox.app.passaporteweb.com.br/sso/initiate/"
    # _OAUTH_ACCESS_TOKEN_URL = "https://sandbox.app.passaporteweb.com.br/sso/token/"
    # _OAUTH_AUTHORIZE_URL = "https://sandbox.app.passaporteweb.com.br/sso/authorize/"
    # _OAUTH_AUTHENTICATE_URL = "https://sandbox.app.passaporteweb.com.br/sso/fetchuserdata/"
    _OAUTH_NO_CALLBACKS = False

    def __init__(self, *args, **kwargs):
        super(LoginHandler, self).__init__(*args, **kwargs)

        self.base_url = self.settings["passaporte_web"]["base_api"]
        self._OAUTH_REQUEST_TOKEN_URL = self.base_url + "/sso/initiate/"
        self._OAUTH_ACCESS_TOKEN_URL = self.base_url + "/sso/token/"
        self._OAUTH_AUTHORIZE_URL = self.base_url + "/sso/authorize/"
        self._OAUTH_AUTHENTICATE_URL = self.base_url + "/sso/fetchuserdata/"

    def _get_credentials(self):
        return OAuth1Service(
            consumer_key =  self.settings["passaporte_web"]["key"],
            consumer_secret = self.settings["passaporte_web"]["secret"],
            request_token_url = self._OAUTH_REQUEST_TOKEN_URL,
            access_token_url = self._OAUTH_ACCESS_TOKEN_URL,
            authorize_url = self._OAUTH_AUTHORIZE_URL,
        )

    def _get_oauth_session(self):
        credentials = self._get_credentials()
        request_cookie = self.get_cookie("_oauth_request_token")
        token, secret = [base64.b64decode(escape.utf8(i)) for i in request_cookie.split("|")]

        return credentials.get_auth_session(token, secret,
            method="POST",
            data={'oauth_verifier': self.get_argument('oauth_verifier', None)})

    @tornado.web.asynchronous
    def get(self):
        if self.get_argument("oauth_token", None):
            user = self.get_authenticated_user()

            if not user:
                raise tornado.web.HTTPError(403, "Not authorized.")

            self.set_secure_cookie("user", user["email"])
            self.redirect(self.get_argument("next", "/"))
        else:
            self.authorize_redirect(
                callback_uri=self.settings["passaporte_web"]["callback_uri"]
            )

    def get_authenticated_user(self):
        session = self._get_oauth_session()
        user_data = session.get(self._OAUTH_AUTHENTICATE_URL).json()

        if not user_data["email"] in self.settings["passaporte_web"]["admins"]:
            return None

        return user_data

    def _oauth_consumer_token(self):
        return dict(
            key=self.settings["passaporte_web"]["key"],
            secret=self.settings["passaporte_web"]["secret"])

class LogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie('user')
        self.render('404.html', message='Successfully logged out!')
