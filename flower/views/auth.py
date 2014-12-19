from __future__ import absolute_import

import re
import json

import tornado.web
import tornado.auth
from tornado.concurrent import return_future

from tornado import httpclient

from ..views import BaseHandler


class LoginHandler(BaseHandler, tornado.auth.OAuthMixin):

    _OAUTH_REQUEST_TOKEN_URL = "https://sandbox.app.passaporteweb.com.br/sso/initiate/"
    _OAUTH_ACCESS_TOKEN_URL = "https://sandbox.app.passaporteweb.com.br/sso/token/"
    _OAUTH_AUTHORIZE_URL = "https://sandbox.app.passaporteweb.com.br/sso/authorize/"
    _OAUTH_AUTHENTICATE_URL = "https://sandbox.app.passaporteweb.com.br/sso/fetchuserdata/"
    _OAUTH_NO_CALLBACKS = False

    @tornado.gen.coroutine
    def get(self):
        if self.get_argument("oauth_token", None):
            user = yield self.get_authenticated_user()
        else:
            yield self.authorize_redirect(
                callback_uri="http://127.0.0.1:5555",

            )

    def _oauth_consumer_token(self):
        return dict(
            key=self.settings["passaporte_web"]["key"],
            secret=self.settings["passaporte_web"]["secret"])


class LogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie('user')
        self.render('404.html', message='Successfully logged out!')
