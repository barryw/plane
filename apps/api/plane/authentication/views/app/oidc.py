# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import secrets
import time

import jwt
import requests
from django.db import IntegrityError
from django.http import HttpResponseRedirect
from django.views import View

from plane.authentication.adapter.error import AUTHENTICATION_ERROR_CODES, AuthenticationException
from plane.authentication.provider.oauth.oidc import OIDCProvider, oidc_error
from plane.authentication.utils.host import base_host
from plane.authentication.utils.login import user_login
from plane.authentication.utils.redirection_path import get_redirection_path
from plane.authentication.utils.user_auth_workflow import post_user_auth_workflow
from plane.license.models import Instance
from plane.utils.path_validator import get_safe_redirect_url


def error_redirect(request, next_path, exc):
    return HttpResponseRedirect(get_safe_redirect_url(
        base_url=base_host(request=request, is_app=True), next_path=next_path, params=exc.get_error_dict()
    ))


OIDC_ERRORS = (AuthenticationException, requests.RequestException, jwt.PyJWTError, ValueError, TypeError, KeyError)


class OIDCInitiateEndpoint(View):
    def get(self, request):
        request.session.pop("oidc_flow", None)
        next_path = request.GET.get("next_path")
        instance = Instance.objects.first()
        if instance is None or not instance.is_setup_done:
            return error_redirect(request, next_path, AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["INSTANCE_NOT_CONFIGURED"],
                error_message="INSTANCE_NOT_CONFIGURED",
            ))
        flow = {
            "state": secrets.token_urlsafe(32),
            "nonce": secrets.token_urlsafe(32),
            "verifier": secrets.token_urlsafe(64),
            "started": time.time(),
            "next_path": next_path,
        }
        try:
            provider = OIDCProvider(request, state=flow["state"], nonce=flow["nonce"], verifier=flow["verifier"])
            request.session["oidc_flow"] = flow
            return HttpResponseRedirect(provider.get_auth_url())
        except OIDC_ERRORS as exc:
            return error_redirect(request, next_path, exc if isinstance(exc, AuthenticationException) else oidc_error())


class OIDCCallbackEndpoint(View):
    def get(self, request):
        # Consume before any network request so failures and replays both fail closed.
        flow = request.session.pop("oidc_flow", None)
        next_path = flow.get("next_path") if flow else None
        if (
            not flow
            or not request.GET.get("state")
            or not secrets.compare_digest(request.GET["state"], flow["state"])
            or not 0 <= time.time() - flow["started"] <= 600
            or request.GET.get("error")
            or not request.GET.get("code")
        ):
            return error_redirect(request, next_path, oidc_error())
        try:
            provider = OIDCProvider(
                request, code=request.GET["code"], nonce=flow["nonce"], verifier=flow["verifier"],
                callback=post_user_auth_workflow,
            )
            user = provider.authenticate()
            user_login(request=request, user=user, is_app=True)
            return HttpResponseRedirect(get_safe_redirect_url(
                base_url=base_host(request=request, is_app=True),
                next_path=next_path or get_redirection_path(user=user), params={},
            ))
        except (*OIDC_ERRORS, IntegrityError) as exc:
            return error_redirect(request, next_path, exc if isinstance(exc, AuthenticationException) else oidc_error())
