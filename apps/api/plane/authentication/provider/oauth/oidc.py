# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import hashlib
import os
from datetime import timedelta
from urllib.parse import urlencode, urlsplit

import jwt
import requests
from django.db import transaction
from django.utils import timezone

from plane.authentication.adapter.error import AUTHENTICATION_ERROR_CODES, AuthenticationException
from plane.authentication.adapter.oauth import OauthAdapter
from plane.db.models import Account


def oidc_enabled():
    return all(os.environ.get(key) for key in ("OIDC_ISSUER_URL", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET"))


def oidc_error():
    return AuthenticationException(
        error_code=AUTHENTICATION_ERROR_CODES["AUTHENTICATION_FAILED"],
        error_message="AUTHENTICATION_FAILED",
    )


class OIDCProvider(OauthAdapter):
    """One operator-configured OIDC issuer, using authorization code + PKCE."""

    def __init__(self, request, code=None, state=None, nonce=None, verifier=None, callback=None):
        if not oidc_enabled():
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OAUTH_NOT_CONFIGURED"],
                error_message="OAUTH_NOT_CONFIGURED",
            )
        self.issuer = os.environ["OIDC_ISSUER_URL"]
        self.nonce = nonce
        self.verifier = verifier
        origin = urlsplit(self.issuer)
        if origin.scheme != "https" or not origin.hostname or origin.username or origin.query or origin.fragment:
            raise oidc_error()
        self.origin = (origin.scheme, origin.netloc)
        metadata = self.fetch_json("GET", f"{self.issuer.rstrip('/')}/.well-known/openid-configuration")
        if metadata.get("issuer") != self.issuer:
            raise oidc_error()
        for key in ("authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri"):
            endpoint = metadata.get(key, "")
            parsed = urlsplit(endpoint)
            # Keep discovery from sending credentials to another origin.
            if (parsed.scheme, parsed.netloc) != self.origin or parsed.username or parsed.fragment:
                raise oidc_error()
        self.jwks_uri = metadata["jwks_uri"]
        web_url = os.environ.get("WEB_URL", "").rstrip("/")
        if urlsplit(web_url).scheme != "https":
            raise oidc_error()
        redirect_uri = f"{web_url}/auth/oidc/callback/"
        client_id = os.environ["OIDC_CLIENT_ID"]
        params = {
            "client_id": client_id,
            "response_type": "code",
            "scope": "openid profile email",
            "redirect_uri": redirect_uri,
            "state": state,
            "nonce": nonce,
            "code_challenge": jwt.utils.base64url_encode(hashlib.sha256(verifier.encode()).digest()).decode(),
            "code_challenge_method": "S256",
        }
        super().__init__(
            request=request,
            provider="oidc",
            client_id=client_id,
            client_secret=os.environ["OIDC_CLIENT_SECRET"],
            scope=params["scope"],
            redirect_uri=redirect_uri,
            auth_url=f"{metadata['authorization_endpoint']}?{urlencode(params)}",
            token_url=metadata["token_endpoint"],
            userinfo_url=metadata["userinfo_endpoint"],
            code=code,
            callback=callback,
        )

    @staticmethod
    def fetch_json(method, url, **kwargs):
        response = requests.request(method, url, timeout=10, allow_redirects=False, **kwargs)
        if response.status_code != 200:
            raise oidc_error()
        data = response.json()
        if not isinstance(data, dict):
            raise oidc_error()
        return data

    def set_token_data(self):
        tokens = self.fetch_json(
            "POST",
            self.token_url,
            auth=(self.client_id, self.client_secret),
            data={
                "grant_type": "authorization_code",
                "code": self.code,
                "redirect_uri": self.redirect_uri,
                "code_verifier": self.verifier,
            },
        )
        id_token = tokens.get("id_token")
        if not isinstance(id_token, str) or not tokens.get("access_token"):
            raise oidc_error()
        signing_key = jwt.PyJWKClient(
            self.jwks_uri, headers={"User-Agent": "Plane-OIDC/1.0"}, timeout=10
        ).get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256", "ES256"],
            audience=self.client_id,
            issuer=self.issuer,
            options={"require": ["exp", "iat", "iss", "aud", "sub", "nonce"]},
        )
        if not isinstance(claims["sub"], str) or not claims["sub"] or claims["nonce"] != self.nonce:
            raise oidc_error()
        if claims.get("azp", self.client_id) != self.client_id:
            raise oidc_error()
        if isinstance(claims["aud"], list) and len(claims["aud"]) > 1 and "azp" not in claims:
            raise oidc_error()
        self.claims = claims
        self.token_data = {
            "access_token": tokens["access_token"],
            "refresh_token": tokens.get("refresh_token"),
            "access_token_expired_at": timezone.now() + timedelta(seconds=int(tokens.get("expires_in", 300))),
            "id_token": id_token,
        }

    def set_user_data(self):
        profile = self.fetch_json(
            "GET", self.userinfo_url, headers={"Authorization": f"Bearer {self.token_data['access_token']}"}
        )
        if profile.get("sub") != self.claims["sub"] or profile.get("email_verified") is not True:
            raise oidc_error()
        email = self.sanitize_email(profile.get("email"))
        # Namespace subjects by issuer; never link two subjects by email silently.
        self.subject = hashlib.sha256(f"{self.issuer}\0{self.claims['sub']}".encode()).hexdigest()
        self.user_data = {
            "email": email,
            "user": {
                "first_name": profile.get("given_name", ""),
                "last_name": profile.get("family_name", ""),
                "provider_id": self.subject,
                "is_password_autoset": True,
            },
        }

    @transaction.atomic
    def complete_login_or_signup(self):
        email = self.user_data["email"]
        account = Account.objects.select_related("user").filter(provider="oidc", provider_account_id=self.subject).first()
        if account and account.user.email != email:
            raise oidc_error()
        if Account.objects.filter(provider="oidc", user__email=email).exclude(provider_account_id=self.subject).exists():
            raise oidc_error()
        return super().complete_login_or_signup()

    def create_update_account(self, user):
        Account.objects.update_or_create(
            provider="oidc", provider_account_id=self.subject, defaults={"user": user, **self.token_data}
        )
