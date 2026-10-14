# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import hashlib
import time
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import RequestFactory

from plane.authentication.adapter.error import AuthenticationException
from plane.authentication.provider.oauth.oidc import OIDCProvider, oidc_enabled
from plane.authentication.views.app.oidc import OIDCCallbackEndpoint, OIDCInitiateEndpoint
from plane.db.models import Account

ISSUER = "https://auth.example.com/application/o/plane/"
METADATA = {
    "issuer": ISSUER,
    "authorization_endpoint": "https://auth.example.com/application/o/authorize/",
    "token_endpoint": "https://auth.example.com/application/o/token/",
    "userinfo_endpoint": "https://auth.example.com/application/o/userinfo/",
    "jwks_uri": f"{ISSUER}jwks/",
}


@pytest.fixture(autouse=True)
def oidc_env(monkeypatch, settings):
    settings.WEB_URL = "https://plane.example.com"
    monkeypatch.setenv("OIDC_ISSUER_URL", ISSUER)
    monkeypatch.setenv("OIDC_CLIENT_ID", "plane")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "secret")
    monkeypatch.setenv("WEB_URL", "https://plane.example.com")


@pytest.fixture
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def token(signing_key, **changes):
    claims = {"iss": ISSUER, "aud": "plane", "sub": "user-1", "exp": int(time.time()) + 300,
              "iat": int(time.time()), "nonce": "nonce"}
    claims.update(changes)
    return jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": "test"})


def provider():
    with patch.object(OIDCProvider, "fetch_json", return_value=METADATA):
        return OIDCProvider(RequestFactory().get("/"), code="code", state="state", nonce="nonce", verifier="verifier")


@pytest.mark.unit
def test_authorization_uses_pkce_nonce_and_fixed_callback():
    params = parse_qs(urlsplit(provider().get_auth_url()).query)
    assert params["redirect_uri"] == ["https://plane.example.com/auth/oidc/callback/"]
    assert params["state"] == ["state"]
    assert params["nonce"] == ["nonce"]
    assert params["code_challenge_method"] == ["S256"]
    assert params["code_challenge"] == [jwt.utils.base64url_encode(hashlib.sha256(b"verifier").digest()).decode()]


@pytest.mark.unit
@pytest.mark.parametrize("key,value", [("issuer", "https://wrong.example.com/"),
                                        ("token_endpoint", "https://evil.example.com/token"),
                                        ("jwks_uri", "http://auth.example.com/keys")])
def test_rejects_untrusted_discovery(key, value):
    with patch.object(OIDCProvider, "fetch_json", return_value={**METADATA, key: value}):
        with pytest.raises(AuthenticationException):
            OIDCProvider(RequestFactory().get("/"), nonce="nonce", verifier="verifier")


@pytest.mark.unit
def test_disabled_without_secret(monkeypatch):
    monkeypatch.delenv("OIDC_CLIENT_SECRET")
    assert not oidc_enabled()
    with pytest.raises(AuthenticationException):
        provider()


@pytest.mark.unit
@pytest.mark.parametrize("changes", [
    {"iss": "https://wrong.example.com/"}, {"aud": "other-client"}, {"nonce": "wrong"},
    {"exp": 1}, {"sub": ""}, {"azp": "other-client"}, {"aud": ["plane", "other-client"]},
])
def test_rejects_invalid_id_token(signing_key, changes):
    oidc = provider()
    with patch.object(oidc, "fetch_json", return_value={"id_token": token(signing_key, **changes), "access_token": "access"}), \
            patch("jwt.PyJWKClient.get_signing_key_from_jwt", return_value=SimpleNamespace(key=signing_key.public_key())):
        with pytest.raises((AuthenticationException, jwt.PyJWTError)):
            oidc.set_token_data()


@pytest.mark.unit
def test_rejects_wrong_signing_key(signing_key):
    oidc = provider()
    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with patch.object(oidc, "fetch_json", return_value={"id_token": token(wrong_key), "access_token": "access"}), \
            patch("jwt.PyJWKClient.get_signing_key_from_jwt", return_value=SimpleNamespace(key=signing_key.public_key())):
        with pytest.raises(jwt.InvalidSignatureError):
            oidc.set_token_data()


@pytest.mark.unit
def test_valid_token_and_verified_profile(signing_key):
    oidc = provider()
    with patch.object(oidc, "fetch_json", return_value={"id_token": token(signing_key), "access_token": "access"}) as fetch, \
            patch("jwt.PyJWKClient.get_signing_key_from_jwt", return_value=SimpleNamespace(key=signing_key.public_key())):
        oidc.set_token_data()
        assert fetch.call_args.kwargs["data"]["code_verifier"] == "verifier"
    with patch.object(oidc, "fetch_json", return_value={"sub": "user-1", "email": "USER@example.com", "email_verified": True}):
        oidc.set_user_data()
    assert oidc.user_data["email"] == "user@example.com"
    assert oidc.user_data["user"]["is_password_autoset"] is True


@pytest.mark.unit
@pytest.mark.parametrize("profile", [
    {"sub": "wrong", "email": "user@example.com", "email_verified": True},
    {"sub": "user-1", "email": "user@example.com", "email_verified": False},
    {"sub": "user-1", "email": "user@example.com"},
    {"sub": "user-1", "email": "invalid", "email_verified": True},
])
def test_rejects_invalid_profile(profile):
    oidc = provider()
    oidc.claims = {"sub": "user-1"}
    oidc.token_data = {"access_token": "access"}
    with patch.object(oidc, "fetch_json", return_value=profile), pytest.raises(AuthenticationException):
        oidc.set_user_data()


def callback_request(query="state=state&code=code", **flow_changes):
    request = RequestFactory().get(f"/auth/oidc/callback/?{query}")
    request.session = {"oidc_flow": {"state": "state", "nonce": "nonce", "verifier": "verifier",
                                    "started": time.time(), "next_path": "/workspace/", **flow_changes}}
    return request


@pytest.mark.unit
@pytest.mark.parametrize("query,flow", [("code=code", {}), ("state=wrong&code=code", {}), ("state=%C3%A9&code=code", {}),
                                          ("state=state", {}), ("state=state&code=code&error=access_denied", {}),
                                          ("state=state&code=code", {"started": 1})])
def test_callback_fails_closed_and_consumes_state(query, flow):
    request = callback_request(query, **flow)
    with patch("plane.authentication.views.app.oidc.OIDCProvider") as adapter:
        response = OIDCCallbackEndpoint.as_view()(request)
    assert "error_code=5999" in response.url
    assert "oidc_flow" not in request.session
    adapter.assert_not_called()


@pytest.mark.unit
def test_callback_logs_in_once_and_blocks_replay():
    request = callback_request()
    with patch("plane.authentication.views.app.oidc.OIDCProvider") as adapter, \
            patch("plane.authentication.views.app.oidc.user_login") as login:
        response = OIDCCallbackEndpoint.as_view()(request)
        assert response.url.endswith("/workspace/")
        login.assert_called_once()
        assert adapter.call_args.kwargs["nonce"] == "nonce"
        replay = OIDCCallbackEndpoint.as_view()(request)
        assert "error_code=5999" in replay.url
        assert adapter.call_count == 1


@pytest.mark.unit
def test_initiation_stores_new_flow_and_clears_stale_next_path():
    request = RequestFactory().get("/auth/oidc/")
    request.session = {"oidc_flow": {"next_path": "https://evil.example.com"}}
    with patch("plane.authentication.views.app.oidc.Instance.objects.first", return_value=SimpleNamespace(is_setup_done=True)), \
            patch.object(OIDCProvider, "fetch_json", return_value=METADATA):
        response = OIDCInitiateEndpoint.as_view()(request)
    assert response.status_code == 302
    assert request.session["oidc_flow"]["next_path"] is None
    assert len(request.session["oidc_flow"]["verifier"]) >= 43


@pytest.mark.unit
@pytest.mark.django_db
def test_subject_cannot_move_to_different_email(create_user):
    Account.objects.create(user=create_user, provider="oidc", provider_account_id="subject", access_token="access")
    oidc = provider()
    oidc.subject = "subject"
    oidc.user_data = {"email": "other@example.com"}
    with pytest.raises(AuthenticationException):
        oidc.complete_login_or_signup()


@pytest.mark.unit
@pytest.mark.django_db
def test_email_cannot_relink_to_another_subject(create_user):
    Account.objects.create(user=create_user, provider="oidc", provider_account_id="old-subject", access_token="access")
    oidc = provider()
    oidc.subject = "new-subject"
    oidc.user_data = {"email": create_user.email}
    with pytest.raises(AuthenticationException):
        oidc.complete_login_or_signup()
