# Authentik OIDC for Community Edition

This fork adds native OIDC login to Plane Community Edition v1.4.2. It uses the
existing account, signup, invitation, deactivation and session workflows. No
Commercial Edition code or license mechanism is involved.

Set these server-side environment variables on the API:

| Variable | Value |
| --- | --- |
| `WEB_URL` | `https://plane.barrywalker.io` |
| `OIDC_ISSUER_URL` | `https://auth.barrywalker.io/application/o/plane/` |
| `OIDC_CLIENT_ID` | The confidential Authentik client ID |
| `OIDC_CLIENT_SECRET` | The client secret (Kubernetes Secret) |
| `OIDC_DISPLAY_NAME` | `Authentik` (optional label) |

Create an Authentik OAuth2 provider with a signing certificate and the default
`openid`, `profile`, and `email` scope mappings. Set the strict redirect URI to
`https://plane.barrywalker.io/auth/oidc/callback/`. Bind the application to the
staff group. The provider must return `email_verified: true`; only verified
addresses can link to an existing Plane account. Review the source of that claim
in Authentik before granting users access. Do not allow users to edit their own
email to an address they have not verified.

The login button appears when all three OIDC credentials are set. Client secrets
are never returned by the instance API. The main app supports OIDC; God Mode
retains its separate administrator login, and public Spaces retain upstream auth.
Disable ordinary password/magic login in instance settings if OIDC should be the
only main-app login method. Signup must remain enabled (or users must have pending
workspace invitations) for first-time OIDC users.

The adapter requires HTTPS, same-origin discovery endpoints, PKCE S256, one-use
state (10-minute lifetime), nonce, signed RS256/ES256 ID tokens, exact issuer,
audience/authorized party, expiry, and matching UserInfo subject. Subject links
include the issuer and reject email/subject changes rather than reassigning an
account. An administrator must resolve legitimate identity/email changes.

Run tests:

```sh
docker compose -f docker-compose-test.yml run --rm --build api-tests \
  pytest plane/tests/unit/views/test_oidc.py
```

Build the backend with `apps/api/Dockerfile.oidc` (context `apps/api`) and the web
with `apps/web/Dockerfile.web` (repository root). Other components use the matching
upstream v1.4.2 images. Keep custom images versioned and update the fork when
upstream publishes fixes. A Source code link on the login page points to this
public fork.
