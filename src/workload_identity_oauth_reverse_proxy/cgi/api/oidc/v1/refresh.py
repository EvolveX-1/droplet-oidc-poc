#!/usr/bin/env python3
"""
/v1/oidc/refresh

- Takes a refresh token (Bearer).
- Validates it is role:id-token-refresh and not expired.
- Rotates the refresh token (returns a NEW refresh_token) + returns a fresh access token.

Env:
  ID_TOKEN_TTL_SECONDS: access token TTL (recommended 900)
  ID_TOKEN_REFRESH_TTL_SECONDS: refresh token TTL (recommended 2592000 = 30 days)
"""

import json
import os
import time

import jwt

import cgi_helper
import do_api
import oidc_helper


def _json_error(code: int, err_id: str, message: str):
    return code, {"Content-Type": "application/json"}, json.dumps({"id": err_id, "message": message})


def _get_bearer_token(environ) -> str:
    auth = environ.get("HTTP_AUTHORIZATION", "") or ""
    parts = auth.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return ""


def _decode_unverified(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False, "verify_aud": False})


def handler(env, _):
    tok = _get_bearer_token(env)
    if not tok:
        return _json_error(401, "unauthorized", "Missing Bearer token")

    # quick exp check so invalid/expired tokens are 401 (not 500)
    try:
        payload = _decode_unverified(tok)
    except Exception:
        return _json_error(401, "unauthorized", "Invalid token")

    now = int(time.time())
    exp = int(payload.get("exp") or 0)
    if exp and exp < now:
        return _json_error(401, "unauthorized", "Invalid or expired token")

    try:
        oidc_token = oidc_helper.OIDCToken.from_string(tok)
        oidc_token.assert_is_role("id-token-refresh")
    except Exception:
        return _json_error(401, "unauthorized", "Invalid or expired token")

    # load droplet to re-derive subject from tags (source of truth)
    try:
        droplet = do_api.do_droplet_get(oidc_token.droplet_id)
    except Exception:
        return _json_error(401, "unauthorized", "Invalid or expired token")

    subjects = do_api.extract_subs_from_tags(droplet.get("tags") or [])
    if not subjects:
        return _json_error(401, "unauthorized", "Droplet missing oidc-sub tag")

    access_ttl = int(os.environ.get("ID_TOKEN_TTL_SECONDS", "900"))
    refresh_ttl = int(os.environ.get("ID_TOKEN_REFRESH_TTL_SECONDS", "2592000"))

    claims = {
        "sub": subjects[0],
        "droplet_id": droplet["id"],
        "ttl": access_ttl,
    }

    refresh_claims = {
        "sub": f"actx:{oidc_token.actx}:role:id-token-refresh",
        "id-token-refresh": True,
        "droplet_id": droplet["id"],
        "ttl": refresh_ttl,
    }

    return (
        200,
        {"Content-Type": "application/json"},
        json.dumps(
            {
                "token": oidc_helper.OIDCToken.create(oidc_token.actx, claims).as_string,
                "refresh_token": oidc_helper.OIDCToken.create(oidc_token.actx, refresh_claims).as_string,
            }
        ),
    )


if __name__ == "__main__":
    cgi_helper.cgid(handler)
