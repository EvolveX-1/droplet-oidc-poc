# -*- coding: utf-8 -*-
"""
OIDC helper utilities for the DigitalOcean Workload Identity OAuth reverse proxy.

Goals of this module:
- Never return HTTP 500 for "bad token" / "missing claims" situations.
  Those should raise cgi_helper.UnauthorizedException so the CGI wrapper can
  translate them into a 401 JSON response.
- Ensure any JWT claims we *create* are JSON-serializable (UUID/datetime -> str/int).
"""

from __future__ import annotations

import base64
import dataclasses
import datetime
import json
import logging
import os
import urllib.parse
from typing import Any, Callable

import jwt

from . import cgi_helper
from . import jwt_helper

logger = logging.getLogger(__package__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _env_int(name: str, default: int) -> int:
    v = (os.environ.get(name) or "").strip()
    if not v:
        return default
    try:
        return int(v)
    except Exception:
        return default


def _to_epoch_seconds(dt: datetime.datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return int(dt.timestamp())


def _json_safe(obj: Any) -> Any:
    """
    Convert common non-JSON types that can accidentally appear in JWT claims.
    """
    if isinstance(obj, datetime.datetime):
        return _to_epoch_seconds(obj)
    # date (no time)
    if isinstance(obj, datetime.date) and not isinstance(obj, datetime.datetime):
        return int(datetime.datetime(obj.year, obj.month, obj.day, tzinfo=datetime.timezone.utc).timestamp())
    # UUIDs
    try:
        import uuid as _uuid
        if isinstance(obj, _uuid.UUID):
            return str(obj)
    except Exception:
        pass
    return obj


def _sanitize_claims(claims: dict) -> dict:
    """
    Deep-ish sanitize a claims dict so json.dumps never raises due to UUID/datetime.
    """
    out: dict[str, Any] = {}
    for k, v in (claims or {}).items():
        if isinstance(v, dict):
            out[k] = _sanitize_claims(v)
        elif isinstance(v, list):
            out[k] = [_json_safe(x) for x in v]
        else:
            out[k] = _json_safe(v)
    return out


def _parse_actx_and_api_from_aud(aud: str) -> tuple[str, str]:
    """
    Expected audience format: api://<api>?actx=<identifier>
    """
    if not aud or not isinstance(aud, str):
        raise cgi_helper.UnauthorizedException("token missing aud")

    if not aud.startswith("api://"):
        raise cgi_helper.UnauthorizedException("aud must start with api://")

    parsed = urllib.parse.urlparse(aud)
    # urlparse("api://x?actx=y") => scheme=api, netloc=x, query=actx=y
    api = parsed.netloc
    qs = urllib.parse.parse_qs(parsed.query or "")
    actx_list = qs.get("actx") or []
    if len(actx_list) != 1 or not actx_list[0]:
        raise cgi_helper.UnauthorizedException("token missing actx")
    return actx_list[0], api


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class OIDCToken:
    actx: str
    api: str
    aud: str
    sub: str
    claims: dict
    as_string: str

    @classmethod
    def create(cls, actx: str, claims: dict, api: str | None = None) -> "OIDCToken":
        """
        Create a signed JWT using the local RSA signing key (jwt_helper.key).
        - Ensures exp/iat are epoch seconds.
        - Ensures claims are JSON serializable.
        """
        if api is None:
            api = "DigitalOcean"

        # default TTL: 15 min (or env override)
        ttl = int((claims or {}).get("ttl") or _env_int("ID_TOKEN_TTL_SECONDS", 900))
        now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())

        audience = f"api://{api}?actx={actx}"

        c = _sanitize_claims(dict(claims or {}))
        c.pop("ttl", None)

        # Required-ish claims
        c.setdefault("aud", audience)
        c.setdefault("iss", (os.environ.get("THIS_ENDPOINT") or os.environ.get("JWT_ISSUER_URL") or "").strip())
        if not c.get("iss"):
            # We prefer explicit env, but fail safe with something readable.
            c["iss"] = "unknown-issuer"

        c["iat"] = int(c.get("iat", now))
        c["exp"] = int(c.get("exp", now + ttl))

        # sub is required for our policy matching; enforce presence.
        sub = str(c.get("sub") or "")
        if not sub:
            raise cgi_helper.UnauthorizedException("missing sub")
        c["sub"] = sub

        token_as_string = jwt.encode(c, jwt_helper.key, algorithm="RS256")
        return cls(
            actx=actx,
            api=api,
            aud=audience,
            sub=sub,
            claims=c,
            as_string=token_as_string,
        )

    @classmethod
    def validate(
        cls,
        token: str,
        *,
        api: str | None = None,
        get_issuers: Callable[[str, str], list[str]] | None = None,
    ) -> "OIDCToken":
        """
        Validate a JWT:
        - Structural checks
        - Extract actx/api from aud (NOT from iss)
        - Ensure iss is present
        - Verify signature using issuer JWKS via jwt_helper.get_keys()
        """
        if token == "0" or not token:
            raise cgi_helper.UnauthorizedException("Unable to authenticate you, no token")

        if token.count(".") != 2:
            raise cgi_helper.UnauthorizedException("token not jwt-ish")

        # Decode payload without verifying signature to extract iss/aud
        try:
            _hdr_b64, payload_b64, _sig = token.split(".", 2)
            payload_b64 += "=" * ((4 - (len(payload_b64) % 4)) % 4)
            unverified_payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode("utf-8")))
        except Exception:
            raise cgi_helper.UnauthorizedException("invalid token payload")

        issuer = unverified_payload.get("iss")
        if not issuer:
            raise cgi_helper.UnauthorizedException("token missing iss")

        aud = unverified_payload.get("aud")
        actx, parsed_api = _parse_actx_and_api_from_aud(aud)

        if api is None:
            api = parsed_api

        # Determine which issuers are allowed for this api/actx
        issuers = []
        if get_issuers is not None:
            try:
                issuers.extend(get_issuers(api, actx))
            except Exception:
                # never hard-fail issuer discovery; we'll still validate against issuer in token
                pass
        # Always allow the issuer embedded in the token
        issuers.append(issuer)
        issuers = list(dict.fromkeys([x for x in issuers if x]))  # de-dupe, drop empties

        # Verify using the issuer's JWKS. jwt_helper.get_keys accepts base endpoint (scheme+netloc).
        parsed_issuer = urllib.parse.urlparse(issuer)
        base_endpoint = f"{parsed_issuer.scheme}://{parsed_issuer.netloc}"

        keys = jwt_helper.get_keys(base_endpoint, api=api)

        last_err: Exception | None = None
        for iss in issuers:
            try:
                claims = jwt.decode(
                    token,
                    keys,
                    algorithms=["RS256"],
                    audience=aud,
                    issuer=iss,
                    options={"require": ["exp", "iat", "iss", "sub"]},
                )
                sub = str(claims.get("sub") or "")
                if not sub:
                    raise cgi_helper.UnauthorizedException("missing sub")
                return cls(
                    actx=actx,
                    api=api,
                    aud=str(claims.get("aud") or aud),
                    sub=sub,
                    claims=claims,
                    as_string=token,
                )
            except jwt.PyJWTError as e:
                last_err = e
                continue

        raise cgi_helper.UnauthorizedException(f"invalid token: {last_err}")  # type: ignore[arg-type]
