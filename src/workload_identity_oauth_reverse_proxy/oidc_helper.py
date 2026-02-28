"""
OIDC/JWT helper utilities for the DigitalOcean OIDC reverse-proxy app.

Key goals for this helper (based on field issues we hit):
- Never crash the API handlers on obvious auth failures (return 401/4xx upstream).
- Keep token creation/validation logic self-contained and dependency-light.
- Be backward-compatible with older code paths (e.g., allow an optional `api`
  field on tokens without breaking callers).

This module is imported by provisioning/prove/refresh routes.
"""
from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import jwt

from .common import THIS_ENDPOINT
from . import database
from .jwt_helper import JWT_ALGORITHM, JWT_ISSUER_URL, JWT_SIGNING_KEY_PRIVATE_PEM, JWT_SIGNING_KEY_PUBLIC_PEM


# ------------------------- Exceptions -------------------------

class UnauthorizedError(Exception):
    """Raised for authentication/authorization failures."""


class AuthContextMissingFromSubjectError(UnauthorizedError):
    """Raised when a token subject is missing the expected auth context."""


# ------------------------- Config -------------------------

DEFAULT_API = "DigitalOcean"

def _int_env(name: str, default: int) -> int:
    v = os.environ.get(name)
    if not v:
        return default
    try:
        return int(v)
    except Exception:
        return default

# Recommended defaults:
# - Provisioning token TTL should be long enough to survive cloud-init delays, but short.
# - Access/refresh TTLs are handled by their own flows; this is for ID-like tokens.
ID_TOKEN_TTL_SECONDS = _int_env("ID_TOKEN_TTL_SECONDS", 15 * 60)  # 900s default


# ------------------------- Helpers -------------------------

def _b64url_json(payload: Dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("ascii").rstrip("=")

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _aud_for(actx: str, api: str) -> str:
    # Include actx in aud for unambiguous binding.
    return f"api://{api}?actx={actx}"

def _normalize_actx_from_aud(aud: str) -> Optional[str]:
    # Extract actx=<...> from audience string.
    # aud may be "api://DigitalOcean?actx=TEAM_UUID" or a list; caller handles list.
    try:
        if "actx=" not in aud:
            return None
        return aud.split("actx=", 1)[1].split("&", 1)[0]
    except Exception:
        return None


# ------------------------- Token type -------------------------

@dataclass(frozen=True)
class OIDCToken:
    """
    Representation of a signed JWT created/validated by this service.
    """
    actx: str
    aud: str
    sub: str
    claims: Dict[str, Any]
    as_string: str
    # Optional field kept for backward compatibility (some earlier iterations used it).
    api: str = DEFAULT_API

    @staticmethod
    def _load_keys() -> Tuple[str, str]:
        """
        Returns (private_pem, public_pem) as UTF-8 strings.
        Values are sourced from jwt_helper/database (already initialized elsewhere).
        """
        priv = JWT_SIGNING_KEY_PRIVATE_PEM
        pub = JWT_SIGNING_KEY_PUBLIC_PEM

        # jwt_helper exports bytes in some versions. Normalize to str.
        if isinstance(priv, (bytes, bytearray)):
            priv = priv.decode("utf-8")
        if isinstance(pub, (bytes, bytearray)):
            pub = pub.decode("utf-8")

        return priv, pub

    @classmethod
    def create(
        cls,
        actx: str,
        claims: Dict[str, Any],
        *,
        api: str = DEFAULT_API,
        ttl_seconds: Optional[int] = None,
    ) -> "OIDCToken":
        """
        Create and sign a JWT.

        NOTE: We intentionally DO NOT enforce a specific `sub` format here.
        Callers (provisioning/issue) should set `sub` appropriately.
        """
        if not actx:
            raise ValueError("actx required")
        if "sub" not in claims or not claims["sub"]:
            raise ValueError("claims.sub required")

        ttl = int(ttl_seconds if ttl_seconds is not None else ID_TOKEN_TTL_SECONDS)
        now = _utcnow()
        exp = now + timedelta(seconds=max(60, ttl))  # never less than 60s

        # Standard claims
        full_claims = dict(claims)
        full_claims.setdefault("iss", JWT_ISSUER_URL or THIS_ENDPOINT)
        full_claims.setdefault("iat", int(now.timestamp()))
        full_claims.setdefault("nbf", int(now.timestamp()))
        full_claims.setdefault("exp", int(exp.timestamp()))
        full_claims.setdefault("aud", _aud_for(actx, api))

        # Sign
        priv_pem, _ = cls._load_keys()
        token_str = jwt.encode(full_claims, priv_pem, algorithm=JWT_ALGORITHM)

        aud = full_claims["aud"]
        sub = full_claims["sub"]
        return cls(actx=actx, api=api, aud=aud, sub=sub, claims=full_claims, as_string=token_str)

    @classmethod
    def validate(
        cls,
        token: str,
        *,
        expected_api: str = DEFAULT_API,
        require_actx_in_aud: bool = True,
        leeway_seconds: int = 10,
    ) -> "OIDCToken":
        """
        Validate a JWT and return an OIDCToken.

        - Always verifies signature.
        - Verifies `iss` if present.
        - Verifies expiry.
        - Verifies audience format and extracts `actx`.
        """
        if not token or token.count(".") != 2:
            raise UnauthorizedError("token not jwt-ish")

        _, pub_pem = cls._load_keys()

        # Decode; we validate audience manually because it includes query params.
        try:
            decoded = jwt.decode(
                token,
                pub_pem,
                algorithms=[JWT_ALGORITHM],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": False,
                },
                leeway=leeway_seconds,
            )
        except jwt.ExpiredSignatureError:
            raise UnauthorizedError("token expired")
        except jwt.InvalidTokenError as e:
            raise UnauthorizedError(f"invalid token: {e}")

        aud_claim = decoded.get("aud")
        aud: Optional[str] = None
        if isinstance(aud_claim, str):
            aud = aud_claim
        elif isinstance(aud_claim, (list, tuple)) and aud_claim:
            # PyJWT may decode aud as list.
            aud = str(aud_claim[0])

        if not aud:
            raise UnauthorizedError("token missing aud")

        actx = _normalize_actx_from_aud(aud) if require_actx_in_aud else None
        if require_actx_in_aud and not actx:
            raise UnauthorizedError("token missing actx")

        # Optional issuer check (allow legacy tokens that omitted iss during earlier experiments)
        iss = decoded.get("iss")
        if iss and JWT_ISSUER_URL and iss != JWT_ISSUER_URL:
            raise UnauthorizedError("token bad iss")

        sub = decoded.get("sub")
        if not sub:
            raise UnauthorizedError("token missing sub")

        # Keep api best-effort
        api = expected_api
        # If aud begins with api://X, prefer X
        if aud.startswith("api://"):
            api = aud[len("api://"):].split("?", 1)[0] or expected_api

        return cls(actx=actx or "", api=api, aud=aud, sub=sub, claims=decoded, as_string=token)
