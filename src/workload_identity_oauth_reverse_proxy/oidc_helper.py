import dataclasses
import base64
import datetime
import json
import os
import urllib.error
import urllib.request
import urllib.parse

import jwt

from . import jwt_helper
from . import cgi_helper

def _env_int(name: str, default: int) -> int:
    v = os.environ.get(name, "").strip()
    if not v:
        return default
    try:
        return int(v)
    except Exception:
        return default

@dataclasses.dataclass
class OIDCToken:
    actx: str
    sub: str
    claims: dict

    @property
    def as_string(self) -> str:
        return jwt.encode(self.claims, jwt_helper.key, algorithm="RS256")

    @staticmethod
    def validate(token: str, api=None):
        # quick structural check
        if token.count(".") != 2:
            raise cgi_helper.UnauthorizedException("token not jwt-ish")

        # decode payload without verifying signature to extract aud/iss
        header_b64, payload_b64, _sig = token.split(".", 2)
        payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
        try:
            unverified_payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode("utf-8")))
        except Exception:
            raise cgi_helper.UnauthorizedException("invalid token payload")

        issuer = unverified_payload.get("iss")
        if not issuer:
            raise cgi_helper.UnauthorizedException("token missing iss")
        parsed_issuer = urllib.parse.urlparse(issuer)
        actx = parsed_issuer.query.split("actx=", maxsplit=1)[1] if "actx=" in parsed_issuer.query else None
        if not actx:
            raise cgi_helper.UnauthorizedException("token missing actx")

        # verify signature using issuer JWKS
        oidc_api_endpoint = f"{parsed_issuer.scheme}://{parsed_issuer.netloc}"
        keys = jwt_helper.get_keys(oidc_api_endpoint, api=api)
        try:
            claims = jwt.decode(token, keys, algorithms=["RS256"], audience=unverified_payload.get("aud"))
        except Exception as e:
            raise cgi_helper.UnauthorizedException(f"invalid token: {e}")

        return OIDCToken(actx=actx, sub=claims.get("sub", ""), claims=claims)

    @staticmethod
    def create(actx: str, claims: dict, api=None):
        # ttl in seconds
        ttl = int(claims.get("ttl") or _env_int("ID_TOKEN_TTL_SECONDS", 900))
        now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        claims = dict(claims)
        claims["iat"] = now
        claims["exp"] = now + ttl
        # Ensure iss/aud exist (caller typically sets them)
        # We leave them untouched if provided.
        return OIDCToken(actx=actx, sub=claims.get("sub", ""), claims=claims)
