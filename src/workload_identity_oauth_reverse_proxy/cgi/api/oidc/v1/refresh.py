import sys
import json
import os

from ..... import cgi_helper
from ..... import oidc_helper

# no-callback refresh:
# - validates refresh token (Bearer)
# - mints NEW access token + rotates refresh token
# - does NOT call any droplet API / callback
# - requires refresh token to contain "oidc_sub" (set in prove.py)

def _env_int(name: str, default: int) -> int:
    v = (os.environ.get(name) or "").strip()
    if not v:
        return default
    try:
        return int(v)
    except Exception:
        return default

@cgi_helper.json_response
def cgi_handler():
    # body is currently unused, but keep JSON parsing to match previous behavior
    try:
        _ = json.load(sys.stdin)
    except Exception:
        _ = {}

    token, _token_is_oidc = cgi_helper.get_token()
    refresh = oidc_helper.OIDCToken.validate(token)

    if not refresh.claims.get("id-token-refresh"):
        raise cgi_helper.UnauthorizedException("not a refresh token")

    subject = refresh.claims.get("oidc_sub")
    if not subject:
        raise cgi_helper.UnauthorizedException("refresh token missing oidc_sub (redeploy prove.py and re-seed)")

    access_ttl = _env_int("ID_TOKEN_TTL_SECONDS", 900)               # 15 minutes
    refresh_ttl = _env_int("ID_TOKEN_REFRESH_TTL_SECONDS", 2592000)  # 30 days

    access_claims = {"sub": subject, "ttl": access_ttl}
    refresh_claims = {
        "sub": refresh.claims.get("sub") or f"actx:{refresh.actx}:role:id-token-refresh",
        "id-token-refresh": True,
        "ttl": refresh_ttl,
        "oidc_sub": subject,
    }

    return {
        "token": oidc_helper.OIDCToken.create(refresh.actx, access_claims).as_string,
        "refresh_token": oidc_helper.OIDCToken.create(refresh.actx, refresh_claims).as_string,
    }

if __name__ == "__main__":
    cgi_handler()
