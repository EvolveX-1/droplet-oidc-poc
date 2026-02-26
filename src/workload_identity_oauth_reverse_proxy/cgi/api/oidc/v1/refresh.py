#!/usr/bin/env python3
"""/v1/oidc/refresh (CGI)

Validates a refresh token and returns:
  - short-lived ID token (token)
  - rotated refresh token (refresh_token)

Runtime env (recommended):
  ID_TOKEN_TTL_SECONDS=900
  ID_TOKEN_REFRESH_TTL_SECONDS=2592000   # 30 days
"""

import json
import os

from . import cgi_helper
from . import do_api
from . import oauth_helper
from . import oidc_helper


DEFAULT_ID_TOKEN_TTL_SECONDS = 900
DEFAULT_REFRESH_TTL_SECONDS = 60 * 60 * 24 * 30  # 30 days


def _int_env(name: str, default: int) -> int:
    try:
        v = int(os.environ.get(name, str(default)).strip())
        return v if v > 0 else default
    except Exception:
        return default


@cgi_helper.json_response
def main() -> dict:
    token, _ = cgi_helper.get_token()

    try:
        oidc_token = oidc_helper.OIDCToken.validate(token)
    except Exception:
        raise cgi_helper.UnauthorizedException("invalid_or_expired_refresh_token")

    if not oidc_token.claims.get("id-token-refresh"):
        raise cgi_helper.UnauthorizedException("not_a_refresh_token")

    droplet_id = oidc_token.claims.get("droplet_id")
    if not droplet_id:
        raise cgi_helper.UnauthorizedException("refresh_token_missing_droplet_id")

    try:
        team_token = oauth_helper.retrieve_oauth_token(oidc_token.actx)
        droplet = do_api.do_droplet_get(team_token, droplet_id)
    except Exception:
        raise cgi_helper.ServerException("droplet_lookup_failed")

    sub = f"actx:{oidc_token.actx}:role:id-token"
    for tag in droplet.get("tags", []) or []:
        if isinstance(tag, str) and tag.startswith("oidc-sub:"):
            sub = tag[len("oidc-sub:") :]
            break

    id_ttl = _int_env("ID_TOKEN_TTL_SECONDS", DEFAULT_ID_TOKEN_TTL_SECONDS)
    refresh_ttl = _int_env("ID_TOKEN_REFRESH_TTL_SECONDS", DEFAULT_REFRESH_TTL_SECONDS)

    access_token = oidc_helper.OIDCToken.create(
        oidc_token.actx,
        {"sub": sub, "droplet_id": droplet_id, "ttl": id_ttl},
    )

    rotated_refresh = oidc_helper.OIDCToken.create(
        oidc_token.actx,
        {
            "sub": f"actx:{oidc_token.actx}:role:id-token-refresh",
            "droplet_id": droplet_id,
            "id-token-refresh": True,
            "ttl": refresh_ttl,
        },
    )

    return {
        "token": access_token.as_string,
        "refresh_token": rotated_refresh.as_string,
        "ttl_seconds": id_ttl,
        "refresh_ttl_seconds": refresh_ttl,
        "droplet_id": droplet_id,
        "sub": sub,
    }


if __name__ == "__main__":
    print(json.dumps(main()))
