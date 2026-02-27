import sys
import json
import os

from ..... import do_api
from ..... import cgi_helper
from ..... import oidc_helper
import oauth_helper

def _env_int(name: str, default: int) -> int:
    v = os.environ.get(name, "").strip()
    if not v:
        return default
    try:
        return int(v)
    except Exception:
        return default

@cgi_helper.json_response
def cgi_handler():
    token, _token_is_oidc = cgi_helper.get_token()
    oidc_token = oidc_helper.OIDCToken.validate(token)

    if "droplet_id" not in oidc_token.claims:
        raise cgi_helper.UnauthorizedException("refresh token does not have droplet_id claim")
    if not oidc_token.claims.get("id-token-refresh", False):
        raise cgi_helper.UnauthorizedException("refresh token does not have id-token-refresh: true claim")

    actx_slug = f"actx:{oidc_token.actx}"
    expected_refresh_subject = f"{actx_slug}:role:id-token-refresh"
    if expected_refresh_subject != oidc_token.sub:
        raise cgi_helper.UnauthorizedException(
            f"subject should have been {expected_refresh_subject!r} but was {oidc_token.sub!r}"
        )

    droplet_id = oidc_token.claims["droplet_id"]

    # Use team token for upstream API call
    team_token = oauth_helper.retrieve_oauth_token(oidc_token.actx)
    droplet = do_api.do_droplet_get(team_token, droplet_id)

    subject = ":".join(
        [actx_slug]
        + [
            tag.split(":", maxsplit=1)[1]
            for tag in droplet["tags"]
            if tag.startswith("oidc-sub:")
            and tag.count(":") == 2
            and tag.split(":")[1] != "actx"
        ]
    )

    access_ttl = _env_int("ID_TOKEN_TTL_SECONDS", 900)
    refresh_ttl = _env_int("ID_TOKEN_REFRESH_TTL_SECONDS", 2592000)

    claims = {"sub": subject, "droplet_id": droplet["id"], "ttl": access_ttl}
    refresh_claims = {
        "sub": expected_refresh_subject,
        "id-token-refresh": True,
        "ttl": refresh_ttl,
        "droplet_id": oidc_token.claims["droplet_id"],
    }

    return {
        "token": oidc_helper.OIDCToken.create(oidc_token.actx, claims).as_string,
        "refresh_token": oidc_helper.OIDCToken.create(oidc_token.actx, refresh_claims).as_string,
    }

if __name__ == "__main__":
    cgi_handler()
