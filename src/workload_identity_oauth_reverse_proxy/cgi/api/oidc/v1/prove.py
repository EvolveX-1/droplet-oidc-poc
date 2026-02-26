#!/usr/bin/env python3
"""No-callback /v1/oidc/prove (CGI)

Caller sends:
  - pubkey: OpenSSH host public key (e.g. /etc/ssh/ssh_host_ed25519_key.pub)
  - sig: OpenSSH signature produced by:
      echo -n "$PROVISIONING_TOKEN" | ssh-keygen -Y sign -n prove-sshd -f /etc/ssh/ssh_host_ed25519_key

Server:
  1) Validates provisioning token (JWT) with oidc_helper
  2) Resolves droplet_id from nonce (DB)
  3) Fetches droplet tags via DO API (to derive subject)
  4) Verifies SSH signature using provisioning.validate_ssh_signature (NO callback)
  5) Mints short-lived ID token + long-lived refresh token

Runtime env (recommended):
  ID_TOKEN_TTL_SECONDS=900
  ID_TOKEN_REFRESH_TTL_SECONDS=2592000   # 30 days
"""

import json
import os
import sys

from . import cgi_helper
from . import do_api
from . import oauth_helper
from . import oidc_helper
from . import provisioning


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
    # provisioning token (Bearer)
    token, _ = cgi_helper.get_token()

    # body
    try:
        req = json.load(sys.stdin) if sys.stdin is not None else {}
    except Exception:
        raise cgi_helper.BadRequestException("invalid_json")

    pubkey = (req.get("pubkey") or "").strip()
    signature = (req.get("sig") or "").strip()
    if not pubkey or not signature:
        raise cgi_helper.BadRequestException("missing_pubkey_or_sig")

    # validate JWT
    try:
        oidc_token = oidc_helper.OIDCToken.validate(token)
    except Exception:
        raise cgi_helper.UnauthorizedException("invalid_or_expired_provisioning_token")

    # droplet lookup (needed for oidc-sub:* tag)
    try:
        team_token = oauth_helper.retrieve_oauth_token(oidc_token.actx)
        droplet_id = provisioning.get_droplet_id(oidc_token.claims["nonce"])
        droplet = do_api.do_droplet_get(team_token, droplet_id)
    except Exception:
        raise cgi_helper.ServerException("droplet_lookup_failed")

    # verify signature (no callback)
    try:
        ok = provisioning.validate_ssh_signature(pubkey, signature, token)
    except Exception:
        raise cgi_helper.ServerException("ssh_signature_verify_failed")

    if not ok:
        raise cgi_helper.UnauthorizedException("invalid_signature")

    # subject from tag
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

    refresh_token = oidc_helper.OIDCToken.create(
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
        "refresh_token": refresh_token.as_string,
        "ttl_seconds": id_ttl,
        "refresh_ttl_seconds": refresh_ttl,
        "droplet_id": droplet_id,
        "sub": sub,
    }


if __name__ == "__main__":
    print(json.dumps(main()))
