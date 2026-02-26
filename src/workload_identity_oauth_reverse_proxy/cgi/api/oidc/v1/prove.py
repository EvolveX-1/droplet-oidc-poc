#!/usr/bin/env python3
"""
/v1/oidc/prove  (NO CALLBACK)

Goal:
- Remove the callback model entirely.
- Prove the droplet possesses the SSH host private key by verifying an SSH signature.
- Then mint:
  - short-lived access token (ID token)
  - long-lived refresh token (rotating)

Request:
  Authorization: Bearer <PROVISIONING_TOKEN>
  JSON body: { "pubkey": "<ssh-ed25519 ...>", "sig": "<SSH SIGNATURE armored text>" }

How to generate sig on the droplet:
  SIG="$(echo -n "$PROVISIONING_TOKEN" | ssh-keygen -Y sign -n prove-sshd -f /etc/ssh/ssh_host_ed25519_key 2>/dev/null)"
  PUBKEY="$(cat /etc/ssh/ssh_host_ed25519_key.pub)"
  curl -X POST "$THIS_ENDPOINT/v1/oidc/prove" \
    -H "Authorization: Bearer ${PROVISIONING_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$(python3 -c 'import json,os; print(json.dumps({"pubkey": os.environ["PUBKEY"], "sig": os.environ["SIG"]}))')"

Env:
  ID_TOKEN_TTL_SECONDS: access token TTL (recommended 900)
  ID_TOKEN_REFRESH_TTL_SECONDS: refresh token TTL (recommended 2592000 = 30 days)
"""

import json
import os
import subprocess
import tempfile
import time

import jwt

import cgi_helper
import do_api
import oidc_helper


def _json_error(code: int, err_id: str, message: str):
    return code, {"Content-Type": "application/json"}, json.dumps({"id": err_id, "message": message})


def _get_bearer_token(environ) -> str:
    auth = environ.get("HTTP_AUTHORIZATION", "") or ""
    # Accept "Bearer <token>"
    parts = auth.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return ""


def _decode_unverified(token: str) -> dict:
    # We rely on signature proof + DO control-plane trust;
    # Here we only need claims like droplet_id/actx/exp.
    return jwt.decode(token, options={"verify_signature": False, "verify_aud": False})


def _verify_ssh_signature(pubkey: str, sig_armored: str, message: str) -> bool:
    """
    Verify an OpenSSH signature with ssh-keygen -Y verify.
    pubkey: one-line OpenSSH public key, e.g. "ssh-ed25519 AAAA... comment"
    sig_armored: output of ssh-keygen -Y sign (armored block with BEGIN/END SSH SIGNATURE)
    message: string to verify (we sign the provisioning token itself)
    """
    if not pubkey.startswith("ssh-"):
        return False
    if "BEGIN SSH SIGNATURE" not in sig_armored:
        return False

    with tempfile.TemporaryDirectory() as td:
        allowed = os.path.join(td, "allowed_signers")
        sigf = os.path.join(td, "sig.txt")
        msgf = os.path.join(td, "msg.txt")

        # allowed_signers format: <principal> <publickey>
        with open(allowed, "w", encoding="utf-8") as f:
            f.write(f"droplet {pubkey.strip()}\n")

        with open(sigf, "w", encoding="utf-8") as f:
            f.write(sig_armored)

        with open(msgf, "w", encoding="utf-8") as f:
            f.write(message)

        # ssh-keygen -Y verify expects message on stdin
        # -I principal must match allowed_signers principal
        p = subprocess.run(
            ["ssh-keygen", "-Y", "verify", "-n", "prove-sshd", "-f", allowed, "-I", "droplet", "-s", sigf],
            stdin=open(msgf, "rb"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return p.returncode == 0


def handler(env, _):
    # 1) Parse bearer token
    prov_token = _get_bearer_token(env)
    if not prov_token:
        return _json_error(401, "unauthorized", "Missing Bearer token")

    # 2) Decode + basic freshness checks (exp)
    try:
        payload = _decode_unverified(prov_token)
    except Exception:
        return _json_error(401, "unauthorized", "Invalid token")

    now = int(time.time())
    exp = int(payload.get("exp") or 0)
    if exp and exp < now:
        return _json_error(401, "unauthorized", "Invalid or expired token")

    # 3) Validate as a provisioning token (expect droplet_id + actx from oidc_helper)
    try:
        oidc_token = oidc_helper.OIDCToken.from_string(prov_token)
        # This function should raise if not a provisioning token
        oidc_token.assert_is_role("provisioning")
    except Exception:
        # Keep it generic; do not leak details
        return _json_error(401, "unauthorized", "Invalid or expired token")

    # 4) Parse JSON body
    try:
        body = cgi_helper.body(env)  # bytes
        data = json.loads(body.decode("utf-8")) if body else {}
    except Exception:
        return _json_error(400, "bad_request", "Invalid JSON body")

    pubkey = (data.get("pubkey") or "").strip()
    sig = data.get("sig") or ""

    if not pubkey or not sig:
        return _json_error(400, "bad_request", "Missing pubkey or sig")

    # 5) Signature verification proves possession of host private key
    if not _verify_ssh_signature(pubkey, sig, prov_token):
        return _json_error(401, "unauthorized", "Signature verification failed")

    # 6) Fetch droplet to derive subject (tag-based)
    try:
        droplet = do_api.do_droplet_get(oidc_token.droplet_id)
    except Exception:
        return _json_error(401, "unauthorized", "Invalid token")

    subjects = do_api.extract_subs_from_tags(droplet.get("tags") or [])
    if not subjects:
        return _json_error(401, "unauthorized", "Droplet missing oidc-sub tag")

    # 7) Mint tokens
    access_ttl = int(os.environ.get("ID_TOKEN_TTL_SECONDS", "900"))
    refresh_ttl = int(os.environ.get("ID_TOKEN_REFRESH_TTL_SECONDS", "2592000"))  # 30 days default

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
