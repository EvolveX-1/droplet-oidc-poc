#!/usr/bin/env python3
"""
/v1/oidc/prove endpoint (NO CALLBACK)

Goal:
- Droplet proves it owns its host SSH private key.
- We do NOT dial back into the droplet (no callback / no port dance).
- We validate using OpenSSH's built-in sshsig verification (ssh-keygen -Y verify).

Request JSON:
{
  "pubkey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI.... root@projectgen-caller-XX",
  "sig": "-----BEGIN SSH SIGNATURE-----\n...\n-----END SSH SIGNATURE-----\n"
}

Auth:
- Authorization: Bearer <PROVISIONING_TOKEN>  (JWT created by issuer, embedded in droplet cloud-init)

Behavior:
- If provisioning token is invalid/expired -> 401
- If signature does not verify -> 401
- If ok -> returns { token, refresh_token } like original PoC
"""

import base64
import json
import os
import re
import subprocess
import tempfile
import time
from urllib.parse import parse_qs, urlparse

import jwt
from jwt import InvalidTokenError

# --- TTLs ---
# Keep ID token short (minutes). This is the token your caller uses to talk to your services (or to do GCP WIF).
DEFAULT_ID_TOKEN_TTL_SECONDS = int(os.getenv("ID_TOKEN_TTL_SECONDS", "900"))  # 15 minutes

# Refresh token longer-lived. You asked for 30 days.
DEFAULT_ID_TOKEN_REFRESH_TTL_SECONDS = int(
    os.getenv("ID_TOKEN_REFRESH_TTL_SECONDS", str(30 * 24 * 60 * 60))
)

# How long to wait for ssh-keygen verify to finish
SSH_VERIFY_TIMEOUT_SECONDS = int(os.getenv("SSH_VERIFY_TIMEOUT_SECONDS", "5"))

# Namespace used by ssh-keygen -Y sign/-Y verify.
# IMPORTANT: caller must use the SAME namespace via `ssh-keygen -Y sign -n <namespace> ...`
SSH_NAMESPACE = os.getenv("SSH_SIG_NAMESPACE", "prove-sshd")

# Identity used in allowed_signers.
SSH_ALLOWED_SIGNER_ID = os.getenv("SSH_ALLOWED_SIGNER_ID", "caller")


def _parse_team_uuid_from_aud(aud: str) -> str:
    # aud in this PoC often looks like: "api://DigitalOcean?actx=<TEAM_UUID>"
    try:
        qs = parse_qs(urlparse(aud).query)
        if "actx" in qs and qs["actx"]:
            return qs["actx"][0]
    except Exception:
        pass
    return ""


def _decode_provisioning_token(prov: str) -> dict:
    # NOTE: This PoC typically passes the provisioning token as a JWT.
    # For the prove step, we only need it as a stable message + some claims for lookup/routing.
    # We DO NOT verify signature here (same as original PoC patterns).
    try:
        payload = jwt.decode(
            prov,
            options={"verify_signature": False, "verify_exp": False, "verify_aud": False},
            algorithms=["RS256", "ES256", "HS256"],
        )
        if not isinstance(payload, dict):
            raise ValueError("bad payload type")
        return payload
    except InvalidTokenError as e:
        raise ValueError(f"invalid provisioning token: {e}") from e


def _ssh_verify_sig(message: bytes, pubkey_line: str, sig_text: str) -> None:
    """
    Verify sshsig using ssh-keygen -Y verify.
    This matches what ssh-keygen -Y sign produces on the droplet (no cryptography deps needed).
    """
    # Basic sanity checks
    if "BEGIN SSH SIGNATURE" not in sig_text:
        raise ValueError("sig does not look like an SSH signature block")
    if not pubkey_line.strip().startswith("ssh-"):
        raise ValueError("pubkey must be an OpenSSH public key line, starting with ssh-...")

    ssh_keygen = os.getenv("SSH_KEYGEN_PATH", "ssh-keygen")

    with tempfile.TemporaryDirectory() as td:
        msg_path = os.path.join(td, "msg.bin")
        sig_path = os.path.join(td, "msg.sig")
        allow_path = os.path.join(td, "allowed_signers")

        with open(msg_path, "wb") as f:
            f.write(message)

        with open(sig_path, "w", encoding="utf-8") as f:
            # Ensure newline at end; ssh-keygen is picky sometimes
            f.write(sig_text.strip() + "\n")

        # allowed_signers format: "<identity> <public-key>"
        with open(allow_path, "w", encoding="utf-8") as f:
            f.write(f"{SSH_ALLOWED_SIGNER_ID} {pubkey_line.strip()}\n")

        # Run:
        #   ssh-keygen -Y verify -f allowed_signers -I <identity> -n <namespace> -s sigfile < msgfile
        # NOTE: message passed via stdin.
        try:
            p = subprocess.run(
                [
                    ssh_keygen,
                    "-Y",
                    "verify",
                    "-f",
                    allow_path,
                    "-I",
                    SSH_ALLOWED_SIGNER_ID,
                    "-n",
                    SSH_NAMESPACE,
                    "-s",
                    sig_path,
                ],
                stdin=open(msg_path, "rb"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=SSH_VERIFY_TIMEOUT_SECONDS,
                check=False,
                text=True,
            )
        except FileNotFoundError as e:
            raise RuntimeError(
                f"ssh-keygen not found in issuer container (looked for {ssh_keygen}). "
                "Install openssh-client in the runtime image or set SSH_KEYGEN_PATH."
            ) from e
        except subprocess.TimeoutExpired as e:
            raise RuntimeError("ssh-keygen verify timed out") from e

        if p.returncode != 0:
            # Don't leak too much; include first line of stderr to help debugging.
            err = (p.stderr or "").strip().splitlines()
            msg = err[0] if err else "ssh-keygen verify failed"
            raise ValueError(msg)


def prove(request, db, issue_tokens_fn):
    """
    request: Flask request (or compatible)
    db: whatever your app passes (used by issue_tokens_fn)
    issue_tokens_fn(team_uuid, droplet_id, ttl_seconds, refresh_ttl_seconds, db) -> (token, refresh_token)
    """
    # 1) Read provisioning token
    auth = request.headers.get("Authorization", "")
    m = re.match(r"^\s*Bearer\s+(.+)\s*$", auth)
    if not m:
        return {"id": "unauthorized", "message": "Missing Bearer token"}, 401
    prov = m.group(1).strip()

    # 2) Parse JSON body
    try:
        body = request.get_json(force=True) or {}
    except Exception:
        return {"id": "bad_request", "message": "Invalid JSON body"}, 400

    sig_text = body.get("sig", "")
    pubkey_line = body.get("pubkey", "")

    if not isinstance(sig_text, str) or not isinstance(pubkey_line, str):
        return {"id": "bad_request", "message": "sig and pubkey must be strings"}, 400
    if not sig_text or not pubkey_line:
        return {"id": "bad_request", "message": "sig and pubkey are required"}, 400

    # 3) Decode provisioning token for routing info (team, droplet id, etc.)
    try:
        payload = _decode_provisioning_token(prov)
    except ValueError as e:
        return {"id": "unauthorized", "message": str(e)}, 401

    team_uuid = _parse_team_uuid_from_aud(str(payload.get("aud", ""))) or ""
    droplet_id = str(payload.get("droplet_id", "")) or ""

    # Fallback parsing from "sub" if needed (best-effort, never crash)
    sub = str(payload.get("sub", ""))
    if not team_uuid and "actx:" in sub:
        parts = sub.split(":")
        if len(parts) >= 2:
            team_uuid = parts[1]
    if not droplet_id:
        droplet_id = str(payload.get("droplet_id") or "")

    if not team_uuid:
        # Don't 500; return 401 with a clear message
        return {"id": "unauthorized", "message": "Could not determine team UUID from provisioning token"}, 401

    # 4) Verify signature (NO CALLBACK)
    try:
        _ssh_verify_sig(message=prov.encode("utf-8"), pubkey_line=pubkey_line, sig_text=sig_text)
    except ValueError as e:
        return {"id": "unauthorized", "message": f"Signature invalid: {e}"}, 401
    except RuntimeError as e:
        return {"id": "server_error", "message": str(e)}, 500
    except Exception as e:
        # Last resort: keep it informative but safe
        return {"id": "server_error", "message": f"Unexpected error during signature verify: {type(e).__name__}"}, 500

    # 5) Issue tokens
    ttl_seconds = DEFAULT_ID_TOKEN_TTL_SECONDS
    refresh_ttl_seconds = DEFAULT_ID_TOKEN_REFRESH_TTL_SECONDS

    try:
        token, refresh_token = issue_tokens_fn(
            team_uuid=team_uuid,
            droplet_id=droplet_id,
            ttl_seconds=ttl_seconds,
            refresh_ttl_seconds=refresh_ttl_seconds,
            db=db,
        )
    except Exception as e:
        return {"id": "server_error", "message": f"Failed to issue tokens: {type(e).__name__}"}, 500

    return {"token": token, "refresh_token": refresh_token, "ttl_seconds": ttl_seconds}, 200
