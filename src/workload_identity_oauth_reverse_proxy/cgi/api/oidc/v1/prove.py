import os
import json
import base64
import time
import logging
from typing import Dict, Any

from flask import Blueprint, request, jsonify

import jwt
from jwt import InvalidTokenError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

prove_bp = Blueprint("prove", __name__)

ISSUER = os.environ.get("OIDC_ISSUER")
AUDIENCE_PREFIX = "api://DigitalOcean?actx="

# Recommended refresh TTL: 30 days
# 30 * 24 * 60 * 60 = 2,592,000 seconds
REFRESH_TTL = int(os.environ.get("ID_TOKEN_REFRESH_TTL_SECONDS", "2592000"))
ACCESS_TTL = int(os.environ.get("ID_TOKEN_TTL_SECONDS", "900"))  # 15 minutes access token

SIGNING_KEY = os.environ.get("OIDC_SIGNING_PRIVATE_KEY")
if not SIGNING_KEY:
    raise RuntimeError("OIDC_SIGNING_PRIVATE_KEY not set")

PRIVATE_KEY = serialization.load_pem_private_key(
    SIGNING_KEY.encode(),
    password=None,
)


def _decode_provisioning_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            options={"verify_signature": False},  # signature validated separately
            algorithms=["RS256", "EdDSA"],
        )
        return payload
    except InvalidTokenError:
        raise ValueError("Invalid provisioning token")


def _verify_signature(token: str, sig_b64: str, pubkey_str: str) -> None:
    try:
        sig_bytes = base64.b64decode(sig_b64)
        pubkey = serialization.load_ssh_public_key(pubkey_str.encode())
        if not isinstance(pubkey, Ed25519PublicKey):
            raise ValueError("Unsupported key type")
        pubkey.verify(sig_bytes, token.encode())
    except (InvalidSignature, ValueError):
        raise ValueError("Invalid signature")


def _issue_tokens(team_uuid: str, droplet_id: str) -> Dict[str, str]:
    now = int(time.time())

    access_payload = {
        "iss": ISSUER,
        "aud": f"{AUDIENCE_PREFIX}{team_uuid}",
        "sub": f"actx:{team_uuid}:droplet:{droplet_id}",
        "iat": now,
        "exp": now + ACCESS_TTL,
    }

    refresh_payload = {
        "iss": ISSUER,
        "aud": f"{AUDIENCE_PREFIX}{team_uuid}",
        "sub": f"actx:{team_uuid}:role:id-token-refresh",
        "iat": now,
        "exp": now + REFRESH_TTL,
        "id-token-refresh": True,
        "droplet_id": droplet_id,
    }

    access_token = jwt.encode(access_payload, PRIVATE_KEY, algorithm="RS256")
    refresh_token = jwt.encode(refresh_payload, PRIVATE_KEY, algorithm="RS256")

    return {
        "token": access_token,
        "refresh_token": refresh_token,
    }


@prove_bp.route("/v1/oidc/prove", methods=["POST"])
def prove():
    try:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"id": "unauthorized", "message": "Missing token"}), 401

        provisioning_token = auth.split(" ", 1)[1]

        body = request.get_json(force=True)
        sig = body.get("sig")
        pubkey = body.get("pubkey")

        if not sig or not pubkey:
            return jsonify({"id": "bad_request", "message": "Missing sig/pubkey"}), 400

        payload = _decode_provisioning_token(provisioning_token)

        team_uuid = payload.get("sub", "").split(":")[1]
        droplet_id = payload.get("sub", "").split(":")[-1]

        _verify_signature(provisioning_token, sig, pubkey)

        tokens = _issue_tokens(team_uuid, droplet_id)

        return jsonify(tokens)

    except ValueError as e:
        return jsonify({"id": "unauthorized", "message": str(e)}), 401

    except Exception as e:
        logging.exception("prove error")
        return jsonify({"id": "server_error", "message": "Unexpected server-side error"}), 500
