import sys
import json
import os

from ..... import cgi_helper
from ..... import oidc_helper

# NOTE: no-callback model: request JSON has { "pubkey": "<ssh-ed25519 ...>", "sig_b64": "<base64 raw ed25519 signature>" }
# Signature is over the provisioning token bytes (the Bearer token).

def _env_int(name: str, default: int) -> int:
    v = os.environ.get(name, "").strip()
    if not v:
        return default
    try:
        return int(v)
    except Exception:
        return default

def _parse_openssh_ed25519_pubkey(pubkey: str) -> bytes:
    """
    Parse OpenSSH ed25519 public key: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... comment'
    Returns 32-byte public key.
    """
    parts = pubkey.strip().split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise ValueError("pubkey must be an OpenSSH ed25519 key starting with 'ssh-ed25519 '")

    import base64, struct
    blob = base64.b64decode(parts[1])
    # SSH wire format: string "ssh-ed25519" + string key(32)
    def read_string(buf, off):
        if off + 4 > len(buf):
            raise ValueError("invalid ssh pubkey blob")
        (ln,) = struct.unpack(">I", buf[off:off+4])
        off += 4
        if off + ln > len(buf):
            raise ValueError("invalid ssh pubkey blob length")
        return buf[off:off+ln], off + ln

    t, off = read_string(blob, 0)
    if t != b"ssh-ed25519":
        raise ValueError("ssh pubkey blob type mismatch")
    k, off = read_string(blob, off)
    if len(k) != 32:
        raise ValueError("ed25519 pubkey length must be 32")
    return k

def _verify_ed25519_sig(pubkey_openssh: str, sig_b64: str, message: bytes) -> None:
    # Delay import so missing deps never cause blank CGI 500 for INVALID tokens.
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception as e:
        raise cgi_helper.ServerErrorException(f"cryptography not available for signature verify: {e}")

    import base64
    pub_raw = _parse_openssh_ed25519_pubkey(pubkey_openssh)
    try:
        sig = base64.b64decode(sig_b64, validate=True)
    except Exception:
        raise ValueError("sig_b64 must be valid base64")
    if len(sig) != 64:
        raise ValueError("ed25519 signature must be 64 bytes")

    pk = Ed25519PublicKey.from_public_bytes(pub_raw)
    pk.verify(sig, message)

@cgi_helper.json_response
def cgi_handler():
    request_obj = json.load(sys.stdin)
    token, _token_is_oidc = cgi_helper.get_token()

    # 1) Validate provisioning token itself (aud/iss/exp + actx extraction)
    oidc_token = oidc_helper.OIDCToken.validate(token)

    pubkey = (request_obj.get("pubkey") or "").strip()
    sig_b64 = (request_obj.get("sig_b64") or "").strip()
    if not pubkey or not sig_b64:
        raise cgi_helper.BadRequestException("Missing pubkey or sig_b64")

    # 2) Verify caller possession of host private key (no callback)
    try:
        _verify_ed25519_sig(pubkey, sig_b64, token.encode("utf-8"))
    except ValueError as e:
        raise cgi_helper.UnauthorizedException(str(e))
    except Exception:
        raise cgi_helper.UnauthorizedException("signature verification failed")

    # 3) Mint tokens. Keep the original subject derivation (no droplet tag lookup here).
    # In your implementation, you likely already embed the droplet_id / role into the provisioning token.
    # If you still need tag-based sub derivation, keep provisioning.validate's droplet lookup.
    # For now: subject becomes id-token role under the same actx.
    actx_slug = f"actx:{oidc_token.actx}"
    subject = f"{actx_slug}:role:id-token"

    access_ttl = _env_int("ID_TOKEN_TTL_SECONDS", 900)
    refresh_ttl = _env_int("ID_TOKEN_REFRESH_TTL_SECONDS", 2592000)

    claims = {"sub": subject}
    refresh_claims = {
        "sub": f"{actx_slug}:role:id-token-refresh",
        "id-token-refresh": True,
        "ttl": refresh_ttl,
    }
    # access token ttl is handled by adding ttl claim too (oidc_helper.create uses claims["ttl"])
    claims["ttl"] = access_ttl

    return {
        "token": oidc_helper.OIDCToken.create(oidc_token.actx, claims).as_string,
        "refresh_token": oidc_helper.OIDCToken.create(oidc_token.actx, refresh_claims).as_string,
    }

if __name__ == "__main__":
    cgi_handler()
