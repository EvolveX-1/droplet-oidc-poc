import sys
import json
import os
import subprocess
import tempfile

from ..... import cgi_helper
from ..... import oidc_helper

# no-callback model:
# Request JSON supports either:
#   A) {"pubkey": "<ssh-ed25519 ...>", "sig": "-----BEGIN SSH SIGNATURE----- ..."}
#   B) {"pubkey": "<ssh-ed25519 ...>", "sig_b64": "<base64 raw ed25519 signature>"}  (optional fallback)

def _env_int(name: str, default: int) -> int:
    v = (os.environ.get(name) or "").strip()
    if not v:
        return default
    try:
        return int(v)
    except Exception:
        return default

def _verify_with_ssh_keygen(pubkey_openssh: str, sig_ssh: str, message: bytes) -> None:
    """
    Verify an OpenSSH "BEGIN SSH SIGNATURE" (produced by `ssh-keygen -Y sign`)
    using `ssh-keygen -Y verify` available in the App Platform image.
    """
    with tempfile.TemporaryDirectory(prefix="prove-") as td:
        allowed = os.path.join(td, "allowed_signers")
        sigf = os.path.join(td, "sig")
        msgf = os.path.join(td, "msg")

        # principal can be any stable string; must match -I
        principal = "host"

        with open(allowed, "w", encoding="utf-8") as f:
            f.write(f"{principal} {pubkey_openssh.strip()}\n")
        with open(sigf, "w", encoding="utf-8") as f:
            f.write(sig_ssh.strip() + "\n")
        with open(msgf, "wb") as f:
            f.write(message)

        # ssh-keygen reads message from stdin; keep it simple
        p = subprocess.run(
            ["ssh-keygen", "-Y", "verify", "-f", allowed, "-I", principal, "-n", "prove-sshd", "-s", sigf],
            input=message,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if p.returncode != 0:
            raise cgi_helper.UnauthorizedException("signature verification failed")

def _parse_openssh_ed25519_pubkey(pubkey: str) -> bytes:
    parts = pubkey.strip().split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise ValueError("pubkey must be an OpenSSH ed25519 key starting with 'ssh-ed25519 '")

    import base64, struct
    blob = base64.b64decode(parts[1])

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

def _verify_ed25519_sig_b64(pubkey_openssh: str, sig_b64: str, message: bytes) -> None:
    # Optional fallback path if someone wants raw signatures.
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception as e:
        raise cgi_helper.ServerErrorException(f"cryptography not available for signature verify: {e}")

    import base64
    pub_raw = _parse_openssh_ed25519_pubkey(pubkey_openssh)
    try:
        sig = base64.b64decode(sig_b64, validate=True)
    except Exception:
        raise cgi_helper.UnauthorizedException("sig_b64 must be valid base64")
    if len(sig) != 64:
        raise cgi_helper.UnauthorizedException("ed25519 signature must be 64 bytes")

    pk = Ed25519PublicKey.from_public_bytes(pub_raw)
    pk.verify(sig, message)

@cgi_helper.json_response
def cgi_handler():
    request_obj = json.load(sys.stdin)

    # Bearer provisioning token
    token, _token_is_oidc = cgi_helper.get_token()
    oidc_token = oidc_helper.OIDCToken.validate(token)

    pubkey = (request_obj.get("pubkey") or "").strip()
    sig_ssh = (request_obj.get("sig") or "").strip()
    sig_b64 = (request_obj.get("sig_b64") or "").strip()

    if not pubkey:
        raise cgi_helper.BadRequestException("Missing pubkey")
    if not sig_ssh and not sig_b64:
        raise cgi_helper.BadRequestException("Missing sig (OpenSSH) or sig_b64 (raw)")

    # Verify proof-of-possession (no callback)
    msg = token.encode("utf-8")
    if sig_ssh:
        _verify_with_ssh_keygen(pubkey, sig_ssh, msg)
    else:
        try:
            _verify_ed25519_sig_b64(pubkey, sig_b64, msg)
        except Exception:
            raise cgi_helper.UnauthorizedException("signature verification failed")

    # Subject derivation: keep consistent with your earlier scheme
    actx_slug = f"actx:{oidc_token.actx}"
    subject = f"{actx_slug}:role:id-token"

    access_ttl = _env_int("ID_TOKEN_TTL_SECONDS", 900)          # 15 minutes
    refresh_ttl = _env_int("ID_TOKEN_REFRESH_TTL_SECONDS", 2592000)  # 30 days

    access_claims = {"sub": subject, "ttl": access_ttl}
    refresh_claims = {
        "sub": f"{actx_slug}:role:id-token-refresh",
        "id-token-refresh": True,
        "ttl": refresh_ttl,
        # IMPORTANT: carry the access-token subject forward so refresh does NOT need any droplet callback.
        "oidc_sub": subject,
    }

    return {
        "token": oidc_helper.OIDCToken.create(oidc_token.actx, access_claims).as_string,
        "refresh_token": oidc_helper.OIDCToken.create(oidc_token.actx, refresh_claims).as_string,
    }

if __name__ == "__main__":
    cgi_handler()
