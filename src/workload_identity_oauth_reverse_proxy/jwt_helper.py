import os
import threading
import jwcrypto.jwk

from .common import THIS_ENDPOINT
from . import database

JWT_ISSUER_URL = THIS_ENDPOINT
JWT_ALGORITHM = "RS256"

_lock = threading.Lock()
_cached_private_jwk = None  # type: ignore


def _load_from_env() -> jwcrypto.jwk.JWK | None:
    pem = os.getenv("JWT_SIGNING_KEY_PRIVATE_PEM", "").strip()
    if not pem:
        return None
    try:
        return jwcrypto.jwk.JWK.from_pem(pem.encode(), password=None)
    except Exception:
        # Bad PEM in env; treat as absent (do not crash import)
        return None


def _load_from_db() -> jwcrypto.jwk.JWK | None:
    try:
        pem = database.get_jwk_pem(JWT_ISSUER_URL)
    except Exception:
        return None
    if not pem:
        return None
    try:
        return jwcrypto.jwk.JWK.from_pem(pem.encode(), password=None)
    except Exception:
        return None


def _save_to_db_best_effort(jwk: jwcrypto.jwk.JWK) -> None:
    try:
        pem = jwk.export_to_pem(private_key=True, password=None).decode()
        database.save_jwk_pem(JWT_ISSUER_URL, pem)
    except Exception:
        # DB down / perms / schema / timeout — do not take down issuer
        return


def get_signing_jwk_private() -> jwcrypto.jwk.JWK:
    """
    Returns a stable signing key (JWK). Lazily loads from:
      1) env JWT_SIGNING_KEY_PRIVATE_PEM (recommended for stability),
      2) database,
      3) generates new key (best-effort persisted).
    Never raises during import-time.
    """
    global _cached_private_jwk
    if _cached_private_jwk is not None:
        return _cached_private_jwk

    with _lock:
        if _cached_private_jwk is not None:
            return _cached_private_jwk

        jwk = _load_from_env()
        if jwk is None:
            jwk = _load_from_db()

        if jwk is None:
            jwk = jwcrypto.jwk.JWK.generate(kty="RSA", size=4096)
            _save_to_db_best_effort(jwk)

        _cached_private_jwk = jwk
        return _cached_private_jwk


def get_signing_key_private_pem() -> str:
    return get_signing_jwk_private().export_to_pem(private_key=True, password=None).decode()


def get_signing_key_public_pem() -> str:
    return get_signing_jwk_private().export_to_pem().decode()