import jwcrypto.jwk

from .common import THIS_ENDPOINT
from . import database

# Public issuer URL for tokens minted by this service
JWT_ISSUER_URL = THIS_ENDPOINT
JWT_ALGORITHM = "RS256"

# --- Load (or lazily generate) the RSA signing key ---
# Upstream modules import these symbols directly:
#   JWT_SIGNING_KEY_PRIVATE_PEM (str)
#   JWT_SIGNING_KEY_PUBLIC_PEM  (str)
_pem = database.get_jwk_pem(JWT_ISSUER_URL)  # may be None on first boot

if _pem is None:
    # First boot: generate and persist a new RSA keypair (4096-bit)
    _jwk_priv = jwcrypto.jwk.JWK.generate(kty="RSA", size=4096)
    JWT_SIGNING_KEY_PRIVATE_PEM = _jwk_priv.export_to_pem(private_key=True, password=None).decode()
    JWT_SIGNING_KEY_PUBLIC_PEM = _jwk_priv.export_to_pem(private_key=False, password=None).decode()
    database.save_jwk_pem(JWT_ISSUER_URL, JWT_SIGNING_KEY_PRIVATE_PEM)
else:
    # Subsequent boots: load existing private key from DB
    if isinstance(_pem, (bytes, bytearray)):
        _pem_str = _pem.decode()
    else:
        _pem_str = str(_pem)

    _jwk_priv = jwcrypto.jwk.JWK.from_pem(_pem_str.encode(), password=None)
    JWT_SIGNING_KEY_PRIVATE_PEM = _pem_str
    JWT_SIGNING_KEY_PUBLIC_PEM = _jwk_priv.export_to_pem(private_key=False, password=None).decode()

# Optional convenience objects (harmless if unused)
JWT_SIGNING_KEY_PRIVATE = _jwk_priv
JWT_SIGNING_KEY_PUBLIC = jwcrypto.jwk.JWK.from_pem(JWT_SIGNING_KEY_PUBLIC_PEM.encode(), password=None)
