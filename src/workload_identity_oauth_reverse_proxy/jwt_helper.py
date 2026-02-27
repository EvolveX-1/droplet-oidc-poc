import jwcrypto.jwk

from .common import THIS_ENDPOINT
from . import database

# -----------------------------------------------------------------------------
# jwt_helper.py
#
# This module is used by multiple parts of the Droplet OIDC PoC:
#  - issuing provisioning tokens (used by /v2/droplets)
#  - issuing short-lived id/access tokens (used by /v1/oidc/issue, /prove, /refresh)
#
# Different modules may import different symbols from here. To avoid breakage,
# we keep a backward-compatible surface:
#   - key            : PRIVATE signing key (PEM string) for PyJWT jwt.encode(...)
#   - public_key_pem : PUBLIC key PEM (string) for publishing JWKS / verification
#   - JWT_ISSUER_URL : issuer
#   - JWT_ALGORITHM  : algorithm name for PyJWT
# -----------------------------------------------------------------------------

JWT_ISSUER_URL = THIS_ENDPOINT
JWT_ALGORITHM = "RS256"

# Load or generate private key
JWT_SIGNING_KEY_PRIVATE_PEM = database.get_jwk_pem(JWT_ISSUER_URL)
generate_jwk = bool(JWT_SIGNING_KEY_PRIVATE_PEM is None)

if generate_jwk:
    JWT_SIGNING_KEY_PRIVATE = jwcrypto.jwk.JWK.generate(kty="RSA", size=4096)
else:
    JWT_SIGNING_KEY_PRIVATE = jwcrypto.jwk.JWK.from_pem(
        JWT_SIGNING_KEY_PRIVATE_PEM.encode(), password=None
    )

# Export PEMs
JWT_SIGNING_KEY_PUBLIC_PEM = JWT_SIGNING_KEY_PRIVATE.export_to_pem()
JWT_SIGNING_KEY_PRIVATE_PEM = JWT_SIGNING_KEY_PRIVATE.export_to_pem(
    private_key=True, password=None
)

# Save key to database if generated (first call)
if generate_jwk:
    database.save_jwk_pem(JWT_ISSUER_URL, JWT_SIGNING_KEY_PRIVATE_PEM.decode())

# -----------------------------------------------------------------------------
# Backward-compatible aliases expected by other modules
# -----------------------------------------------------------------------------

# PyJWT accepts key as a PEM-encoded private key string/bytes.
# Some code paths expect jwt_helper.key (module attribute).
key = JWT_SIGNING_KEY_PRIVATE_PEM.decode()

# Convenience exports (strings) used by JWKS publishing / verification.
private_key_pem = JWT_SIGNING_KEY_PRIVATE_PEM.decode()
public_key_pem = JWT_SIGNING_KEY_PUBLIC_PEM.decode()
