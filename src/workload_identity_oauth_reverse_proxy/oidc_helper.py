import copy
import datetime
import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

import jwcrypto.jwk
import jwt
import jsonschema

from .cgi_helper import UnauthorizedException
from .common import THIS_ENDPOINT
from .jwt_helper import (
    AuthContextMissingFromSubjectError,
    JWT_ALGORITHM,
    JWT_ISSUER_URL,
    JWT_SIGNING_KEY_PRIVATE_PEM,
)


def only_own_issuer(_api: str, _actx: str) -> List[str]:
    # Default issuer list: only this app's own issuer endpoint
    return [THIS_ENDPOINT]


class OIDCValidatorError(Exception):
    pass


@dataclass
class OIDCValidatorConfig:
    issuers: List[str]
    audience: str
    strict_aud: bool = True
    leeway: int = 0
    claim_schema: Optional[Dict[str, Any]] = None


class OIDCValidator:
    def __init__(self, config: OIDCValidatorConfig):
        self.config = config
        self.oidc_configs: Dict[str, Dict[str, Any]] = {}
        self.jwks_clients: Dict[str, jwt.PyJWKClient] = {}
        self.logger = logging.getLogger(__package__).getChild(self.__class__.__qualname__)

        for issuer in self.config.issuers:
            oidc_config_url = f"{issuer}/.well-known/openid-configuration"
            try:
                with urllib.request.urlopen(oidc_config_url) as response:
                    response_body = response.read()
                    self.oidc_configs[issuer] = json.loads(response_body)
            except (urllib.error.URLError, json.JSONDecodeError) as e:
                raise OIDCValidatorError(
                    f"Failed to fetch or parse OIDC config from {oidc_config_url}"
                ) from e

            jwks_uri = self.oidc_configs[issuer]["jwks_uri"]
            self.jwks_clients[issuer] = jwt.PyJWKClient(jwks_uri)

    def validate_token(self, token: str) -> Dict[str, Any]:
        last_error: Exception = jwt.PyJWTError(
            f"Token is not valid for any of the issuers: {list(self.jwks_clients.keys())}"
        )

        for issuer, jwk_client in self.jwks_clients.items():
            try:
                signing_key = jwk_client.get_signing_key_from_jwt(token)
                claims = jwt.decode(
                    token,
                    key=signing_key.key,
                    algorithms=self.oidc_configs[issuer].get(
                        "id_token_signing_alg_values_supported", ["RS256"]
                    ),
                    audience=self.config.audience,
                    issuer=self.oidc_configs[issuer]["issuer"],
                    options={
                        "require": ["exp", "iat", "iss", "sub"],
                        "strict_aud": self.config.strict_aud,
                    },
                    leeway=self.config.leeway,
                )

                if self.config.claim_schema and issuer in self.config.claim_schema:
                    jsonschema.validate(claims, schema=self.config.claim_schema[issuer])

                return claims

            except jwt.PyJWTError as error:
                last_error = error

        raise OIDCValidatorError(
            "OIDC token failed validation against known issuers"
        ) from last_error


@dataclass
class OIDCToken:
    actx: str
    api: str
    aud: str
    sub: str
    claims: Dict[str, Any]
    as_string: str

    @classmethod
    def create(cls, actx: str, claims: Dict[str, Any], api: Optional[str] = None) -> "OIDCToken":
        key_pem = JWT_SIGNING_KEY_PRIVATE_PEM
        if isinstance(key_pem, str):
            key_pem_bytes = key_pem.encode()
        else:
            key_pem_bytes = key_pem

        key = jwcrypto.jwk.JWK.from_pem(key_pem_bytes, password=None)

        algorithm = JWT_ALGORITHM
        issuer = JWT_ISSUER_URL

        api_name = api or "DigitalOcean"
        audience = f"api://{api_name}?actx={actx}"

        claims = copy.deepcopy(claims)

        sub = claims.get("sub")
        if not isinstance(sub, str) or f"actx:{actx}" not in sub:
            raise AuthContextMissingFromSubjectError(
                f"'actx:{actx}' not found in subject {sub!r}"
            )

        now = datetime.datetime.now(tz=datetime.timezone.utc)

        ttl = claims.pop("ttl", None)
        if ttl is None:
            ttl = 60 * 15  # 15 minutes default
        claims["exp"] = now + datetime.timedelta(seconds=int(ttl))
        claims["iat"] = now

        # Preserve provided audience if present; otherwise set it.
        claims.setdefault("aud", audience)
        claims["iss"] = issuer

        token_as_string = jwt.encode(
            claims,
            key_pem_bytes,
            algorithm=algorithm,
            headers={"kid": key.thumbprint()},
        )

        return cls(
            actx=actx,
            api=api_name,
            aud=audience,
            sub=claims["sub"],
            claims=claims,
            as_string=token_as_string,
        )

    @classmethod
    def validate(
        cls,
        token: str,
        *,
        get_issuers: Callable[[str, str], List[str]] = only_own_issuer,
    ) -> "OIDCToken":
        logger = logging.getLogger(__package__).getChild(cls.__qualname__)

        if not token or token == "0":
            raise UnauthorizedException("Unable to authenticate you, no token")

        if token.count(".") != 2:
            raise UnauthorizedException("Invalid token")

        # Extract actx from aud without verifying signature yet
        unverified_payload = jwt.decode(token, options={"verify_signature": False})
        unverified_audience = unverified_payload.get("aud")
        if not isinstance(unverified_audience, str):
            raise UnauthorizedException("Invalid token: missing aud")

        parsed_url = urllib.parse.urlparse(unverified_audience)
        query_params = urllib.parse.parse_qs(parsed_url.query)

        actx_vals = query_params.get("actx", [])
        if len(actx_vals) != 1:
            raise UnauthorizedException(
                "aud does not have actx: api://<api>?actx=<identifier>"
            )
        actx = actx_vals[0]

        # api is "DigitalOcean" in "api://DigitalOcean?actx=..."
        if not unverified_audience.startswith("api://"):
            raise UnauthorizedException("Invalid token: aud must start with api://")

        api = unverified_audience.split("api://", maxsplit=1)[1].split("?", maxsplit=1)[0]

        # Issuer allow-list: always include THIS_ENDPOINT and any additional issuers from policy
        issuers = list(set([THIS_ENDPOINT, *get_issuers(api, actx)]))

        config = OIDCValidatorConfig(
            issuers=issuers,
            audience=f"api://{api}?actx={actx}",
            strict_aud=True,
            leeway=0,
            claim_schema=None,
        )
        logger.info("Validating token using config: %s", config)

        oidc = OIDCValidator(config)
        claims = oidc.validate_token(token)

        audience = claims.get("aud")
        subject = claims.get("sub")
        if not isinstance(audience, str) or not isinstance(subject, str):
            raise UnauthorizedException("Invalid token claims")

        return cls(
            actx=actx,
            api=api,
            aud=audience,
            sub=subject,
            claims=claims,
            as_string=token,
        )
