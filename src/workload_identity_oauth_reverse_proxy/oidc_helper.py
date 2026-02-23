import json
import copy
import uuid
import logging
import datetime
import dataclasses
import urllib.error
import urllib.request
import urllib.parse
from typing import Dict, List, Optional, Any, Callable

import jwt
import jsonschema

from .common import THIS_ENDPOINT
from .jwt_helper import *
from .cgi_helper import UnauthorizedException


def only_own_issuer(_api: str, _actx: str) -> list[str]:
    global THIS_ENDPOINT
    return [THIS_ENDPOINT]


class OIDCValidatorError(Exception):
    pass


@dataclasses.dataclass
class OIDCValidatorConfig:
    issuers: List[str]
    audience: str
    strict_aud: bool = True
    leeway: int = 0
    claim_schema: Optional[Dict[str, Any]] = None


class OIDCValidator:
    def __init__(self, config: OIDCValidatorConfig):
        self.config = config
        self.oidc_configs = {}
        self.jwks_clients = {}
        self.logger = logging.getLogger(__package__).getChild(
            self.__class__.__qualname__
        )

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

            # The PyJWKClient handles its own requests for the JWKS URI
            jwks_uri = self.oidc_configs[issuer]["jwks_uri"]
            self.jwks_clients[issuer] = jwt.PyJWKClient(jwks_uri)

    def validate_token(self, token: str) -> Dict:
        last_error = jwt.PyJWTError(
            f"Token is not valid for any of the issuers: {list(self.jwks_clients.keys())}"
        )
        for issuer, jwk_client in self.jwks_clients.items():
            try:
                signing_key = jwk_client.get_signing_key_from_jwt(token)
                claims = jwt.decode(
                    token,
                    key=signing_key.key,
                    algorithms=self.oidc_configs[issuer][
                        "id_token_signing_alg_values_supported"
                    ],
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


@dataclasses.dataclass
class OIDCToken:
    actx: str
    api: str
    aud: str
    sub: str
    claims: dict
    as_string: str

    @classmethod
    def create(cls, actx: str, claims: dict, api: str | None = None) -> "OIDCToken":
        global JWT_ISSUER_URL
        global JWT_SIGNING_KEY_PRIVATE_PEM
        global JWT_ALGORITHM

        logger = logging.getLogger(__package__).getChild(cls.__qualname__)

        key_pem = JWT_SIGNING_KEY_PRIVATE_PEM
        key = jwcrypto.jwk.JWK.from_pem(key_pem, password=None)
        algorithm = JWT_ALGORITHM
        issuer = JWT_ISSUER_URL
        if api is None:
            api = "DigitalOcean"
        audience = f"api://{api}?actx={actx}"

        claims = copy.deepcopy(claims)
        if not f"actx:{actx}" in claims["sub"]:
            raise AuthContextMissingFromSubjectError(
                f'\'actx:{actx}\' not found in {claims["sub"]!r}'
            )
        if "ttl" in claims:
            claims["exp"] = datetime.datetime.now(
                tz=datetime.timezone.utc
            ) + datetime.timedelta(seconds=claims["ttl"])
            del claims["ttl"]
        else:
            claims["exp"] = datetime.datetime.now(
                tz=datetime.timezone.utc
            ) + datetime.timedelta(seconds=60 * 15)
        claims["iat"] = datetime.datetime.now(tz=datetime.timezone.utc)
        if "aud" not in claims:
            claims["aud"] = audience
        claims["iss"] = issuer
        token_as_string = jwt.encode(
            claims,
            key_pem,
            algorithm=algorithm,
            headers={"kid": key.thumbprint()},
        )
        return cls(
            actx=actx,
            api=api,
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
        get_issuers: Callable[[str, str], list[str]] = only_own_issuer,
    ) -> "OIDCToken":
        global THIS_ENDPOINT
        global JWT_SIGNING_KEY_PUBLIC_PEM

        logger = logging.getLogger(__package__).getChild(cls.__qualname__)

        # Remove "Bearer:"
        if token == "0":
            raise UnauthorizedException("Unable to authenticate you, no token")
        elif token.count(".") != 2:
            raise UnauthorizedException("Invalid token")

        # actx extracted from audience. Audience rebuilt and then
        # used to validate against extracted actx roles policies
        unverified_payload = jwt.decode(token, options={"verify_signature": False})
        unverified_audience = unverified_payload.get("aud")
        parsed_url = urllib.parse.urlparse(unverified_audience)
        query_params = urllib.parse.parse_qs(parsed_url.query)

        if "actx" not in query_params or len(query_params["actx"]) != 1:
            raise UnauthorizedException(
                f"aud does not have actx: api://{parsed_url.hostname}?actx=<identifier>"
            )

        actx = query_params["actx"][0]
        api = unverified_audience.split("api://", maxsplit=1)[1].split("?", maxsplit=1)[
            0
        ]

        issuers = [THIS_ENDPOINT]
        issuers.extend(get_issuers(api, actx))
        issuers = list(set(issuers))

        config = OIDCValidatorConfig(
            issuers=issuers,
            audience=f"api://{api}?actx={actx}",
            strict_aud=True,
            leeway=0,
            claim_schema=None,
        )

        logger.info(f"Validating token using config: {config}")
        oidc = OIDCValidator(config)

        try:
            claims = oidc.validate_token(token)
        except OIDCValidatorError as e:
            # Expired/invalid tokens must be a clean 401, not a 500
            raise UnauthorizedException("Invalid or expired token") from e

        audience = claims.get("aud")
        subject = claims.get("sub")
        return cls(
            actx=actx,
            api=api,
            aud=audience,
            sub=subject,
            claims=claims,
            as_string=token,
        )