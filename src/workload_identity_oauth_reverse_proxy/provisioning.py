# -*- coding: utf-8 -*-
"""
Provisioning helpers for creating cloud-init user-data for ProjectGen caller droplets.

Primary bug fixed:
- JWT creation failed with `TypeError: Object of type UUID is not JSON serializable`
  during droplet creation through the issuer proxy.

This file is intentionally conservative: we only sanitize the claims we pass into
OIDCToken.create() and keep the rest of the provisioning flow unchanged.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any

from . import oidc_helper


def _sanitize_for_json(obj: Any) -> Any:
    """
    Convert values commonly found in claims (UUID, datetime) into JSON-safe shapes.
    Delegates to oidc_helper's sanitizer if present.
    """
    try:
        # reuse the exact sanitizer used by OIDCToken.create
        from .oidc_helper import _sanitize_claims  # type: ignore
        if isinstance(obj, dict):
            return _sanitize_claims(obj)
    except Exception:
        pass

    # fallback (very small)
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            out[k] = str(v) if k in ("team_uuid", "org_id", "user_id") else v
        return out
    return obj


@dataclasses.dataclass(frozen=True)
class ProvisioningData:
    team_uuid: str
    this_endpoint: str
    provisioning_token: str

    @classmethod
    def create(cls, *, team_uuid: str, this_endpoint: str, actx: str, sub: str, ttl: int = 900) -> "ProvisioningData":
        """
        Create a provisioning token that will be injected into cloud-init user-data.

        NOTE: `team_uuid` must be a string here (not uuid.UUID).
        """
        claims = {
            "sub": sub,
            "team_uuid": team_uuid,
            "ttl": int(ttl),
        }
        claims = _sanitize_for_json(claims)

        token = oidc_helper.OIDCToken.create(actx=actx, claims=claims, api="DigitalOcean")

        # sanity: make sure jwt.encode would succeed (no UUID/datetime)
        json.dumps(token.claims)

        return cls(
            team_uuid=team_uuid,
            this_endpoint=this_endpoint,
            provisioning_token=token.as_string,
        )
