"""JWKS retrieval with caching and JWT verification against the injected clock."""

from __future__ import annotations

import base64
import binascii
import json
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any, Protocol

import httpx
import jwt

from gxp_agent_runtime.domain.errors import UnauthorizedError

ACCEPTED_ALGORITHMS = ("RS256", "ES256", "EdDSA")
JWS_SEGMENTS = 3


class KeyResolver(Protocol):
    async def key_for(self, kid: str) -> Any: ...


class StaticJwks:
    """Resolver backed by a JWKS document held in memory."""

    def __init__(self, jwks: dict[str, Any]) -> None:
        self._keys = {k["kid"]: jwt.PyJWK(k).key for k in jwks.get("keys", []) if "kid" in k}

    async def key_for(self, kid: str) -> Any:
        key = self._keys.get(kid)
        if key is None:
            raise UnauthorizedError(f"unknown signing key {kid!r}")
        return key


class RemoteJwks:
    """Fetches a JWKS URL, caches it, and refreshes once on an unknown ``kid``.

    Refreshes are rate limited so tokens carrying random ``kid`` values
    cannot be used to hammer the issuer.
    """

    def __init__(
        self,
        url: str,
        *,
        client: httpx.AsyncClient,
        ttl_s: float = 300.0,
        min_refresh_interval_s: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._url = url
        self._client = client
        self._ttl = ttl_s
        self._min_refresh = min_refresh_interval_s
        self._clock = clock
        self._keys: dict[str, Any] = {}
        self._fetched_at: float | None = None

    async def _refresh(self) -> None:
        response = await self._client.get(self._url)
        response.raise_for_status()
        document = response.json()
        self._keys = {k["kid"]: jwt.PyJWK(k).key for k in document.get("keys", []) if "kid" in k}
        self._fetched_at = self._clock()

    async def key_for(self, kid: str) -> Any:
        now = self._clock()
        stale = self._fetched_at is None or now - self._fetched_at > self._ttl
        may_refresh = self._fetched_at is None or now - self._fetched_at >= self._min_refresh
        if stale or (kid not in self._keys and may_refresh):
            try:
                await self._refresh()
            except (httpx.HTTPError, ValueError, KeyError, jwt.PyJWTError) as exc:
                if kid not in self._keys:
                    raise UnauthorizedError(f"cannot fetch signing keys from {self._url}") from exc
        key = self._keys.get(kid)
        if key is None:
            raise UnauthorizedError(f"unknown signing key {kid!r}")
        return key


def unverified_issuer(token: str) -> str | None:
    """Read ``iss`` to route a token to the verifier for that issuer.

    Used only to choose which key set and audience to verify against; the
    chosen verifier then checks the signature and every claim.
    """
    parts = token.split(".")
    if len(parts) != JWS_SEGMENTS:
        return None
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, binascii.Error):
        return None
    issuer = payload.get("iss") if isinstance(payload, dict) else None
    return issuer if isinstance(issuer, str) else None


async def verify_jwt(
    token: str,
    resolver: KeyResolver,
    *,
    issuer: str,
    audience: str,
    now: datetime,
    leeway_s: int = 30,
    algorithms: tuple[str, ...] = ACCEPTED_ALGORITHMS,
) -> dict[str, Any]:
    """Verify signature, issuer and audience; time claims against ``now``.

    Rejects ``alg: none`` and any algorithm outside ``algorithms``.
    """
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise UnauthorizedError("malformed token") from exc
    alg = header.get("alg")
    kid = header.get("kid")
    if alg not in algorithms or not isinstance(kid, str):
        raise UnauthorizedError("token algorithm or key id not accepted")
    key = await resolver.key_for(kid)
    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            key=key,
            algorithms=[alg],
            issuer=issuer,
            audience=audience,
            options={
                "require": ["exp", "iat", "iss", "sub", "aud"],
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
    except jwt.PyJWTError as exc:
        raise UnauthorizedError(f"token rejected: {type(exc).__name__}") from exc
    instant = now.timestamp()
    exp, iat, nbf = claims.get("exp"), claims.get("iat"), claims.get("nbf")
    if not isinstance(exp, int | float) or not isinstance(iat, int | float):
        raise UnauthorizedError("token time claims must be numeric")
    if instant > exp + leeway_s:
        raise UnauthorizedError("token rejected: ExpiredSignatureError")
    if iat > instant + leeway_s:
        raise UnauthorizedError("token rejected: issued in the future")
    if isinstance(nbf, int | float) and nbf > instant + leeway_s:
        raise UnauthorizedError("token rejected: not yet valid")
    return claims
