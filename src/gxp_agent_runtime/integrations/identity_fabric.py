"""Typed client for agent-identity-fabric (github.com/kogunlowo123/agent-identity-fabric).

Wire formats: RFC 7523 jwt-bearer at ``/oauth2/token``, RFC 7662 at
``/oauth2/introspect`` and the fabric's ``/v1/authorize`` decision point.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from gxp_agent_runtime.domain.errors import DependencyError, UnauthorizedError
from gxp_agent_runtime.domain.ports import Clock

JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"


class IssuedToken(BaseModel):
    model_config = ConfigDict(frozen=True)

    access_token: str
    token_type: str
    expires_in: int = Field(gt=0)
    scope: str = ""


class Actor(BaseModel):
    model_config = ConfigDict(frozen=True)

    sub: str
    act: Actor | None = None

    def subjects(self) -> list[str]:
        return [self.sub, *(self.act.subjects() if self.act else [])]


class Introspection(BaseModel):
    model_config = ConfigDict(frozen=True)

    active: bool
    sub: str | None = None
    scope: str | None = None
    exp: int | None = None
    act: Actor | None = None
    agent_status: str | None = None

    @property
    def scopes(self) -> frozenset[str]:
        return frozenset((self.scope or "").split())


class FabricAuthorizeRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    action: str
    resource_type: str
    resource_id: str = "*"
    resource_classification: int = Field(default=3, ge=0, le=3)
    resource_attributes: dict[str, Any] = Field(default_factory=dict)
    environment: dict[str, Any] = Field(default_factory=dict)


class FabricDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision: Literal["allow", "deny", "require_approval"]
    agent: str
    action: str
    matched_rules: tuple[str, ...] = ()
    policy_version: str = ""
    policy_digest: str = ""
    reason: str = ""
    delegation_chain: tuple[str, ...] = ()


class IdentityFabricClient:
    def __init__(self, base_url: str, *, client: httpx.AsyncClient) -> None:
        self._base = base_url.rstrip("/")
        self._client = client

    async def _post(
        self,
        path: str,
        *,
        data: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        try:
            return await self._client.post(
                f"{self._base}{path}", data=data, json=json, headers=headers
            )
        except httpx.HTTPError as exc:
            raise DependencyError(f"identity fabric unreachable: {type(exc).__name__}") from exc

    @staticmethod
    def _parse[M: BaseModel](model: type[M], response: httpx.Response) -> M:
        try:
            return model.model_validate(response.json())
        except (ValueError, ValidationError) as exc:
            raise DependencyError("identity fabric returned an unexpected body") from exc

    async def issue_token(
        self, client_id: str, assertion: str, *, scopes: frozenset[str] | None = None
    ) -> IssuedToken:
        form = {"grant_type": JWT_BEARER, "client_id": client_id, "assertion": assertion}
        if scopes:
            form["scope"] = " ".join(sorted(scopes))
        response = await self._post("/oauth2/token", data=form)
        if response.status_code in (400, 401):
            raise UnauthorizedError("identity fabric refused the runtime's credential request")
        if response.status_code != 200:
            raise DependencyError(f"identity fabric token endpoint returned {response.status_code}")
        return self._parse(IssuedToken, response)

    async def introspect(self, token: str) -> Introspection:
        response = await self._post("/oauth2/introspect", data={"token": token})
        if response.status_code != 200:
            raise DependencyError(f"identity fabric introspection returned {response.status_code}")
        return self._parse(Introspection, response)

    async def authorize(self, token: str, request: FabricAuthorizeRequest) -> FabricDecision:
        response = await self._post(
            "/v1/authorize",
            json=request.model_dump(mode="json"),
            headers={"Authorization": f"Bearer {token}"},
        )
        if response.status_code == 401:
            raise UnauthorizedError("identity fabric rejected the agent credential")
        if response.status_code != 200:
            raise DependencyError(f"identity fabric authorize returned {response.status_code}")
        return self._parse(FabricDecision, response)


class RuntimeCredentials:
    """The runtime's own fabric credential, presented to validated systems.

    The workload token is the projected service-account token mounted by
    Kubernetes; it is re-read on every refresh because the kubelet rotates it.
    """

    def __init__(
        self,
        fabric: IdentityFabricClient,
        *,
        client_id: str,
        workload_token_file: Path,
        clock: Clock,
        refresh_margin: timedelta = timedelta(seconds=60),
    ) -> None:
        self._fabric = fabric
        self._client_id = client_id
        self._token_file = workload_token_file
        self._clock = clock
        self._margin = refresh_margin
        self._token: str | None = None
        self._expires_at: datetime | None = None

    async def bearer(self) -> str:
        now = self._clock.now()
        if (
            self._token is None
            or self._expires_at is None
            or now >= self._expires_at - self._margin
        ):
            assertion = self._token_file.read_text(encoding="utf-8").strip()
            issued = await self._fabric.issue_token(self._client_id, assertion)
            self._token = issued.access_token
            self._expires_at = now + timedelta(seconds=issued.expires_in)
        return self._token
