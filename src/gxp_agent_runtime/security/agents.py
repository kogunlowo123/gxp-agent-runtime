"""Authentication and authorization of calling agents.

With the identity fabric configured, every agent credential is introspected
(so suspension and revocation take effect immediately) and every action is
authorized by the fabric's decision point before the runtime's own GxP
policy runs. Without it, fabric-issued credentials are verified offline
against the fabric JWKS and the runtime's local policy engine is the only
decision point. There is no mode that admits unauthenticated agents.
"""

from __future__ import annotations

import fnmatch
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from gxp_agent_runtime.domain.errors import ForbiddenError, UnauthorizedError
from gxp_agent_runtime.domain.ports import Clock
from gxp_agent_runtime.integrations.identity_fabric import (
    Actor,
    FabricAuthorizeRequest,
    IdentityFabricClient,
)
from gxp_agent_runtime.security.jwks import KeyResolver, verify_jwt


class AgentPrincipal(BaseModel):
    model_config = ConfigDict(frozen=True)

    agent_id: str
    scopes: frozenset[str]
    delegation_chain: tuple[str, ...] = ()
    token: str = Field(repr=False, exclude=True)

    def allows(self, action: str) -> bool:
        return any(fnmatch.fnmatchcase(action, scope) for scope in self.scopes)


def bearer_token(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise UnauthorizedError("agent bearer token required")
    token = authorization[7:].strip()
    if not token:
        raise UnauthorizedError("agent bearer token required")
    return token


def _chain(raw: Any) -> tuple[str, ...]:
    if not isinstance(raw, dict):
        return ()
    return tuple(Actor.model_validate(raw).subjects())


class AgentGateway(Protocol):
    mode: str

    async def authenticate(self, authorization: str | None) -> AgentPrincipal: ...

    async def authorize(
        self,
        principal: AgentPrincipal,
        *,
        action: str,
        resource_id: str,
        attributes: dict[str, Any],
    ) -> str | None:
        """Return the external decision (or None when local only); raise when denied."""
        ...


class FabricAgentGateway:
    mode = "identity-fabric"

    def __init__(self, fabric: IdentityFabricClient) -> None:
        self._fabric = fabric

    async def authenticate(self, authorization: str | None) -> AgentPrincipal:
        token = bearer_token(authorization)
        result = await self._fabric.introspect(token)
        if not result.active or not result.sub:
            raise UnauthorizedError("agent credential is not active")
        return AgentPrincipal(
            agent_id=result.sub,
            scopes=result.scopes,
            delegation_chain=tuple(result.act.subjects()) if result.act else (),
            token=token,
        )

    async def authorize(
        self,
        principal: AgentPrincipal,
        *,
        action: str,
        resource_id: str,
        attributes: dict[str, Any],
    ) -> str | None:
        decision = await self._fabric.authorize(
            principal.token,
            FabricAuthorizeRequest(
                action=action,
                resource_type="gxp-action",
                resource_id=resource_id,
                resource_attributes=attributes,
                environment={"purpose_of_use": "gxp-operations"},
            ),
        )
        if decision.decision == "deny":
            raise ForbiddenError(f"identity fabric denied {action}: {decision.reason}")
        return decision.decision


class LocalAgentGateway:
    mode = "local"

    def __init__(self, resolver: KeyResolver, *, issuer: str, audience: str, clock: Clock) -> None:
        self._resolver = resolver
        self._issuer = issuer
        self._audience = audience
        self._clock = clock

    async def authenticate(self, authorization: str | None) -> AgentPrincipal:
        token = bearer_token(authorization)
        claims = await verify_jwt(
            token,
            self._resolver,
            issuer=self._issuer,
            audience=self._audience,
            now=self._clock.now(),
            algorithms=("EdDSA",),
        )
        scope = claims.get("scope", "")
        return AgentPrincipal(
            agent_id=str(claims["sub"]),
            scopes=frozenset(scope.split()) if isinstance(scope, str) else frozenset(),
            delegation_chain=_chain(claims.get("act")),
            token=token,
        )

    async def authorize(
        self,
        principal: AgentPrincipal,
        *,
        action: str,
        resource_id: str,
        attributes: dict[str, Any],
    ) -> str | None:
        return None
