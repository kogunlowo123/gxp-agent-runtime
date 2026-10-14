"""Human users (system owners, approvers, QA, auditors) via the enterprise OIDC provider.

Signing requires a fresh re-authentication (21 CFR 11.200(a)): the signer
presents an ID token obtained by re-entering credentials at the IdP with the
challenge nonce, ``prompt=login`` and ``max_age`` set. The token must belong
to the session's subject, carry the nonce, have a recent ``auth_time`` and
name at least one recognised authentication method (RFC 8176 ``amr``).
"""

from __future__ import annotations

import hmac
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, ConfigDict

from gxp_agent_runtime.domain.errors import ForbiddenError, SignatureError, UnauthorizedError
from gxp_agent_runtime.domain.models import Role
from gxp_agent_runtime.domain.ports import Clock
from gxp_agent_runtime.security.jwks import KeyResolver, verify_jwt

RFC8176_METHODS = frozenset(
    {"pwd", "mfa", "otp", "hwk", "swk", "sc", "pin", "fpt", "face", "iris", "retina", "kba", "user"}
)


class HumanPrincipal(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str
    name: str
    roles: frozenset[str]

    def has(self, *roles: Role) -> bool:
        return bool(self.roles.intersection(r.value for r in roles))


class Reauthentication(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str
    name: str
    auth_time: datetime
    methods: tuple[str, ...]


def require_role(principal: HumanPrincipal, *allowed: Role) -> None:
    if not principal.has(*allowed):
        raise ForbiddenError(f"requires one of roles {sorted(r.value for r in allowed)}")


class HumanAuthenticator:
    def __init__(
        self,
        resolver: KeyResolver,
        *,
        issuer: str,
        audience: str,
        clock: Clock,
        roles_claim: str = "roles",
        name_claim: str = "name",
        reauth_max_age: timedelta = timedelta(minutes=5),
        accepted_methods: Iterable[str] = RFC8176_METHODS,
    ) -> None:
        self._resolver = resolver
        self.issuer = issuer
        self._audience = audience
        self._clock = clock
        self._roles_claim = roles_claim
        self._name_claim = name_claim
        self._reauth_max_age = reauth_max_age
        self._methods = frozenset(accepted_methods)

    async def authenticate(self, authorization: str | None) -> HumanPrincipal:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise UnauthorizedError("bearer token required")
        claims = await verify_jwt(
            authorization[7:].strip(),
            self._resolver,
            issuer=self.issuer,
            audience=self._audience,
            now=self._clock.now(),
        )
        raw = claims.get(self._roles_claim, [])
        roles = (
            frozenset(r for r in raw if isinstance(r, str))
            if isinstance(raw, list)
            else frozenset()
        )
        name = claims.get(self._name_claim)
        return HumanPrincipal(
            subject=str(claims["sub"]),
            name=name if isinstance(name, str) and name.strip() else str(claims["sub"]),
            roles=roles,
        )

    async def verify_reauthentication(
        self, token: str, *, subject: str, nonce: str
    ) -> Reauthentication:
        now = self._clock.now()
        try:
            claims = await verify_jwt(
                token, self._resolver, issuer=self.issuer, audience=self._audience, now=now
            )
        except UnauthorizedError as exc:
            raise SignatureError(f"re-authentication token invalid: {exc.message}") from exc
        if str(claims["sub"]) != subject:
            raise SignatureError("re-authentication was performed by a different user")
        presented = claims.get("nonce")
        if not isinstance(presented, str) or not hmac.compare_digest(presented, nonce):
            raise SignatureError("re-authentication is not bound to this signing challenge")
        auth_time = claims.get("auth_time")
        if not isinstance(auth_time, int | float):
            raise SignatureError("re-authentication token has no auth_time")
        authenticated = datetime.fromtimestamp(auth_time, UTC)
        if now - authenticated > self._reauth_max_age or authenticated - now > timedelta(
            seconds=30
        ):
            raise SignatureError(
                f"credentials must be re-entered within {int(self._reauth_max_age.total_seconds())}"
                " s of signing"
            )
        amr = claims.get("amr", [])
        methods = tuple(m for m in amr if isinstance(m, str)) if isinstance(amr, list) else ()
        if not self._methods.intersection(methods):
            raise SignatureError("re-authentication did not use an accepted authentication method")
        name = claims.get(self._name_claim)
        return Reauthentication(
            subject=subject,
            name=name if isinstance(name, str) and name.strip() else subject,
            auth_time=authenticated,
            methods=methods,
        )
