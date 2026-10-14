"""Identity fabric client and gateways, validated-system connector, JWKS handling."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest

from gxp_agent_runtime.domain.errors import (
    DependencyError,
    ForbiddenError,
    UnauthorizedError,
)
from gxp_agent_runtime.domain.models import ActionRequest
from gxp_agent_runtime.infrastructure.connectors import HttpActionConnector
from gxp_agent_runtime.integrations.identity_fabric import (
    FabricAuthorizeRequest,
    IdentityFabricClient,
    RuntimeCredentials,
)
from gxp_agent_runtime.security.agents import FabricAgentGateway, LocalAgentGateway
from gxp_agent_runtime.security.jwks import RemoteJwks, StaticJwks, unverified_issuer, verify_jwt
from tests.conftest import (
    AGENT,
    AGENT_AUDIENCE,
    AGENT_ISSUER,
    FakeAgentIssuer,
    FakeClock,
    FakeLims,
    read_status_spec,
)

FABRIC = "https://identity.corp.test"


class FakeFabric:
    """agent-identity-fabric wire shapes (RFC 7523 / 7662 and /v1/authorize)."""

    def __init__(self) -> None:
        self.decision = "allow"
        self.active = True
        self.status = 200
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.status != 200:
            return httpx.Response(self.status, json={"error": "x", "error_description": "y"})
        if request.url.path == "/oauth2/token":
            form = dict(x.split("=", 1) for x in request.content.decode().split("&"))
            assert form["grant_type"].startswith("urn%3Aietf")
            return httpx.Response(
                200,
                json={
                    "access_token": f"runtime-token-{len(self.requests)}",
                    "token_type": "Bearer",
                    "expires_in": 600,
                    "scope": "lims:write",
                },
            )
        if request.url.path == "/oauth2/introspect":
            if not self.active:
                return httpx.Response(200, json={"active": False})
            return httpx.Response(
                200,
                json={
                    "active": True,
                    "sub": AGENT,
                    "scope": "gxp:read gxp:execute:lims.*",
                    "act": {"sub": "spiffe://agents.corp.test/agent/qc/orchestrator"},
                },
            )
        if request.url.path == "/v1/authorize":
            body = json.loads(request.content)
            return httpx.Response(
                200,
                json={
                    "decision": self.decision,
                    "agent": AGENT,
                    "action": body["action"],
                    "resource": f"{body['resource_type']}:{body['resource_id']}",
                    "matched_rules": ["allow-scoped-actions"],
                    "policy_version": "2026.10.0",
                    "policy_digest": "sha256:" + "a" * 64,
                    "reason": "explicit allow",
                    "delegation_chain": [],
                },
            )
        return httpx.Response(404)


def fabric_client(fake: FakeFabric) -> IdentityFabricClient:
    return IdentityFabricClient(
        FABRIC, client=httpx.AsyncClient(transport=httpx.MockTransport(fake))
    )


@pytest.mark.urs("URS-013")
async def test_fabric_gateway_introspects_and_authorizes() -> None:
    fake = FakeFabric()
    gateway = FabricAgentGateway(fabric_client(fake))
    principal = await gateway.authenticate("Bearer agent-token")
    assert principal.agent_id == AGENT
    assert principal.delegation_chain == ("spiffe://agents.corp.test/agent/qc/orchestrator",)
    assert principal.allows("gxp:execute:lims.result.release")
    decision = await gateway.authorize(
        principal, action="gxp:execute:lims.result.release", resource_id="k", attributes={}
    )
    assert decision == "allow"
    sent = json.loads(fake.requests[-1].content)
    assert sent["resource_type"] == "gxp-action"
    assert sent["environment"] == {"purpose_of_use": "gxp-operations"}
    assert fake.requests[-1].headers["authorization"] == "Bearer agent-token"

    fake.decision = "deny"
    with pytest.raises(ForbiddenError, match="identity fabric denied"):
        await gateway.authorize(principal, action="a", resource_id="k", attributes={})
    fake.active = False
    with pytest.raises(UnauthorizedError, match="not active"):
        await gateway.authenticate("Bearer revoked")
    with pytest.raises(UnauthorizedError):
        await gateway.authenticate(None)
    with pytest.raises(UnauthorizedError):
        await gateway.authenticate("Bearer ")


async def test_fabric_client_error_mapping(tmp_path: Path) -> None:
    fake = FakeFabric()
    client = fabric_client(fake)
    fake.status = 500
    with pytest.raises(DependencyError):
        await client.introspect("t")
    with pytest.raises(DependencyError):
        await client.authorize("t", FabricAuthorizeRequest(action="a", resource_type="r"))
    with pytest.raises(DependencyError):
        await client.issue_token("c", "a")
    fake.status = 401
    with pytest.raises(UnauthorizedError):
        await client.authorize("t", FabricAuthorizeRequest(action="a", resource_type="r"))
    with pytest.raises(UnauthorizedError):
        await client.issue_token("c", "a")

    def garbage(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<html>")

    broken = IdentityFabricClient(
        FABRIC, client=httpx.AsyncClient(transport=httpx.MockTransport(garbage))
    )
    with pytest.raises(DependencyError, match="unexpected body"):
        await broken.introspect("t")

    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    offline = IdentityFabricClient(
        FABRIC, client=httpx.AsyncClient(transport=httpx.MockTransport(down))
    )
    with pytest.raises(DependencyError, match="unreachable"):
        await offline.introspect("t")


async def test_runtime_credentials_are_cached_until_near_expiry(tmp_path: Path) -> None:
    fake = FakeFabric()
    token_file = tmp_path / "token"
    token_file.write_text("projected-sa-token\n", encoding="utf-8")
    clock = FakeClock()
    credentials = RuntimeCredentials(
        fabric_client(fake),
        client_id="spiffe://agents.corp.test/agent/platform/gxp-runtime",
        workload_token_file=token_file,
        clock=clock,
    )
    first = await credentials.bearer()
    assert await credentials.bearer() == first
    clock.advance(seconds=560)
    assert await credentials.bearer() != first
    form = fake.requests[0].content.decode()
    assert "assertion=projected-sa-token" in form


@pytest.mark.urs("URS-013")
async def test_local_gateway_verifies_fabric_credentials(
    issuer: FakeAgentIssuer, clock: FakeClock
) -> None:
    gateway = LocalAgentGateway(
        StaticJwks(issuer.jwks()), issuer=AGENT_ISSUER, audience=AGENT_AUDIENCE, clock=clock
    )
    token = issuer.token(
        act={"sub": "spiffe://a/agent/x/orch", "act": {"sub": "spiffe://a/agent/x/root"}}
    )
    principal = await gateway.authenticate(f"Bearer {token}")
    assert principal.delegation_chain == ("spiffe://a/agent/x/orch", "spiffe://a/agent/x/root")
    assert await gateway.authorize(principal, action="x", resource_id="y", attributes={}) is None
    clock.advance(minutes=30)
    with pytest.raises(UnauthorizedError, match="Expired"):
        await gateway.authenticate(f"Bearer {token}")


async def test_jwks_resolution_and_verification(issuer: FakeAgentIssuer, clock: FakeClock) -> None:
    calls = 0

    def serve(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=issuer.jwks())

    ticks = [0.0]
    remote = RemoteJwks(
        "https://identity.corp.test/jwks",
        client=httpx.AsyncClient(transport=httpx.MockTransport(serve)),
        clock=lambda: ticks[0],
    )
    assert await remote.key_for(issuer.kid) is not None
    with pytest.raises(UnauthorizedError, match="unknown signing key"):
        await remote.key_for("other")
    assert calls == 1  # refresh rate-limited
    ticks[0] = 400.0
    await remote.key_for(issuer.kid)
    assert calls == 2

    token = issuer.token()
    assert unverified_issuer(token) == AGENT_ISSUER
    assert unverified_issuer("garbage") is None
    assert unverified_issuer("a.!!!.c") is None
    assert unverified_issuer("a.WzFd.c") is None
    resolver = StaticJwks(issuer.jwks())
    claims = await verify_jwt(
        token, resolver, issuer=AGENT_ISSUER, audience=AGENT_AUDIENCE, now=clock.now()
    )
    assert claims["sub"] == AGENT
    future = jwt.encode(
        {
            "iss": AGENT_ISSUER,
            "sub": "s",
            "aud": AGENT_AUDIENCE,
            "iat": 4102444800,
            "exp": 4102448400,
        },
        issuer.key,
        algorithm="EdDSA",
        headers={"kid": issuer.kid},
    )
    with pytest.raises(UnauthorizedError, match="future"):
        await verify_jwt(
            future, resolver, issuer=AGENT_ISSUER, audience=AGENT_AUDIENCE, now=clock.now()
        )
    now = int(clock.now().timestamp())
    not_yet = jwt.encode(
        {
            "iss": AGENT_ISSUER,
            "sub": "s",
            "aud": AGENT_AUDIENCE,
            "iat": now,
            "exp": now + 900,
            "nbf": now + 600,
        },
        issuer.key,
        algorithm="EdDSA",
        headers={"kid": issuer.kid},
    )
    with pytest.raises(UnauthorizedError, match="not yet valid"):
        await verify_jwt(
            not_yet, resolver, issuer=AGENT_ISSUER, audience=AGENT_AUDIENCE, now=clock.now()
        )
    no_kid = jwt.encode({"sub": "s"}, issuer.key, algorithm="EdDSA")
    with pytest.raises(UnauthorizedError, match="key id"):
        await verify_jwt(
            no_kid, resolver, issuer=AGENT_ISSUER, audience=AGENT_AUDIENCE, now=clock.now()
        )


def _request(**overrides: Any) -> ActionRequest:
    from gxp_agent_runtime.domain.models import (
        AlcoaAssessment,
        PolicyOutcome,
        RequestStatus,
    )
    from gxp_agent_runtime.domain.risk import RiskClassifier

    spec = read_status_spec()
    clock = FakeClock()
    values: dict[str, Any] = {
        "request_id": "req-1",
        "action_key": spec.key,
        "action_id": spec.action_id,
        "version": spec.version,
        "definition_digest": spec.digest,
        "system_id": spec.system_id,
        "agent_id": AGENT,
        "inputs": {"sample_id": "S-1001"},
        "inputs_digest": "sha256:" + "a" * 64,
        "justification": "status check before release",
        "performed_at": clock.now(),
        "received_at": clock.now(),
        "risk": RiskClassifier().assess(spec),
        "policy": PolicyOutcome(
            decision="allow", matched_rules=(), policy_version="1", policy_digest="d", reason="r"
        ),
        "alcoa": AlcoaAssessment(checks=()),
        "status": RequestStatus.EXECUTING,
        "updated_at": clock.now(),
    }
    values.update(overrides)
    return ActionRequest(**values)


@pytest.mark.urs("URS-016")
async def test_connector_retries_with_same_idempotency_key() -> None:
    from tests.conftest import lims_system

    system_cmd = lims_system()
    from gxp_agent_runtime.domain.models import ValidatedSystem

    clock = FakeClock()
    system = ValidatedSystem(
        **system_cmd.model_dump(), registered_at=clock.now(), updated_at=clock.now()
    )
    lims = FakeLims(unavailable=2)
    sleeps: list[float] = []

    async def sleep(seconds: float) -> None:
        sleeps.append(seconds)

    class Credentials:
        async def bearer(self) -> str:
            return "runtime-credential"

    connector = HttpActionConnector(
        httpx.AsyncClient(transport=httpx.MockTransport(lims)),
        clock=clock,
        credentials=Credentials(),
        sleep=sleep,
    )
    result = await connector.execute(system, read_status_spec(), _request())
    assert result.succeeded
    assert result.attempts == 3
    assert set(lims.idempotency_keys) == {"req-1"}
    assert sleeps == [0.5, 1.0]
    assert lims.calls[0].headers["authorization"] == "Bearer runtime-credential"

    lims.unavailable = 5
    exhausted = await connector.execute(system, read_status_spec(), _request())
    assert not exhausted.succeeded
    assert exhausted.error is not None
    assert "after 3 attempts" in exhausted.error

    def flaky(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    timeouts = HttpActionConnector(
        httpx.AsyncClient(transport=httpx.MockTransport(flaky)), clock=clock, sleep=sleep
    )
    timed_out = await timeouts.execute(system, read_status_spec(), _request())
    assert timed_out.error is not None
    assert "ReadTimeout" in timed_out.error

    def not_json(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<ok/>")

    odd = HttpActionConnector(
        httpx.AsyncClient(transport=httpx.MockTransport(not_json)), clock=clock
    )
    parsed = await odd.execute(system, read_status_spec(), _request())
    assert not parsed.succeeded
    assert parsed.error == "system response is not a JSON object"
    assert parsed.response_digest is not None
    assert parsed.response_digest.startswith("sha256:")

    def empty(_: httpx.Request) -> httpx.Response:
        return httpx.Response(202)

    accepted = HttpActionConnector(
        httpx.AsyncClient(transport=httpx.MockTransport(empty)), clock=clock
    )
    assert (await accepted.execute(system, read_status_spec(), _request())).outputs == {}
    assert clock.now() - result.started_at < timedelta(seconds=1)
