"""Fault injection: the runtime fails closed and never executes without evidence."""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from gxp_agent_runtime.application.commands import CreateChallenge
from gxp_agent_runtime.application.runtime import GxpRuntime
from gxp_agent_runtime.config import Settings
from gxp_agent_runtime.domain.errors import DependencyError, UnauthorizedError
from gxp_agent_runtime.domain.models import RecordType, RequestStatus, SignatureMeaning
from gxp_agent_runtime.infrastructure.database import make_engine
from gxp_agent_runtime.runtime.container import Container, build_container
from gxp_agent_runtime.security.agents import LocalAgentGateway
from gxp_agent_runtime.security.jwks import RemoteJwks
from tests.conftest import (
    AGENT_AUDIENCE,
    AGENT_ISSUER,
    APPROVER,
    QA,
    FakeAgentIssuer,
    FakeClock,
    FakeIdp,
    FakeLims,
    agent_principal,
    submission,
)

pytestmark = [pytest.mark.chaos, pytest.mark.urs("URS-020")]


def test_database_outage_flips_readiness(client: TestClient) -> None:
    container = client.app.state.container  # type: ignore[attr-defined]
    assert client.get("/readyz").status_code == 200
    healthy = container.engine
    container.engine = make_engine("sqlite+aiosqlite:////nonexistent/dir/db.sqlite")
    try:
        assert client.get("/readyz").status_code == 503
        assert client.get("/healthz").status_code == 200
    finally:
        container.engine = healthy


async def test_validated_system_outage_produces_failed_record(
    provisioned: GxpRuntime, clock: FakeClock, lims: FakeLims
) -> None:
    lims.unavailable = 10
    view = await provisioned.submit(agent_principal(), submission(clock))
    assert view.status == "failed"
    record = await provisioned.get_record(view.request_id)
    assert record.error is not None
    assert "503" in record.error
    assert set(lims.idempotency_keys) == {view.request_id}
    assert (await provisioned.verify_record(view.request_id)).record_signature_valid


@pytest.mark.urs("URS-017")
async def test_audit_failure_blocks_the_action(
    provisioned: GxpRuntime, clock: FakeClock, lims: FakeLims
) -> None:
    async def broken(_: object) -> None:
        raise OSError("audit storage unavailable")

    provisioned._audit._sink.append = broken  # type: ignore[method-assign]
    with pytest.raises(OSError, match="audit storage"):
        await provisioned.submit(agent_principal(), submission(clock))
    assert lims.calls == []
    assert await provisioned.list_requests() == []


async def test_identity_fabric_outage_fails_closed(
    settings: Settings, idp: FakeIdp, clock: FakeClock, lims: FakeLims, tmp_path: Path
) -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("fabric unreachable", request=request)

    fabric_settings = settings.model_copy(update={"fabric_url": "https://identity.corp.test"})
    container: Container = await build_container(
        fabric_settings,
        fabric_transport=httpx.MockTransport(down),
        connector_transport=httpx.MockTransport(lims),
        clock=clock,
    )
    try:
        with pytest.raises(DependencyError, match="unreachable"):
            await container.runtime.agents.authenticate("Bearer any-agent-token")
    finally:
        await container.aclose()
    assert lims.calls == []


async def test_agent_key_endpoint_outage_fails_closed(
    issuer: FakeAgentIssuer, clock: FakeClock
) -> None:
    def down(_: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    gateway = LocalAgentGateway(
        RemoteJwks(
            f"{AGENT_ISSUER}/.well-known/jwks.json",
            client=httpx.AsyncClient(transport=httpx.MockTransport(down)),
        ),
        issuer=AGENT_ISSUER,
        audience=AGENT_AUDIENCE,
        clock=clock,
    )
    with pytest.raises(UnauthorizedError, match="cannot fetch"):
        await gateway.authenticate(f"Bearer {issuer.token()}")


@pytest.mark.urs("URS-016")
async def test_concurrent_final_signatures_execute_exactly_once(
    provisioned: GxpRuntime, idp: FakeIdp, clock: FakeClock, lims: FakeLims
) -> None:
    view = await provisioned.submit(agent_principal(), submission(clock, "lims.result.release"))
    prepared = []
    for who, meaning in (
        (APPROVER, SignatureMeaning.APPROVAL),
        (QA, SignatureMeaning.QUALITY_APPROVAL),
    ):
        challenge = await provisioned.create_challenge(
            CreateChallenge(
                record_type=RecordType.ACTION_REQUEST, record_id=view.request_id, meaning=meaning
            ),
            who=idp.principal(who),
        )
        prepared.append((who, challenge))
    outcomes = await asyncio.gather(
        *(
            provisioned.sign(
                who=idp.principal(who),
                challenge_id=challenge.challenge_id,
                reauthentication_token=idp.reauth(who, challenge.nonce),
                reason="Concurrent approval from the review board.",
            )
            for who, challenge in prepared
        ),
        return_exceptions=True,
    )
    assert not [o for o in outcomes if isinstance(o, BaseException)]
    request = await provisioned.get_request(view.request_id)
    assert request.status is RequestStatus.COMPLETED
    assert len(request.signature_ids) == 2
    assert len(lims.calls) == 1


async def test_jwks_timeout_fails_closed(issuer: FakeAgentIssuer) -> None:
    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timeout", request=request)

    remote = RemoteJwks(
        "https://x/jwks", client=httpx.AsyncClient(transport=httpx.MockTransport(slow))
    )
    with pytest.raises(UnauthorizedError):
        await remote.key_for(issuer.kid)
