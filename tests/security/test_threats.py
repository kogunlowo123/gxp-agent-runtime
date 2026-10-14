"""Adversarial tests mapped to docs/security/threat-model.md (T-ids in docstrings)."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from gxp_agent_runtime.application.runtime import GxpRuntime
from gxp_agent_runtime.domain.errors import ForbiddenError, SignatureError
from gxp_agent_runtime.domain.models import RecordType, SignatureMeaning
from gxp_agent_runtime.infrastructure.database import audit_events, records
from gxp_agent_runtime.runtime.container import Container
from tests.conftest import (
    APPROVER,
    AUDITOR,
    OWNER,
    QA,
    FakeAgentIssuer,
    FakeClock,
    FakeIdp,
    FakeLims,
    agent_principal,
    bearer,
    sign,
    submission,
)
from tests.e2e.test_http_lifecycle import MCP_HEADERS, provision_http, release_body

pytestmark = pytest.mark.security


def _b64(obj: dict[str, object]) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


@pytest.mark.urs("URS-013")
def test_t1_t2_forged_and_unsigned_agent_credentials(
    client: TestClient, idp: FakeIdp, issuer: FakeAgentIssuer
) -> None:
    """T1 spoofing with an attacker key and a guessed kid; T2 alg=none and HS256 confusion."""
    provision_http(client, idp)
    genuine = jwt.decode(issuer.token(), options={"verify_signature": False})
    forged = jwt.encode(
        genuine, Ed25519PrivateKey.generate(), algorithm="EdDSA", headers={"kid": issuer.kid}
    )
    unsigned = f"{_b64({'alg': 'none', 'kid': issuer.kid})}.{_b64(genuine)}."
    hmac = jwt.encode(genuine, "k" * 32, algorithm="HS256", headers={"kid": issuer.kid})
    for token in (forged, unsigned, hmac):
        response = client.get("/v1/actions", headers=bearer(token))
        assert response.status_code == 401, token
        assert response.headers["www-authenticate"] == "Bearer"
    expired = issuer.token(ttl=-300)
    assert client.get("/v1/actions", headers=bearer(expired)).status_code == 401


@pytest.mark.urs("URS-013")
def test_t3_token_confusion_between_humans_and_agents(
    client: TestClient, idp: FakeIdp, issuer: FakeAgentIssuer
) -> None:
    """T3: a QA user's token is not an agent credential and vice versa."""
    provision_http(client, idp)
    assert client.get("/v1/actions", headers=bearer(idp.user(QA))).status_code == 401
    assert client.get("/v1/action-requests", headers=bearer(issuer.token())).status_code == 401
    assert (
        client.post(
            "/v1/signatures/challenges",
            json={"record_type": "action-request", "record_id": "x", "meaning": "approval"},
            headers=bearer(issuer.token()),
        ).status_code
        == 401
    )


@pytest.mark.urs("URS-013", "URS-008")
async def test_t4_t5_scope_and_object_level_authorization(
    provisioned: GxpRuntime, clock: FakeClock
) -> None:
    """T4 excessive agency outside scopes; T5 broken object level authorization."""
    narrow = agent_principal(scopes=("gxp:read", "gxp:execute:lims.sample.*"))
    denied = await provisioned.submit(narrow, submission(clock, "lims.result.release"))
    assert denied.status == "denied"
    assert "deny-out-of-scope" in denied.policy.matched_rules
    mine = await provisioned.submit(agent_principal(), submission(clock))
    thief = agent_principal(sub="spiffe://agents.corp.test/agent/other/bot")
    from gxp_agent_runtime.domain.errors import NotFoundError

    with pytest.raises(NotFoundError):
        await provisioned.agent_record(thief, mine.request_id)


@pytest.mark.urs("URS-003")
async def test_t6_reauthentication_replayed_on_another_challenge(
    provisioned: GxpRuntime, idp: FakeIdp, clock: FakeClock
) -> None:
    """T6: a captured re-authentication token cannot sign a different record."""
    from gxp_agent_runtime.application.commands import CreateChallenge

    first = await provisioned.submit(agent_principal(), submission(clock, "lims.result.release"))
    second = await provisioned.submit(agent_principal(), submission(clock, "lims.result.release"))
    approver = idp.principal(APPROVER)
    a = await provisioned.create_challenge(
        CreateChallenge(
            record_type=RecordType.ACTION_REQUEST,
            record_id=first.request_id,
            meaning=SignatureMeaning.APPROVAL,
        ),
        who=approver,
    )
    b = await provisioned.create_challenge(
        CreateChallenge(
            record_type=RecordType.ACTION_REQUEST,
            record_id=second.request_id,
            meaning=SignatureMeaning.APPROVAL,
        ),
        who=approver,
    )
    captured = idp.reauth(APPROVER, a.nonce)
    with pytest.raises(SignatureError, match="not bound"):
        await provisioned.sign(
            who=approver,
            challenge_id=b.challenge_id,
            reauthentication_token=captured,
            reason="x" * 10,
        )


@pytest.mark.urs("URS-003", "URS-009")
async def test_t7_tampered_record_and_transplanted_signature_are_detected(
    provisioned: GxpRuntime, container: Container, idp: FakeIdp, clock: FakeClock
) -> None:
    """T7 tampering with stored execution records; signatures copied between records."""
    view = await provisioned.submit(agent_principal(), submission(clock, "lims.result.release"))
    await sign(
        provisioned,
        idp,
        APPROVER,
        RecordType.ACTION_REQUEST,
        view.request_id,
        SignatureMeaning.APPROVAL,
    )
    await sign(
        provisioned,
        idp,
        QA,
        RecordType.ACTION_REQUEST,
        view.request_id,
        SignatureMeaning.QUALITY_APPROVAL,
    )
    assert (await provisioned.verify_record(view.request_id)).verified

    async with container.engine.begin() as conn:
        document = (
            await conn.execute(
                select(records.c.document).where(records.c.record_id == view.request_id)
            )
        ).scalar_one()
        altered = json.loads(document)
        altered["outputs"]["disposition"] = "non-conforming"
        await conn.execute(
            update(records)
            .where(records.c.record_id == view.request_id)
            .values(document=json.dumps(altered))
        )
    tampered = await provisioned.verify_record(view.request_id)
    assert not tampered.verified
    assert not tampered.record_digest_valid
    assert "original" in [c.principle.value for c in tampered.alcoa.failures]

    other = await provisioned.submit(agent_principal(), submission(clock, "lims.result.release"))
    transplanted = json.loads(document)
    transplanted["request_digest"] = (await provisioned.get_request(other.request_id)).record_digest
    async with container.engine.begin() as conn:
        await conn.execute(
            update(records)
            .where(records.c.record_id == view.request_id)
            .values(document=json.dumps(transplanted))
        )
    result = await provisioned.verify_record(view.request_id)
    assert not any(s.linked_to_record for s in result.signatures)
    assert not result.verified


@pytest.mark.urs("URS-017")
async def test_t8_audit_trail_tampering_is_detected(
    provisioned: GxpRuntime, container: Container, clock: FakeClock
) -> None:
    """T8 repudiation: editing or deleting an audit event breaks the signed chain."""
    await provisioned.submit(agent_principal(), submission(clock))
    assert (await provisioned.verify_audit()).intact
    async with container.engine.begin() as conn:
        row = (
            await conn.execute(
                select(audit_events.c.sequence, audit_events.c.document).where(
                    audit_events.c.sequence == 3
                )
            )
        ).one()
        event = json.loads(row.document)
        event["actor"] = "someone-else"
        await conn.execute(
            update(audit_events)
            .where(audit_events.c.sequence == 3)
            .values(document=json.dumps(event))
        )
    report = await provisioned.verify_audit()
    assert not report.intact
    assert report.chains[0].error is not None
    assert "sequence 3" in report.chains[0].error


@pytest.mark.urs("URS-008")
def test_t9_t10_role_escalation_and_self_approval_over_http(
    client: TestClient, idp: FakeIdp
) -> None:
    """T9: auditors and approvers cannot apply QA meanings; T10: authors cannot self-validate."""
    owner = bearer(idp.user(OWNER))
    from tests.conftest import lims_system, read_status_spec

    client.post("/v1/systems", json=lims_system().model_dump(mode="json"), headers=owner)
    client.post(
        "/v1/action-definitions",
        json={"spec": read_status_spec().model_dump(mode="json"), "validation_reference": "OQ-1"},
        headers=owner,
    )
    body = {
        "record_type": "action-definition",
        "record_id": read_status_spec().key,
        "meaning": "validation-approval",
    }
    for who in (AUDITOR, APPROVER):
        assert (
            client.post(
                "/v1/signatures/challenges", json=body, headers=bearer(idp.user(who))
            ).status_code
            == 403
        )
    author_with_qa = (OWNER[0], OWNER[1], ("gxp-system-owner", "gxp-qa"))
    response = client.post(
        "/v1/signatures/challenges", json=body, headers=bearer(idp.user(author_with_qa))
    )
    assert response.status_code == 403
    assert response.json()["error"] == "signature_rejected"


@pytest.mark.urs("URS-001")
async def test_t11_inputs_cannot_escape_the_binding_path(
    provisioned: GxpRuntime, idp: FakeIdp, clock: FakeClock, lims: FakeLims
) -> None:
    """T11 injection: input values are URL-encoded into the registered path template."""
    view = await provisioned.submit(
        agent_principal(),
        submission(
            clock,
            "lims.result.comment",
            inputs={"sample_id": "../../admin/users?drop=1", "comment": "investigation note"},
        ),
    )
    await sign(
        provisioned,
        idp,
        QA,
        RecordType.ACTION_REQUEST,
        view.request_id,
        SignatureMeaning.QUALITY_APPROVAL,
    )
    raw = lims.calls[-1].url.raw_path.decode()
    assert raw == "/api/v1/results/..%2F..%2Fadmin%2Fusers%3Fdrop%3D1/comments"
    assert lims.calls[-1].url.host == "lims.corp.test"


@pytest.mark.urs("URS-014")
def test_t12_credentials_in_requests_are_rejected(
    client: TestClient, idp: FakeIdp, issuer: FakeAgentIssuer
) -> None:
    """T12 sensitive information disclosure into permanent GxP records."""
    provision_http(client, idp)
    response = client.post(
        "/v1/action-requests",
        json=release_body(context={"batch_id": "B-7", "note": "ghp_" + "a" * 36}),
        headers=bearer(issuer.token()),
    )
    assert response.status_code == 422
    assert response.json()["error"] == "validation_failed"


@pytest.mark.urs("URS-018")
def test_t13_mcp_rejects_foreign_host_headers(client: TestClient, issuer: FakeAgentIssuer) -> None:
    """T13 DNS rebinding against the MCP endpoint."""
    response = client.post(
        "/mcp/",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={**MCP_HEADERS, **bearer(issuer.token()), "host": "attacker.test"},
    )
    assert response.status_code in {400, 403, 421}


@pytest.mark.urs("URS-013")
async def test_t14_deep_delegation_is_denied(provisioned: GxpRuntime, clock: FakeClock) -> None:
    """T14 confused deputy through long delegation chains."""
    chain = ("spiffe://agents.corp.test/agent/a/one", "spiffe://agents.corp.test/agent/a/two")
    view = await provisioned.submit(agent_principal(chain=chain), submission(clock))
    assert view.status == "denied"
    assert "deny-deep-delegation" in view.policy.matched_rules


@pytest.mark.urs("URS-002", "URS-020")
async def test_t15_validated_system_redirects_are_not_followed(
    provisioned: GxpRuntime, clock: FakeClock, lims: FakeLims
) -> None:
    """T15 SSRF via redirect from a compromised integration endpoint."""
    lims.reject_with = 302
    view = await provisioned.submit(agent_principal(), submission(clock))
    assert view.status == "failed"
    assert len(lims.calls) == 1


def test_t16_oversized_and_malformed_requests(client: TestClient, issuer: FakeAgentIssuer) -> None:
    """T16 unrestricted resource consumption and mass assignment."""
    agent = bearer(issuer.token())
    too_many = release_body(context={f"k{i}": "v" for i in range(25)})
    assert client.post("/v1/action-requests", json=too_many, headers=agent).status_code == 422
    extra = release_body(status="completed")
    assert client.post("/v1/action-requests", json=extra, headers=agent).status_code == 422
    future = release_body(performed_at=(datetime.now(UTC) + timedelta(days=1)).isoformat())
    assert client.post("/v1/action-requests", json=future, headers=agent).status_code == 404


async def test_t17_auditor_cannot_mutate_and_owner_cannot_sign(
    provisioned: GxpRuntime, idp: FakeIdp, clock: FakeClock
) -> None:
    """T17 broken function level authorization."""
    view = await provisioned.submit(agent_principal(), submission(clock, "lims.result.release"))
    with pytest.raises(ForbiddenError):
        await sign(
            provisioned,
            idp,
            OWNER,
            RecordType.ACTION_REQUEST,
            view.request_id,
            SignatureMeaning.APPROVAL,
        )
    with pytest.raises(ForbiddenError):
        await sign(
            provisioned,
            idp,
            AUDITOR,
            RecordType.ACTION_REQUEST,
            view.request_id,
            SignatureMeaning.REJECTION,
        )


def test_t18_mcp_credential_failures_are_audited(client: TestClient, idp: FakeIdp) -> None:
    """T18: failed MCP authentication leaves evidence."""
    response = client.post(
        "/mcp/",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "list_gxp_actions", "arguments": {}},
        },
        headers={**MCP_HEADERS, "authorization": "Bearer not.a.token"},
    )
    assert response.json()["result"]["isError"] is True
    audit = client.get("/v1/audit/verification", headers=bearer(idp.user(AUDITOR))).json()
    assert audit["intact"] is True
    assert audit["events_verified"] >= 1
    assert httpx.codes.OK == 200
