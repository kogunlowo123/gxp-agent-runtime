"""End-to-end over HTTP: the whole GxP flow as system owners, QA, approvers and agents use it,
through REST, MCP (streamable HTTP) and A2A JSON-RPC."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.conftest import (
    AGENT,
    APPROVER,
    AUDITOR,
    OWNER,
    QA,
    QA2,
    SOURCE,
    FakeAgentIssuer,
    FakeIdp,
    FakeLims,
    bearer,
    lims_system,
    read_status_spec,
    release_spec,
)

pytestmark = pytest.mark.e2e

MCP_HEADERS = {
    "accept": "application/json, text/event-stream",
    "mcp-protocol-version": "2025-06-18",
}


def http_sign(
    client: TestClient,
    idp: FakeIdp,
    who: tuple[str, str, tuple[str, ...]],
    record_type: str,
    record_id: str,
    meaning: str,
) -> dict[str, Any]:
    challenge = client.post(
        "/v1/signatures/challenges",
        json={"record_type": record_type, "record_id": record_id, "meaning": meaning},
        headers=bearer(idp.user(who)),
    )
    assert challenge.status_code == 201, challenge.text
    body = challenge.json()
    signed = client.post(
        "/v1/signatures",
        json={
            "challenge_id": body["challenge_id"],
            "reauthentication_token": idp.reauth(who, body["nonce"]),
            "reason": "Reviewed per SOP-QA-021 section 6.",
        },
        headers=bearer(idp.user(who)),
    )
    assert signed.status_code == 201, signed.text
    result: dict[str, Any] = signed.json()
    return result


def provision_http(client: TestClient, idp: FakeIdp) -> None:
    owner = bearer(idp.user(OWNER))
    system = client.post("/v1/systems", json=lims_system().model_dump(mode="json"), headers=owner)
    assert system.status_code == 201, system.text
    for spec in (read_status_spec(), release_spec()):
        created = client.post(
            "/v1/action-definitions",
            json={"spec": spec.model_dump(mode="json"), "validation_reference": "OQ-2026-117"},
            headers=owner,
        )
        assert created.status_code == 201, created.text
        assert created.json()["status"] == "draft"
        validated = http_sign(client, idp, QA, "action-definition", spec.key, "validation-approval")
        assert validated["record_status"] == "validated"


def release_body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "action_id": "lims.result.release",
        "inputs": {"sample_id": "S-1001", "disposition": "conforming", "batch_id": "B-7"},
        "justification": "All assays within SPEC-114 rev 6 limits; reviewer checklist done.",
        "context": {"batch_id": "B-7"},
        "source_records": [SOURCE.model_dump()],
        "performed_at": (datetime.now(UTC) - timedelta(seconds=5)).isoformat(),
    }
    body.update(overrides)
    return body


@pytest.mark.urs("URS-001", "URS-002", "URS-003", "URS-006", "URS-009", "URS-017", "URS-021")
def test_full_gxp_lifecycle_over_rest(
    client: TestClient, idp: FakeIdp, issuer: FakeAgentIssuer, lims: FakeLims
) -> None:
    provision_http(client, idp)
    agent = bearer(issuer.token())
    catalog = client.get("/v1/actions", headers=agent).json()["items"]
    assert {a["action_id"] for a in catalog} == {"lims.sample.read-status", "lims.result.release"}

    preview = client.post("/v1/actions/assess", json=release_body(), headers=agent).json()
    assert preview["risk"]["priority"] == "high"
    assert preview["would_execute_immediately"] is False

    submitted = client.post("/v1/action-requests", json=release_body(), headers=agent)
    assert submitted.status_code == 201, submitted.text
    request = submitted.json()
    assert request["status"] == "pending_approval"
    request_id = request["request_id"]

    queue = client.get(
        "/v1/action-requests",
        params={"status": "pending_approval"},
        headers=bearer(idp.user(APPROVER)),
    ).json()
    assert [r["request_id"] for r in queue["items"]] == [request_id]

    http_sign(client, idp, APPROVER, "action-request", request_id, "approval")
    done = http_sign(client, idp, QA2, "action-request", request_id, "quality-approval")
    assert done["record_status"] == "completed"
    assert done["execution_record_id"] == request_id
    assert lims.released == {"S-1001": "released"}

    own = client.get(f"/v1/action-requests/{request_id}", headers=agent).json()
    assert own["status"] == "completed"
    record = client.get(f"/v1/execution-records/{request_id}", headers=agent).json()
    assert record["outputs"]["status"] == "released"
    assert len(record["signatures"]) == 2
    auditor = bearer(idp.user(AUDITOR))
    verification = client.get(
        f"/v1/execution-records/{request_id}/verification", headers=auditor
    ).json()
    assert verification["verified"] is True
    assert client.get(f"/v1/execution-records/{request_id}", headers=auditor).status_code == 200
    assert client.get(f"/v1/action-requests/{request_id}", headers=auditor).status_code == 200
    signatures = client.get(
        "/v1/signatures",
        params={"record_type": "action-request", "record_id": request_id},
        headers=auditor,
    ).json()["items"]
    assert sorted(s["meaning"] for s in signatures) == ["approval", "quality-approval"]
    audit = client.get("/v1/audit/verification", headers=auditor).json()
    assert audit["intact"] is True
    assert audit["events_verified"] > 10

    assert client.get("/v1/systems", headers=auditor).json()["items"][0]["system_id"] == (
        "lims-prod"
    )
    assert client.get("/v1/systems/lims-prod", headers=auditor).status_code == 200
    definitions = client.get(
        "/v1/action-definitions", params={"status": "validated"}, headers=auditor
    ).json()["items"]
    assert len(definitions) == 2
    assert (
        client.get("/v1/action-definitions/lims.result.release/1.0.0", headers=auditor).json()[
            "status"
        ]
        == "validated"
    )

    now = datetime.now(UTC)
    review = client.post(
        "/v1/periodic-reviews",
        json={
            "system_id": "lims-prod",
            "period_start": (now - timedelta(days=1)).isoformat(),
            "period_end": now.isoformat(),
        },
        headers=bearer(idp.user(OWNER)),
    )
    assert review.status_code == 201, review.text
    review_id = review.json()["review_id"]
    assert review.json()["metrics"]["executions_completed"] == 1
    approved = http_sign(client, idp, QA, "periodic-review", review_id, "review")
    assert approved["record_status"] == "approved"
    assert client.get(f"/v1/periodic-reviews/{review_id}", headers=auditor).json()["status"] == (
        "approved"
    )

    metrics = client.get("/metrics").text
    assert 'gxp_electronic_signatures_total{meaning="quality-approval"} 1.0' in metrics
    assert 'gxp_executions_total{status="completed",system="lims-prod"} 1.0' in metrics
    assert "gxp_http_request_duration_seconds" in metrics


@pytest.mark.urs("URS-018", "URS-013")
def test_mcp_tools(client: TestClient, idp: FakeIdp, issuer: FakeAgentIssuer) -> None:
    provision_http(client, idp)
    headers = {**MCP_HEADERS, "authorization": f"Bearer {issuer.token()}"}

    def rpc(method: str, params: dict[str, Any] | None = None, **extra: str) -> dict[str, Any]:
        response = client.post(
            "/mcp/",
            json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
            headers={**headers, **extra},
        )
        assert response.status_code == 200, response.text
        result: dict[str, Any] = response.json()
        return result

    init = rpc(
        "initialize",
        {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "1"},
        },
    )
    assert init["result"]["serverInfo"]["name"] == "gxp-agent-runtime"
    tools = {t["name"]: t for t in rpc("tools/list")["result"]["tools"]}
    assert set(tools) == {
        "list_gxp_actions",
        "assess_gxp_action",
        "request_gxp_action",
        "get_gxp_request",
        "get_execution_record",
    }
    assert "outputSchema" in tools["request_gxp_action"]
    assert "action_id" in tools["request_gxp_action"]["inputSchema"]["properties"]

    listed = rpc("tools/call", {"name": "list_gxp_actions", "arguments": {}})["result"]
    assert len(listed["structuredContent"]["actions"]) == 2
    args = {
        "action_id": "lims.sample.read-status",
        "inputs": {"sample_id": "S-1001"},
        "justification": "Check status before preparing the release package.",
        "performed_at": datetime.now(UTC).isoformat(),
    }
    assessed = rpc("tools/call", {"name": "assess_gxp_action", "arguments": args})["result"]
    assert assessed["structuredContent"]["would_execute_immediately"] is True
    called = rpc("tools/call", {"name": "request_gxp_action", "arguments": args})["result"]
    assert called["isError"] is False
    request_id = called["structuredContent"]["request_id"]
    assert called["structuredContent"]["status"] == "completed"
    status = rpc(
        "tools/call", {"name": "get_gxp_request", "arguments": {"request_id": request_id}}
    )["result"]
    assert status["structuredContent"]["status"] == "completed"
    record = rpc(
        "tools/call", {"name": "get_execution_record", "arguments": {"record_id": request_id}}
    )["result"]
    assert record["structuredContent"]["outputs"]["status"] == "in-review"

    missing = rpc("tools/call", {"name": "get_gxp_request", "arguments": {"request_id": "nope"}})[
        "result"
    ]
    assert missing["isError"] is True
    assert "not_found" in missing["content"][0]["text"]
    invalid = rpc(
        "tools/call",
        {"name": "request_gxp_action", "arguments": {**args, "justification": ""}},
    )["result"]
    assert invalid["isError"] is True
    anonymous = rpc(
        "tools/call", {"name": "list_gxp_actions", "arguments": {}}, authorization="Bearer x.y.z"
    )["result"]
    assert anonymous["isError"] is True
    assert "unauthorized" in anonymous["content"][0]["text"]


@pytest.mark.urs("URS-018")
def test_a2a_agent_card_and_jsonrpc(
    client: TestClient, idp: FakeIdp, issuer: FakeAgentIssuer
) -> None:
    provision_http(client, idp)
    card = client.get("/.well-known/agent-card.json").json()
    assert card["url"] == "https://gxp-runtime.corp.test/a2a"
    assert {
        "name",
        "description",
        "url",
        "version",
        "capabilities",
        "skills",
        "securitySchemes",
    } <= set(card)
    agent = bearer(issuer.token())

    def call(method: str, params: dict[str, Any]) -> dict[str, Any]:
        response = client.post(
            "/a2a",
            json={"jsonrpc": "2.0", "id": "r1", "method": method, "params": params},
            headers=agent,
        )
        assert response.status_code == 200, response.text
        body: dict[str, Any] = response.json()
        return body

    message = {
        "role": "user",
        "messageId": "m-1",
        "contextId": "ctx-release-B-7",
        "parts": [{"kind": "data", "data": release_body()}],
    }
    task = call("message/send", {"message": message})["result"]
    assert task["kind"] == "task"
    assert task["contextId"] == "ctx-release-B-7"
    assert task["status"]["state"] == "input-required"
    assessed = call(
        "message/send",
        {
            "message": {
                **message,
                "parts": [{"kind": "data", "data": {**release_body(), "skill": "assess"}}],
            }
        },
    )["result"]
    assert assessed["kind"] == "message"
    assert assessed["parts"][0]["data"]["risk"]["priority"] == "high"

    http_sign(client, idp, APPROVER, "action-request", task["id"], "approval")
    http_sign(client, idp, QA, "action-request", task["id"], "quality-approval")
    polled = call("tasks/get", {"id": task["id"]})["result"]
    assert polled["status"]["state"] == "completed"
    assert polled["artifacts"][0]["parts"][0]["data"]["agent_id"] == AGENT

    assert call("tasks/get", {"id": "missing"})["error"]["code"] == -32001
    assert call("tasks/get", {})["error"]["code"] == -32602
    assert call("tasks/cancel", {"id": task["id"]})["error"]["code"] == -32601
    assert call("message/send", {"message": {"parts": []}})["error"]["code"] == -32602
    assert call("message/send", {})["error"]["code"] == -32602
    unknown = call(
        "message/send",
        {
            "message": {
                **message,
                "parts": [{"kind": "data", "data": release_body(action_id="lims.none")}],
            }
        },
    )
    assert unknown["error"]["code"] == -32602
    narrow = client.post(
        "/a2a",
        json={"jsonrpc": "2.0", "id": 2, "method": "tasks/get", "params": {"id": task["id"]}},
        headers=bearer(issuer.token(scopes=("gxp:execute:lims.*",))),
    ).json()
    assert narrow["error"]["code"] == -32003
    bad_json = client.post(
        "/a2a", content=b"{nope", headers={**agent, "content-type": "application/json"}
    )
    assert bad_json.json()["error"]["code"] == -32700
    bad_rpc = client.post("/a2a", json={"jsonrpc": "1.0", "id": 9, "method": "x"}, headers=agent)
    assert bad_rpc.json() == {
        "jsonrpc": "2.0",
        "id": 9,
        "error": {"code": -32600, "message": "invalid request"},
    }
    assert client.post("/a2a", json={}).status_code == 401


@pytest.mark.urs("URS-021")
def test_operational_endpoints(client: TestClient) -> None:
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/readyz").json() == {"status": "ready"}
    response = client.get("/healthz", headers={"X-Correlation-ID": "trace-123"})
    assert response.headers["x-correlation-id"] == "trace-123"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    generated = client.get("/healthz", headers={"X-Correlation-ID": "x" * 200})
    assert generated.headers["x-correlation-id"] != "x" * 200
    keys = client.get("/.well-known/jwks.json").json()["keys"]
    assert [k["use"] for k in keys] == ["records", "audit"]
    assert all(k["alg"] == "EdDSA" for k in keys)


def test_error_bodies(client: TestClient, idp: FakeIdp, issuer: FakeAgentIssuer) -> None:
    owner = bearer(idp.user(OWNER))
    missing = client.post("/v1/systems", json=lims_system().model_dump(mode="json"))
    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"
    assert missing.json()["error"] == "unauthorized"
    wrong_role = client.post(
        "/v1/systems", json=lims_system().model_dump(mode="json"), headers=bearer(idp.user(QA))
    )
    assert wrong_role.status_code == 403
    invalid = client.post("/v1/systems", json={"system_id": "x"}, headers=owner)
    assert invalid.status_code == 422
    assert invalid.json()["error"] == "invalid_request"
    assert client.get("/v1/systems/none", headers=owner).status_code == 404
    agent_on_human = client.get("/v1/systems", headers=bearer(issuer.token()))
    assert agent_on_human.status_code == 401
    unknown_action = client.post(
        "/v1/action-requests", json=release_body(), headers=bearer(issuer.token())
    )
    assert unknown_action.status_code == 404
