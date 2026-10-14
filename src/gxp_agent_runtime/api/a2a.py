"""A2A (Agent2Agent) protocol surface: Agent Card and JSON-RPC 2.0 endpoint.

``message/send`` accepts a message whose data part names an action; the
runtime answers with a Task whose id is the action request id. Requests that
wait for electronic signatures are reported as ``input-required`` and can be
polled with ``tasks/get``. Assessment-only messages (``skill: assess``) are
answered with a Message carrying the risk preview.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Annotated, Any

from agentic_core.domain.identifiers import new_id
from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from gxp_agent_runtime import __version__
from gxp_agent_runtime.api.routes import Deps
from gxp_agent_runtime.application.commands import RequestView, SubmitAction
from gxp_agent_runtime.domain.errors import (
    DependencyError,
    ForbiddenError,
    GxpError,
    NotFoundError,
)
from gxp_agent_runtime.domain.models import SourceRecord
from gxp_agent_runtime.runtime.container import Container
from gxp_agent_runtime.security.agents import AgentPrincipal

router = APIRouter()

PROTOCOL_VERSION = "0.3.0"

TASK_STATES = {
    "pending_approval": "input-required",
    "executing": "working",
    "completed": "completed",
    "failed": "failed",
    "rejected": "rejected",
    "denied": "rejected",
    "expired": "canceled",
}

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
TASK_NOT_FOUND = -32001
FORBIDDEN = -32003
UNAVAILABLE = -32000


class JsonRpcRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    jsonrpc: str = Field(pattern=r"^2\.0$")
    id: str | int | None = None
    method: str = Field(min_length=1, max_length=64)
    params: dict[str, Any] = Field(default_factory=dict)


class ActionMessage(BaseModel):
    """The data part of an A2A message addressed to this runtime."""

    model_config = ConfigDict(extra="forbid")

    skill: str = Field(default="execute", pattern=r"^(execute|assess)$")
    action_id: str
    version: str | None = None
    inputs: dict[str, Any]
    justification: str
    context: dict[str, str] = Field(default_factory=dict)
    source_records: list[SourceRecord] = Field(default_factory=list)
    performed_at: datetime


def agent_card(public_base: str) -> dict[str, Any]:
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "name": "GxP Agent Runtime",
        "description": (
            "Executes agent actions against validated GxP systems through registered, "
            "versioned action definitions with GAMP 5 risk classification, 21 CFR Part 11 "
            "electronic signatures and ALCOA+ execution records."
        ),
        "url": f"{public_base}/a2a",
        "preferredTransport": "JSONRPC",
        "version": __version__,
        "documentationUrl": "https://github.com/kogunlowo123/gxp-agent-runtime",
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
            "stateTransitionHistory": False,
        },
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": [
            {
                "id": "execute-gxp-action",
                "name": "Execute GxP action",
                "description": (
                    "Request a validated action. Low-risk actions run at once; others wait for "
                    "electronic signatures and are reported as input-required."
                ),
                "tags": ["gxp", "part-11", "validated-systems"],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "assess-gxp-action",
                "name": "Assess GxP action risk",
                "description": "GAMP 5 risk class and priority, ALCOA+ checks and policy outcome.",
                "tags": ["gxp", "gamp5", "risk"],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "get-gxp-task",
                "name": "Get action status",
                "description": "Poll an action request (tasks/get) for approval and execution.",
                "tags": ["gxp"],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            },
        ],
        "securitySchemes": {
            "agentCredential": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
                "description": "Agent credential issued by agent-identity-fabric",
            }
        },
        "security": [{"agentCredential": []}],
    }


@router.get("/.well-known/agent-card.json", tags=["a2a"])
async def card(c: Deps) -> dict[str, Any]:
    return agent_card(c.settings.public_base)


def _error(rpc_id: str | int | None, code: int, message: str) -> JSONResponse:
    return JSONResponse(
        {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}
    )


def _result(rpc_id: str | int | None, result: dict[str, Any]) -> JSONResponse:
    return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "result": result})


def task_of(view: RequestView, context_id: str) -> dict[str, Any]:
    state = TASK_STATES[view.status]
    text = view.status_reason or f"request {view.status}"
    return {
        "kind": "task",
        "id": view.request_id,
        "contextId": context_id,
        "status": {
            "state": state,
            "timestamp": datetime.now(UTC).isoformat(),
            "message": {
                "kind": "message",
                "role": "agent",
                "messageId": new_id(),
                "parts": [{"kind": "text", "text": text}],
            },
        },
        "artifacts": [
            {
                "artifactId": f"request-{view.request_id}",
                "name": "gxp-action-request",
                "parts": [{"kind": "data", "data": view.model_dump(mode="json")}],
            }
        ],
    }


def _action_message(params: dict[str, Any]) -> tuple[ActionMessage, str]:
    message = params.get("message")
    if not isinstance(message, dict):
        raise ValueError("params.message is required")
    parts = message.get("parts")
    if not isinstance(parts, list):
        raise ValueError("message.parts must be a list")
    data = next(
        (p.get("data") for p in parts if isinstance(p, dict) and p.get("kind") == "data"), None
    )
    if not isinstance(data, dict):
        raise ValueError("message needs a data part describing the action")
    context_id = message.get("contextId")
    return ActionMessage.model_validate(data), (
        context_id if isinstance(context_id, str) and context_id else new_id()
    )


class RpcError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


Handler = Callable[[Container, AgentPrincipal, dict[str, Any]], Awaitable[dict[str, Any]]]


async def message_send(
    c: Container, principal: AgentPrincipal, params: dict[str, Any]
) -> dict[str, Any]:
    try:
        action, context_id = _action_message(params)
        command = SubmitAction(
            action_id=action.action_id,
            version=action.version,
            inputs=action.inputs,
            justification=action.justification,
            context=action.context,
            source_records=tuple(action.source_records),
            performed_at=action.performed_at,
        )
    except (ValueError, ValidationError) as exc:
        raise RpcError(INVALID_PARAMS, f"invalid params: {exc}"[:500]) from exc
    if action.skill == "assess":
        preview = await c.runtime.preview(principal, command)
        return {
            "kind": "message",
            "role": "agent",
            "messageId": new_id(),
            "contextId": context_id,
            "parts": [{"kind": "data", "data": preview.model_dump(mode="json")}],
        }
    view = await c.runtime.submit(principal, command)
    await c.runtime.record_event(
        principal.agent_id,
        "a2a.message",
        f"request:{view.request_id}",
        view.status,
        {"context_id": context_id},
    )
    return task_of(view, context_id)


async def tasks_get(
    c: Container, principal: AgentPrincipal, params: dict[str, Any]
) -> dict[str, Any]:
    task_id = params.get("id")
    if not isinstance(task_id, str):
        raise RpcError(INVALID_PARAMS, "params.id is required")
    await c.runtime.authorize_read(principal)
    try:
        view = await c.runtime.agent_request(principal, task_id)
    except NotFoundError as exc:
        raise RpcError(TASK_NOT_FOUND, exc.message) from exc
    return task_of(view, task_id)


METHODS: dict[str, Handler] = {"message/send": message_send, "tasks/get": tasks_get}


def _rpc_code(exc: GxpError) -> int:
    if isinstance(exc, ForbiddenError):
        return FORBIDDEN
    if isinstance(exc, DependencyError):
        return UNAVAILABLE
    return INVALID_PARAMS


@router.post("/a2a", tags=["a2a"])
async def jsonrpc(
    request: Request, c: Deps, authorization: Annotated[str | None, Header()] = None
) -> JSONResponse:
    principal = await c.runtime.agents.authenticate(authorization)
    try:
        body = await request.json()
    except ValueError:
        return _error(None, PARSE_ERROR, "parse error")
    try:
        rpc = JsonRpcRequest.model_validate(body)
    except ValidationError:
        rpc_id = body.get("id") if isinstance(body, dict) else None
        return _error(
            rpc_id if isinstance(rpc_id, str | int) else None, INVALID_REQUEST, "invalid request"
        )
    handler = METHODS.get(rpc.method)
    if handler is None:
        return _error(rpc.id, METHOD_NOT_FOUND, f"method {rpc.method} not found")
    c.metrics.channel_calls.labels("a2a", rpc.method).inc()
    try:
        return _result(rpc.id, await handler(c, principal, rpc.params))
    except RpcError as exc:
        return _error(rpc.id, exc.code, exc.message)
    except GxpError as exc:
        return _error(rpc.id, _rpc_code(exc), f"{exc.code}: {exc.message}")
