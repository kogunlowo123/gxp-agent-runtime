"""MCP tools (official ``mcp`` SDK, streamable HTTP) for agents.

Each tool authenticates the caller's bearer credential, applies the same
authorization as the REST API, writes an audit event for the call, and
returns a typed result whose JSON Schema is advertised in ``tools/list``.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from datetime import datetime
from typing import Any

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import BaseModel, ValidationError
from starlette.applications import Starlette

from gxp_agent_runtime import __version__
from gxp_agent_runtime.application.commands import (
    ActionCatalogEntry,
    ActionPreview,
    RequestView,
    SubmitAction,
)
from gxp_agent_runtime.domain.errors import GxpError
from gxp_agent_runtime.domain.models import ExecutionRecord, SourceRecord
from gxp_agent_runtime.runtime.container import Container
from gxp_agent_runtime.security.agents import AgentPrincipal

ContainerGetter = Callable[[], Container]


class CatalogResult(BaseModel):
    actions: list[ActionCatalogEntry]


def _submission(
    *,
    action_id: str,
    inputs: dict[str, Any],
    justification: str,
    performed_at: datetime,
    version: str | None,
    context: dict[str, str] | None,
    source_records: list[SourceRecord] | None,
) -> SubmitAction:
    try:
        return SubmitAction(
            action_id=action_id,
            version=version,
            inputs=inputs,
            justification=justification,
            context=context or {},
            source_records=tuple(source_records or ()),
            performed_at=performed_at,
        )
    except ValidationError as exc:
        raise ToolError(f"invalid_request: {exc.error_count()} validation error(s)") from exc


def build_mcp(
    get_container: ContainerGetter, *, allowed_hosts: Sequence[str]
) -> tuple[MCPServer[Any], Starlette]:
    server: MCPServer[Any] = MCPServer(
        name="gxp-agent-runtime",
        title="GxP Agent Runtime",
        description="Execute agent actions against validated GxP systems under Part 11 controls",
        version=__version__,
        log_level="WARNING",
    )

    async def guarded[T](
        ctx: Context, tool: str, resource: str, call: Callable[[AgentPrincipal], Awaitable[T]]
    ) -> T:
        c = get_container()
        c.metrics.channel_calls.labels("mcp", tool).inc()
        headers = ctx.headers or {}
        try:
            principal = await c.runtime.agents.authenticate(headers.get("authorization"))
        except GxpError as exc:
            await c.runtime.record_event(
                "anonymous", f"mcp.{tool}", resource, "unauthenticated", {"error": exc.code}
            )
            raise ToolError(f"{exc.code}: {exc.message}") from exc
        try:
            result = await call(principal)
        except GxpError as exc:
            await c.runtime.record_event(
                principal.agent_id, f"mcp.{tool}", resource, "error", {"error": exc.code}
            )
            raise ToolError(f"{exc.code}: {exc.message}") from exc
        await c.runtime.record_event(principal.agent_id, f"mcp.{tool}", resource, "success", {})
        return result

    @server.tool(
        name="list_gxp_actions",
        description="List validated action definitions this agent may request.",
    )
    async def list_gxp_actions(ctx: Context) -> CatalogResult:
        async def call(principal: AgentPrincipal) -> CatalogResult:
            return CatalogResult(actions=await get_container().runtime.catalog(principal))

        return await guarded(ctx, "list_gxp_actions", "catalog", call)

    @server.tool(
        name="assess_gxp_action",
        description=(
            "Classify a prospective action (GAMP 5 risk, ALCOA+ checks, policy) without "
            "submitting it. Returns the signatures that would be required."
        ),
    )
    async def assess_gxp_action(
        *,
        action_id: str,
        inputs: dict[str, Any],
        justification: str,
        performed_at: datetime,
        ctx: Context,
        version: str | None = None,
        context: dict[str, str] | None = None,
        source_records: list[SourceRecord] | None = None,
    ) -> ActionPreview:
        command = _submission(
            action_id=action_id,
            inputs=inputs,
            justification=justification,
            performed_at=performed_at,
            version=version,
            context=context,
            source_records=source_records,
        )

        async def call(principal: AgentPrincipal) -> ActionPreview:
            return await get_container().runtime.preview(principal, command)

        return await guarded(ctx, "assess_gxp_action", f"action:{action_id}", call)

    @server.tool(
        name="request_gxp_action",
        description=(
            "Submit an action against a validated system. Low-risk actions execute at once; "
            "others wait for 21 CFR Part 11 electronic signatures (status pending_approval)."
        ),
    )
    async def request_gxp_action(
        *,
        action_id: str,
        inputs: dict[str, Any],
        justification: str,
        performed_at: datetime,
        ctx: Context,
        version: str | None = None,
        context: dict[str, str] | None = None,
        source_records: list[SourceRecord] | None = None,
    ) -> RequestView:
        command = _submission(
            action_id=action_id,
            inputs=inputs,
            justification=justification,
            performed_at=performed_at,
            version=version,
            context=context,
            source_records=source_records,
        )

        async def call(principal: AgentPrincipal) -> RequestView:
            return await get_container().runtime.submit(principal, command)

        return await guarded(ctx, "request_gxp_action", f"action:{action_id}", call)

    @server.tool(
        name="get_gxp_request",
        description="Status, risk assessment and outstanding signatures of one of your requests.",
    )
    async def get_gxp_request(request_id: str, ctx: Context) -> RequestView:
        async def call(principal: AgentPrincipal) -> RequestView:
            runtime = get_container().runtime
            await runtime.authorize_read(principal)
            return await runtime.agent_request(principal, request_id)

        return await guarded(ctx, "get_gxp_request", f"request:{request_id}", call)

    @server.tool(
        name="get_execution_record",
        description="The signed execution record (inputs/outputs digests, signatures, ALCOA+).",
    )
    async def get_execution_record(record_id: str, ctx: Context) -> ExecutionRecord:
        async def call(principal: AgentPrincipal) -> ExecutionRecord:
            runtime = get_container().runtime
            await runtime.authorize_read(principal)
            return await runtime.agent_record(principal, record_id)

        return await guarded(ctx, "get_execution_record", f"execution-record:{record_id}", call)

    app = server.streamable_http_app(
        streamable_http_path="/",
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(allowed_hosts),
            allowed_origins=[],
        ),
    )
    return server, app
