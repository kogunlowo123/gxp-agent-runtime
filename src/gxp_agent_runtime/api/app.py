"""FastAPI application factory: REST API, MCP (streamable HTTP) and A2A."""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from contextlib import asynccontextmanager

from agentic_core.observability import bind_correlation_id, get_logger
from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from gxp_agent_runtime import __version__
from gxp_agent_runtime.api.a2a import router as a2a_router
from gxp_agent_runtime.api.mcp_server import build_mcp
from gxp_agent_runtime.api.routes import router
from gxp_agent_runtime.domain.errors import GxpError
from gxp_agent_runtime.runtime.container import Container

ContainerFactory = Callable[[], Awaitable[Container]]

log = get_logger("gxp_agent_runtime.api")


async def expire_pending_forever(
    container: Container,
    interval_s: float,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> None:
    """Expire requests whose approval window elapsed; refresh the overdue-review gauge."""
    while True:
        try:
            await container.runtime.expire_pending()
            await container.runtime.list_systems()
        except Exception:
            log.exception("expiry_sweep_failed")
        await sleep(interval_s)


def create_app(
    factory: ContainerFactory,
    *,
    mcp_allowed_hosts: Sequence[str] = (),
    sweep_interval_s: float = 60.0,
) -> FastAPI:
    holder: dict[str, Container] = {}

    def current() -> Container:
        return holder["container"]

    mcp, mcp_app = build_mcp(current, allowed_hosts=mcp_allowed_hosts)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        container = await factory()
        holder["container"] = container
        app.state.container = container
        sweeper = asyncio.create_task(expire_pending_forever(container, sweep_interval_s))
        log.info("startup", version=__version__, chain=container.chain_id)
        try:
            async with mcp.session_manager.run():
                yield
        finally:
            sweeper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await sweeper
            await container.aclose()

    app = FastAPI(
        title="GxP Agent Runtime",
        version=__version__,
        description=(
            "Executes AI agent actions against validated systems through registered, versioned "
            "action definitions: GAMP 5 risk classification, 21 CFR Part 11 electronic "
            "signatures, ALCOA+ data integrity checks and signed execution records."
        ),
        lifespan=lifespan,
    )
    app.include_router(router)
    app.include_router(a2a_router)
    app.mount("/mcp", mcp_app)

    @app.middleware("http")
    async def correlation_and_metrics(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        incoming = request.headers.get("x-correlation-id")
        cid = incoming if incoming and len(incoming) <= 64 and incoming.isprintable() else None
        started = time.perf_counter()
        with bind_correlation_id(cid) as bound:
            response = await call_next(request)
        response.headers["X-Correlation-ID"] = bound
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        route = request.scope.get("route")
        path = getattr(route, "path", None) or (
            "/mcp" if request.url.path.startswith("/mcp") else "unmatched"
        )
        container: Container | None = getattr(request.app.state, "container", None)
        if container is not None:
            container.metrics.requests.labels(
                request.method, path, str(response.status_code)
            ).observe(time.perf_counter() - started)
        return response

    @app.exception_handler(GxpError)
    async def gxp_error(_: Request, exc: GxpError) -> JSONResponse:
        headers = {"WWW-Authenticate": "Bearer"} if exc.status == 401 else None
        return JSONResponse(
            status_code=exc.status,
            content={"error": exc.code, "error_description": exc.message},
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": "invalid_request",
                "error_description": "request failed validation",
                "details": [
                    {"loc": [str(p) for p in e.get("loc", ())], "msg": str(e.get("msg", ""))}
                    for e in exc.errors()
                ],
            },
        )

    return app
