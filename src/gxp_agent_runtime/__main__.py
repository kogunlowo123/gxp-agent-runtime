"""Process entry point: ``python -m gxp_agent_runtime``."""

from __future__ import annotations

import os

import uvicorn
from agentic_core.observability import configure_logging, configure_telemetry
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

from gxp_agent_runtime import __version__
from gxp_agent_runtime.api.app import create_app
from gxp_agent_runtime.config import Settings
from gxp_agent_runtime.runtime.container import build_container


def main() -> None:
    settings = Settings()  # populated from GXP_* environment variables
    configure_logging(
        service="gxp-agent-runtime", environment=settings.environment, level=settings.log_level
    )
    exporter = None
    if settings.otlp_endpoint:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (  # noqa: PLC0415
            OTLPSpanExporter,
        )

        exporter = OTLPSpanExporter(endpoint=settings.otlp_endpoint)
    configure_telemetry(
        service_name="gxp-agent-runtime",
        service_version=__version__,
        environment=settings.environment,
        span_exporter=exporter,
    )
    app = create_app(
        lambda: build_container(settings),
        mcp_allowed_hosts=settings.mcp_hosts,
        sweep_interval_s=settings.expiry_sweep_seconds,
    )
    FastAPIInstrumentor.instrument_app(app, excluded_urls="healthz,readyz,metrics")
    uvicorn.run(
        app,
        host=os.environ.get("GXP_HOST", "127.0.0.1"),
        port=int(os.environ.get("GXP_PORT", "8080")),
        proxy_headers=True,
        forwarded_allow_ips=os.environ.get("GXP_FORWARDED_ALLOW_IPS", "127.0.0.1"),
        log_config=None,
        access_log=False,
    )


if __name__ == "__main__":
    main()
