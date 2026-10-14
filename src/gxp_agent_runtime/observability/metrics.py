"""Service metrics exposed on /metrics in Prometheus text format."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram


class RuntimeMetrics:
    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()
        self.requests = Histogram(
            "gxp_http_request_duration_seconds",
            "HTTP request latency",
            ["method", "route", "status"],
            registry=self.registry,
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
        )
        self.action_requests = Counter(
            "gxp_action_requests_total",
            "Action requests by initial outcome",
            ["action", "outcome", "priority"],
            registry=self.registry,
        )
        self.executions = Counter(
            "gxp_executions_total",
            "Executions against validated systems",
            ["system", "status"],
            registry=self.registry,
        )
        self.execution_duration = Histogram(
            "gxp_execution_duration_seconds",
            "Validated-system call duration",
            ["system"],
            registry=self.registry,
            buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
        )
        self.signatures = Counter(
            "gxp_electronic_signatures_total",
            "Electronic signatures applied",
            ["meaning"],
            registry=self.registry,
        )
        self.signature_failures = Counter(
            "gxp_signature_failures_total",
            "Rejected signing attempts",
            ["reason"],
            registry=self.registry,
        )
        self.alcoa_failures = Counter(
            "gxp_alcoa_failures_total",
            "ALCOA+ principle failures",
            ["principle", "stage"],
            registry=self.registry,
        )
        self.pending_expired = Counter(
            "gxp_pending_requests_expired_total",
            "Requests that expired awaiting signatures",
            registry=self.registry,
        )
        self.channel_calls = Counter(
            "gxp_agent_channel_calls_total",
            "Agent calls by channel (rest, mcp, a2a)",
            ["channel", "operation"],
            registry=self.registry,
        )
        self.reviews_overdue = Gauge(
            "gxp_systems_review_overdue",
            "Validated systems whose periodic review is overdue",
            registry=self.registry,
        )
