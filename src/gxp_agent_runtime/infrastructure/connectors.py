"""Executes action bindings against validated systems over HTTPS.

Every call carries ``Idempotency-Key: <request id>`` so a retry after a
timeout cannot execute the same GxP action twice. Transport failures and
502/503/504 are retried with the same key; any other non-success status is
a failed execution that becomes part of the record.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

import httpx
from agentic_core.domain.provenance import content_digest
from agentic_core.observability import correlation_id

from gxp_agent_runtime.domain.models import ActionRequest, ActionSpec, ValidatedSystem
from gxp_agent_runtime.domain.ports import Clock

RETRYABLE_STATUSES = frozenset({502, 503, 504})


class BearerSource(Protocol):
    async def bearer(self) -> str: ...


@dataclass(frozen=True)
class ConnectorResult:
    succeeded: bool
    http_status: int | None
    outputs: dict[str, Any] | None
    response_digest: str | None
    error: str | None
    attempts: int
    started_at: datetime
    completed_at: datetime


class ActionConnector(Protocol):
    async def execute(
        self, system: ValidatedSystem, spec: ActionSpec, request: ActionRequest
    ) -> ConnectorResult: ...


class HttpActionConnector:
    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        clock: Clock,
        credentials: BearerSource | None = None,
        max_attempts: int = 3,
        backoff_s: float = 0.5,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._client = client
        self._clock = clock
        self._credentials = credentials
        self._max_attempts = max_attempts
        self._backoff = backoff_s
        self._sleep = sleep

    async def execute(
        self, system: ValidatedSystem, spec: ActionSpec, request: ActionRequest
    ) -> ConnectorResult:
        started = self._clock.now()
        url = system.base_url + spec.binding.render_path(request.inputs)
        headers = {
            "Idempotency-Key": request.request_id,
            "X-GxP-Action": spec.key,
            "X-GxP-Agent": request.agent_id,
            "Accept": "application/json",
        }
        cid = correlation_id()
        if cid:
            headers["X-Correlation-ID"] = cid
        if self._credentials is not None:
            headers["Authorization"] = f"Bearer {await self._credentials.bearer()}"
        body = spec.binding.body(request.inputs)

        error = "no attempt made"
        for attempt in range(1, self._max_attempts + 1):
            try:
                response = await self._client.request(
                    spec.binding.method, url, json=body, headers=headers
                )
            except httpx.TransportError as exc:
                error = f"transport error: {type(exc).__name__}"
            else:
                if response.status_code in RETRYABLE_STATUSES:
                    error = f"system returned {response.status_code}"
                else:
                    return self._result(spec, response, attempt, started)
            if attempt < self._max_attempts:
                await self._sleep(self._backoff * 2 ** (attempt - 1))
        return ConnectorResult(
            succeeded=False,
            http_status=None,
            outputs=None,
            response_digest=None,
            error=f"{error} after {self._max_attempts} attempts",
            attempts=self._max_attempts,
            started_at=started,
            completed_at=self._clock.now(),
        )

    def _result(
        self, spec: ActionSpec, response: httpx.Response, attempt: int, started: datetime
    ) -> ConnectorResult:
        raw = response.content
        digest = content_digest(raw)
        completed = self._clock.now()
        if response.status_code not in spec.binding.success_statuses:
            return ConnectorResult(
                succeeded=False,
                http_status=response.status_code,
                outputs=None,
                response_digest=digest,
                error=f"system rejected the action with HTTP {response.status_code}",
                attempts=attempt,
                started_at=started,
                completed_at=completed,
            )
        try:
            payload = response.json() if raw else {}
        except ValueError:
            payload = None
        if not isinstance(payload, dict):
            return ConnectorResult(
                succeeded=False,
                http_status=response.status_code,
                outputs=None,
                response_digest=digest,
                error="system response is not a JSON object",
                attempts=attempt,
                started_at=started,
                completed_at=completed,
            )
        return ConnectorResult(
            succeeded=True,
            http_status=response.status_code,
            outputs=payload,
            response_digest=digest,
            error=None,
            attempts=attempt,
            started_at=started,
            completed_at=completed,
        )
