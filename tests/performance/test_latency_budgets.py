"""Latency budgets for hot paths. Loose enough for shared CI runners."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

import pytest

from gxp_agent_runtime.application.runtime import GxpRuntime
from gxp_agent_runtime.domain.alcoa import AlcoaChecker
from gxp_agent_runtime.domain.risk import RiskClassifier
from tests.conftest import AGENT, SOURCE, FakeClock, agent_principal, release_spec, submission

pytestmark = [pytest.mark.performance, pytest.mark.urs("URS-004", "URS-005")]


def test_classification_and_integrity_checks_budget() -> None:
    classifier, checker, spec = RiskClassifier(), AlcoaChecker(), release_spec()
    now = datetime.now(UTC)
    inputs = {"sample_id": "S-1001", "disposition": "conforming", "batch_id": "B-1"}
    started = time.perf_counter()
    for _ in range(500):
        classifier.assess(spec)
        checker.assess_request(
            spec=spec,
            agent_id=AGENT,
            inputs=inputs,
            justification="Results reviewed against specification.",
            context={"batch_id": "B-1"},
            source_records=(SOURCE,),
            performed_at=now - timedelta(seconds=5),
            received_at=now,
        )
    per_call_ms = (time.perf_counter() - started) * 1000 / 500
    assert per_call_ms < 5


async def test_autonomous_low_risk_round_trip_budget(
    provisioned: GxpRuntime, clock: FakeClock
) -> None:
    """Submit, classify, authorize, execute, sign and read back a record."""
    started = time.perf_counter()
    for _ in range(20):
        view = await provisioned.submit(agent_principal(), submission(clock))
        assert view.status == "completed"
    per_request_ms = (time.perf_counter() - started) * 1000 / 20
    assert per_request_ms < 500
