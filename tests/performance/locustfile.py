"""Load profile for a deployed runtime.

Run against a staging deployment whose validated-system bindings point at
test instances, never production:

    GXP_LOAD_AGENT_TOKEN=<agent credential> \
    locust -f tests/performance/locustfile.py --host https://<staging runtime> \
           --users 100 --spawn-rate 10 --run-time 10m --headless

Agents read the catalog and assess far more often than they submit, and
submissions are dominated by low-risk read actions.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

from locust import HttpUser, between, task

TOKEN = os.environ.get("GXP_LOAD_AGENT_TOKEN", "")
ACTION = os.environ.get("GXP_LOAD_ACTION_ID", "lims.sample.read-status")
SAMPLE = os.environ.get("GXP_LOAD_SAMPLE_ID", "S-1001")


def body() -> dict[str, object]:
    return {
        "action_id": ACTION,
        "inputs": {"sample_id": SAMPLE},
        "justification": "Load test of the read-only status action.",
        "performed_at": datetime.now(UTC).isoformat(),
    }


class AgentTraffic(HttpUser):
    wait_time = between(0.1, 0.5)

    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {TOKEN}"}

    @task(5)
    def catalog(self) -> None:
        self.client.get("/v1/actions", headers=self.headers(), name="/v1/actions")

    @task(5)
    def assess(self) -> None:
        self.client.post(
            "/v1/actions/assess", json=body(), headers=self.headers(), name="/v1/actions/assess"
        )

    @task(2)
    def submit(self) -> None:
        self.client.post(
            "/v1/action-requests", json=body(), headers=self.headers(), name="/v1/action-requests"
        )
