"""Persistence and the full approval flow against a real PostgreSQL (CI service container).

Runs when GXP_TEST_DATABASE_URL points at PostgreSQL, e.g.
postgresql+asyncpg://gxp:ci-only@localhost:5432/gxp
"""

from __future__ import annotations

import os

import pytest

from gxp_agent_runtime.application.runtime import GxpRuntime
from gxp_agent_runtime.domain.errors import ConflictError
from gxp_agent_runtime.domain.models import RecordType, SignatureMeaning
from gxp_agent_runtime.infrastructure.database import SqlRequestRepository
from gxp_agent_runtime.runtime.container import Container
from tests.conftest import APPROVER, QA, FakeClock, FakeIdp, agent_principal, sign, submission

URL = os.environ.get("GXP_TEST_DATABASE_URL", "")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.urs("URS-009", "URS-016", "URS-017"),
    pytest.mark.skipif(not URL.startswith("postgresql"), reason="PostgreSQL not configured"),
]


async def test_approval_flow_and_cas_on_postgres(
    provisioned: GxpRuntime, container: Container, idp: FakeIdp, clock: FakeClock
) -> None:
    view = await provisioned.submit(agent_principal(), submission(clock, "lims.result.release"))
    requests = SqlRequestRepository(container.engine)
    stored = await requests.get(view.request_id)
    assert stored is not None
    await requests.replace(stored.model_copy(update={"revision": 1}), expected_revision=0)
    with pytest.raises(ConflictError):
        await requests.replace(stored.model_copy(update={"revision": 1}), expected_revision=0)
    await sign(
        provisioned,
        idp,
        APPROVER,
        RecordType.ACTION_REQUEST,
        view.request_id,
        SignatureMeaning.APPROVAL,
    )
    done = await sign(
        provisioned,
        idp,
        QA,
        RecordType.ACTION_REQUEST,
        view.request_id,
        SignatureMeaning.QUALITY_APPROVAL,
    )
    assert done.record_status == "completed"
    assert (await provisioned.verify_record(view.request_id)).verified
    assert (await provisioned.verify_audit()).intact
