"""Ports the application layer depends on. Adapters live in infrastructure."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Protocol

from agentic_core.audit import AuditEvent

from gxp_agent_runtime.domain.models import (
    ActionDefinition,
    ActionRequest,
    ElectronicSignature,
    ExecutionRecord,
    PeriodicReview,
    RecordType,
    RequestStatus,
    SigningChallenge,
    ValidatedSystem,
    ValidationStatus,
)


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemRepository(Protocol):
    async def add(self, system: ValidatedSystem) -> None: ...

    async def get(self, system_id: str) -> ValidatedSystem | None: ...

    async def update(self, system: ValidatedSystem) -> None: ...

    async def list(self) -> Sequence[ValidatedSystem]: ...


class DefinitionRepository(Protocol):
    async def add(self, definition: ActionDefinition) -> None: ...

    async def get(self, action_id: str, version: str) -> ActionDefinition | None: ...

    async def versions(self, action_id: str) -> Sequence[ActionDefinition]: ...

    async def update(self, definition: ActionDefinition) -> None: ...

    async def list(
        self, *, status: ValidationStatus | None = None
    ) -> Sequence[ActionDefinition]: ...


class RequestRepository(Protocol):
    async def add(self, request: ActionRequest) -> None: ...

    async def get(self, request_id: str) -> ActionRequest | None: ...

    async def replace(self, request: ActionRequest, *, expected_revision: int) -> None:
        """Compare-and-swap on ``revision``; raises ConflictError on a lost race."""
        ...

    async def list(
        self,
        *,
        status: RequestStatus | None = None,
        system_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[ActionRequest]: ...

    async def in_period(
        self, system_id: str, start: datetime, end: datetime
    ) -> Sequence[ActionRequest]: ...

    async def expired_pending(self, now: datetime) -> Sequence[ActionRequest]: ...


class SignatureRepository(Protocol):
    async def add(self, signature: ElectronicSignature) -> None: ...

    async def get(self, signature_id: str) -> ElectronicSignature | None: ...

    async def for_record(
        self, record_type: RecordType, record_id: str
    ) -> Sequence[ElectronicSignature]: ...


class ChallengeRepository(Protocol):
    async def add(self, challenge: SigningChallenge) -> None: ...

    async def get(self, challenge_id: str) -> SigningChallenge | None: ...

    async def consume(self, challenge_id: str, at: datetime) -> bool:
        """Mark used exactly once; False when already used."""
        ...


class RecordRepository(Protocol):
    async def add(self, record: ExecutionRecord) -> None: ...

    async def get(self, record_id: str) -> ExecutionRecord | None: ...

    async def recent_outcomes(self, action_id: str, limit: int) -> Sequence[str]: ...

    async def in_period(
        self, system_id: str, start: datetime, end: datetime
    ) -> Sequence[ExecutionRecord]: ...


class ReviewRepository(Protocol):
    async def add(self, review: PeriodicReview) -> None: ...

    async def get(self, review_id: str) -> PeriodicReview | None: ...

    async def update(self, review: PeriodicReview) -> None: ...


class AuditReader(Protocol):
    async def chains(self) -> Sequence[str]: ...

    async def events(self, chain_id: str) -> Sequence[AuditEvent]: ...

    async def count_resource(self, resource: str) -> int: ...
