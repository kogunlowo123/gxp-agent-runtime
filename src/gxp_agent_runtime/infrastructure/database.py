"""SQLAlchemy Core persistence. PostgreSQL in production; SQLite in tests.

Aggregates are stored as JSON documents next to the columns used for
lookups. Action requests use a revision column for compare-and-swap so two
replicas can never both apply the final approval or both start execution.
Audit chains live in the same database, one chain per process instance.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from datetime import UTC, datetime

from agentic_core.audit import AuditEvent
from sqlalchemy import (
    Column,
    DateTime,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    and_,
    func,
    insert,
    select,
    update,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from gxp_agent_runtime.domain.errors import ConflictError, NotFoundError
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

metadata = MetaData()

systems = Table(
    "validated_systems",
    metadata,
    Column("system_id", String(64), primary_key=True),
    Column("document", Text, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)

definitions = Table(
    "action_definitions",
    metadata,
    Column("action_id", String(120), primary_key=True),
    Column("version", String(32), primary_key=True),
    Column("status", String(16), nullable=False),
    Column("document", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Index("ix_definitions_status", "status"),
)

requests = Table(
    "action_requests",
    metadata,
    Column("request_id", String(64), primary_key=True),
    Column("status", String(24), nullable=False),
    Column("action_id", String(120), nullable=False),
    Column("system_id", String(64), nullable=False),
    Column("agent_id", String(512), nullable=False),
    Column("revision", Integer, nullable=False),
    Column("document", Text, nullable=False),
    Column("received_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=True),
    Index("ix_requests_status", "status"),
    Index("ix_requests_system_received", "system_id", "received_at"),
)

signatures = Table(
    "electronic_signatures",
    metadata,
    Column("signature_id", String(64), primary_key=True),
    Column("record_type", String(32), nullable=False),
    Column("record_id", String(160), nullable=False),
    Column("document", Text, nullable=False),
    Column("signed_at", DateTime(timezone=True), nullable=False),
    Index("ix_signatures_record", "record_type", "record_id"),
)

challenges = Table(
    "signing_challenges",
    metadata,
    Column("challenge_id", String(64), primary_key=True),
    Column("document", Text, nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("used_at", DateTime(timezone=True), nullable=True),
)

records = Table(
    "execution_records",
    metadata,
    Column("record_id", String(64), primary_key=True),
    Column("action_id", String(120), nullable=False),
    Column("system_id", String(64), nullable=False),
    Column("status", String(16), nullable=False),
    Column("document", Text, nullable=False),
    Column("completed_at", DateTime(timezone=True), nullable=False),
    Index("ix_records_action_completed", "action_id", "completed_at"),
    Index("ix_records_system_completed", "system_id", "completed_at"),
)

reviews = Table(
    "periodic_reviews",
    metadata,
    Column("review_id", String(64), primary_key=True),
    Column("system_id", String(64), nullable=False),
    Column("status", String(16), nullable=False),
    Column("document", Text, nullable=False),
    Column("generated_at", DateTime(timezone=True), nullable=False),
)

audit_events = Table(
    "audit_events",
    metadata,
    Column("chain_id", String(128), primary_key=True),
    Column("sequence", Integer, primary_key=True),
    Column("resource", String(256), nullable=False),
    Column("action", String(128), nullable=False),
    Column("document", Text, nullable=False),
    Column("timestamp", DateTime(timezone=True), nullable=False),
    Index("ix_audit_resource", "resource"),
)

schema_version = Table(
    "schema_version",
    metadata,
    Column("version", Integer, primary_key=True),
)

SCHEMA_VERSION = 1


def make_engine(url: str) -> AsyncEngine:
    return create_async_engine(url, pool_pre_ping=True)


async def create_schema(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
        current = (await conn.execute(select(schema_version.c.version))).scalar()
        if current is None:
            await conn.execute(insert(schema_version).values(version=SCHEMA_VERSION))


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class SqlSystemRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def add(self, system: ValidatedSystem) -> None:
        try:
            async with self._engine.begin() as conn:
                await conn.execute(
                    insert(systems).values(
                        system_id=system.system_id,
                        document=system.model_dump_json(),
                        updated_at=system.updated_at,
                    )
                )
        except IntegrityError as exc:
            raise ConflictError(f"system {system.system_id} already registered") from exc

    async def get(self, system_id: str) -> ValidatedSystem | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(systems.c.document).where(systems.c.system_id == system_id)
                )
            ).first()
        return ValidatedSystem.model_validate_json(row[0]) if row else None

    async def update(self, system: ValidatedSystem) -> None:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                update(systems)
                .where(systems.c.system_id == system.system_id)
                .values(document=system.model_dump_json(), updated_at=system.updated_at)
            )
            if result.rowcount == 0:
                raise NotFoundError(f"system {system.system_id} not found")

    async def list(self) -> Sequence[ValidatedSystem]:
        async with self._engine.connect() as conn:
            rows = (
                await conn.execute(select(systems.c.document).order_by(systems.c.system_id))
            ).all()
        return [ValidatedSystem.model_validate_json(r[0]) for r in rows]


class SqlDefinitionRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def add(self, definition: ActionDefinition) -> None:
        try:
            async with self._engine.begin() as conn:
                await conn.execute(
                    insert(definitions).values(
                        action_id=definition.spec.action_id,
                        version=definition.spec.version,
                        status=definition.status.value,
                        document=definition.model_dump_json(),
                        created_at=definition.created_at,
                    )
                )
        except IntegrityError as exc:
            raise ConflictError(f"{definition.key} already registered") from exc

    async def get(self, action_id: str, version: str) -> ActionDefinition | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(definitions.c.document).where(
                        and_(definitions.c.action_id == action_id, definitions.c.version == version)
                    )
                )
            ).first()
        return ActionDefinition.model_validate_json(row[0]) if row else None

    async def versions(self, action_id: str) -> Sequence[ActionDefinition]:
        async with self._engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(definitions.c.document).where(definitions.c.action_id == action_id)
                )
            ).all()
        found = [ActionDefinition.model_validate_json(r[0]) for r in rows]
        return sorted(found, key=lambda d: d.spec.version_tuple)

    async def update(self, definition: ActionDefinition) -> None:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                update(definitions)
                .where(
                    and_(
                        definitions.c.action_id == definition.spec.action_id,
                        definitions.c.version == definition.spec.version,
                    )
                )
                .values(status=definition.status.value, document=definition.model_dump_json())
            )
            if result.rowcount == 0:
                raise NotFoundError(f"{definition.key} not found")

    async def list(self, *, status: ValidationStatus | None = None) -> Sequence[ActionDefinition]:
        query = select(definitions.c.document).order_by(
            definitions.c.action_id, definitions.c.created_at
        )
        if status is not None:
            query = query.where(definitions.c.status == status.value)
        async with self._engine.connect() as conn:
            rows = (await conn.execute(query)).all()
        return [ActionDefinition.model_validate_json(r[0]) for r in rows]


class SqlRequestRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def add(self, request: ActionRequest) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                insert(requests).values(
                    request_id=request.request_id,
                    status=request.status.value,
                    action_id=request.action_id,
                    system_id=request.system_id,
                    agent_id=request.agent_id,
                    revision=request.revision,
                    document=request.model_dump_json(),
                    received_at=request.received_at,
                    expires_at=request.expires_at,
                )
            )

    async def get(self, request_id: str) -> ActionRequest | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(requests.c.document).where(requests.c.request_id == request_id)
                )
            ).first()
        return ActionRequest.model_validate_json(row[0]) if row else None

    async def replace(self, request: ActionRequest, *, expected_revision: int) -> None:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                update(requests)
                .where(
                    and_(
                        requests.c.request_id == request.request_id,
                        requests.c.revision == expected_revision,
                    )
                )
                .values(
                    status=request.status.value,
                    revision=request.revision,
                    document=request.model_dump_json(),
                    expires_at=request.expires_at,
                )
            )
            if result.rowcount == 0:
                raise ConflictError(
                    f"request {request.request_id} was modified concurrently; retry"
                )

    async def list(
        self,
        *,
        status: RequestStatus | None = None,
        system_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[ActionRequest]:
        query = (
            select(requests.c.document)
            .order_by(requests.c.received_at.desc(), requests.c.request_id)
            .limit(limit)
            .offset(offset)
        )
        if status is not None:
            query = query.where(requests.c.status == status.value)
        if system_id is not None:
            query = query.where(requests.c.system_id == system_id)
        async with self._engine.connect() as conn:
            rows = (await conn.execute(query)).all()
        return [ActionRequest.model_validate_json(r[0]) for r in rows]

    async def in_period(
        self, system_id: str, start: datetime, end: datetime
    ) -> Sequence[ActionRequest]:
        query = select(requests.c.document).where(
            and_(
                requests.c.system_id == system_id,
                requests.c.received_at >= _aware(start),
                requests.c.received_at < _aware(end),
            )
        )
        async with self._engine.connect() as conn:
            rows = (await conn.execute(query)).all()
        return [ActionRequest.model_validate_json(r[0]) for r in rows]

    async def expired_pending(self, now: datetime) -> Sequence[ActionRequest]:
        query = select(requests.c.document).where(
            and_(
                requests.c.status == RequestStatus.PENDING_APPROVAL.value,
                requests.c.expires_at < _aware(now),
            )
        )
        async with self._engine.connect() as conn:
            rows = (await conn.execute(query)).all()
        return [ActionRequest.model_validate_json(r[0]) for r in rows]


class SqlSignatureRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def add(self, signature: ElectronicSignature) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                insert(signatures).values(
                    signature_id=signature.signature_id,
                    record_type=signature.record_type.value,
                    record_id=signature.record_id,
                    document=signature.model_dump_json(),
                    signed_at=signature.signed_at,
                )
            )

    async def get(self, signature_id: str) -> ElectronicSignature | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(signatures.c.document).where(signatures.c.signature_id == signature_id)
                )
            ).first()
        return ElectronicSignature.model_validate_json(row[0]) if row else None

    async def for_record(
        self, record_type: RecordType, record_id: str
    ) -> Sequence[ElectronicSignature]:
        query = (
            select(signatures.c.document)
            .where(
                and_(
                    signatures.c.record_type == record_type.value,
                    signatures.c.record_id == record_id,
                )
            )
            .order_by(signatures.c.signed_at, signatures.c.signature_id)
        )
        async with self._engine.connect() as conn:
            rows = (await conn.execute(query)).all()
        return [ElectronicSignature.model_validate_json(r[0]) for r in rows]


class SqlChallengeRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def add(self, challenge: SigningChallenge) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                insert(challenges).values(
                    challenge_id=challenge.challenge_id,
                    document=challenge.model_dump_json(),
                    expires_at=challenge.expires_at,
                    used_at=None,
                )
            )

    async def get(self, challenge_id: str) -> SigningChallenge | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(challenges.c.document, challenges.c.used_at).where(
                        challenges.c.challenge_id == challenge_id
                    )
                )
            ).first()
        if row is None:
            return None
        challenge = SigningChallenge.model_validate_json(row[0])
        used = row[1]
        return challenge.model_copy(update={"used_at": _aware(used) if used else None})

    async def consume(self, challenge_id: str, at: datetime) -> bool:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                update(challenges)
                .where(
                    and_(challenges.c.challenge_id == challenge_id, challenges.c.used_at.is_(None))
                )
                .values(used_at=at)
            )
        return bool(result.rowcount == 1)


class SqlRecordRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def add(self, record: ExecutionRecord) -> None:
        try:
            async with self._engine.begin() as conn:
                await conn.execute(
                    insert(records).values(
                        record_id=record.record_id,
                        action_id=record.action_key.split("@", 1)[0],
                        system_id=record.system_id,
                        status=record.status,
                        document=record.model_dump_json(),
                        completed_at=record.completed_at,
                    )
                )
        except IntegrityError as exc:
            raise ConflictError(f"execution record {record.record_id} already exists") from exc

    async def get(self, record_id: str) -> ExecutionRecord | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(records.c.document).where(records.c.record_id == record_id)
                )
            ).first()
        return ExecutionRecord.model_validate_json(row[0]) if row else None

    async def recent_outcomes(self, action_id: str, limit: int) -> Sequence[str]:
        query = (
            select(records.c.status)
            .where(records.c.action_id == action_id)
            .order_by(records.c.completed_at.desc())
            .limit(limit)
        )
        async with self._engine.connect() as conn:
            rows = (await conn.execute(query)).all()
        return [str(r[0]) for r in rows]

    async def in_period(
        self, system_id: str, start: datetime, end: datetime
    ) -> Sequence[ExecutionRecord]:
        query = select(records.c.document).where(
            and_(
                records.c.system_id == system_id,
                records.c.completed_at >= _aware(start),
                records.c.completed_at < _aware(end),
            )
        )
        async with self._engine.connect() as conn:
            rows = (await conn.execute(query)).all()
        return [ExecutionRecord.model_validate_json(r[0]) for r in rows]


class SqlReviewRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def add(self, review: PeriodicReview) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                insert(reviews).values(
                    review_id=review.review_id,
                    system_id=review.system_id,
                    status=review.status.value,
                    document=review.model_dump_json(),
                    generated_at=review.generated_at,
                )
            )

    async def get(self, review_id: str) -> PeriodicReview | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(reviews.c.document).where(reviews.c.review_id == review_id)
                )
            ).first()
        return PeriodicReview.model_validate_json(row[0]) if row else None

    async def update(self, review: PeriodicReview) -> None:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                update(reviews)
                .where(reviews.c.review_id == review.review_id)
                .values(status=review.status.value, document=review.model_dump_json())
            )
            if result.rowcount == 0:
                raise NotFoundError(f"periodic review {review.review_id} not found")


class SqlAuditSink:
    """agentic-core AuditSink storing one hash chain per process instance.

    The (chain_id, sequence) primary key makes a forked or replayed chain
    fail loudly instead of silently interleaving.
    """

    def __init__(self, engine: AsyncEngine, chain_id: str) -> None:
        self._engine = engine
        self.chain_id = chain_id

    async def append(self, event: AuditEvent) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                insert(audit_events).values(
                    chain_id=self.chain_id,
                    sequence=event.sequence,
                    resource=event.resource[:256],
                    action=event.action[:128],
                    document=event.model_dump_json(),
                    timestamp=event.timestamp,
                )
            )

    async def read(self) -> AsyncIterator[AuditEvent]:
        for event in await SqlAuditReader(self._engine).events(self.chain_id):
            yield event

    async def tail(self) -> AuditEvent | None:
        query = (
            select(audit_events.c.document)
            .where(audit_events.c.chain_id == self.chain_id)
            .order_by(audit_events.c.sequence.desc())
            .limit(1)
        )
        async with self._engine.connect() as conn:
            row = (await conn.execute(query)).first()
        return AuditEvent.model_validate_json(row[0]) if row else None


class SqlAuditReader:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def chains(self) -> Sequence[str]:
        async with self._engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(audit_events.c.chain_id).distinct().order_by(audit_events.c.chain_id)
                )
            ).all()
        return [str(r[0]) for r in rows]

    async def events(self, chain_id: str) -> Sequence[AuditEvent]:
        query = (
            select(audit_events.c.document)
            .where(audit_events.c.chain_id == chain_id)
            .order_by(audit_events.c.sequence)
        )
        async with self._engine.connect() as conn:
            rows = (await conn.execute(query)).all()
        return [AuditEvent.model_validate_json(r[0]) for r in rows]

    async def count_resource(self, resource: str) -> int:
        async with self._engine.connect() as conn:
            value = (
                await conn.execute(
                    select(func.count())
                    .select_from(audit_events)
                    .where(audit_events.c.resource == resource)
                )
            ).scalar()
        return int(value or 0)
