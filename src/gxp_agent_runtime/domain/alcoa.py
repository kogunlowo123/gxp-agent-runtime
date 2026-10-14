"""ALCOA+ data integrity checks (MHRA GXP Data Integrity Guidance, FDA 2018 guidance).

Requests are checked before any decision is taken; execution records are
checked after they are written and read back, so the "enduring" and
"available" principles are verified against storage rather than assumed.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta
from itertools import pairwise
from typing import Any

from jsonschema import Draft202012Validator

from gxp_agent_runtime.domain.models import (
    DIGEST,
    ActionSpec,
    AlcoaAssessment,
    AlcoaCheck,
    AlcoaPrinciple,
    ElectronicSignature,
    ExecutionRecord,
    SignatureRequirement,
    SourceRecord,
    digest_of,
)

P = AlcoaPrinciple
_ALLOWED_CONTROL = {"\n", "\t"}


def schema_errors(schema: dict[str, Any], instance: Any, *, limit: int = 10) -> list[str]:
    validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
    errors = sorted(validator.iter_errors(instance), key=lambda e: list(e.absolute_path))
    return [
        f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
        for e in errors[:limit]
    ]


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from _strings(v)
    elif isinstance(value, list | tuple):
        for item in value:
            yield from _strings(item)


def _illegible(value: Any) -> list[str]:
    bad: list[str] = []
    for text in _strings(value):
        if any((not ch.isprintable()) and ch not in _ALLOWED_CONTROL for ch in text):
            bad.append(text[:40].encode("unicode_escape").decode())
    return bad


def _nulls(value: Any, path: str = "") -> list[str]:
    found: list[str] = []
    if value is None:
        found.append(path or "<root>")
    elif isinstance(value, dict):
        for k, v in value.items():
            found.extend(_nulls(v, f"{path}/{k}" if path else str(k)))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            found.extend(_nulls(v, f"{path}/{i}"))
    return found


def check(principle: AlcoaPrinciple, failures: Sequence[str], ok: str) -> AlcoaCheck:
    return AlcoaCheck(
        principle=principle,
        passed=not failures,
        detail=ok if not failures else "; ".join(failures),
    )


class AlcoaChecker:
    def __init__(
        self,
        *,
        max_clock_skew: timedelta = timedelta(minutes=2),
        max_activity_age: timedelta = timedelta(minutes=15),
        max_recording_delay: timedelta = timedelta(seconds=30),
    ) -> None:
        self._skew = max_clock_skew
        self._max_age = max_activity_age
        self._recording_delay = max_recording_delay

    def assess_request(
        self,
        *,
        spec: ActionSpec,
        agent_id: str,
        inputs: dict[str, Any],
        justification: str,
        context: dict[str, str],
        source_records: Sequence[SourceRecord],
        performed_at: datetime,
        received_at: datetime,
    ) -> AlcoaAssessment:
        attributable = (
            [] if agent_id.startswith("spiffe://") else ["agent identity is not a SPIFFE ID"]
        )

        legible = [
            f"non-printable characters in {s!r}"
            for s in _illegible([inputs, justification, context])
        ]

        contemporaneous: list[str] = []
        if performed_at.tzinfo is None:
            contemporaneous.append("performed_at must carry a UTC offset")
        else:
            if performed_at - received_at > self._skew:
                contemporaneous.append("performed_at is in the future beyond allowed clock skew")
            if received_at - performed_at > self._max_age:
                delay = int((received_at - performed_at).total_seconds())
                contemporaneous.append(
                    f"activity recorded {delay} s after it was performed "
                    f"(limit {int(self._max_age.total_seconds())} s)"
                )

        original: list[str] = []
        if spec.requires_source_record and not source_records:
            original.append("action requires a cited source record with its digest")

        accurate = schema_errors(spec.input_schema, inputs)

        complete = [f"null value at {p}" for p in _nulls(inputs)]
        if len(justification.strip()) < 10:
            complete.append("justification must state why the action is needed")

        consistent = [
            f"context[{key}]={value!r} contradicts inputs[{key}]={inputs[key]!r}"
            for key, value in context.items()
            if key in inputs and str(inputs[key]) != value
        ]

        return AlcoaAssessment(
            checks=(
                check(P.ATTRIBUTABLE, attributable, f"attributed to {agent_id}"),
                check(P.LEGIBLE, legible, "all values printable"),
                check(P.CONTEMPORANEOUS, contemporaneous, "recorded at time of activity"),
                check(P.ORIGINAL, original, f"{len(source_records)} source record(s) cited"),
                check(P.ACCURATE, accurate, "inputs conform to the validated input schema"),
                check(P.COMPLETE, complete, "no missing values; justification present"),
                check(P.CONSISTENT, consistent, "context consistent with inputs"),
            )
        )

    def assess_record(
        self,
        *,
        record: ExecutionRecord,
        output_schema: dict[str, Any],
        required: Sequence[SignatureRequirement],
        signatures: Sequence[ElectronicSignature],
    ) -> AlcoaAssessment:
        """Content principles, evaluated before the record is written."""
        attributable = [] if record.agent_id else ["record has no agent identity"]
        attributable += [
            f"signature {s.signature_id} has no signer" for s in signatures if not s.signer_subject
        ]

        legible = [f"non-printable characters in {s!r}" for s in _illegible(record.outputs)]

        contemporaneous: list[str] = []
        if record.recorded_at - record.completed_at > self._recording_delay:
            contemporaneous.append("record written later than the allowed recording delay")

        original: list[str] = []
        if record.outputs is not None and record.outputs_digest != digest_of(record.outputs):
            original.append("outputs digest does not match outputs")
        if record.status == "completed" and (
            record.response_digest is None or not DIGEST.fullmatch(record.response_digest)
        ):
            original.append("raw response digest missing")

        accurate: list[str] = []
        if record.outputs is not None:
            accurate = schema_errors(output_schema, record.outputs)

        signed = {s.meaning for s in signatures}
        complete = [
            f"missing {r.meaning.value} signature" for r in required if r.meaning not in signed
        ]

        consistent: list[str] = []
        times = [record.received_at, *[s.signed_at for s in signatures], record.started_at]
        if any(a > b for a, b in pairwise(times)):
            consistent.append("signatures must fall between request receipt and execution start")
        if not record.received_at <= record.started_at <= record.completed_at <= record.recorded_at:
            consistent.append("timestamps are not in received/started/completed/recorded order")
        bad_links = [s.signature_id for s in signatures if s.record_digest != record.request_digest]
        if bad_links:
            consistent.append(f"signatures not linked to this request: {bad_links}")

        return AlcoaAssessment(
            checks=(
                check(P.ATTRIBUTABLE, attributable, "agent and signers identified"),
                check(P.LEGIBLE, legible, "outputs printable"),
                check(P.CONTEMPORANEOUS, contemporaneous, "recorded at time of execution"),
                check(P.ORIGINAL, original, "digests of original response and outputs retained"),
                check(P.ACCURATE, accurate, "outputs conform to the validated output schema"),
                check(P.COMPLETE, complete, "all required signatures present"),
                check(P.CONSISTENT, consistent, "timestamps ordered; signatures linked"),
            )
        )

    @staticmethod
    def assess_storage(
        *, record: ExecutionRecord, audit_events: int, readback: ExecutionRecord | None
    ) -> AlcoaAssessment:
        """Enduring and available, evaluated against what storage returns."""
        enduring = [] if audit_events > 0 else ["no audit event references this record"]
        available: list[str] = []
        if readback is None:
            available.append("record could not be read back from storage")
        elif readback.model_dump(mode="json") != record.model_dump(mode="json"):
            available.append("stored record differs from the written record")
        return AlcoaAssessment(
            checks=(
                check(P.ENDURING, enduring, f"{audit_events} audit event(s) reference the record"),
                check(P.AVAILABLE, available, "record retrievable and identical"),
            )
        )
