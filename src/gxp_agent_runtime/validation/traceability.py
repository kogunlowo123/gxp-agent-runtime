"""Validation evidence package: URS -> test traceability matrix with executed results.

User requirements live in ``docs/validation/urs.yaml``. Tests declare which
requirements they verify with ``@pytest.mark.urs("URS-001", ...)`` (or a
module-level ``pytestmark``). Test files are parsed, not imported, so the
generator runs anywhere. Results come from the JUnit XML that ``pytest
--junitxml`` writes in the same CI run, which makes the package objective
evidence for computerized system validation (FDA CSA, GAMP 5 OQ).
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Literal

import yaml
from agentic_core.domain.provenance import canonical_json, content_digest
from defusedxml import ElementTree
from pydantic import BaseModel, ConfigDict, Field, field_validator

URS_ID = re.compile(r"^URS-\d{3}$")

Outcome = Literal["passed", "failed", "skipped", "not-executed"]
RowStatus = Literal["verified", "failed", "not-executed", "untraced"]


class Requirement(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    title: str = Field(min_length=3)
    requirement: str = Field(min_length=10)
    risk: Literal["high", "medium", "low"]
    references: tuple[str, ...] = ()

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not URS_ID.fullmatch(value):
            raise ValueError("requirement id must look like URS-001")
        return value


class TestCase(BaseModel):
    model_config = ConfigDict(frozen=True)

    node_id: str
    suite: str
    requirements: tuple[str, ...]


class TraceRow(BaseModel):
    model_config = ConfigDict(frozen=True)

    requirement: Requirement
    tests: tuple[str, ...]
    outcomes: dict[str, Outcome]
    status: RowStatus


class PackageSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    requirements: int
    verified: int
    failed: int
    not_executed: int
    untraced: int
    traced_tests: int
    orphan_references: tuple[str, ...]
    trace_coverage: float

    @property
    def acceptable(self) -> bool:
        return (
            self.failed == 0
            and self.untraced == 0
            and self.not_executed == 0
            and not self.orphan_references
        )


class ValidationPackage(BaseModel):
    model_config = ConfigDict(frozen=True)

    system: str
    version: str
    commit: str | None
    generated_at: datetime
    summary: PackageSummary
    matrix: tuple[TraceRow, ...]
    digest: str = ""

    def content(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude={"digest"})


def load_requirements(path: Path) -> list[Requirement]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not isinstance(document.get("requirements"), list):
        raise ValueError(f"{path} must contain a 'requirements' list")
    requirements = [Requirement.model_validate(r) for r in document["requirements"]]
    ids = [r.id for r in requirements]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise ValueError(f"duplicate requirement ids: {duplicates}")
    return requirements


def _urs_ids(node: ast.expr) -> list[str]:
    """IDs from ``pytest.mark.urs("URS-001", ...)`` expressions (possibly in a list)."""
    found: list[str] = []
    candidates = node.elts if isinstance(node, ast.List | ast.Tuple) else [node]
    for candidate in candidates:
        if (
            isinstance(candidate, ast.Call)
            and isinstance(candidate.func, ast.Attribute)
            and candidate.func.attr == "urs"
        ):
            found.extend(
                arg.value
                for arg in candidate.args
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
            )
    return found


def _module_marks(tree: ast.Module) -> list[str]:
    marks: list[str] = []
    for statement in tree.body:
        if isinstance(statement, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "pytestmark" for t in statement.targets
        ):
            marks.extend(_urs_ids(statement.value))
    return marks


def _functions(
    body: Iterable[ast.stmt], prefix: str, inherited: list[str]
) -> Iterable[tuple[str, list[str]]]:
    for statement in body:
        if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef) and (
            statement.name.startswith("test")
        ):
            own = [i for d in statement.decorator_list for i in _urs_ids(d)]
            yield f"{prefix}{statement.name}", inherited + own
        elif isinstance(statement, ast.ClassDef) and statement.name.startswith("Test"):
            own = [i for d in statement.decorator_list for i in _urs_ids(d)]
            yield from _functions(statement.body, f"{prefix}{statement.name}::", inherited + own)


def discover_tests(tests_dir: Path, *, root: Path) -> list[TestCase]:
    tests_dir, root = tests_dir.resolve(), root.resolve()
    cases: list[TestCase] = []
    for path in sorted(tests_dir.rglob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        relative = path.relative_to(root).as_posix()
        suite = path.relative_to(tests_dir).parts[0] if path.parent != tests_dir else "root"
        for name, ids in _functions(tree.body, f"{relative}::", _module_marks(tree)):
            if ids:
                cases.append(
                    TestCase(node_id=name, suite=suite, requirements=tuple(sorted(set(ids))))
                )
    return cases


def load_results(junit_xml: Path) -> dict[str, Outcome]:
    """Map ``path::[Class::]function`` to the worst outcome over its parametrizations."""
    rank: dict[Outcome, int] = {"passed": 0, "skipped": 1, "not-executed": 2, "failed": 3}
    results: dict[str, Outcome] = {}
    tree = ElementTree.parse(junit_xml)
    for case in tree.iter("testcase"):
        classname = case.get("classname", "")
        name = re.sub(r"\[.*\]$", "", case.get("name", ""))
        parts = classname.split(".")
        # classname is dotted module path, optionally followed by a Test* class.
        if parts and parts[-1].startswith("Test"):
            module, klass = parts[:-1], [parts[-1]]
        else:
            module, klass = parts, []
        node = "::".join(["/".join(module) + ".py", *klass, name])
        outcome: Outcome = "passed"
        if case.find("failure") is not None or case.find("error") is not None:
            outcome = "failed"
        elif case.find("skipped") is not None:
            outcome = "skipped"
        previous = results.get(node)
        if previous is None or rank[outcome] > rank[previous]:
            results[node] = outcome
    return results


def build_package(
    requirements: Sequence[Requirement],
    tests: Sequence[TestCase],
    results: dict[str, Outcome] | None,
    *,
    system: str,
    version: str,
    commit: str | None,
    generated_at: datetime,
) -> ValidationPackage:
    known = {r.id for r in requirements}
    orphans = sorted({i for t in tests for i in t.requirements if i not in known})
    rows: list[TraceRow] = []
    for requirement in requirements:
        tracing = sorted(t.node_id for t in tests if requirement.id in t.requirements)
        outcomes: dict[str, Outcome] = {
            node: (results.get(node, "not-executed") if results is not None else "not-executed")
            for node in tracing
        }
        status: RowStatus
        if not tracing:
            status = "untraced"
        elif any(o == "failed" for o in outcomes.values()):
            status = "failed"
        elif any(o == "passed" for o in outcomes.values()) and all(
            o in {"passed", "skipped"} for o in outcomes.values()
        ):
            status = "verified"
        else:
            status = "not-executed"
        rows.append(
            TraceRow(
                requirement=requirement, tests=tuple(tracing), outcomes=outcomes, status=status
            )
        )
    count = {s: sum(1 for r in rows if r.status == s) for s in ("verified", "failed", "untraced")}
    traced = len(rows) - count["untraced"]
    summary = PackageSummary(
        requirements=len(rows),
        verified=count["verified"],
        failed=count["failed"],
        not_executed=sum(1 for r in rows if r.status == "not-executed"),
        untraced=count["untraced"],
        traced_tests=len(tests),
        orphan_references=tuple(orphans),
        trace_coverage=round(traced / len(rows), 4) if rows else 0.0,
    )
    package = ValidationPackage(
        system=system,
        version=version,
        commit=commit,
        generated_at=generated_at,
        summary=summary,
        matrix=tuple(rows),
    )
    return package.model_copy(update={"digest": content_digest(canonical_json(package.content()))})


def render_markdown(package: ValidationPackage) -> str:
    s = package.summary
    lines = [
        f"# Traceability matrix: {package.system} {package.version}",
        "",
        f"- Commit: `{package.commit or 'unknown'}`",
        f"- Generated: {package.generated_at.isoformat()}",
        f"- Package digest: `{package.digest}`",
        f"- Requirements: {s.requirements}; verified {s.verified}; failed {s.failed}; "
        f"not executed {s.not_executed}; untraced {s.untraced}",
        f"- Trace coverage: {s.trace_coverage:.0%}; tests tracing requirements: {s.traced_tests}",
    ]
    if s.orphan_references:
        lines.append(
            f"- Unknown requirement ids referenced by tests: {', '.join(s.orphan_references)}"
        )
    lines += ["", "| Requirement | Risk | Status | Verifying tests |", "|---|---|---|---|"]
    for row in package.matrix:
        tests = "<br>".join(f"`{t}` ({row.outcomes[t]})" for t in row.tests) or "none"
        lines.append(
            f"| {row.requirement.id} {row.requirement.title} | {row.requirement.risk} | "
            f"{row.status} | {tests} |"
        )
    return "\n".join(lines) + "\n"
