"""Validation evidence package: URS discovery, JUnit results, matrix statuses, CLI."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from gxp_agent_runtime.validation.__main__ import main
from gxp_agent_runtime.validation.traceability import (
    build_package,
    discover_tests,
    load_requirements,
    load_results,
    render_markdown,
)
from tests.conftest import ROOT

pytestmark = pytest.mark.urs("URS-019")

URS = """
requirements:
  - {id: URS-001, title: One, requirement: First requirement text, risk: high}
  - {id: URS-002, title: Two, requirement: Second requirement text, risk: medium}
  - {id: URS-003, title: Three, requirement: Third requirement text, risk: low}
  - {id: URS-004, title: Four, requirement: Fourth requirement text, risk: low}
"""

TESTS = """
import pytest

pytestmark = [pytest.mark.unit, pytest.mark.urs("URS-001")]


@pytest.mark.urs("URS-002")
def test_one():
    pass


async def test_two():
    pass


@pytest.mark.urs("URS-009")
class TestGroup:
    @pytest.mark.urs("URS-003")
    def test_three(self):
        pass

    def helper(self):
        pass
"""

JUNIT = """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest">
  <testcase classname="tests.unit.test_sample" name="test_one"/>
  <testcase classname="tests.unit.test_sample" name="test_two[a]"/>
  <testcase classname="tests.unit.test_sample" name="test_two[b]"><failure message="x"/></testcase>
  <testcase classname="tests.unit.test_sample.TestGroup" name="test_three">
    <skipped message="y"/>
  </testcase>
</testsuite></testsuites>
"""


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / "tests" / "unit").mkdir(parents=True)
    (tmp_path / "tests" / "unit" / "test_sample.py").write_text(TESTS, encoding="utf-8")
    (tmp_path / "tests" / "test_root.py").write_text("def test_untagged():\n    pass\n", "utf-8")
    (tmp_path / "urs.yaml").write_text(URS, encoding="utf-8")
    (tmp_path / "junit.xml").write_text(JUNIT, encoding="utf-8")
    return tmp_path


def test_discovery_reads_module_function_and_class_marks(workspace: Path) -> None:
    cases = {c.node_id: c for c in discover_tests(workspace / "tests", root=workspace)}
    assert set(cases) == {
        "tests/unit/test_sample.py::test_one",
        "tests/unit/test_sample.py::test_two",
        "tests/unit/test_sample.py::TestGroup::test_three",
    }
    assert cases["tests/unit/test_sample.py::test_one"].requirements == ("URS-001", "URS-002")
    assert cases["tests/unit/test_sample.py::TestGroup::test_three"].requirements == (
        "URS-001",
        "URS-003",
        "URS-009",
    )
    assert cases["tests/unit/test_sample.py::test_two"].suite == "unit"


def test_results_take_worst_outcome_across_parametrizations(workspace: Path) -> None:
    results = load_results(workspace / "junit.xml")
    assert results["tests/unit/test_sample.py::test_one"] == "passed"
    assert results["tests/unit/test_sample.py::test_two"] == "failed"
    assert results["tests/unit/test_sample.py::TestGroup::test_three"] == "skipped"


def test_package_statuses_digest_and_markdown(workspace: Path) -> None:
    requirements = load_requirements(workspace / "urs.yaml")
    tests = discover_tests(workspace / "tests", root=workspace)
    package = build_package(
        requirements,
        tests,
        load_results(workspace / "junit.xml"),
        system="s",
        version="0.1.0",
        commit="abc",
        generated_at=datetime(2026, 10, 14, tzinfo=UTC),
    )
    statuses = {row.requirement.id: row.status for row in package.matrix}
    assert statuses == {
        "URS-001": "failed",
        "URS-002": "verified",
        "URS-003": "not-executed",
        "URS-004": "untraced",
    }
    assert package.summary.orphan_references == ("URS-009",)
    assert package.summary.trace_coverage == 0.75
    assert not package.summary.acceptable
    assert package.digest.startswith("sha256:")
    unexecuted = build_package(
        requirements,
        tests,
        None,
        system="s",
        version="0",
        commit=None,
        generated_at=datetime(2026, 10, 14, tzinfo=UTC),
    )
    assert {r.status for r in unexecuted.matrix} == {"not-executed", "untraced"}
    markdown = render_markdown(package)
    assert "| URS-004 Four | low | untraced | none |" in markdown
    assert "URS-009" in markdown


def test_requirements_file_is_validated(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("requirements: nope\n", encoding="utf-8")
    with pytest.raises(ValueError, match="requirements"):
        load_requirements(bad)
    dup = tmp_path / "dup.yaml"
    dup.write_text(
        "requirements:\n"
        "  - {id: URS-001, title: One, requirement: First requirement, risk: low}\n"
        "  - {id: URS-001, title: Two, requirement: Second requirement, risk: low}\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate"):
        load_requirements(dup)
    wrong = tmp_path / "wrong.yaml"
    wrong.write_text(
        "requirements:\n  - {id: REQ-1, title: One, requirement: First requirement, risk: low}\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="URS-001"):
        load_requirements(wrong)


def test_cli_strict_mode(workspace: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = workspace / "dist" / "package.json"
    md = workspace / "dist" / "matrix.md"
    args = [
        "--urs",
        str(workspace / "urs.yaml"),
        "--tests",
        str(workspace / "tests"),
        "--root",
        str(workspace),
        "--junit",
        str(workspace / "junit.xml"),
        "--out",
        str(out),
        "--markdown",
        str(md),
        "--commit",
        "abc123",
    ]
    assert main(args) == 0
    assert main([*args, "--strict"]) == 1
    assert json.loads(out.read_text(encoding="utf-8"))["commit"] == "abc123"
    assert md.read_text(encoding="utf-8").startswith("# Traceability matrix")
    assert "untraced=1" in capsys.readouterr().out


def test_repository_requirements_are_all_traced() -> None:
    """Every URS in this repository is verified by at least one test, and no test cites
    an unknown requirement. Executed results are added in CI (see release workflow)."""
    requirements = load_requirements(ROOT / "docs" / "validation" / "urs.yaml")
    tests = discover_tests(ROOT / "tests", root=ROOT)
    package = build_package(
        requirements,
        tests,
        None,
        system="gxp-agent-runtime",
        version="0.1.0",
        commit=None,
        generated_at=datetime(2026, 10, 14, tzinfo=UTC),
    )
    assert package.summary.untraced == 0, [
        r.requirement.id for r in package.matrix if r.status == "untraced"
    ]
    assert package.summary.orphan_references == ()
