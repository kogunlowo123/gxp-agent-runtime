"""Generate the validation evidence package.

uv run pytest --junitxml=dist/junit.xml
uv run python -m gxp_agent_runtime.validation --junit dist/junit.xml \
    --out dist/validation-package.json --markdown dist/traceability-matrix.md --strict
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from gxp_agent_runtime import __version__
from gxp_agent_runtime.validation.traceability import (
    build_package,
    discover_tests,
    load_requirements,
    load_results,
    render_markdown,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m gxp_agent_runtime.validation")
    parser.add_argument("--urs", type=Path, default=Path("docs/validation/urs.yaml"))
    parser.add_argument("--tests", type=Path, default=Path("tests"))
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--junit", type=Path, help="JUnit XML from pytest --junitxml")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--markdown", type=Path)
    parser.add_argument("--commit", default=os.environ.get("GITHUB_SHA"))
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit 1 unless every requirement is traced and verified by passing tests",
    )
    args = parser.parse_args(argv)

    package = build_package(
        load_requirements(args.urs),
        discover_tests(args.tests, root=args.root),
        load_results(args.junit) if args.junit else None,
        system="gxp-agent-runtime",
        version=__version__,
        commit=args.commit,
        generated_at=datetime.now(UTC),
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(package.model_dump_json(indent=2) + "\n", encoding="utf-8")
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(render_markdown(package), encoding="utf-8")
    s = package.summary
    sys.stdout.write(
        f"requirements={s.requirements} verified={s.verified} failed={s.failed} "
        f"not_executed={s.not_executed} untraced={s.untraced} digest={package.digest}\n"
    )
    if args.strict and not s.acceptable:
        sys.stderr.write("validation package is not acceptable for release\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
