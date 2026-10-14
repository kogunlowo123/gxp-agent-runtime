# Contributing

## Setup

```bash
uv sync
make check
```

## Requirements for every change

- `make check` passes: ruff, black, mypy `--strict`, bandit, contract drift,
  tests with at least 90% branch coverage.
- New behaviour has tests. Security controls need adversarial cases in
  `tests/security`; dependency failures need cases in `tests/chaos`.
- Tests that verify a user requirement carry `@pytest.mark.urs("URS-nnn")`.
  A new requirement goes into `docs/validation/urs.yaml` together with the
  tests that verify it; `make validation` must stay green (every requirement
  traced and verified).
- Changes to `policies/gxp-runtime.yaml`, the risk method
  (`src/gxp_agent_runtime/domain/risk.py`) or the signing ceremony are
  GxP-relevant changes: describe the impact on validated state in the pull
  request and update `docs/compliance/control-mapping.md` when a control
  changes.
- Public API changes are recorded in `CHANGELOG.md` and regenerate the
  contracts (`uv run python -m gxp_agent_runtime.contracts`).
- Architecturally significant decisions get an ADR in
  `docs/architecture/adr/`.
- No credentials, patient data or real batch records in code, tests or
  fixtures. Use synthetic data only.

## Commit messages

Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`,
`chore:`). Breaking changes use `!` and a `BREAKING CHANGE:` footer.

## Review

Changes to `src/gxp_agent_runtime/security`, `src/gxp_agent_runtime/domain`,
`policies/`, `docs/validation/` or `deployments/` need approval from a code
owner (see `CODEOWNERS`).
