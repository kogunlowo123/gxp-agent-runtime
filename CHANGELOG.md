# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [0.1.0] - 2026-10-14

### Added

- Registry of validated systems and versioned, content-addressed action
  definitions (JSON Schema inputs/outputs, HTTPS binding) with a
  draft -> validated -> retired lifecycle gated by QA electronic signatures.
- GAMP 5 (2nd edition) functional risk assessment: severity, probability
  (software category plus observed failure rate), risk class, detectability
  and risk priority, with recorded rationale.
- ALCOA+ checks on every request and every execution record, including
  read-back verification of records (enduring, available).
- 21 CFR Part 11 approval workflow: single-use signing challenges, OIDC
  re-authentication bound by nonce with `auth_time` and `amr` checks,
  signature manifests (printed name, time, meaning) signed with Ed25519 and
  linked to the record digest; separation of duties.
- Execution through validated-system bindings with idempotency keys,
  retries, no redirects; signed execution records with input, output and
  raw-response digests.
- Periodic review generation and QA approval that maintains or suspends a
  system's validated state; overdue reviews block agent actions.
- Signed, hash-chained audit trail per process instance in PostgreSQL with
  on-demand verification.
- agent-identity-fabric integration (introspection, authorization,
  jwt-bearer runtime credentials) with an offline verification mode.
- MCP tools (streamable HTTP) and A2A Agent Card with JSON-RPC
  `message/send` and `tasks/get`.
- Validation evidence package generator: URS -> test traceability matrix
  with executed results, produced in CI and attached to releases.
- Helm chart, Kubernetes namespace and secret sync, Terraform for AWS
  (reference), Azure and GCP; Prometheus alerts and Grafana dashboard.
- CI: lint, types, SAST, contract drift, tests (unit, security, chaos,
  performance, e2e, PostgreSQL integration), validation evidence,
  Helm/kubeconform, Terraform validate, Trivy, Syft, Grype, Semgrep,
  container smoke test.
