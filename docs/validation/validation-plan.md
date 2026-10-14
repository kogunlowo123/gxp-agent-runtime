# Validation approach and acceptance criteria

## Approach

The runtime follows a risk-based computer software assurance approach
(FDA CSA guidance, GAMP 5 2nd edition):

| Stage | Evidence | Produced by |
|---|---|---|
| User requirements | `docs/validation/urs.yaml` (URS-001 to URS-021) | Product owner and QA, code-owned |
| Functional and design specification | `docs/architecture/*`, JSON Schemas in `schemas/`, OpenAPI | Engineering |
| Risk assessment | GAMP 5 method in ADR-0002; threat model and risk register | Engineering and QA |
| Verification (OQ) | Automated tests with URS markers; JUnit results; validation package (`validation-package.json`, `traceability-matrix.md`) | CI on every push; attached to every release |
| Supplier evidence | SBOM, image provenance attestation, Trivy/Grype/Semgrep results | Release workflow |
| Installation (IQ) | Image digest, chart version, Terraform outputs, startup runbook checklist | Deploying site |
| Performance (PQ) | Site action definitions validated with their own OQ references; first periodic review | Deploying site |

`python -m gxp_agent_runtime.validation --strict` fails when any requirement
lacks a verifying test, any verifying test failed or did not run, or any test
cites an unknown requirement. The release cannot be produced otherwise.

## Acceptance criteria

| # | Criterion | Verified by |
|---|---|---|
| AC1 | An agent cannot change a validated system except through a validated definition version of a validated system whose review is current | URS-001, URS-002, URS-011, URS-012 |
| AC2 | High-priority actions execute only after approval and QA approval by two different people; medium after QA approval | URS-004, URS-006, URS-008 |
| AC3 | Each signature requires fresh re-authentication bound to a single-use challenge and is linked to the record digest | URS-003 |
| AC4 | Requests failing ALCOA+ are denied and the reasons recorded | URS-005 |
| AC5 | Every execution yields a signed record that verifies, including after read-back | URS-009 |
| AC6 | Tampering with records or the audit trail is detected | URS-009, URS-017 |
| AC7 | Dependency failures never lead to unrecorded or duplicate execution | URS-016, URS-020 |
| AC8 | Agents use the same controls through REST, MCP and A2A | URS-013, URS-018 |
| AC9 | Periodic reviews summarise the period and control validated state | URS-015 |
| AC10 | The release carries a strict validation package; branch coverage >= 90% | URS-019, CI |

## Change control

Changes to the policy, the risk method, the signing ceremony or the URS are
GxP-relevant: they require code-owner approval, a CHANGELOG entry, and a
release with a new validation package. Deploying sites assess each release
against their own action definitions before upgrading.
