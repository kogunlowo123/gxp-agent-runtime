# Compliance control mapping

The evidence column names what an auditor or inspector can inspect. URS IDs
refer to `docs/validation/urs.yaml`; the release's validation package shows
the executed tests for each.

## 21 CFR Part 11 and EU GMP Annex 11

| Requirement | Implementation | Evidence | URS |
|---|---|---|---|
| 11.10(a) validation | Validated systems and validated definition versions only; validation package per release | Registry, definition digests, `validation-package.json` | URS-001, URS-002, URS-019 |
| 11.10(b) accurate and complete copies | Records retrievable as JSON with digests; verification endpoint | `GET /v1/execution-records/{id}[/verification]` | URS-009 |
| 11.10(c) record protection | Signed records, encrypted PostgreSQL, PITR, WORM exports | Terraform, verification results | URS-009, URS-017 |
| 11.10(d) limited system access | OIDC roles for people; fabric credentials and scopes for agents | IdP configuration, policy, audit | URS-013 |
| 11.10(e) audit trail | Signed hash chains for every decision and change; operator-independent, time-stamped | `/v1/audit/verification` | URS-017 |
| 11.10(f) operational checks | Enforced sequence: pending -> signatures -> executing (CAS) -> completed/failed | Request status history in audit | URS-006, URS-007, URS-016 |
| 11.10(g) authority checks | Meaning-to-role map; SoD; policy | Signature records, policy digest | URS-008 |
| 11.10(h) device checks | Agent identity attested by the fabric (workload attestation) | Fabric audit | URS-013 |
| 11.10(k) documentation control | Definitions versioned and digest-pinned; policy in Git with code owners | Git history, definition lifecycle signatures | URS-011 |
| 11.50 signature manifestations | Printed name, date/time, meaning in every signature and record | `electronic-signature.schema.json` | URS-003 |
| 11.70 signature/record linking | Signature covers the record digest; Ed25519 over the manifest | Verification `linked_to_record` | URS-003 |
| 11.100 uniqueness | Signer subject from the enterprise IdP | Signature records | URS-003 |
| 11.200(a) two components, re-entry | OIDC re-authentication per signing with `auth_time`, `amr`, nonce | Signature `auth_time`, `auth_methods` | URS-003 |
| Annex 11 s.4 validation | GAMP 5 risk-based approach; CI evidence | Validation plan, package | URS-004, URS-019 |
| Annex 11 s.9 audit trails | As 11.10(e) | As above | URS-017 |
| Annex 11 s.11 periodic evaluation | Periodic review generation, QA approval, overdue blocking | `periodic-review` records | URS-012, URS-015 |
| Annex 11 s.14 electronic signature | As 11.50/11.70/11.200 | As above | URS-003 |

## Data integrity (ALCOA+)

| Principle | Request check | Record check |
|---|---|---|
| Attributable | SPIFFE agent identity; delegation chain | Agent and every signer identified |
| Legible | No control characters | Outputs printable |
| Contemporaneous | `performed_at` within skew and 15-minute window | Recorded within 30 s of completion |
| Original | Cited source records with digests where required | Raw-response and output digests |
| Accurate | Inputs match the validated input schema | Outputs match the validated output schema |
| Complete | No nulls; justification present | All required signatures present |
| Consistent | Context agrees with inputs | Timestamps ordered; signatures linked to the request digest |
| Enduring | Write-ahead audit event | Audit events reference the record |
| Available | Retrievable through API | Read back and compared after write |

## Other frameworks

| Control objective | SOC 2 (TSC 2017) | ISO/IEC 27001:2022 | NIST SP 800-53 r5 | NIST AI RMF 1.0 | HIPAA Security Rule | Evidence |
|---|---|---|---|---|---|---|
| Least privilege for agents | CC6.3 | 5.15, 8.2 | AC-6 | MANAGE 2.4 | 164.308(a)(4) | Scopes, policy decisions |
| Human oversight of high-risk AI actions | CC8.1 | 5.37 | CA-7 | GOVERN 1.4, MANAGE 1.3 | n/a | Signature routing, risk rationale |
| Change management of capabilities and policy | CC8.1 | 8.32 | CM-3, CM-5 | GOVERN 1.4 | 164.308(a)(8) | Definition lifecycle, Git |
| Audit and accountability | CC7.2 | 8.15 | AU-2, AU-9, AU-10 | MEASURE 2.8 | 164.312(b) | Audit chains |
| Integrity of records | CC7.1 | 8.24 | SI-7, SC-13 | MEASURE 2.7 | 164.312(c)(1) | Record signatures |
| Identification and authentication | CC6.1 | 5.17 | IA-2, IA-9, IA-11 (re-auth) | GOVERN 1.4 | 164.312(d) | IdP, fabric |
| Monitoring and response | CC7.3 | 5.24 | IR-4, SI-4 | MANAGE 4.1 | 164.308(a)(6) | Alerts, runbooks |
| Availability and recovery | A1.2 | 8.14 | CP-9, CP-10 | n/a | 164.308(a)(7) | HA, PITR, DR runbook |

HIPAA applies only where action inputs contain PHI (for example clinical
trial sample identifiers linked to participants); the runtime treats all
requests as RESTRICTED regardless.

## FDA computer software assurance

The runtime is intended for use as a configured component (GAMP category 4)
of the deploying organisation's quality system. Assurance activities:
automated unit, security, chaos, performance, e2e and integration tests with
executed results traced to the URS (validation package); vendor-style
evidence (SBOM, provenance attestation, vulnerability scans) from the
release; site-specific PQ against the organisation's own action definitions.
