# Threat model

## Assets

| Asset | Impact if compromised |
|---|---|
| Validated systems reachable through the runtime | Unauthorised changes to GxP records, batch disposition, patient risk |
| Action definitions and GxP policy | Agents gain capabilities nobody validated |
| E-signature manifests and record-signing key | Forged approvals; loss of non-repudiation |
| Execution records and audit chains | Loss of evidence; data-integrity finding; regulatory action |
| Agent credentials (in transit) | Impersonation of an agent |
| Human sessions and re-authentication tokens | Signing in someone else's name |

## Trust boundaries

1. Agents -> runtime (REST, MCP, A2A); untrusted callers and untrusted content.
2. Humans -> runtime (enterprise OIDC).
3. Runtime -> agent-identity-fabric, enterprise IdP JWKS.
4. Runtime -> validated systems (HTTPS).
5. Runtime -> PostgreSQL, secret manager, evidence storage.

## STRIDE

| ID | Threat | Category | Control | Test |
|---|---|---|---|---|
| T1 | Forged agent credential (attacker key, guessed kid) | Spoofing | Fabric introspection or EdDSA verification against fabric JWKS | `tests/security::test_t1_t2_forged_and_unsigned_agent_credentials` |
| T2 | `alg: none`, HS256 key confusion | Spoofing | Exactly the accepted algorithms; kid required | same |
| T3 | Human token used as agent credential or the reverse | Spoofing / elevation | Separate issuers, audiences and dependency per caller type | `test_t3_token_confusion_between_humans_and_agents` |
| T4 | Agent performs actions outside its mandate | Elevation (excessive agency) | `gxp:execute:<action>` scopes, fabric decision, `deny-out-of-scope` | `test_t4_t5_scope_and_object_level_authorization` |
| T5 | Agent reads another agent's requests or records | Information disclosure | Ownership check (404) | same |
| T6 | Replay of a captured re-authentication token | Spoofing | Nonce bound to one challenge; single-use CAS | `test_t6_reauthentication_replayed_on_another_challenge`, `tests/unit/test_signatures.py` |
| T7 | Tampering with a stored record; copying signatures between records | Tampering / repudiation | Record digest + Ed25519 signature; signatures cover the request digest; verification endpoint | `test_t7_tampered_record_and_transplanted_signature_are_detected` |
| T8 | Editing or deleting audit events | Repudiation | Hash chain + Ed25519 signatures; verification; periodic review | `test_t8_audit_trail_tampering_is_detected` |
| T9 | Auditor or approver applies a QA meaning | Elevation | Meaning-to-role map | `test_t9_t10_role_escalation_and_self_approval_over_http` |
| T10 | Author validates own definition; same person signs twice | Elevation (SoD) | SoD checks | same, `tests/unit/test_runtime.py::test_separation_of_duties` |
| T11 | Path traversal or parameter injection into the validated system | Tampering | JSON Schema validation, percent-encoded path placeholders, fixed binding | `test_t11_inputs_cannot_escape_the_binding_path` |
| T12 | Credentials written into permanent GxP records | Information disclosure | Secret scanner on all request text before storage | `test_t12_credentials_in_requests_are_rejected` |
| T13 | DNS rebinding against `/mcp` | Spoofing | Host allow list in MCP transport security | `test_t13_mcp_rejects_foreign_host_headers` |
| T14 | Confused deputy through delegation chains | Elevation | Max one hop; delegated actions need approval | `test_t14_deep_delegation_is_denied` |
| T15 | SSRF via redirect from a compromised integration endpoint | Information disclosure | Redirects not followed; HTTPS base URLs only | `test_t15_validated_system_redirects_are_not_followed` |
| T16 | Oversized or mass-assignment payloads | DoS / tampering | `extra="forbid"`, size limits, paging limits | `test_t16_oversized_and_malformed_requests` |
| T17 | Function-level authorization bypass | Elevation | Role checks per endpoint and meaning | `test_t17_auditor_cannot_mutate_and_owner_cannot_sign` |
| T18 | Silent credential probing on MCP | Repudiation | Unauthenticated calls audited | `test_t18_mcp_credential_failures_are_audited` |
| T19 | Duplicate execution after timeout or concurrent approvals | Tampering | Idempotency key; CAS to `executing` | `tests/chaos::test_concurrent_final_signatures_execute_exactly_once`, connector tests |
| T20 | Evidence not written when storage fails | Repudiation | Write-ahead audit; storage read-back verification | `tests/chaos::test_audit_failure_blocks_the_action` |

## MITRE ATT&CK (Enterprise)

| Technique | Mitigation |
|---|---|
| T1078 Valid Accounts | Agents never hold validated-system credentials; humans re-authenticate per signature |
| T1528 Steal Application Access Token | Short-lived fabric credentials; introspection; audience checks |
| T1550.001 Application Access Token | Nonce-bound re-authentication; single-use challenges |
| T1565.001 Stored Data Manipulation | Signed records and audit chains; verification; periodic review |
| T1070 Indicator Removal | Audit deletion breaks the chain; WORM exports |
| T1190 Exploit Public-Facing Application | Input schemas, fixed bindings, Semgrep/Bandit, image scanning |

## MITRE ATLAS (AI-specific)

| Technique | Relevance | Control |
|---|---|---|
| AML.T0051 LLM Prompt Injection | Injected content steers an agent to request harmful actions | The runtime does not trust agent intent: scopes, validated definitions, schema checks and human signatures bound what any agent can do |
| AML.T0053 LLM Plugin Compromise | A tool (MCP) used to reach systems beyond intent | MCP tools expose only the runtime's controlled operations |
| AML.T0048 External Harms | Agent action harms product or patient | GAMP 5 risk routing; high priority needs two human signatures |

## OWASP Top 10 for LLM Applications (2025)

| Risk | Control |
|---|---|
| LLM01 Prompt Injection | Out-of-band controls (scopes, policy, signatures) independent of prompt content |
| LLM02 Sensitive Information Disclosure | Secret scanning of requests; agents see only their own records |
| LLM05 Improper Output Handling | Agent output (inputs) validated against JSON Schema before reaching systems |
| LLM06 Excessive Agency | Validated definitions only; risk-based human approval; delegation limit |
| LLM08 Vector and Embedding Weaknesses | Not applicable: no retrieval in the control path |
| LLM09 Misinformation | Justification and cited source records with digests are reviewed by signers |

## OWASP API Security Top 10 (2023)

| Risk | Control |
|---|---|
| API1 BOLA | Ownership checks on requests and records |
| API2 Broken Authentication | Signed tokens, algorithm allow list, issuer/audience/time checks with injected clock |
| API3 Broken Object Property Level Authorization | `extra="forbid"`; status fields not client-settable |
| API4 Unrestricted Resource Consumption | Size limits, paging limits, HPA, connector timeouts |
| API5 Broken Function Level Authorization | Role per endpoint and per signature meaning |
| API6 Unrestricted Access to Sensitive Business Flows | Approvals cannot be bypassed: execution only from CAS-guarded state |
| API8 Security Misconfiguration | Production refuses ephemeral keys and plain HTTP; Helm `required` values |
| API10 Unsafe Consumption of APIs | HTTPS only, no redirects, response must be a JSON object matching the output schema |

## Risk register

| ID | Risk | Likelihood | Impact | Owner | Treatment | Residual |
|---|---|---|---|---|---|---|
| R1 | Record-signing key exfiltration | Low | Critical | Security Ops | Secret manager + KMS, key rotation runbook, retired keys kept public only | Low |
| R2 | Mis-specified action definition validated | Medium | High | QA | SoD on validation, OQ reference required, digest pinned, versioned changes | Medium |
| R3 | Policy or risk matrix change weakens approvals | Low | High | QA / AI governance | CODEOWNERS, policy digest in every decision, tests on matrix | Low |
| R4 | Validated system accepts a call but returns an error later | Medium | Medium | System owner | Failed records are deviations; alerting; periodic review failure rate | Low |
| R5 | Offline agent verification misses a revocation for up to 15 minutes | Low | Medium | Platform | Fabric mode in production (ADR-0004) | Low |
| R6 | Database administrator deletes audit rows | Low | High | Platform / QA | Chain verification, periodic review, WORM exports, DB access logging | Low |
| R7 | IdP does not emit `amr` / `auth_time` | Medium | Medium | IAM | Signing refused until configured; documented in startup runbook | Low |
