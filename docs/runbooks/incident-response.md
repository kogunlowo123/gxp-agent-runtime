# Runbook: incident response

Severity follows the quality impact: anything that may have changed a GxP
record incorrectly is a quality event and QA is informed within one hour.

## Elevated 5xx

1. `kubectl -n gxp-runtime logs deploy/gxp-gxp-agent-runtime --since=15m | jq 'select(.level=="error")'`.
2. `dependency_unavailable` errors: identity fabric or a JWKS endpoint is
   down. Agents are refused (fail closed); nothing executes. Restore the
   dependency; no data correction needed.
3. Database errors: check `/readyz` on each pod and the RDS event log;
   follow [disaster recovery](disaster-recovery.md) if the primary is lost.

## Failed executions

`GxpExecutionFailures` fires on repeated `failed` records for one system.

1. List failed records for the system and read `error` and `http_status`.
2. Treat each as a deviation in the QMS; the execution record is the
   primary evidence (verify it with `/v1/execution-records/{id}/verification`).
3. If the validated system may have applied the change despite the error
   (timeouts), ask the system owner to check by the idempotency key (request
   id) before any re-submission.
4. If failures come from schema drift on the system side, retire the
   affected definition version and register a corrected one.

## Data integrity

`GxpAlcoaFailuresOnRecords` means a stored record failed a check.

1. Run `/v1/execution-records/{id}/verification` for the affected records.
2. Run `/v1/audit/verification`; a broken chain is a critical quality event.
3. Freeze changes: suspend the system through a periodic review with
   conclusion `remediation-required`, or scale agents' scopes down in the
   fabric.
4. Preserve evidence: snapshot the database and export `audit_events` to the
   evidence bucket before any correction.

## Signature failures

`GxpSignatureFailureSpike` may indicate someone trying to sign as another
user or replaying tokens.

1. Query audit events `signature.apply` with outcome `rejected` for the
   window; group by actor and reason.
2. Notify the IAM team to review IdP sign-in logs for those subjects.
3. If an account is suspected compromised, disable it in the IdP; pending
   requests it signed remain linked to the signer and can be rejected by QA.

## Replicas down

Fewer than two pods scraped: check node capacity, recent rollouts
(`helm history`), and PDB. Roll back per [rollback](rollback.md) if the
latest release is the cause.
