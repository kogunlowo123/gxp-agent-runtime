# Runbook: rollback

The schema is additive within 0.x (`schema_version` table), so an
application rollback within 0.x does not require database changes. Records,
signatures and audit chains written by the newer version remain verifiable
by the older one (same formats, published keys).

```bash
helm -n gxp-runtime history gxp
helm -n gxp-runtime rollback gxp <revision> --wait
kubectl -n gxp-runtime rollout status deployment/gxp-gxp-agent-runtime
curl -sf "$GXP/readyz"
```

Document the rollback in the change record with the image digests of both
versions and the validation package of the version restored.

Policy-only regressions: revert the commit touching
`policies/gxp-runtime.yaml`, release, and confirm the `policy_digest` in new
requests matches the reverted file.

Definition regressions are not rolled back by deployment: QA retires the
faulty version (`retirement` signature) and requests fall back to the
previous validated version.
