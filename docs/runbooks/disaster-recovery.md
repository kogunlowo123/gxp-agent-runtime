# Runbook: disaster recovery

| Target | Value |
|---|---|
| RPO | 5 minutes (PostgreSQL PITR) |
| RTO | 1 hour |

The runtime is stateless; all GxP state (registry, requests, signatures,
records, reviews, audit chains) is in PostgreSQL.

## Database loss or corruption

1. Stop agent traffic: scale the deployment to zero
   (`kubectl -n gxp-runtime scale deploy/gxp-gxp-agent-runtime --replicas=0`).
2. Restore to a new instance with point-in-time recovery to just before the
   incident (AWS: `aws rds restore-db-instance-to-point-in-time`; Azure:
   Flexible Server restore; GCP: Cloud SQL clone to timestamp).
3. Update the database URL secret; External Secrets refreshes within an hour
   (or force: `kubectl annotate externalsecret gxp-agent-runtime-database force-sync=$(date +%s) --overwrite`).
4. Scale back up and run `/v1/audit/verification`; it must report
   `intact: true`.
5. Requests submitted between the restore point and the incident are lost;
   compare the latest exported audit events (below) with the restored chains
   and record the gap as a deviation. Validated systems can be queried by
   idempotency key to reconcile executions.

## Audit and evidence exports

Export audit chains daily to the Object Lock bucket so a database loss
cannot erase evidence:

```bash
psql "$DATABASE_URL" -c "\copy (SELECT document FROM audit_events WHERE timestamp >= now() - interval '1 day' ORDER BY chain_id, sequence) TO STDOUT" \
  | gzip | aws s3 cp - "s3://<evidence bucket>/audit/$(date +%F).jsonl.gz"
```

Each line is a complete signed event; chains can be verified offline with
agentic-core `verify_chain` and the audit public key from
`/.well-known/jwks.json`.

## Region loss

Restore the latest cross-region snapshot (enable automated snapshot copy on
RDS), apply Terraform in the recovery region, deploy the chart with the same
signing keys (replicated secrets), and repoint DNS. Validated systems must be
available in the recovery region; otherwise agent actions stay blocked.

## Key loss

Losing the record or audit private key does not lose evidence: records stay
verifiable with the public key. Generate new keys per
[key rotation](key-rotation.md) and keep the old public keys in
`trusted_public_keys_dir`.
