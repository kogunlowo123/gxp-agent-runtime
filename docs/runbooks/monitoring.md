# Runbook: monitoring

## Signals

| Signal | Source | Normal |
|---|---|---|
| `gxp:request_errors:ratio_5m` | Recording rule | < 0.001 |
| p99 latency by route | `gxp_http_request_duration_seconds` | submit < 2 s, challenges < 300 ms |
| `gxp_action_requests_total{outcome,priority}` | Counter | Denied share stable per release |
| `gxp_executions_total{system,status}` | Counter | Failed close to zero |
| `gxp_execution_duration_seconds{system}` | Histogram | Within the system's own SLO |
| `gxp_electronic_signatures_total{meaning}` / `gxp_signature_failures_total{reason}` | Counters | Failures rare |
| `gxp_alcoa_failures_total{principle,stage}` | Counter | `stage="record"` always zero |
| `gxp_pending_requests_expired_total` | Counter | Low |
| `gxp_systems_review_overdue` | Gauge | 0 |
| `gxp_agent_channel_calls_total{channel,operation}` | Counter | REST/MCP/A2A mix |
| Traces | OTLP | Span per request with DB and outbound spans |
| Logs | JSON on stdout | `correlation_id` on every line |

Alerts: `configs/prometheus/alerts.yaml`. Dashboard:
`configs/grafana/gxp-agent-runtime.json`.

## Latency

1. Dashboard "Validated-system call p99": if one system is slow, the delay
   is downstream; check the system's status page and connector retries
   (`attempts` in the `action.execute` audit event).
2. All routes slow: check PostgreSQL CPU/connections, then pod CPU
   throttling; scale up to the HPA ceiling if CPU-bound.
3. Signing slow: check IdP JWKS reachability (`cannot fetch signing keys`).

## Approval backlog

`GxpApprovalsExpiring` means agents' requests time out before people sign.
List the queue (`GET /v1/action-requests?status=pending_approval`) per system,
inform the process owner, and consider whether a definition's risk inputs
(impact, detectability) are overstated; changing them is a new definition
version validated by QA, not a configuration change.

## Tracing a request

Every response has `X-Correlation-ID`, also stored in audit events. To
follow one request across logs and audit:

```sql
SELECT chain_id, sequence, action, document::json->>'outcome'
FROM audit_events
WHERE document::json->>'correlation_id' = '<id>'
ORDER BY timestamp;
```
