# Cost and scalability

## Load profile

GxP agent traffic is modest in volume and dominated by reads: catalog
lookups and assessments outnumber submissions, and most submissions are
low-risk reads. The expensive path is the human approval, measured in
minutes, not the runtime. The runtime is sized for latency and availability,
not throughput.

## Scaling

| Dimension | Mechanism |
|---|---|
| Request concurrency | Stateless pods behind a Service; HPA on CPU (3-10 replicas) |
| Database | Single PostgreSQL primary; every write is small (one JSON document plus index columns); add read replicas for reporting if review queries grow |
| Validated-system calls | Bounded by each system's own capacity; the connector applies timeouts and backoff, never parallel retries |
| Audit | One chain per process; appends are serialized per process only, so replicas do not contend |
| Approval concurrency | Compare-and-swap on request revision; concurrent signers converge without locks |

The performance suite (`tests/performance`) enforces budgets for risk
classification plus ALCOA+ checks (< 5 ms) and a full autonomous round trip
including the signed record (< 500 ms with SQLite). `locustfile.py` drives a
staging deployment.

## Cost drivers (AWS reference)

| Component | Driver | Notes |
|---|---|---|
| EKS pods | 3 x (0.25-1 vCPU, 384-768 MiB) | Usually fits on shared platform nodes |
| RDS PostgreSQL Multi-AZ | Instance class (default `db.r6g.large`) and storage | Largest line item; a smaller class is adequate for most sites |
| S3 Object Lock | Evidence volume x retention (default 10 years) | Validation packages and daily audit exports are small |
| KMS, Secrets Manager | Per key and per secret | Negligible |
| Data transfer | Calls to validated systems | Usually in-region |

The runtime calls no LLM: there is no per-token cost in the control path.
Agents' own model costs are outside this service.

## Trade-offs

- Strong consistency (CAS, write-ahead audit, read-back verification) adds
  a few database round trips per action; acceptable for GxP volumes and
  required for evidence.
- Per-process audit chains avoid cross-replica coordination at the cost of
  many short chains; verification handles any number of chains.
