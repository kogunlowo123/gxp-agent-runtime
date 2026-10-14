# Runbook: periodic review of a validated system

Each system has a review interval (30 to 1095 days). When the review is
overdue, policy rule `deny-periodic-review-overdue` blocks every agent
action against the system and `GxpPeriodicReviewOverdue` fires.

## Generate

A system owner or QA generates the review for the period since the last one:

```bash
curl -s -X POST "$GXP/v1/periodic-reviews" -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"system_id":"lims-prod","period_start":"2026-01-01T00:00:00Z","period_end":"2026-10-01T00:00:00Z"}'
```

The review contains: requests by status, completed and failed executions,
failure rate, signatures by meaning, ALCOA+ failures in records, definitions
validated and retired in the period, and the audit-trail verification
result. Findings are raised for audit integrity failure, failure rate above
5%, any record ALCOA+ failure, expired approvals, and an already overdue
review. The conclusion is `remains-validated` or `remediation-required`.

## Review and approve

1. QA reads the review and the linked records, raises deviations or CAPAs
   for findings.
2. QA (not the person who generated it) signs with meaning `review` using the
   signing ceremony.
3. Approval sets the system's `last_reviewed_at` to the signature time.
   `remains-validated` keeps or restores the system to `validated`;
   `remediation-required` sets it to `suspended` and agent actions stop.
4. After remediation, generate and approve a new review covering the
   remediation period; a `remains-validated` conclusion restores the system.

Store the approved review JSON in the evidence bucket with the system's
periodic review record.
