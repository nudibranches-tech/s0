# ADR-011: Summarised audit for platform identities the control plane names

- **Status**: Accepted — implemented (src/audit/summary.rs, src/audit/sink.rs, src/audit/record.rs, src/pdp/bundle.rs, src/access/mod.rs)
- **Date**: 2026-11-10
- **Owners**: gateway team (this repo); listing the identities is control-plane integration
- **Related**: `src/audit/summary.rs` (`Summaries`), `src/audit/sink.rs` (`AuditSink::emit`,
  `Worker::close_summaries`), `src/audit/record.rs` (`AccessSummary`), `src/pdp/bundle.rs`
  (`Bundle::audit_summary_subjects`), `tests/audit_summary.rs`; amends ADR-002 D1

## Context

ADR-002 fixes one decision record per request, attributed to the end user. A platform job
that reads whole buckets breaks the assumption behind that granularity. A backup copier
reading every object of a tenant through the gateway is one identity, doing one thing, a
million times.

- **Noise.** The trail fills with records that say the same thing, and a reader looking
  for a person's access has to page past them.
- **Loss.** The sink never holds a request: on a full queue it drops the record
  (`s0_audit_queue_dropped_total`). A copy of many small objects at a parallelism of 16 to
  64 can outrun a worker that ships one batch at a time. Records are then dropped
  whoever's request they were, which in a regulated deployment is an incident of its own.

Not auditing such a job is not an option. Its identity is the broadest reader in the
organization, and a leaked credential for it must still leave a trail.

## Decision

1. **Service accounts named by the control plane.** `org_settings.audit_summary_subjects`
   lists `sa:<client id>` keys (`principal_subject_key`), read once per bundle revision.
   Any other key, `user:<sub>` included, is ignored with a warning: a person's trail stays
   one record per request (ADR-002), whatever the bundle says. The request must also carry
   a service-account principal. Absent, or anything but an array of strings, the list
   summarises nobody: a list that cannot be read never makes the trail coarser.
2. **Only what cannot widen anything is summarised.** That is an allowed `read_objects`,
   `list_objects` or `read` request by a listed account, whose forward succeeded. A denial,
   a failed forward, a request that was never forwarded and every other verb keep their
   own record.
3. **One record per operation and session.** The window key is the subject, organization,
   tenant, backend, bucket, verb, s3s operation, HTTP method, access-key id and whether the
   request was presigned. A `HEAD` never hides among `GET`s, and a second session or a
   presigned URL using the account's key lands in a window of its own.
4. **When a window closes.** It closes when it has been open for
   `audit.summary_window_secs` (60 by default) or stands for `audit.summary_max_requests`
   requests (10 000 by default), whichever comes first. Both must be positive, checked at
   load. A full window waits for the worker beside the open ones, and the next request
   opens a new one.
5. **Its own path, the same envelope.** A summary's `path` is `s3/authz/summary`, as a gate
   record has its own. Its input is the first request's, without object, prefix, query or
   headers, and its `result` carries no obligations, so it names no single object or
   listing. It carries `gateway.summary`: `operation`, `requests`, `first_at` and `last_at`
   (the earliest and latest decision times), `access_key_id`, `presigned`. Its
   `decision_id` is the first request's.
6. **Never through the queue.** Requests are folded before the queue. The worker ships
   closed windows on its flush tick. On shutdown it takes every summary before draining
   the queue, and from then on nothing is folded: a late request keeps its own record, so
   its loss is counted like any other.
7. **Counted.** `s0_audit_summarized_total` counts the requests folded, and
   `s0_audit_summaries_emitted_total` the records handed on. A summary that is lost (spill
   at its cap, hard kill) counts as one record in `s0_audit_dropped_total`.
8. **Rollout order.** A consumer must understand `s3/authz/summary` before its control plane
   lists any account. Until a bundle lists one, nothing changes: no record is folded, and
   the wire shape of every record is the one ADR-002 fixes.

## Alternatives considered

- **Exempting the identity from audit.** Rejected: it removes the trail of the broadest
  reader, which is the one a leak investigation needs most.
- **Sampling one request in N.** Rejected: a sampled trail cannot say how much was read,
  and the requests it skips are skipped silently.
- **A gateway-side list in the config file.** Rejected: which identities are platform jobs
  is the control plane's knowledge, and a list in a ConfigMap drifts from the grants that
  give those identities their reach. In the bundle it changes with the same revision.
- **Summarising denials too.** Rejected: a denial of a platform identity is either a
  deliberate deny or a misconfiguration, and in both cases the detail is the point.
- **Keeping `s3/authz/decision` for summaries.** Rejected: a consumer that ignores the
  `gateway.summary` block would count N requests as one, silently.

## Consequences

- A listed account's reads are visible as volume per operation, session and bucket, not
  per object. The object keys it read are not in the trail, by design; the control plane
  keeps its own per-run record of what such a job did.
- A leaked key used from elsewhere shows as another access-key id or a presigned window.
  A stolen session token used alongside the job, with the same key and no presign, falls
  in the job's window, visible only as volume beyond what the job reports.
- A graceful shutdown ships every summary. A hard kill can lose the open windows, up to
  `summary_window_secs` of a listed account's reads.
- The `decision_id` handed to a client as its request id resolves to the summary for the
  first request of a window, and to nothing for the later ones. This only affects
  successful reads by a listed account; an error always has its own record.
