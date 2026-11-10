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

1. **Named by the control plane.** `org_settings.audit_summary_subjects` lists subject keys
   in the projection's key space (`principal_subject_key`: `sa:<client id>`,
   `user:<sub>`). It is read once per bundle revision. Absent, or anything but an array of
   strings, summarises nobody: a list that cannot be read never makes the trail coarser.
2. **Only what cannot widen anything is summarised.** That is an allowed `read_objects`,
   `list_objects` or `read` request by a listed subject, whose forward succeeded. A
   denial, a failed forward, a request that was never forwarded and every other verb keep
   their own record.
3. **One record per subject, verb, bucket and window.** The key also carries the tenant,
   the organization and the backend. A window ships when it has been open for
   `audit.summary_window_secs` (60 by default) or when it stands for
   `audit.summary_max_requests` requests (10 000 by default), whichever comes first. Both
   must be positive, checked at load.
4. **Same envelope, one more block.** A summary is the first request's record with its
   object, prefix, query and header subset removed, so it cannot be read as naming one
   object. It carries `gateway.summary`: `requests`, `first_at`, `last_at`. Its
   `decision_id` is the first request's. A consumer that ignores the block still reads a
   well-formed decision record.
5. **No queue slot.** Requests are folded before the queue. The worker ships a closed
   window on its flush tick and every open one on shutdown, ahead of the final flush. A
   window that fills ships through the queue, like any record.
6. **Counted.** `s0_audit_summarized_total` counts the requests folded, and
   `s0_audit_summaries_emitted_total` the records. A summary that is lost counts in
   `s0_audit_dropped_total` like any record.

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

## Consequences

- A listed identity's reads are visible as volume per bucket and window, not per object.
  The object keys it read are not in the trail, by design. The control plane keeps its own
  per-run record of what such a job did.
- Up to one window of summaries can be lost on a hard kill. A graceful shutdown ships them.
- The `decision_id` handed to a client as its request id resolves to the summary for the
  first request of a window, and to nothing for the later ones. This only affects successful
  reads by a listed identity; an error always has its own record.
