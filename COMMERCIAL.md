# Commercial license

s0 is **source-available, not open source**. Until the change date
(`2030-08-18`), running it in production inside a company requires a paid
commercial license from Nudibranches. Everything else — reading the code,
modifying it, redistributing it, and using it outside production — is free
under the [Business Source License 1.1](LICENSE).

Write to **<contact@nudibranches.tech>** for terms and pricing.

## Do you need one?

| What you are doing | License |
|---|---|
| Reading, forking, patching, redistributing the source | Free |
| Evaluating, developing, testing, CI, benchmarking, security research, demos — including against copies of production data | Free, companies included |
| Production use by an individual on their own behalf, a non-profit, a school, or a public research body | Free |
| Production use by a company, **including a purely internal deployment** that only secures your own object storage | **Paid** |
| Production use on behalf of a company by a contractor, subsidiary, or cloud partner | **Paid** |
| Offering s0 to third parties as a hosted or managed service | **Paid** |

"Production" means s0 is relied upon to authorize access to a system that
serves your users or customers. A staging environment that no customer traffic
reaches is not production; a staging environment that gates real customer data
is.

The table is a reading aid. [`LICENSE`](LICENSE) is what governs, and its
definitions of *Non-Commercial Use* and *Commercial Entity* are the ones that
count.

## What the commercial license grants

The right to make production use of the covered versions of s0, for the
licensed legal entity and its affiliates, for the term of the agreement,
without the restrictions of the Additional Use Grant. Support, response times,
and any other commitment are whatever the signed agreement says — the BSL
grants no warranty and no support, and neither does this page.

## Pricing

Not published. Pricing depends on how much of your access path s0 sits on, so
it is quoted per organization. Include in your email:

- the legal entity that would hold the license, and its affiliates in scope;
- how many production gateways, environments, and object-storage backends;
- whether the traffic is internal only, or customer-facing;
- roughly how many buckets and how much request volume;
- your target start date, and what support you expect.

## Already in production without one?

Write to us and we will regularize it. Getting you licensed is the point; a
missed license is a conversation, not an ambush.

## After the change date

On `2030-08-18` the versions covered by the current [`LICENSE`](LICENSE) become
available under Apache-2.0 and the commercial license stops being necessary for
them. Versions released later carry their own change date and remain under BSL
until it passes. See [`docs/releasing.md`](docs/releasing.md).
