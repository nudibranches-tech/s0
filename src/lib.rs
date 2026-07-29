//! s0 — S3 authorization gateway.
//!
//! An S3-compatible **authorization gateway**: it terminates the S3
//! protocol, makes a per-request OPA decision on the *parsed* request, and re-issues
//! allowed requests to a backend under a per-tenant credential. Enforcement lives in
//! the gateway's own policy — never in a backend-native feature — so one model
//! holds uniformly over Ceph RGW and remote S3, with one per-user audit trail.
//!
//! Module map:
//! - [`authz`]    — the OPA input contract and the decision type: the core seam.
//! - [`pdp`]      — policy decision point: regorus + sidecar engines, revision cache.
//! - [`auth`]     — identity / credential authority + own STS.
//! - [`access`]   — the OPA gate: deny-by-default `check` + typed per-op hooks.
//! - [`proxy`]    — per-(backend,tenant) client pool + dispatch.
//! - [`audit`]    — one reasoned decision record per request.
//! - [`gateway`]  — assembled shared context.
//! - [`server`]   — S3 front + hyper serving.
//! - [`admin`]    — health / readiness / metrics, on a listener of its own.
//! - [`internal`] — the **authenticated** console-mediated session mint, on a
//!   listener of its own (never the admin listener, never the data plane).
//! - [`shutdown`] — the one signal every listener drains on.
//! - [`secret`]   — `Secret<T>`: a configured credential that cannot be printed.

pub mod access;
pub mod admin;
pub mod audit;
pub mod auth;
pub mod authz;
pub mod bundle_refresh;
pub mod config;
pub mod error;
pub mod gateway;
pub mod identity;
pub mod internal;
pub mod mint;
pub mod model;
pub mod pdp;
pub mod proxy;
pub mod secret;
pub mod server;
pub mod shutdown;
