//! The s3s route table: the smallest request that resolves to each operation.
//!
//! Extracted from the pinned crate's own `resolve_route`
//! (`~/.cargo/registry/src/*/s3s-0.14.1/src/ops/generated.rs`) and checked in, because
//! s3s exposes no enumeration of its routes. Two files need it and for opposite
//! reasons, which is why it lives here rather than in either:
//!
//! - `tests/gate_blackbox.rs` drives every row over real HTTP, to prove `check` refuses
//!   every operation `OP_TABLE` does not enforce;
//! - `tests/golden_capture.rs` uses the method and URI so a captured `RequestMeta` is
//!   the one a real client produces, not `GET /`.
//!
//! `tests/op_coverage.rs` pins the s3s version, so a dependency bump fails there first
//! and this table is regenerated with the operation list.

use std::sync::OnceLock;

const ROUTES: &str = include_str!("../data/s3s-0.14.1-routes.tsv");

/// One operation's minimal reachable request.
#[derive(Debug, Clone)]
pub struct Route {
    pub op: &'static str,
    pub method: &'static str,
    pub path: &'static str,
    /// Decoded query pairs. A valueless S3 sub-resource (`?acl`) is `("acl", "")`.
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    /// `PostObject`: a browser form upload, authenticated by a signed POST policy and
    /// routed before `resolve_route` is ever consulted.
    pub multipart: bool,
}

impl Route {
    /// Path plus query, i.e. what lands in `S3Request::uri`.
    pub fn request_target(&self) -> String {
        if self.query.is_empty() {
            return self.path.to_string();
        }
        let qs = self
            .query
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        format!("{}?{qs}", self.path)
    }
}

pub fn all() -> &'static [Route] {
    static TABLE: OnceLock<Vec<Route>> = OnceLock::new();
    TABLE.get_or_init(parse)
}

/// The row for one operation. Panics rather than returning `None`: every s3s operation
/// has a row, and a missing one means the table is stale.
pub fn route(op: &str) -> &'static Route {
    all()
        .iter()
        .find(|r| r.op == op)
        .unwrap_or_else(|| panic!("{op} has no row in the s3s route table"))
}

fn parse() -> Vec<Route> {
    let rows: Vec<Route> = ROUTES
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            assert_eq!(f.len(), 5, "malformed route row: {line:?}");
            let query = f[3]
                .split('&')
                .filter(|s| !s.is_empty())
                .map(|kv| {
                    let (k, v) = kv.split_once('=').expect("query pair");
                    (k.to_string(), v.to_string())
                })
                .collect();
            let multipart = f[4] == "@multipart";
            let headers = if multipart {
                Vec::new()
            } else {
                f[4].split(',')
                    .filter(|s| !s.is_empty())
                    .map(|kv| {
                        let (k, v) = kv.split_once('=').expect("header pair");
                        (k.to_string(), v.to_string())
                    })
                    .collect()
            };
            Route {
                op: f[0],
                method: f[1],
                path: f[2],
                query,
                headers,
                multipart,
            }
        })
        .collect();
    assert_eq!(
        rows.len(),
        99,
        "the route table must cover every s3s 0.14.1 operation"
    );
    rows
}
