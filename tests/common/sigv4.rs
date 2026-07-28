//! A minimal AWS SigV4 signer for raw S3 requests.
//!
//! The black-box gate test has to reach **every** operation s3s can route, and an SDK
//! cannot get there: it exposes one typed builder per operation, so covering the tail
//! means one hand-written call per op, and it has no way at all to express `PostObject`
//! (a browser form upload). Driving raw HTTP instead lets the test be table-driven off
//! the route table extracted from s3s itself.
//!
//! The signature must be *real*: s3s verifies it before it resolves the route, so a
//! bad signature produces a 403 that looks exactly like a gate denial. That failure
//! mode would make the whole file pass vacuously, which is why every assertion in
//! `gate_blackbox.rs` checks the error *body* names the operation, and why there are
//! positive controls signed by this same code.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub const REGION: &str = "us-east-1";
pub const SERVICE: &str = "s3";

/// A request to sign. Header names must be lowercase; all of them are signed.
pub struct RawRequest {
    pub method: &'static str,
    /// Decoded path, e.g. `/reports/2024/q1.csv`.
    pub path: String,
    /// Decoded query pairs. A valueless S3 sub-resource (`?acl`) is `("acl", "")`.
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl RawRequest {
    pub fn new(method: &'static str, path: impl Into<String>) -> Self {
        RawRequest {
            method,
            path: path.into(),
            query: Vec::new(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    #[must_use]
    pub fn query(mut self, k: &str, v: &str) -> Self {
        self.query.push((k.to_string(), v.to_string()));
        self
    }

    #[must_use]
    pub fn header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.to_ascii_lowercase(), v.to_string()));
        self
    }

    #[must_use]
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// The request line + query as it goes on the wire.
    pub fn url(&self, base: &str) -> String {
        let path = uri_encode(&self.path, false);
        if self.query.is_empty() {
            return format!("{base}{path}");
        }
        let qs = self
            .query
            .iter()
            .map(|(k, v)| format!("{}={}", uri_encode(k, true), uri_encode(v, true)))
            .collect::<Vec<_>>()
            .join("&");
        format!("{base}{path}?{qs}")
    }

    /// Sign with SigV4 header authentication and return every header to send.
    ///
    /// `host` must be exactly the `Host` the client will put on the wire, because it is
    /// part of the canonical request.
    pub fn sign(&self, host: &str, access_key: &str, secret_key: &str) -> Vec<(String, String)> {
        let now = chrono::Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date = now.format("%Y%m%d").to_string();
        let payload_hash = hex::encode(Sha256::digest(&self.body));

        let mut signed: Vec<(String, String)> = vec![
            ("host".into(), host.to_string()),
            ("x-amz-content-sha256".into(), payload_hash.clone()),
            ("x-amz-date".into(), amz_date.clone()),
        ];
        signed.extend(self.headers.iter().cloned());
        signed.sort_by(|a, b| a.0.cmp(&b.0));

        let canonical_headers: String = signed
            .iter()
            .map(|(k, v)| format!("{k}:{}\n", v.trim()))
            .collect();
        let signed_header_names = signed
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>()
            .join(";");

        let mut encoded_query: Vec<(String, String)> = self
            .query
            .iter()
            .map(|(k, v)| (uri_encode(k, true), uri_encode(v, true)))
            .collect();
        encoded_query.sort();
        let canonical_query = encoded_query
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");

        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            self.method,
            uri_encode(&self.path, false),
            canonical_query,
            canonical_headers,
            signed_header_names,
            payload_hash,
        );

        let scope = format!("{date}/{REGION}/{SERVICE}/aws4_request");
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );
        let signature = hex::encode(hmac(
            &signing_key(secret_key, &date),
            string_to_sign.as_bytes(),
        ));

        let mut out = signed;
        out.push((
            "authorization".into(),
            format!(
                "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, \
                 SignedHeaders={signed_header_names}, Signature={signature}"
            ),
        ));
        out
    }
}

/// The signature over a base64 POST policy — the only authentication a browser form
/// upload carries. `PostObject` is unreachable any other way, and it is the operation
/// whose s3s default *forwards* rather than 501s, so it is the one most worth reaching.
pub fn sign_post_policy(policy_b64: &str, secret_key: &str, date: &str) -> String {
    hex::encode(hmac(&signing_key(secret_key, date), policy_b64.as_bytes()))
}

fn signing_key(secret_key: &str, date: &str) -> Vec<u8> {
    let k = hmac(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    let k = hmac(&k, REGION.as_bytes());
    let k = hmac(&k, SERVICE.as_bytes());
    hmac(&k, b"aws4_request")
}

fn hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// AWS's URI encoding: unreserved characters pass through, everything else is
/// percent-encoded uppercase. `/` is preserved in paths and encoded in query values —
/// matching `s3s::sig_v4::methods::uri_encode`, which is what the gateway verifies with.
pub fn uri_encode(input: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'~' | b'.' => {
                out.push(b as char);
            }
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Standard base64 with padding. Needed only for the POST policy document; pulling in a
/// base64 crate for 20 lines would be a dependency for a test fixture.
pub fn base64(input: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            A[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            A[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}
