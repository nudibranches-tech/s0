//! `Secret<T>` — a value that cannot be printed.
//!
//! Every plaintext credential this process holds arrives through configuration — the STS
//! key ring, each tenant's backend owner secret, every static access key — and lives in a
//! struct that `derive(Debug)`. One `tracing::debug!(?cfg)` or one `#[derive(Debug)]` on
//! an enclosing error type would put the whole key ring in the log aggregator. A
//! hand-written `Debug` per struct only fixes today's fields, so the redaction lives on
//! the *type*: [`Secret::expose`] is the one greppable exit. Deliberately absent are
//! `Display`, so a secret cannot be interpolated with `{}`, and `Serialize`, which would
//! put the plaintext into any JSON the enclosing struct lands in.

use std::fmt;

use serde::Deserialize;

/// A configured secret. See the module docs for why `Debug` is redacted and why there
/// is no `Display` and no `Serialize`.
#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    pub fn new(value: T) -> Self {
        Secret(value)
    }

    /// The plaintext. Named to be conspicuous at the call site and in review: every
    /// use of a secret in the clear is one `grep expose()` away.
    pub fn expose(&self) -> &T {
        &self.0
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Debug for Secret<T> {
    /// Prints no part of the value — not a prefix, not a length. A length is a real
    /// hint about a key, and a prefix of a hex master key is a piece of the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl<T> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Secret(value)
    }
}

/// So `"…".into()` still reaches a `Secret<String>` field, as it does for the `String`
/// fields beside it: if the type makes constructing a config awkward, the next struct
/// quietly goes back to `String`.
impl From<&str> for Secret<String> {
    fn from(value: &str) -> Self {
        Secret(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_never_prints_itself() {
        let s = Secret::new("hunter2-super-secret".to_string());
        for rendered in [
            format!("{s:?}"),
            format!("{s:#?}"),
            format!("{:?}", vec![&s]),
        ] {
            assert!(
                !rendered.contains("hunter2"),
                "the plaintext leaked into a Debug rendering: {rendered}"
            );
        }
        assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
        // Not even the length, which is a real hint about a key.
        assert!(!format!("{s:?}").contains("20"));
        assert_eq!(s.expose(), "hunter2-super-secret");
    }

    #[test]
    fn a_secret_deserializes_from_the_bare_scalar() {
        // The wire form is the bare scalar: a `{"v": {"secret": "..."}}` wrapper would be
        // a breaking config change for no benefit.
        #[derive(Deserialize)]
        struct Holder {
            key: Secret<String>,
        }
        let h: Holder = serde_json::from_str(r#"{"key":"abc"}"#).unwrap();
        assert_eq!(h.key.expose(), "abc");
    }
}
