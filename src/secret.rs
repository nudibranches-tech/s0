//! `Secret<T>` — a value that cannot be printed.
//!
//! Every plaintext credential this process holds arrives through configuration:
//! the STS master-key ring and token signing key, each tenant's backend owner secret,
//! and every long-lived static access key's secret. All of them live in structs that
//! `derive(Debug)`, and this deployment logs JSON into a shared pipeline. One
//! `tracing::debug!(?cfg)`, one `unwrap()` on a config-carrying `Result`, one
//! `#[derive(Debug)]` on an enclosing error type, and the whole key ring is in
//! VictoriaLogs — which in a hospital or government tenancy is an incident, not a
//! papercut. That is the same defect class the master plan records as M0 issue 2
//! ("live session tokens and decoded JWT claims logged at `info!`") and M0 issue 3.
//!
//! A hand-written `Debug` on each config struct would fix today's structs and nothing
//! else: the next field someone adds is plaintext again unless they remember. So the
//! redaction lives on the *type*. A `Secret<String>` prints as `Secret(<redacted>)`
//! wherever it appears — inside a config, inside an error, inside a tuple, at any
//! nesting depth — and the only way to the plaintext is to write [`Secret::expose`],
//! which is greppable and reviewable.
//!
//! Deliberately absent:
//!
//! - **`Display`** — so a secret cannot be interpolated with `{}`. `expose()` is the
//!   only exit.
//! - **`Serialize`** — a config is deserialized, never written back. Adding it would
//!   put the plaintext into any JSON the struct lands in, which is the same pipeline
//!   this type exists to keep it out of.

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
/// fields beside it. Adopting the type must not make constructing a config awkward, or
/// the next struct will quietly go back to `String`.
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
        // The wire form is unchanged: every shipped config, ConfigMap and Secret keeps
        // working. A `{"v": {"secret": "..."}}` wrapper would have been a breaking
        // config change for no benefit.
        #[derive(Deserialize)]
        struct Holder {
            key: Secret<String>,
        }
        let h: Holder = serde_json::from_str(r#"{"key":"abc"}"#).unwrap();
        assert_eq!(h.key.expose(), "abc");
    }
}
