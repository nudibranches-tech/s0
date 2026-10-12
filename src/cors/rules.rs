//! CORS rule evaluation, with S3's contract: the first rule in the configuration that
//! matches wins.
//!
//! A rule is a set of allowed origins, methods and request headers, plus what to expose
//! and how long a browser may cache the answer. Origins and headers may carry `*`
//! wildcards. S3 limits each entry to one wildcard; a pattern with several is matched as a
//! glob here, which can only differ for a configuration S3 itself would have refused to
//! store.
//!
//! The evaluation is pure: it sees the request's origin, method and requested headers and
//! the rules, and nothing else. It decides what a response may say, never whether a
//! request is allowed.

use s3s::dto::CORSRule;

/// What `Access-Control-Allow-Origin` says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowOrigin {
    /// The rule allows `*`, so the answer is `*` whoever asked.
    Any,
    /// The rule names origins, so the answer echoes the one that asked.
    Origin(String),
}

impl AllowOrigin {
    pub fn as_header_value(&self) -> &str {
        match self {
            AllowOrigin::Any => "*",
            AllowOrigin::Origin(origin) => origin,
        }
    }
}

/// What a matching rule lets a response say about an actual (non-preflight) request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub allow_origin: AllowOrigin,
    pub expose_headers: Vec<String>,
}

/// What a matching rule lets the answer to a preflight say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightGrant {
    pub grant: Grant,
    /// Every method the rule allows, as S3 lists them.
    pub allow_methods: Vec<String>,
    /// The requested headers, all of which the rule allows. Echoed rather than copied
    /// from the rule, so a `*` rule answers with names the browser can compare against.
    pub allow_headers: Vec<String>,
    pub max_age_seconds: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    allowed_origins: Vec<String>,
    allowed_methods: Vec<String>,
    /// Lowercased: header names are case-insensitive.
    allowed_headers: Vec<String>,
    expose_headers: Vec<String>,
    max_age_seconds: Option<u32>,
}

impl Rule {
    fn from_dto(rule: &CORSRule) -> Self {
        Rule {
            allowed_origins: rule.allowed_origins.clone(),
            allowed_methods: rule.allowed_methods.clone(),
            allowed_headers: rule
                .allowed_headers
                .iter()
                .flatten()
                .map(|h| h.to_ascii_lowercase())
                .collect(),
            expose_headers: rule.expose_headers.clone().unwrap_or_default(),
            max_age_seconds: rule.max_age_seconds.and_then(|s| u32::try_from(s).ok()),
        }
    }

    fn allows_origin(&self, origin: &str) -> bool {
        self.allowed_origins.iter().any(|p| glob(p, origin))
    }

    fn allows_method(&self, method: &str) -> bool {
        self.allowed_methods.iter().any(|m| m == method)
    }

    fn allows_header(&self, header: &str) -> bool {
        self.allowed_headers.iter().any(|p| glob(p, header))
    }

    fn allow_origin(&self, origin: &str) -> AllowOrigin {
        if self.allowed_origins.iter().any(|o| o == "*") {
            AllowOrigin::Any
        } else {
            AllowOrigin::Origin(origin.to_string())
        }
    }

    fn grant(&self, origin: &str) -> Grant {
        Grant {
            allow_origin: self.allow_origin(origin),
            expose_headers: self.expose_headers.clone(),
        }
    }
}

/// A bucket's CORS configuration: its rules, in the order the bucket owner wrote them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CorsConfig {
    rules: Vec<Rule>,
}

impl CorsConfig {
    pub fn from_rules(rules: &[CORSRule]) -> Self {
        CorsConfig {
            rules: rules.iter().map(Rule::from_dto).collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The answer to a preflight, or `None` when no rule allows it.
    ///
    /// A rule matches only if it allows the origin, the requested method **and every**
    /// requested header; a rule that allows two of the three is skipped in favour of a
    /// later one, as S3 does. `request_headers` are lowercased, see
    /// [`parse_request_headers`].
    pub fn preflight(
        &self,
        origin: &str,
        method: &str,
        request_headers: &[String],
    ) -> Option<PreflightGrant> {
        self.rules
            .iter()
            .find(|r| {
                r.allows_origin(origin)
                    && r.allows_method(method)
                    && request_headers.iter().all(|h| r.allows_header(h))
            })
            .map(|r| PreflightGrant {
                grant: r.grant(origin),
                allow_methods: r.allowed_methods.clone(),
                allow_headers: request_headers.to_vec(),
                max_age_seconds: r.max_age_seconds,
            })
    }

    /// What the response to an actual request with this origin and method may carry, or
    /// `None` when no rule allows it. There are no requested headers to check: the
    /// browser decided to send the request on the strength of the preflight.
    pub fn actual(&self, origin: &str, method: &str) -> Option<Grant> {
        self.rules
            .iter()
            .find(|r| r.allows_origin(origin) && r.allows_method(method))
            .map(|r| r.grant(origin))
    }
}

/// The header names in an `Access-Control-Request-Headers` value, lowercased and trimmed.
pub fn parse_request_headers(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect()
}

/// `*` matches any run of characters, including none; every other character matches
/// itself. The pieces between wildcards must appear in order, the first as a prefix and
/// the last as a suffix that does not overlap what came before it.
fn glob(pattern: &str, text: &str) -> bool {
    let segments: Vec<&str> = pattern.split('*').collect();
    let Some((head, tail)) = segments.split_first() else {
        return false;
    };
    let Some((last, middle)) = tail.split_last() else {
        return pattern == text;
    };
    let Some(mut rest) = text.strip_prefix(head) else {
        return false;
    };
    for segment in middle {
        match rest.find(segment) {
            Some(at) => rest = &rest[at + segment.len()..],
            None => return false,
        }
    }
    rest.ends_with(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(origins: &[&str], methods: &[&str], headers: &[&str]) -> CORSRule {
        CORSRule {
            allowed_origins: origins.iter().map(|s| s.to_string()).collect(),
            allowed_methods: methods.iter().map(|s| s.to_string()).collect(),
            allowed_headers: (!headers.is_empty())
                .then(|| headers.iter().map(|s| s.to_string()).collect()),
            ..Default::default()
        }
    }

    fn exposing(rule: CORSRule, headers: &[&str]) -> CORSRule {
        CORSRule {
            expose_headers: Some(headers.iter().map(|s| s.to_string()).collect()),
            ..rule
        }
    }

    fn aging(rule: CORSRule, seconds: i32) -> CORSRule {
        CORSRule {
            max_age_seconds: Some(seconds),
            ..rule
        }
    }

    fn config(rules: Vec<CORSRule>) -> CorsConfig {
        CorsConfig::from_rules(&rules)
    }

    fn hdrs(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_wildcard_matches_any_run_including_none() {
        for (pattern, text, want) in [
            ("*", "", true),
            ("*", "https://app.example.com", true),
            ("https://app.example.com", "https://app.example.com", true),
            ("https://app.example.com", "https://app.example.org", false),
            ("https://*.example.com", "https://app.example.com", true),
            ("https://*.example.com", "https://.example.com", true),
            ("https://*.example.com", "https://app.example.org", false),
            ("https://*.example.com", "http://app.example.com", false),
            ("x-amz-meta-*", "x-amz-meta-tag", true),
            ("x-amz-meta-*", "x-amz-meta-", true),
            ("x-amz-meta-*", "x-amz-met", false),
            ("a*a", "a", false),
            ("a*a", "aa", true),
            ("a*b*c", "abc", true),
            ("a*b*c", "axxbyyc", true),
            ("a*b*c", "acb", false),
            ("a*b*c", "ab", false),
            ("", "", true),
            ("", "a", false),
        ] {
            assert_eq!(glob(pattern, text), want, "{pattern:?} against {text:?}");
        }
    }

    #[test]
    fn an_origin_is_matched_exactly_and_case_sensitively() {
        let cfg = config(vec![rule(&["https://app.example.com"], &["PUT"], &[])]);
        assert!(cfg.actual("https://app.example.com", "PUT").is_some());
        assert!(cfg.actual("https://APP.example.com", "PUT").is_none());
        assert!(
            cfg.actual("https://app.example.com.evil.test", "PUT")
                .is_none()
        );
        assert!(cfg.actual("null", "PUT").is_none());
    }

    #[test]
    fn a_star_rule_answers_star_and_a_named_rule_echoes_the_origin() {
        let any = config(vec![rule(&["*"], &["PUT"], &[])]);
        assert_eq!(
            any.actual("https://a.test", "PUT").unwrap().allow_origin,
            AllowOrigin::Any
        );
        let named = config(vec![rule(
            &["https://a.test", "https://b.test"],
            &["PUT"],
            &[],
        )]);
        let granted = named.actual("https://b.test", "PUT").unwrap();
        assert_eq!(
            granted.allow_origin,
            AllowOrigin::Origin("https://b.test".into())
        );
        assert_eq!(granted.allow_origin.as_header_value(), "https://b.test");
        assert_eq!(AllowOrigin::Any.as_header_value(), "*");
        // A wildcard *pattern* is not the `*` rule: the answer still names the origin.
        let pattern = config(vec![rule(&["https://*.test"], &["PUT"], &[])]);
        assert_eq!(
            pattern
                .actual("https://c.test", "PUT")
                .unwrap()
                .allow_origin,
            AllowOrigin::Origin("https://c.test".into())
        );
    }

    #[test]
    fn a_method_the_rule_does_not_list_is_refused() {
        let cfg = config(vec![rule(&["*"], &["PUT"], &["content-type"])]);
        assert!(
            cfg.preflight("https://a.test", "PUT", &hdrs(&["content-type"]))
                .is_some()
        );
        assert!(
            cfg.preflight("https://a.test", "GET", &hdrs(&["content-type"]))
                .is_none()
        );
        assert!(cfg.preflight("https://a.test", "DELETE", &[]).is_none());
        assert!(cfg.actual("https://a.test", "GET").is_none());
        assert!(
            cfg.actual("https://a.test", "put").is_none(),
            "methods are case-sensitive, as S3's enumerated values are"
        );
    }

    #[test]
    fn every_requested_header_must_be_allowed() {
        let cfg = config(vec![rule(
            &["*"],
            &["PUT"],
            &["content-type", "x-amz-meta-*"],
        )]);
        assert!(cfg.preflight("https://a.test", "PUT", &[]).is_some());
        assert!(
            cfg.preflight(
                "https://a.test",
                "PUT",
                &hdrs(&["content-type", "x-amz-meta-k"])
            )
            .is_some()
        );
        assert!(
            cfg.preflight(
                "https://a.test",
                "PUT",
                &hdrs(&["content-type", "authorization"])
            )
            .is_none(),
            "one disallowed header refuses the whole preflight"
        );
    }

    #[test]
    fn header_names_are_case_insensitive_on_both_sides() {
        let cfg = config(vec![rule(&["*"], &["PUT"], &["Content-Type"])]);
        let requested = parse_request_headers("CONTENT-TYPE");
        assert_eq!(requested, hdrs(&["content-type"]));
        assert!(cfg.preflight("https://a.test", "PUT", &requested).is_some());
    }

    #[test]
    fn a_star_header_rule_allows_any_requested_header_and_echoes_them() {
        let cfg = config(vec![rule(&["*"], &["PUT"], &["*"])]);
        let requested = hdrs(&["content-type", "x-custom"]);
        let granted = cfg.preflight("https://a.test", "PUT", &requested).unwrap();
        assert_eq!(granted.allow_headers, requested);
    }

    #[test]
    fn a_rule_with_no_allowed_headers_refuses_a_preflight_that_asks_for_one() {
        let cfg = config(vec![rule(&["*"], &["PUT"], &[])]);
        assert!(cfg.preflight("https://a.test", "PUT", &[]).is_some());
        assert!(
            cfg.preflight("https://a.test", "PUT", &hdrs(&["content-type"]))
                .is_none()
        );
    }

    #[test]
    fn the_first_matching_rule_wins_and_a_partial_match_is_skipped() {
        let first = exposing(rule(&["https://a.test"], &["GET"], &[]), &["x-first"]);
        let second = exposing(
            rule(&["https://a.test"], &["PUT"], &["content-type"]),
            &["ETag"],
        );
        let third = exposing(rule(&["*"], &["PUT"], &["content-type"]), &["x-third"]);
        let cfg = config(vec![first, second, third]);

        // The first rule allows the origin but not the method, so it is skipped.
        let put = cfg
            .preflight("https://a.test", "PUT", &hdrs(&["content-type"]))
            .unwrap();
        assert_eq!(put.grant.expose_headers, vec!["ETag".to_string()]);
        assert_eq!(
            put.grant.allow_origin,
            AllowOrigin::Origin("https://a.test".into())
        );

        // Another origin falls through to the `*` rule.
        let other = cfg
            .preflight("https://z.test", "PUT", &hdrs(&["content-type"]))
            .unwrap();
        assert_eq!(other.grant.expose_headers, vec!["x-third".to_string()]);
        assert_eq!(other.grant.allow_origin, AllowOrigin::Any);

        // The first rule wins when it matches.
        let get = cfg.actual("https://a.test", "GET").unwrap();
        assert_eq!(get.expose_headers, vec!["x-first".to_string()]);
    }

    #[test]
    fn a_preflight_reports_the_rules_methods_expose_list_and_max_age() {
        let r = aging(
            exposing(
                rule(&["*"], &["PUT", "GET"], &["content-type"]),
                &["ETag", "x-amz-request-id"],
            ),
            3000,
        );
        let granted = config(vec![r])
            .preflight("https://a.test", "PUT", &hdrs(&["content-type"]))
            .unwrap();
        assert_eq!(granted.allow_methods, hdrs(&["PUT", "GET"]));
        assert_eq!(
            granted.grant.expose_headers,
            hdrs(&["ETag", "x-amz-request-id"])
        );
        assert_eq!(granted.max_age_seconds, Some(3000));
        assert_eq!(granted.allow_headers, hdrs(&["content-type"]));
    }

    #[test]
    fn a_negative_max_age_is_dropped() {
        let r = aging(rule(&["*"], &["PUT"], &[]), -1);
        let granted = config(vec![r])
            .preflight("https://a.test", "PUT", &[])
            .unwrap();
        assert_eq!(granted.max_age_seconds, None);
    }

    #[test]
    fn no_rules_allow_nothing() {
        let cfg = CorsConfig::default();
        assert!(cfg.is_empty());
        assert!(cfg.preflight("https://a.test", "PUT", &[]).is_none());
        assert!(cfg.actual("https://a.test", "PUT").is_none());
    }

    #[test]
    fn requested_headers_split_on_commas_and_drop_blanks() {
        assert_eq!(
            parse_request_headers(" Content-Type , x-amz-meta-a,, "),
            hdrs(&["content-type", "x-amz-meta-a"])
        );
        assert!(parse_request_headers("").is_empty());
        assert!(parse_request_headers(" , ").is_empty());
    }
}
