//! The virtual root, and paths that cannot escape it (ADR-009 D6).
//!
//! An account is confined to one `(bucket, prefix)`. The bucket is never a path component:
//! `/` is the root and nothing a client sends can name another bucket. Every path argument
//! is normalized here **before anything else** looks at it:
//!
//! 1. the bytes must be UTF-8;
//! 2. NUL, any control character and `\` are refused;
//! 3. relative paths resolve against `/` (the server keeps no working directory);
//! 4. runs of `/` collapse, `.` components drop, a trailing `/` drops;
//! 5. `..` is refused — except in `REALPATH`, which resolves it lexically and clamps at `/`;
//! 6. the key is `home.prefix + relative`, at most 1,024 bytes;
//! 7. an assertion that the key starts with `home.prefix` runs after mapping.
//!
//! No Unicode normalization: NFC and NFD forms of one name are two keys, as on the backend.

/// S3's own key-length ceiling.
pub const MAX_KEY_LEN: usize = 1024;

/// Why a path was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    /// Not valid UTF-8: no key can match it.
    NotUtf8,
    /// NUL, a control character, or `\`.
    ForbiddenChar,
    /// A `..` component outside `REALPATH`.
    DotDot,
    /// The mapped key exceeds [`MAX_KEY_LEN`].
    TooLong,
    /// The post-mapping assertion failed. Unreachable by construction; kept as defence in
    /// depth.
    Escape,
}

impl PathError {
    pub fn message(self) -> &'static str {
        match self {
            PathError::NotUtf8 => "invalid file name: not UTF-8",
            PathError::ForbiddenChar => "invalid file name: control character or backslash",
            PathError::DotDot => "'..' is not supported in paths; use an absolute path",
            PathError::TooLong => "file name too long",
            PathError::Escape => "path escapes the home directory",
        }
    }
}

/// An account's virtual root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Home {
    pub bucket: String,
    /// Empty (the whole bucket) or `/`-terminated. Enforced at bundle load.
    pub prefix: String,
}

/// A path that passed normalization and mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapped {
    /// The client-visible absolute path (`/`, `/a/b`).
    pub virt: String,
    /// The backend key. For `/` this is `home.prefix` itself.
    pub key: String,
    /// True for the virtual root.
    pub is_root: bool,
}

impl Mapped {
    /// The listing prefix for this path as a directory: `key/`, unless the key is empty
    /// (a home of the whole bucket) or already ends in `/` (the root under a prefix).
    pub fn dir_prefix(&self) -> String {
        dir_prefix(&self.key)
    }

    /// The last path component, as a listing would name it.
    pub fn file_name(&self) -> &str {
        self.virt.rsplit('/').next().unwrap_or("")
    }
}

/// `key/`, unless the key is empty or already `/`-terminated.
pub fn dir_prefix(key: &str) -> String {
    if key.is_empty() || key.ends_with('/') {
        key.to_string()
    } else {
        format!("{key}/")
    }
}

fn check_chars(s: &str) -> Result<(), PathError> {
    if s.chars().any(|c| c == '\\' || c.is_control()) {
        return Err(PathError::ForbiddenChar);
    }
    Ok(())
}

/// Steps 1–5 for every request except `REALPATH`: the normalized components.
pub fn components(raw: &[u8]) -> Result<Vec<&str>, PathError> {
    let s = std::str::from_utf8(raw).map_err(|_| PathError::NotUtf8)?;
    check_chars(s)?;
    let mut out = Vec::new();
    for c in s.split('/') {
        match c {
            "" | "." => {}
            ".." => return Err(PathError::DotDot),
            other => out.push(other),
        }
    }
    Ok(out)
}

impl Home {
    /// Map one client path onto a key under this home (steps 1–7).
    pub fn map(&self, raw: &[u8]) -> Result<Mapped, PathError> {
        let comps = components(raw)?;
        self.map_components(&comps)
    }

    fn map_components(&self, comps: &[&str]) -> Result<Mapped, PathError> {
        let rel = comps.join("/");
        let key = format!("{}{rel}", self.prefix);
        if key.len() > MAX_KEY_LEN {
            return Err(PathError::TooLong);
        }
        if !key.starts_with(&self.prefix) {
            return Err(PathError::Escape);
        }
        Ok(Mapped {
            virt: format!("/{rel}"),
            key,
            is_root: comps.is_empty(),
        })
    }

    /// The child of a listed directory, from a backend key or common prefix. `None` when
    /// the name could not be reached by path (ADR-009 D6): such entries are omitted from
    /// `READDIR` and counted.
    pub fn child_name<'a>(&self, listed_prefix: &str, key: &'a str) -> Option<&'a str> {
        let rest = key.strip_prefix(listed_prefix)?;
        let name = rest.strip_suffix('/').unwrap_or(rest);
        listing_name_ok(name).then_some(name)
    }
}

/// `REALPATH`: the one place `..` means anything. Resolves lexically and clamps at `/`,
/// touching no storage. Returns the canonical absolute path.
pub fn realpath(raw: &[u8]) -> Result<String, PathError> {
    let s = std::str::from_utf8(raw).map_err(|_| PathError::NotUtf8)?;
    check_chars(s)?;
    let mut stack: Vec<&str> = Vec::new();
    for c in s.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            other => stack.push(other),
        }
    }
    let out = format!("/{}", stack.join("/"));
    if out.len() > MAX_KEY_LEN {
        return Err(PathError::TooLong);
    }
    Ok(out)
}

/// Whether a name read back from a listing is reachable by path. An empty name, `.`,
/// `..`, a `/` inside it, a backslash or a control character is not.
pub fn listing_name_ok(name: &str) -> bool {
    !(name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.chars().any(|c| c == '\\' || c.is_control()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> Home {
        Home {
            bucket: "inbound".into(),
            prefix: "partner-x/".into(),
        }
    }

    #[test]
    fn the_root_maps_to_the_prefix_and_lists_it_once() {
        let m = home().map(b"/").unwrap();
        assert!(m.is_root);
        assert_eq!(m.key, "partner-x/");
        assert_eq!(m.dir_prefix(), "partner-x/", "never partner-x//");
        let whole = Home {
            bucket: "b".into(),
            prefix: String::new(),
        };
        assert_eq!(whole.map(b"/").unwrap().dir_prefix(), "");
    }

    #[test]
    fn relative_paths_resolve_against_root_and_slashes_collapse() {
        assert_eq!(home().map(b"a//b/./c/").unwrap().key, "partner-x/a/b/c");
        assert_eq!(home().map(b"a").unwrap().virt, "/a");
    }

    #[test]
    fn dot_dot_is_refused_everywhere_but_realpath() {
        for p in [&b"/../x"[..], b"/a/../../x", b"..", b"a/.."] {
            assert_eq!(home().map(p).unwrap_err(), PathError::DotDot, "{p:?}");
        }
        assert_eq!(realpath(b"/a/..").unwrap(), "/");
        assert_eq!(
            realpath(b"/../../etc").unwrap(),
            "/etc",
            "clamps at the root"
        );
        assert_eq!(realpath(b".").unwrap(), "/");
    }

    #[test]
    fn encodings_backslashes_and_controls_cannot_escape() {
        assert_eq!(
            home().map(b"/a\\..\\b").unwrap_err(),
            PathError::ForbiddenChar
        );
        assert_eq!(home().map(b"/a\0b").unwrap_err(), PathError::ForbiddenChar);
        assert_eq!(home().map(b"/a\nb").unwrap_err(), PathError::ForbiddenChar);
        assert_eq!(
            home().map(b"/a\x7fb").unwrap_err(),
            PathError::ForbiddenChar
        );
        assert_eq!(
            home().map(b"/\xc0\xae\xc0\xae/x").unwrap_err(),
            PathError::NotUtf8
        );
        // Percent-encoding is just characters: it names a literal key, never a parent.
        assert_eq!(home().map(b"/%2e%2e/x").unwrap().key, "partner-x/%2e%2e/x");
    }

    #[test]
    fn keys_are_bounded() {
        let long = vec![b'a'; MAX_KEY_LEN];
        assert_eq!(home().map(&long).unwrap_err(), PathError::TooLong);
    }

    #[test]
    fn link_like_listing_names_are_unreachable() {
        let h = home();
        assert_eq!(h.child_name("partner-x/", "partner-x/a.csv"), Some("a.csv"));
        assert_eq!(h.child_name("partner-x/", "partner-x/dir/"), Some("dir"));
        assert_eq!(h.child_name("partner-x/", "partner-x/../y"), None);
        assert_eq!(h.child_name("partner-x/", "partner-x//"), None);
        assert_eq!(h.child_name("partner-x/", "partner-x/a\\b"), None);
        assert_eq!(h.child_name("partner-x/", "other/a"), None);
    }

    #[test]
    fn no_unicode_normalization() {
        let nfc = home().map("/é".as_bytes()).unwrap().key;
        let nfd = home().map("/e\u{301}".as_bytes()).unwrap().key;
        assert_ne!(nfc, nfd);
    }
}
