//! ADR-009 D3 / E5: every russh `Handler` method is overridden.
//!
//! russh 0.63.3's defaults answer `exec`, `shell`, `env`, `pty-req` and `subsystem` with
//! `Ok(())` **without replying** — the fail-open shape the s3s hooks have. Rust cannot
//! reject a default method that was left in place, so the guarantee is this test, in the
//! style of `tests/op_coverage.rs`:
//!
//! - `tests/data/russh-0.63.3-handler.txt` lists every `Handler` method of the pinned
//!   version, and is compared against the pinned source when it is available locally;
//! - every listed method must appear as an `fn` in s0's `impl Handler`;
//! - the pin itself is asserted, so a version bump re-opens the list.

const HANDLER_METHODS: &str = include_str!("data/russh-0.63.3-handler.txt");
const TRANSPORT: &str = include_str!("../src/sftp/transport.rs");
const CARGO_TOML: &str = include_str!("../Cargo.toml");

fn listed() -> Vec<&'static str> {
    HANDLER_METHODS
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
}

/// The `fn` names inside `impl russh::server::Handler for SshHandler { … }`.
fn overridden() -> Vec<String> {
    let start = TRANSPORT
        .find("impl russh::server::Handler for SshHandler {")
        .expect("the Handler impl must exist in src/sftp/transport.rs");
    let body = &TRANSPORT[start..];
    let mut depth = 0i32;
    let mut end = body.len();
    for (i, c) in body.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = i;
                    break;
                }
            }
            _ => {}
        }
    }
    body[..end]
        .lines()
        .filter_map(|l| {
            let l = l.trim_start();
            let l = l.strip_prefix("async ").unwrap_or(l);
            let rest = l.strip_prefix("fn ")?;
            Some(rest.split(['(', '<']).next().unwrap_or("").to_string())
        })
        .collect()
}

#[test]
fn russh_is_pinned_exactly() {
    assert!(
        CARGO_TOML.contains("russh = \"=0.63.3\""),
        "russh is no longer pinned to =0.63.3: regenerate tests/data/russh-0.63.3-handler.txt \
         from the new version's `trait Handler`, rename it, and override every new method"
    );
}

#[test]
fn every_handler_method_of_the_pinned_russh_is_overridden() {
    let have = overridden();
    let missing: Vec<&str> = listed()
        .into_iter()
        .filter(|m| !have.iter().any(|h| h == m))
        .collect();
    assert!(
        missing.is_empty(),
        "these russh Handler methods keep their default — some of which answer without \
         replying (E5): {missing:?}. Override each one in src/sftp/transport.rs."
    );
    assert_eq!(listed().len(), 34, "russh 0.63.3's Handler has 34 methods");
}

#[test]
fn the_reference_list_matches_the_pinned_source_when_it_is_available() {
    // Read from the local cargo registry when present; CI caches it. A missing source is
    // a skip with a reason, never a pass that checked nothing silently.
    let home = std::env::var("CARGO_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|_| std::env::var("HOME").map(|h| std::path::Path::new(&h).join(".cargo")));
    let Ok(home) = home else {
        eprintln!("SKIP: no CARGO_HOME/HOME to find the russh source");
        return;
    };
    let Ok(dirs) = std::fs::read_dir(home.join("registry/src")) else {
        eprintln!("SKIP: no cargo registry sources");
        return;
    };
    for d in dirs.flatten() {
        let src = d.path().join("russh-0.63.3/src/server/mod.rs");
        let Ok(text) = std::fs::read_to_string(&src) else {
            continue;
        };
        let start = text.find("pub trait Handler").expect("trait Handler");
        let body = &text[start..];
        let end = body.find("\n}\n").expect("end of trait");
        let methods: Vec<String> = body[..end]
            .lines()
            .filter_map(|l| {
                let l = l.trim_start();
                l.strip_prefix("fn ")
                    .map(|r| r.split(['(', '<']).next().unwrap_or("").to_string())
            })
            .collect();
        assert_eq!(
            methods,
            listed(),
            "tests/data/russh-0.63.3-handler.txt does not match {src:?}"
        );
        return;
    }
    eprintln!("SKIP: russh-0.63.3 source not found in the local cargo registry");
}
