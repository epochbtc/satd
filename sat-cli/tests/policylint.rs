//! Integration tests for `sat-cli policylint` — drives the compiled binary
//! end-to-end (parse → cost report → advisory → exit code), the contract CI and
//! operators depend on. The engine's own logic is unit-tested in `satd-policy`;
//! this pins the CLI surface: exit codes, the caret diagnostic, and the flags.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sat-cli")
}

/// Write `contents` to a uniquely-named temp file and return its path.
fn temp_policy(tag: &str, contents: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("satcli-policylint-{tag}-{}.policy", std::process::id()));
    let mut f = std::fs::File::create(&p).unwrap();
    f.write_all(contents.as_bytes()).unwrap();
    p
}

#[test]
fn valid_file_exits_zero_with_cost_report() {
    let path = temp_policy(
        "valid",
        "version 1\nquarantine cheap when tx.fee_rate < 1000\n",
    );
    let out = Command::new(bin())
        .arg("policylint")
        .arg(&path)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains("version 1 — 1 rule,"), "{stdout}");
    assert!(stdout.contains("budget"), "{stdout}");
    assert!(stdout.contains("cheap"), "{stdout}");
    std::fs::remove_file(&path).ok();
}

#[test]
fn load_error_exits_one_with_caret_diagnostic() {
    let path = temp_policy("err", "version 1\nquarantine bad when tx.fee_rate + 1\n");
    let out = Command::new(bin())
        .arg("policylint")
        .arg(&path)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr: {stderr}");
    assert!(stderr.contains("type error"), "{stderr}");
    // The caret line is the whole point of the diagnostic.
    assert!(stderr.contains('^'), "{stderr}");
    std::fs::remove_file(&path).ok();
}

#[test]
fn unreadable_file_exits_two() {
    let mut missing = std::env::temp_dir();
    missing.push(format!("satcli-policylint-missing-{}.policy", std::process::id()));
    let out = Command::new(bin())
        .arg("policylint")
        .arg(&missing)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot read policy file"));
}

#[test]
fn advisory_fires_by_default_and_is_silenced_by_flag() {
    // A p2a-referencing quarantine rule trips the L2-shape advisory. It also
    // trips the semantic danger gate (p2a is an anchor-output enforcement shape),
    // so pass --allow-dangerous-filters to keep this test focused on the advisory
    // section rather than the exit code (the gate has its own tests below).
    let path = temp_policy(
        "adv",
        "version 1\nquarantine anchors when any outputs (out.script_type == p2a)\n",
    );

    let default = Command::new(bin())
        .arg("policylint")
        .arg(&path)
        .arg("--allow-dangerous-filters")
        .output()
        .unwrap();
    assert!(default.status.success());
    let s = String::from_utf8_lossy(&default.stdout);
    assert!(s.contains("ADVISORIES"), "expected advisory by default: {s}");
    assert!(s.contains("anchor"), "{s}");

    let quiet = Command::new(bin())
        .arg("policylint")
        .arg(&path)
        .arg("--allow-dangerous-filters")
        .arg("--no-advisories")
        .output()
        .unwrap();
    // Advisory never changes the exit code, and --no-advisories drops the section.
    assert!(quiet.status.success());
    let q = String::from_utf8_lossy(&quiet.stdout);
    assert!(!q.contains("ADVISORIES"), "advisory should be silenced: {q}");

    std::fs::remove_file(&path).ok();
}

#[test]
fn relay_dangerous_rule_exits_three_unless_allowed() {
    // A bare (relay+template) quarantine matching an LN enforcement shape is
    // refused by default with exit 3.
    let path = temp_policy(
        "danger",
        "version 1\nquarantine csv when any inputs (in.leaf_script.count_op(OP_CHECKSEQUENCEVERIFY) > 0)\n",
    );

    let strict = Command::new(bin())
        .arg("policylint")
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(
        strict.status.code(),
        Some(3),
        "stderr: {}",
        String::from_utf8_lossy(&strict.stderr)
    );
    assert!(
        String::from_utf8_lossy(&strict.stderr).contains("WITHHOLD RELAY"),
        "{}",
        String::from_utf8_lossy(&strict.stderr)
    );

    let allowed = Command::new(bin())
        .arg("policylint")
        .arg(&path)
        .arg("--allow-dangerous-filters")
        .output()
        .unwrap();
    assert!(allowed.status.success(), "override must exit 0");

    std::fs::remove_file(&path).ok();
}

#[test]
fn template_only_dangerous_rule_warns_but_exits_zero() {
    // The same enforcement-matching rule scoped `on template` still relays, so it
    // warns but does not fail (E1 is about relay homogeneity).
    let path = temp_policy(
        "tmpl",
        "version 1\nquarantine csv on template when any inputs (in.leaf_script.count_op(OP_CHECKSEQUENCEVERIFY) > 0)\n",
    );
    let out = Command::new(bin())
        .arg("policylint")
        .arg(&path)
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("LIGHTNING-ENFORCEMENT DANGER"),
        "expected the danger section to still report the template-only match"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn safe_ruleset_reports_no_danger() {
    let path = temp_policy(
        "safe",
        "version 1\nquarantine cheap when tx.fee_rate < 1000\n",
    );
    let out = Command::new(bin())
        .arg("policylint")
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("No Lightning-enforcement danger findings."),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn explain_renders_plain_english() {
    let path = temp_policy(
        "explain",
        "version 1\nallow own when tx.source == rpc\n",
    );
    let out = Command::new(bin())
        .arg("policylint")
        .arg(&path)
        .arg("--explain")
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("EXPLANATIONS:"), "{s}");
    assert!(s.contains("accept immediately"), "{s}");
    assert!(s.contains("the submission source is rpc"), "{s}");
    std::fs::remove_file(&path).ok();
}
