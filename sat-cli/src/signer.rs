//! External signer dispatch (HWI / Bitcoin-Core-compatible).
//!
//! Drives an external signer executable — the `hwi` tool, an airgap/SSS signer,
//! or any conforming script — as a subprocess, so the private key lives in that
//! process and never touches `sat-cli` or the daemon. We speak the arg-based
//! contract from Bitcoin Core's `doc/external-signer.md`:
//!
//! - `<signer…> enumerate` → `[{"fingerprint":"a1b2c3d4","name":"…"}, …]`
//! - `<signer…> --fingerprint=<fp> --chain <net> signtx "<base64-psbt>"`
//!   → `{"psbt":"<signed-base64>"}` on success, `{"error":"<msg>"}` on failure.
//!
//! The signer argv is passed directly to `Command` (never through a shell), so
//! the operator-supplied `--signer` string is not an injection vector.
//!
//! Note: a hardware device only signs inputs that carry `bip32_derivation` for
//! its own key, so it acts on properly-formed PSBTs (from a wallet that knows
//! the device xpub), not satd's bare `createpsbt` output.

use std::process::Command;

#[derive(Debug, Clone, serde::Deserialize)]
pub struct SignerDevice {
    pub fingerprint: String,
    #[serde(default)]
    pub name: Option<String>,
}

/// Split the operator `--signer` string into an argv. The first element is the
/// executable; the rest are leading arguments we keep before the verb/flags.
pub fn parse_signer_argv(s: &str) -> Result<Vec<String>, String> {
    let argv = shlex::split(s)
        .ok_or_else(|| "could not parse --signer command (unbalanced quotes?)".to_string())?;
    if argv.is_empty() {
        return Err("--signer command is empty".to_string());
    }
    Ok(argv)
}

/// Run `<signer> enumerate` and parse the device list.
pub fn enumerate(signer_argv: &[String]) -> Result<Vec<SignerDevice>, String> {
    let stdout = run(signer_argv, &["enumerate".to_string()])?;
    parse_enumerate_json(&stdout)
}

/// Run `<signer> --fingerprint=<fp> --chain <net> signtx <psbt>` and return the
/// signed PSBT (base64), or the signer's reported error.
pub fn signtx(
    signer_argv: &[String],
    fingerprint: &str,
    chain: &str,
    psbt_b64: &str,
) -> Result<String, String> {
    let args = vec![
        format!("--fingerprint={fingerprint}"),
        "--chain".to_string(),
        chain.to_string(),
        "signtx".to_string(),
        psbt_b64.to_string(),
    ];
    let stdout = run(signer_argv, &args)?;
    parse_signtx_json(&stdout)
}

/// Spawn the signer subprocess (blocking — hardware signing waits on the user
/// confirming on-device, so there is intentionally no timeout). Returns stdout
/// on success. On a non-zero exit we still return stdout when it carries JSON
/// (HWI may exit non-zero with a structured `{"error":…}`); otherwise we build
/// an error from stderr and the exit code.
fn run(signer_argv: &[String], extra: &[String]) -> Result<String, String> {
    let output = Command::new(&signer_argv[0])
        .args(&signer_argv[1..])
        .args(extra)
        .output()
        .map_err(|e| format!("failed to run signer '{}': {e}", signer_argv[0]))?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if output.status.success() || stdout.trim_start().starts_with(['{', '[']) {
        return Ok(stdout);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = if !stderr.trim().is_empty() {
        stderr.trim().to_string()
    } else {
        stdout.trim().to_string()
    };
    Err(format!(
        "signer exited with {}: {detail}",
        output
            .status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signal".to_string())
    ))
}

fn parse_enumerate_json(stdout: &str) -> Result<Vec<SignerDevice>, String> {
    serde_json::from_str(stdout.trim())
        .map_err(|e| format!("could not parse signer enumerate output: {e}"))
}

fn parse_signtx_json(stdout: &str) -> Result<String, String> {
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .map_err(|e| format!("could not parse signer signtx output: {e}"))?;
    if let Some(psbt) = v.get("psbt").and_then(|p| p.as_str()) {
        return Ok(psbt.to_string());
    }
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        return Err(format!("signer reported: {err}"));
    }
    Err("signer signtx output had neither \"psbt\" nor \"error\"".to_string())
}

/// Resolve which device fingerprint to sign with. An explicit `--fingerprint`
/// wins; otherwise auto-pick when exactly one device is present. Zero devices,
/// or more than one without an explicit choice, is a hard error — we never
/// silently pick among multiple devices.
fn pick_fingerprint(devices: &[SignerDevice], requested: Option<&str>) -> Result<String, String> {
    if let Some(fp) = requested {
        return Ok(fp.to_string());
    }
    match devices {
        [] => Err("no signer devices found; is the device connected and unlocked?".to_string()),
        [one] => Ok(one.fingerprint.clone()),
        many => {
            let fps: Vec<&str> = many.iter().map(|d| d.fingerprint.as_str()).collect();
            Err(format!(
                "multiple signer devices found ({}); pass --fingerprint to choose one",
                fps.join(", ")
            ))
        }
    }
}

/// Discover the fingerprint to use: explicit override, else enumerate + auto-pick.
pub fn resolve_fingerprint(
    signer_argv: &[String],
    requested: Option<&str>,
) -> Result<String, String> {
    if let Some(fp) = requested {
        return Ok(fp.to_string());
    }
    let devices = enumerate(signer_argv)?;
    let fp = pick_fingerprint(&devices, None)?;
    // Surface which device was auto-selected so the operator can confirm it.
    if let Some(dev) = devices.iter().find(|d| d.fingerprint == fp) {
        match &dev.name {
            Some(name) => eprintln!("signer: using device {} ({name})", dev.fingerprint),
            None => eprintln!("signer: using device {}", dev.fingerprint),
        }
    }
    Ok(fp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_and_quoted_argv() {
        assert_eq!(parse_signer_argv("hwi").unwrap(), vec!["hwi"]);
        assert_eq!(
            parse_signer_argv("python3 -m hwilib").unwrap(),
            vec!["python3", "-m", "hwilib"]
        );
        assert_eq!(
            parse_signer_argv("\"/opt/my signer\" --flag").unwrap(),
            vec!["/opt/my signer", "--flag"]
        );
    }

    #[test]
    fn rejects_empty_or_unbalanced_argv() {
        assert!(parse_signer_argv("").is_err());
        assert!(parse_signer_argv("   ").is_err());
        assert!(parse_signer_argv("hwi \"unbalanced").is_err());
    }

    #[test]
    fn parses_enumerate_list() {
        let out = r#"[{"fingerprint":"a1b2c3d4","name":"trezor"},{"fingerprint":"deadbeef"}]"#;
        let devices = parse_enumerate_json(out).unwrap();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].fingerprint, "a1b2c3d4");
        assert_eq!(devices[0].name.as_deref(), Some("trezor"));
        assert_eq!(devices[1].name, None); // name is optional
    }

    #[test]
    fn rejects_malformed_enumerate() {
        assert!(parse_enumerate_json("not json").is_err());
    }

    #[test]
    fn parses_signtx_success_and_error() {
        assert_eq!(
            parse_signtx_json(r#"{"psbt":"cHNidP8BAA=="}"#).unwrap(),
            "cHNidP8BAA=="
        );
        let err = parse_signtx_json(r#"{"error":"user cancelled"}"#).unwrap_err();
        assert!(err.contains("user cancelled"), "got: {err}");
        assert!(parse_signtx_json(r#"{"unexpected":1}"#).is_err());
        assert!(parse_signtx_json("garbage").is_err());
    }

    #[test]
    fn fingerprint_selection_rules() {
        let dev = |fp: &str| SignerDevice {
            fingerprint: fp.to_string(),
            name: None,
        };
        // explicit override always wins
        assert_eq!(
            pick_fingerprint(&[dev("aaaa")], Some("bbbb")).unwrap(),
            "bbbb"
        );
        // exactly one device auto-picks
        assert_eq!(pick_fingerprint(&[dev("aaaa")], None).unwrap(), "aaaa");
        // zero is an error
        assert!(pick_fingerprint(&[], None).is_err());
        // many without a choice is an error that lists them
        let err = pick_fingerprint(&[dev("aaaa"), dev("bbbb")], None).unwrap_err();
        assert!(err.contains("aaaa") && err.contains("bbbb"), "got: {err}");
    }
}
