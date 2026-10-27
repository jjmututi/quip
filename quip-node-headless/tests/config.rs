//! Config loader tests.

use std::io::Write;
use std::process::Command;

/// Write `body` to a temporary file and return it.
fn write_config(body: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().expect("temp file");
    f.write_all(body.as_bytes()).expect("write");
    f
}

/// Run the binary with `--check-config` and return (exit code, stdout, stderr).
fn check_config(path: &std::path::Path) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_quip-node-headless"))
        .arg("--config")
        .arg(path)
        .arg("--check-config")
        .output()
        .expect("run binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn dev_mode_accepts_minimal_config() {
    let f = write_config("mode = \"development\"\n");
    let (code, stdout, _) = check_config(f.path());
    assert_eq!(code, 0);
    assert!(stdout.contains("config OK"));
}

#[test]
fn production_mode_rejects_missing_bind() {
    let f = write_config("mode = \"production\"\n");
    let (code, _, stderr) = check_config(f.path());
    assert_ne!(code, 0);
    assert!(
        stderr.contains("missing required field: bind"),
        "stderr: {stderr}"
    );
}

#[test]
fn production_mode_rejects_literal_seed() {
    let f = write_config(
        "mode = \"production\"\n\
         bind = \"127.0.0.1:0\"\n\
         seed = \"4242424242424242424242424242424242424242424242424242424242424242\"\n\
         store_path = \"/tmp/store\"\n\
         auto_serve_pins = true\n\
         relay_capable = false\n",
    );
    let (code, _, stderr) = check_config(f.path());
    assert_ne!(code, 0);
    assert!(
        stderr.contains("production mode requires `seed` to be a file path"),
        "stderr: {stderr}"
    );
}

/// A config naming a capability the binary does not know is rejected at
/// configuration time, before the node binds.
#[test]
fn config_rejects_unknown_capability() {
    let f = write_config(
        "mode = \"development\"\n\
         [capabilities]\n\
         extra = [\"NOT_A_CAPABILITY\"]\n",
    );
    let (code, _, stderr) = check_config(f.path());
    assert_ne!(code, 0);
    assert!(
        stderr.contains("unknown capability: NOT_A_CAPABILITY"),
        "stderr: {stderr}"
    );
}

/// Row 4's closure test: a capability set that is *named* correctly but
/// violates the dependency closure (`MERKLE_RANGE` requires `BLAKE3`) is
/// rejected by `Handshake::new_checked` at configuration time, not at
/// the first handshake.
#[test]
fn config_rejects_closure_violation() {
    let f = write_config(
        "mode = \"development\"\n\
         [capabilities]\n\
         extra = [\"MERKLE_RANGE\"]\n",
    );
    let (code, _, stderr) = check_config(f.path());
    assert_ne!(code, 0);
    assert!(
        stderr.contains("rejected by Handshake::new_checked"),
        "stderr: {stderr}"
    );
}
