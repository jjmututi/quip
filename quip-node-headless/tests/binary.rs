//! The binary starts, accepts a peer, and shuts down cleanly.
//!
//! This is M9.7's acceptance test. It proves: the binary binds from a
//! development-mode config, a second in-process node completes the QUIC
//! handshake and the §16 establishment flow against it, a `get` is
//! accepted for delivery to it, and SIGTERM (what `systemd stop` sends)
//! produces a clean exit 0 through the shutdown module.
//!
//! What it does not prove: that the binary's node *answers* the `get`.
//! `get` is not auto-served — `quip-node` surfaces it as a
//! `NodeEvent::Message` for the application to handle — and the binary
//! has no application handler for it, so a response is not part of
//! M9.7's contract. The serve path below the verb level (bind, accept,
//! establish, deliver) is what is exercised.

use std::io::Write;
use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quip_core::dvv::Dvv;
use quip_core::time::{Clock, SystemClock};
use quip_net::crypto::Ed25519Signer;
use quip_net::message::Message;
use quip_net::sync::GetRequest;
use quip_node::{Node, NodeConfig};

/// Kills the child on drop, so a failed assertion does not leave a node
/// process running.
struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Pick a loopback UDP port that is free right now.
///
/// The socket is closed before the binary starts; the window between
/// the probe and the binary's bind is the test's one race, and it is
/// small. The alternative — bind port 0 and parse the address the
/// binary logs — couples the test to the log format.
fn reserve_udp_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").expect("probe socket");
    let port = s.local_addr().expect("probe addr").port();
    drop(s);
    port
}

/// Wait until `port` is taken by someone else — the binary.
fn wait_until_bound(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match UdpSocket::bind(("127.0.0.1", port)) {
            Ok(s) => {
                drop(s);
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return true,
        }
    }
    false
}

#[tokio::test]
async fn binary_starts_connects_sends_and_shuts_down() {
    let port = reserve_udp_port();

    let mut cfg = tempfile::NamedTempFile::new().expect("temp config");
    write!(
        cfg,
        "mode = \"development\"\n\
         bind = \"127.0.0.1:{port}\"\n\
         seed = \"4242424242424242424242424242424242424242424242424242424242424242\"\n"
    )
    .expect("write config");

    let child = Command::new(env!("CARGO_BIN_EXE_quip-node-headless"))
        .arg("--config")
        .arg(cfg.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn binary");
    let mut guard = Guard(child);
    let pid = guard.0.id();

    assert!(
        wait_until_bound(port, Duration::from_secs(20)),
        "binary did not bind 127.0.0.1:{port}"
    );

    // A second node, in this process, dials the binary.
    let signer = Ed25519Signer::from_seed(&[7u8; 32]);
    let now = SystemClock.now();
    let mut node = Node::bind(
        NodeConfig::new("127.0.0.1:0".parse().unwrap(), Arc::new(signer), now)
            .expect("node config"),
    )
    .await
    .expect("bind test node");

    let addr = format!("127.0.0.1:{port}").parse().unwrap();
    let peer = node
        .connect(addr, "localhost")
        .await
        .expect("the binary's node accepts the connection and establishes");

    // T1 `get`: proves the peer task accepts a verb for delivery.
    let local_id = node.local_node_id();
    node.send_to(
        &peer,
        Message::Get(GetRequest {
            resource_id: b"hello".to_vec(),
            their_dvv: Dvv::from_write(local_id, 0),
        }),
    )
    .await
    .expect("send get to the binary's node");

    // SIGTERM, which is what `systemd stop` sends. The shutdown module
    // installs a SIGTERM handler, so this must be a clean exit 0 rather
    // than death by signal.
    Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .expect("send SIGTERM");

    let status = guard.0.wait().expect("wait for binary");
    assert_eq!(
        status.code(),
        Some(0),
        "expected a clean exit 0 on SIGTERM, got {status:?}"
    );
}

#[tokio::test]
async fn binary_check_config_exits_zero_on_dev_config() {
    let mut cfg = tempfile::NamedTempFile::new().expect("temp config");
    writeln!(cfg, "mode = \"development\"").expect("write config");

    let out = Command::new(env!("CARGO_BIN_EXE_quip-node-headless"))
        .arg("--config")
        .arg(cfg.path())
        .arg("--check-config")
        .output()
        .expect("run binary");

    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("config OK"));
}
