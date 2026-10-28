//! M9.6c: the configured witness ring, consumed.
//!
//! Both tests carry the ring in a config file and observe the binary's
//! own log, so what is proven is the parser-to-seed path end to end —
//! not a direct `trust_peer` call, which is what the M9.6a tests already
//! cover (`quip-node/src/lib.rs:2286`, `:2323`).

use std::io::{BufRead, BufReader, Write};
use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use quip_core::time::{Clock, SystemClock};
use quip_net::crypto::Ed25519Signer;
use quip_node::{Node, NodeConfig};

/// Kills the child on drop, so a failed assertion leaves no node behind.
struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn reserve_udp_port() -> u16 {
    let probe = UdpSocket::bind("127.0.0.1:0").expect("probe socket");
    let port = probe.local_addr().expect("probe addr").port();
    drop(probe);
    port
}

/// Spawn the binary with `ring` in its config, capturing its stdout.
///
/// The `Child` is moved into [`Guard`], whose `Drop` kills and waits, so
/// every early return below still reaps it; the lint cannot see through
/// the guard.
#[allow(clippy::zombie_processes)]
fn spawn_with_ring(ring: &[String]) -> (Guard, Arc<Mutex<String>>) {
    let port = reserve_udp_port();
    let mut cfg = tempfile::NamedTempFile::new().expect("temp config");
    let ring_entries = ring
        .iter()
        .map(|id| format!("\"{id}\""))
        .collect::<Vec<_>>()
        .join(", ");
    writeln!(
        cfg,
        "mode = \"development\"\n\
         bind = \"127.0.0.1:{port}\"\n\
         seed = \"4242424242424242424242424242424242424242424242424242424242424242\"\n\
         witness_ring = [{ring_entries}]"
    )
    .expect("write config");

    let mut child = Command::new(env!("CARGO_BIN_EXE_quip-node-headless"))
        .arg("--config")
        .arg(cfg.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn binary");

    let stdout = child.stdout.take().expect("stdout");
    let logs = Arc::new(Mutex::new(String::new()));
    let sink = Arc::clone(&logs);
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let mut buf = sink.lock().expect("log buffer");
            buf.push_str(&strip_ansi(&line));
            buf.push('\n');
        }
    });

    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        match UdpSocket::bind(("127.0.0.1", port)) {
            Ok(s) => {
                drop(s);
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return (Guard(child), logs),
        }
    }
    panic!("binary did not bind 127.0.0.1:{port}");
}

/// Strip ANSI SGR sequences. The binary's fmt subscriber emits colour
/// codes even when stdout is a pipe, so every assertion here works on
/// stripped text.
fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

fn wait_for(logs: &Arc<Mutex<String>>, needle: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if logs.lock().expect("log buffer").contains(needle) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// The binary's own address, read back from its log.
fn bound_port(logs: &Arc<Mutex<String>>) -> u16 {
    let found = wait_for(logs, "node listening", Duration::from_secs(10));
    let text = logs.lock().expect("log buffer").clone();
    assert!(
        found,
        "the binary never logged `node listening`; buffer was: {text:?}"
    );
    text.split("addr=")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|addr| addr.rsplit(':').next())
        .and_then(|p| p.parse().ok())
        .unwrap_or_else(|| panic!("could not parse the bound address; buffer was: {text:?}"))
}

/// Pump a node while polling `logs` for `needle`.
///
/// `Node::connect` returns once the transport handshake completes; the
/// establishment flow keeps running only while the node is pumped. A
/// dialling node that never calls `poll` therefore leaves the *server*
/// half-finished, and the server never emits `Connected` — measured: the
/// binary logged no events at all until this helper existed.
async fn pump_until(
    node: &mut Node,
    logs: &Arc<Mutex<String>>,
    needle: &str,
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if logs.lock().expect("log buffer").contains(needle) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        let _ = node.poll().await;
    }
}

/// A second node in this process, dialling `port`.
async fn test_node_dialling(port: u16) -> (Node, [u8; 32]) {
    let signer = Ed25519Signer::from_seed(&[7u8; 32]);
    let now = SystemClock.now();
    let mut node = Node::bind(
        NodeConfig::new("127.0.0.1:0".parse().unwrap(), Arc::new(signer), now)
            .expect("node config"),
    )
    .await
    .expect("bind test node");
    let local_id = node.local_node_id();
    node.connect(format!("127.0.0.1:{port}").parse().unwrap(), "localhost")
        .await
        .expect("the binary accepts the connection");
    (node, local_id)
}

/// Class 1: a configured ring member is seeded as `Trusted` at first
/// contact.
///
/// The seed is proven by the `accepted=true` field on the `seeded` log
/// line, or by the policy's `Trusted` level where the test can reach
/// the node (see the assertion below). The log line itself fires
/// whether or not `trust_peer` accepted — a refusal is a seeded line
/// with `accepted=false` — so the assertion must be on the accepted
/// value or on the policy, not on the line's presence.
///
/// The policy form is not available here: the node that seeds is inside
/// the binary's process, and `Node::peer_trust`
/// (`quip-node/src/lib.rs:980`) would query *this* process's policy
/// about its own peer. The `accepted` field is therefore the strongest
/// available evidence, and it is enough: it is the return value of
/// `TrustPolicy::record_decision` (`quip-node/src/trust.rs:194`), which
/// is only true when the peer's `StoredClaim` already exists.
#[tokio::test]
async fn configured_ring_seeds_trusted_peers() {
    // The ring must name a NodeId the test controls. The dialling node's
    // identity is fixed by its seed, so it is known before the config is
    // written.
    let member = {
        let signer = Ed25519Signer::from_seed(&[7u8; 32]);
        let now = SystemClock.now();
        let probe = Node::bind(
            NodeConfig::new("127.0.0.1:0".parse().unwrap(), Arc::new(signer), now)
                .expect("probe config"),
        )
        .await
        .expect("bind probe node");
        hex::encode(probe.local_node_id())
    };

    let (_guard, logs) = spawn_with_ring(std::slice::from_ref(&member));
    let port = bound_port(&logs);

    let (mut node, id) = test_node_dialling(port).await;
    assert_eq!(
        hex::encode(id),
        member,
        "the dialling node's identity is fixed by its seed"
    );

    assert!(
        pump_until(
            &mut node,
            &logs,
            &format!("seeded configured ring member as Trusted peer={member} accepted=true"),
            Duration::from_secs(15)
        )
        .await,
        "expected the ring member to be seeded with the decision accepted; log was:\n{}",
        logs.lock().expect("log buffer")
    );
}

/// Class 2 (control): a peer outside the ring is not seeded — the
/// `known_hosts` model, not "trust whoever connects".
///
/// A control that never sees the peer connect proves nothing: it would
/// pass whether the peer connected and was not seeded, or never
/// connected at all. This one asserts the connection first, then the
/// absence of a seed.
#[tokio::test]
async fn configured_ring_ignores_unlisted_peers() {
    let outsider = hex::encode([0xAAu8; 32]);
    let (_guard, logs) = spawn_with_ring(&[outsider]);
    let port = bound_port(&logs);

    let (mut node, _id) = test_node_dialling(port).await;

    // The connection evidence available from outside the binary's process
    // is the dialling node's own view: `Connected` fires at handshake
    // completion, and `Ready` only after the §16 establishment flow —
    // which the binary answers. Both are asserted, so the control cannot
    // pass on a connection that never completed.
    let mut saw_connected = false;
    let mut saw_ready = false;
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline && !(saw_connected && saw_ready) {
        for event in node.poll().await.expect("poll the dialling node") {
            match event {
                quip_node::NodeEvent::Connected { .. } => saw_connected = true,
                quip_node::NodeEvent::Ready { .. } => saw_ready = true,
                _ => {}
            }
        }
    }
    assert!(
        saw_connected,
        "the unlisted peer must connect, or the control proves nothing"
    );
    assert!(
        saw_ready,
        "the establishment flow must complete, or the control proves nothing"
    );

    // Only now does "no seed" mean what it says.
    let text = logs.lock().expect("log buffer").clone();
    assert!(
        !text.contains("seeded configured ring member"),
        "no peer should be seeded; log was:\n{text}"
    );
    assert!(
        text.contains("witness_ring configured"),
        "the ring is loaded even when no member connects; log was:\n{text}"
    );
}
