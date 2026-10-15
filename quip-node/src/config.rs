//! Node configuration.
//!
//! [`NodeConfig`] is everything [`Node`](crate::Node) needs to bind: the socket to
//! listen on, the capability set to advertise, the self-signed Key
//! Claim that names the node, and the shared clock and signer that
//! every peer task reads from. The config is consumed by
//! [`Node::bind_with_store`](crate::Node::bind_with_store) and its
//! derived constructors; it is not stored on a running node.
//!
//! The two shared type aliases [`SharedClock`] and [`SharedSigner`]
//! live here because the config is the only thing that constructs
//! them. They are re-exported from the crate root, so
//! `quip_node::SharedSigner` and `quip_node::SharedClock` remain the
//! canonical spellings.

use quip_core::messages::{KeyClaim, Signer};
use quip_core::time::{Clock, SystemClock, Timestamp};
use quip_net::crypto::Ed25519Signer;
use quip_net::handshake::Capabilities;
use quip_net::Result;

use std::net::SocketAddr;
use std::sync::Arc;

/// A time source that can be moved across threads and shared.
///
/// `quip_core::time::Clock` does not itself require `Send + Sync`,
/// because the trait is also used in single-threaded contexts. The
/// node moves clocks into `tokio::spawn`ed tasks, so it needs the
/// stronger bound. Every implementation in the workspace
/// (`SystemClock`, `ManualClock`) satisfies it already.
pub type SharedClock = Arc<dyn Clock + Send + Sync + 'static>;

/// The node's Ed25519 signer.
///
/// Concrete `Ed25519Signer`, not `dyn Signer`: every verifier in the
/// workspace is `Ed25519Verifier`, so a `dyn` would be strictly less
/// safe with no gain.
pub type SharedSigner = Arc<Ed25519Signer>;

/// Configuration for a [`Node`](crate::Node).
#[derive(Clone)]
pub struct NodeConfig {
    /// UDP address to bind for inbound connections.
    pub bind: SocketAddr,
    /// Capabilities to advertise and accept.
    pub capabilities: Capabilities,
    /// Our self-signed identity claim, derived from `signer`.
    pub key_claim: KeyClaim,
    /// When true (default), the node auto-handles inbound `pin`,
    /// `unpin`, and `query_pins` from its store. When false, those
    /// messages surface as
    /// [`NodeEvent::Message`](crate::NodeEvent::Message) and the
    /// application is responsible for handling them.
    pub auto_serve_pins: bool,
    /// Time source used by peer tasks. Defaults to [`SystemClock`];
    /// tests inject a [`ManualClock`](quip_core::time::ManualClock).
    pub clock: SharedClock,
    /// The node's signer. Shared with the DHT and the discovery
    /// client, so every signature the node produces traces to one
    /// key.
    pub signer: SharedSigner,
    /// Force every NAT session this node starts onto the relay
    /// branch.
    ///
    /// A node behind a symmetric NAT knows a priori that its direct
    /// candidates will fail. Setting this to `true` tells the NAT
    /// state machine to skip the direct-candidate probe ladder and go
    /// straight to relay discovery. The default (`false`) leaves the
    /// four-phase ladder unchanged.
    ///
    /// The session's own candidates are still published; only the
    /// *inbound* direct path is refused. The terminal event is the
    /// same `NatEvent::RelayedPathEstablished` as a relay-by-probe-
    /// failure, and the resulting lifecycle is
    /// [`PeerLifecycle::NatRelayed`](crate::PeerLifecycle::NatRelayed)
    /// either way.
    ///
    /// Added in M9.5b-c part 6.
    pub force_relay: bool,
    /// Whether the node answers an inbound `relay_discovery`.
    ///
    /// Default `false`: a node that has not opted in does not relay
    /// for others. A VPS acting as a rendezvous point sets this to
    /// `true` (M9.7). The answer is a signed `relay_response` naming
    /// this node as the relay, sent on T0 to the peer that asked.
    ///
    /// Added in M9.5b-c part 6.
    pub relay_capable: bool,
}

impl core::fmt::Debug for NodeConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NodeConfig")
            .field("bind", &self.bind)
            .field("capabilities", &self.capabilities)
            .field("key_claim", &self.key_claim)
            .field("auto_serve_pins", &self.auto_serve_pins)
            .field("clock", &"<dyn Clock>")
            .field("signer", &"<Ed25519Signer>")
            .field("force_relay", &self.force_relay)
            .field("relay_capable", &self.relay_capable)
            .finish()
    }
}

impl NodeConfig {
    /// Build a config with baseline capabilities plus NAT traversal
    /// and DHT discovery, a claim derived from `signer`, auto-serving
    /// enabled, the system clock, and relaying disabled.
    ///
    /// `NAT_TRAVERSAL` is what allows a peer to send and receive §12
    /// verbs; without it the transport's capability gate rejects them.
    /// `DHT_DISCOVERY` is what allows the Coral verbs of §13. Neither
    /// is in the baseline set (which is transport-level), so both are
    /// added explicitly here.
    pub fn new(
        bind: SocketAddr,
        signer: SharedSigner,
        now: Timestamp,
    ) -> Result<Self> {
        Ok(Self {
            bind,
            capabilities: Capabilities::baseline()
                | Capabilities(Capabilities::NAT_TRAVERSAL)
                | Capabilities(Capabilities::DHT_DISCOVERY),
            key_claim: make_key_claim(signer.as_ref(), now)?,
            auto_serve_pins: true,
            clock: Arc::new(SystemClock),
            signer,
            force_relay: false,
            relay_capable: false,
        })
    }

    /// Replace the capability set.
    pub fn with_capabilities(mut self, caps: Capabilities) -> Self {
        self.capabilities = caps;
        self
    }

    /// Enable or disable pin auto-serving.
    pub fn with_auto_serve_pins(mut self, on: bool) -> Self {
        self.auto_serve_pins = on;
        self
    }

    /// Replace the time source.
    ///
    /// The clock is read once per peer task iteration, so a frozen or
    /// slowly-advancing
    /// [`ManualClock`](quip_core::time::ManualClock) makes the node
    /// deterministic.
    pub fn with_clock(mut self, clock: SharedClock) -> Self {
        self.clock = clock;
        self
    }

    /// Force every session this node starts onto the relay branch.
    ///
    /// See [`Self::force_relay`] for the semantics. The default
    /// (`false`) preserves the four-phase direct-first ladder.
    pub fn with_force_relay(mut self, on: bool) -> Self {
        self.force_relay = on;
        self
    }

    /// Enable or disable answering inbound `relay_discovery`.
    ///
    /// See [`Self::relay_capable`] for the semantics. The default
    /// (`false`) leaves the responder inert.
    pub fn with_relay_capable(mut self, on: bool) -> Self {
        self.relay_capable = on;
        self
    }
}

/// Build a signed `KeyClaim` for `signer`.
pub fn make_key_claim(signer: &impl Signer, now: Timestamp) -> Result<KeyClaim> {
    let node_id = signer.public_key();
    let unsigned = KeyClaim {
        node_id,
        timestamp: now,
        dht_id: node_id,
        signature: [0u8; 64],
    };
    let payload = unsigned.signing_payload()?;
    let signature = signer.sign_ed25519(&payload);
    Ok(KeyClaim {
        signature,
        ..unsigned
    })
}