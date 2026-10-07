//! FFI surface for the QUIP node.
//!
//! Every public function or type in this module is exposed to Dart
//! through `flutter_rust_bridge`. The generated Dart code lives in
//! `lib/src/rust/` after running `flutter_rust_bridge_codegen generate`.
//!
//! # Scope
//!
//! M10.1 exposed bind + `local_node_id` + `local_addr` + `shutdown`.
//! M10.2 added the event stream. M10.3 adds the trust policy: a
//! first-seen peer is `Unknown` until the application calls
//! [`NodeHandle::trust_peer`] with `Trusted`, and every peer-related
//! event carries the current trust level.

use quip_core::time::{Clock, SystemClock, Timestamp};
use quip_net::crypto::Ed25519Signer;
use quip_net::establishment::{FlowFailure, KtStatus};
use quip_node::trust::PeerTrust as CorePeerTrust;
use quip_node::{Node as CoreNode, NodeConfig, NodeEvent};
use crate::frb_generated::StreamSink;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

// -------------------------------------------------------------------------
// Errors
// -------------------------------------------------------------------------

/// An error surfaced to Dart.
///
/// FRB translates Rust `Result<T, E>` into a Dart `Future<T>` that
/// throws when `E` is returned. `FfiError` is the single error type
/// the FFI layer exposes; the underlying `quip_net::Error` and
/// `quip_node` errors are folded into a human-readable message.
#[derive(Debug, Clone)]
pub struct FfiError {
    /// A human-readable error message.
    pub message: String,
}

impl std::fmt::Display for FfiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for FfiError {}

impl From<quip_net::Error> for FfiError {
    fn from(e: quip_net::Error) -> Self {
        FfiError {
            message: format!("{e}"),
        }
    }
}

impl From<std::net::AddrParseError> for FfiError {
    fn from(e: std::net::AddrParseError) -> Self {
        FfiError {
            message: format!("invalid address: {e}"),
        }
    }
}

/// The type FRB returns to Dart as the result of a call.
pub type FfiResult<T> = Result<T, FfiError>;

// -------------------------------------------------------------------------
// Mirrored enums
// -------------------------------------------------------------------------

/// KT status, mirroring `quip_net::establishment::KtStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KtStatusFfi {
    /// Fewer than 4 witnesses have corroborated the claim.
    Pending,
    /// 4+ independent, non-expired witnesses have corroborated the
    /// claim.
    Verified,
}

impl From<KtStatus> for KtStatusFfi {
    fn from(k: KtStatus) -> Self {
        match k {
            KtStatus::Pending => KtStatusFfi::Pending,
            KtStatus::Verified => KtStatusFfi::Verified,
        }
    }
}

/// Why the establishment flow failed.
///
/// Mirrors `quip_net::establishment::FlowFailure`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowFailureFfi {
    /// The remote did not send a Key Claim within the configured
    /// timeout.
    KeyClaimTimeout,
    /// NAT traversal failed.
    NatFailed,
    /// NAT traversal did not finish within the configured timeout.
    NatTimeout,
    /// Witness discovery did not finish within the configured
    /// timeout.
    DiscoveryTimeout,
}

impl From<FlowFailure> for FlowFailureFfi {
    fn from(f: FlowFailure) -> Self {
        match f {
            FlowFailure::KeyClaimTimeout => FlowFailureFfi::KeyClaimTimeout,
            FlowFailure::NatFailed => FlowFailureFfi::NatFailed,
            FlowFailure::NatTimeout => FlowFailureFfi::NatTimeout,
            FlowFailure::DiscoveryTimeout => {
                FlowFailureFfi::DiscoveryTimeout
            }
        }
    }
}

/// A peer's trust level, mirroring `quip_node::trust::PeerTrust`.
///
/// The UI is expected to render `Trusted` and `Verified` differently:
/// `Trusted` means the application (or the user behind it) accepted
/// the peer explicitly; `Verified` means 4+ independent witnesses have
/// additionally corroborated the peer's Key Claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTrustFfi {
    /// A valid Key Claim seen for the first time. No trust decision
    /// has been made. Treat as unverified.
    Unknown,
    /// The application has explicitly accepted this peer.
    Trusted,
    /// 4+ independent witnesses have corroborated this peer's Key
    /// Claim. Implies `Trusted`.
    Verified,
    /// The peer's Key Claim differs from the pinned one without a
    /// valid rotation chain, or the application has explicitly denied
    /// it.
    Untrusted,
    /// An explicit revocation tombstone exists for this NodeId.
    /// Terminal — no subsequent state transition lifts it.
    Revoked,
}

impl From<CorePeerTrust> for PeerTrustFfi {
    fn from(t: CorePeerTrust) -> Self {
        match t {
            CorePeerTrust::Unknown => PeerTrustFfi::Unknown,
            CorePeerTrust::Trusted => PeerTrustFfi::Trusted,
            CorePeerTrust::Verified => PeerTrustFfi::Verified,
            CorePeerTrust::Untrusted => PeerTrustFfi::Untrusted,
            CorePeerTrust::Revoked => PeerTrustFfi::Revoked,
        }
    }
}

impl From<PeerTrustFfi> for CorePeerTrust {
    fn from(t: PeerTrustFfi) -> Self {
        match t {
            PeerTrustFfi::Unknown => CorePeerTrust::Unknown,
            PeerTrustFfi::Trusted => CorePeerTrust::Trusted,
            PeerTrustFfi::Verified => CorePeerTrust::Verified,
            PeerTrustFfi::Untrusted => CorePeerTrust::Untrusted,
            PeerTrustFfi::Revoked => CorePeerTrust::Revoked,
        }
    }
}

// -------------------------------------------------------------------------
// Events
// -------------------------------------------------------------------------

/// An event surfaced to Dart.
///
/// Simple variants (`Connected`, `Ready`, `EstablishmentFailed`,
/// `Disconnected`, `PeerTrustChanged`) carry typed fields. The verbose
/// variants (`Message`, `Datagram`) carry the wire verb and the raw
/// bytes; a Dart consumer that needs the typed message calls
/// `decode_message` (a later milestone) with the raw payload.
///
/// The `trust` field on peer-related events is the policy's view of
/// the peer at the moment the event fired. A first-seen peer is
/// `Unknown`; the UI is expected to prompt the user, and the
/// application calls `NodeHandle.trustPeer` with the decision.
pub enum NodeEventFfi {
    /// A peer completed the §4 handshake and §16 Key Claim exchange.
    Connected {
        /// The peer's NodeId, as claimed.
        peer: Vec<u8>,
        /// The policy's current trust level for the peer.
        trust: PeerTrustFfi,
    },
    /// The establishment flow reached `Ready`.
    Ready {
        /// The peer.
        peer: Vec<u8>,
        /// KT status at the moment the flow completed.
        kt_status: KtStatusFfi,
        /// The policy's current trust level for the peer.
        trust: PeerTrustFfi,
    },
    /// The establishment flow failed before reaching `Ready`.
    EstablishmentFailed {
        /// The peer.
        peer: Vec<u8>,
        /// Why the flow failed.
        failure: FlowFailureFfi,
        /// The policy's current trust level for the peer.
        trust: PeerTrustFfi,
    },
    /// A peer disconnected.
    Disconnected {
        /// The peer's NodeId.
        peer: Vec<u8>,
        /// The policy's current trust level for the peer at the
        /// moment of disconnection.
        trust: PeerTrustFfi,
    },
    /// The peer's trust level changed.
    ///
    /// Fires when the application calls `trustPeer`, when a claim
    /// mismatch demotes a peer to `Untrusted`, or when the flow
    /// promotes a `Trusted` peer to `Verified`.
    PeerTrustChanged {
        /// The peer.
        peer: Vec<u8>,
        /// The new trust level.
        trust: PeerTrustFfi,
    },
    /// A framed message arrived from `peer` on `tier`.
    Message {
        /// The peer that sent it.
        peer: Vec<u8>,
        /// Tier the message arrived on (0 = Ctrl, 1 = Sync, 2 = Bulk,
        /// 3 = Event).
        tier: u8,
        /// The wire verb.
        verb: String,
        /// The raw encoded payload.
        raw: Vec<u8>,
    },
    /// A T3 datagram arrived from `peer`.
    Datagram {
        /// The peer that sent it.
        peer: Vec<u8>,
        /// The wire verb.
        verb: String,
        /// The raw encoded payload.
        raw: Vec<u8>,
    },
    /// An error occurred on a peer connection, or globally.
    Error {
        /// Peer the error is associated with, if any.
        peer: Option<Vec<u8>>,
        /// A human-readable message.
        message: String,
    },
}

impl NodeEventFfi {
    fn from_rust(event: NodeEvent) -> Self {
        match event {
            NodeEvent::Connected { peer, trust } => NodeEventFfi::Connected {
                peer: peer.to_vec(),
                trust: trust.into(),
            },
            NodeEvent::Ready {
                peer,
                kt_status,
                trust,
            } => NodeEventFfi::Ready {
                peer: peer.to_vec(),
                kt_status: kt_status.into(),
                trust: trust.into(),
            },
            NodeEvent::EstablishmentFailed {
                peer,
                failure,
                trust,
            } => NodeEventFfi::EstablishmentFailed {
                peer: peer.to_vec(),
                failure: failure.into(),
                trust: trust.into(),
            },
            NodeEvent::Disconnected { peer, trust } => {
                NodeEventFfi::Disconnected {
                    peer: peer.to_vec(),
                    trust: trust.into(),
                }
            }
            NodeEvent::PeerTrustChanged { peer, trust } => {
                NodeEventFfi::PeerTrustChanged {
                    peer: peer.to_vec(),
                    trust: trust.into(),
                }
            }
            NodeEvent::Message { peer, tier, msg } => NodeEventFfi::Message {
                peer: peer.to_vec(),
                tier: tier as u8,
                verb: msg.verb().to_string(),
                raw: msg.to_bytes().unwrap_or_default(),
            },
            NodeEvent::Datagram { peer, msg } => NodeEventFfi::Datagram {
                peer: peer.to_vec(),
                verb: msg.verb().to_string(),
                raw: msg.to_bytes().unwrap_or_default(),
            },
            NodeEvent::Error { peer, error } => NodeEventFfi::Error {
                peer: peer.map(|p| p.to_vec()),
                message: format!("{error}"),
            },
        }
    }
}

// -------------------------------------------------------------------------
// NodeHandle
// -------------------------------------------------------------------------

/// A running QUIP node, exposed across the FFI boundary as an opaque
/// handle.
///
/// Dart holds a reference to this object; the underlying Rust `Node`
/// is owned by the handle and dropped when the Dart object is
/// garbage-collected or when `shutdown()` is called explicitly.
pub struct NodeHandle {
    inner: tokio::sync::Mutex<CoreNode>,
    events: std::sync::Mutex<Option<mpsc::Receiver<NodeEvent>>>,
    /// The runtime handle that owns the node's peer tasks. Captured at
    /// `bind` time so `subscribe_events` can spawn the drain task from
    /// a Dart-called sync method without a reactor error.
    runtime: tokio::runtime::Handle,
}

impl NodeHandle {
    /// Bind a new QUIP node.
    ///
    /// `bind_addr` is a `host:port` string, e.g. `"127.0.0.1:0"` to
    /// let the OS choose a port. `seed` is a 32-byte Ed25519 seed;
    /// the node's identity is derived from it and cannot be changed
    /// after bind.
    ///
    /// Returns a handle on success. The node's accept loop and DHT
    /// router are already running by the time this future resolves.
    pub async fn bind(
        bind_addr: String,
        seed: Vec<u8>,
    ) -> FfiResult<NodeHandle> {
        if seed.len() != 32 {
            return Err(FfiError {
                message: format!(
                    "seed must be exactly 32 bytes, got {}",
                    seed.len()
                ),
            });
        }
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&seed);

        let addr: SocketAddr = bind_addr.parse()?;
        let signer = Ed25519Signer::from_seed(&seed_arr);
        let now: Timestamp = SystemClock.now();
        let config = NodeConfig::new(addr, Arc::new(signer), now)?;
        let mut node = CoreNode::bind(config).await?;
        let events = node.take_events();
        let runtime = tokio::runtime::Handle::current();

        Ok(NodeHandle {
            inner: tokio::sync::Mutex::new(node),
            events: std::sync::Mutex::new(events),
            runtime,
        })
    }

    /// The node's `NodeId` — its Ed25519 public key, as 32 raw bytes.
    ///
    /// Dart receives this as a `Uint8List`. The value never changes
    /// for the lifetime of the node.
    pub async fn local_node_id(&self) -> Vec<u8> {
        self.inner.lock().await.local_node_id().to_vec()
    }

    /// The address the node's QUIC endpoint is bound to.
    ///
    /// Useful when `bind_addr` used port 0 and the OS chose the port.
    pub async fn local_addr(&self) -> FfiResult<String> {
        self.inner
            .lock()
            .await
            .local_addr()
            .map(|a| a.to_string())
            .map_err(FfiError::from)
    }

    /// Dial a remote node.
    ///
    /// Returns the peer's NodeId as 32 raw bytes. The returned value
    /// is available as soon as the transport handshake completes;
    /// `NodeEventFfi::Ready` fires later, after the §16 flow completes.
    pub async fn connect(
        &self,
        addr: String,
        server_name: String,
    ) -> FfiResult<Vec<u8>> {
        let addr: SocketAddr = addr.parse()?;
        let mut guard = self.inner.lock().await;
        let peer = guard.connect(addr, &server_name).await?;
        Ok(peer.to_vec())
    }

    /// Subscribe to the node's event stream.
    ///
    /// Returns a Dart `Stream<NodeEventFfi>`. The Rust side spawns a
    /// task that drains the node's internal event channel and writes
    /// each event to the sink. The task ends when Dart cancels the
    /// subscription or the node shuts down.
    ///
    /// Only one subscription per node is allowed; a second call
    /// returns an error.
    pub fn subscribe_events(
        &self,
        sink: StreamSink<NodeEventFfi>,
    ) -> FfiResult<()> {
        let rx = self
            .events
            .lock()
            .ok()
            .and_then(|mut guard| guard.take())
            .ok_or_else(|| FfiError {
                message: "event stream already subscribed".into(),
            })?;

        // `Handle::spawn` works from any thread; `tokio::spawn` does
        // not. The task runs on the runtime that owns the node's peer
        // tasks, not on the caller's thread.
        self.runtime.spawn(async move {
            let mut rx = rx;
            while let Some(event) = rx.recv().await {
                let ffi = NodeEventFfi::from_rust(event);
                if sink.add(ffi).is_err() {
                    break;
                }
            }
        });

        Ok(())
    }

    /// Record the application's trust decision for `peer`.
    ///
    /// The node records every peer's Key Claim on first contact but
    /// does not decide trust by default: a first-seen peer stays
    /// `Unknown` until the application calls this method with
    /// [`PeerTrustFfi::Trusted`]. `Trusted`, `Untrusted`, and
    /// `Revoked` are accepted; `Unknown` and `Verified` are not —
    /// `Unknown` is a starting state, and `Verified` is derived from
    /// the flow's witness discovery, not from application choice.
    ///
    /// Returns `true` if the decision was recorded. On a successful
    /// change, a `NodeEventFfi::PeerTrustChanged` fires on the event
    /// stream.
    pub async fn trust_peer(
        &self,
        peer: Vec<u8>,
        decision: PeerTrustFfi,
    ) -> FfiResult<bool> {
        let peer_id = decode_node_id(&peer)?;
        let decision: CorePeerTrust = decision.into();
        Ok(self
            .inner
            .lock()
            .await
            .trust_peer(&peer_id, decision)
            .await)
    }

    /// Current trust level for `peer`.
    pub async fn peer_trust(
        &self,
        peer: Vec<u8>,
    ) -> FfiResult<PeerTrustFfi> {
        let peer_id = decode_node_id(&peer)?;
        Ok(self
            .inner
            .lock()
            .await
            .peer_trust(&peer_id)
            .await
            .into())
    }

    /// Initiate a graceful shutdown of the node.
    ///
    /// Closes the endpoint; in-flight peer tasks exit on their next
    /// poll. `Drop` on the `NodeHandle` does the same thing, so
    /// calling this is optional — it exists for callers that want an
    /// explicit shutdown before the Dart GC runs.
    pub async fn shutdown(&self) {
        self.inner.lock().await.shutdown();
    }
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

/// Decode a 32-byte `NodeId` from the Dart-side `Vec<u8>`.
fn decode_node_id(bytes: &[u8]) -> FfiResult<[u8; 32]> {
    if bytes.len() != 32 {
        return Err(FfiError {
            message: format!(
                "peer must be exactly 32 bytes, got {}",
                bytes.len()
            ),
        });
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(bytes);
    Ok(id)
}