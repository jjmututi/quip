//! FFI surface for the QUIP node.
//!
//! Every public function or type in this module is exposed to Dart
//! through `flutter_rust_bridge`. The generated Dart code lives in
//! `lib/src/rust/` after running `flutter_rust_bridge_codegen generate`.

use quip_core::time::{Clock, SystemClock, Timestamp};
use quip_net::crypto::Ed25519Signer;
use quip_net::establishment::{FlowFailure, KtStatus};
use quip_node::{Node as CoreNode, NodeConfig, NodeEvent};
use crate::frb_generated::StreamSink;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

/// An error surfaced to Dart.
#[derive(Debug, Clone)]
pub struct FfiError {
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
        FfiError { message: format!("{e}") }
    }
}

impl From<std::net::AddrParseError> for FfiError {
    fn from(e: std::net::AddrParseError) -> Self {
        FfiError {
            message: format!("invalid address: {e}"),
        }
    }
}

pub type FfiResult<T> = Result<T, FfiError>;

/// KT status, mirroring `quip_net::establishment::KtStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KtStatusFfi {
    Pending,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowFailureFfi {
    KeyClaimTimeout,
    NatFailed,
    NatTimeout,
    DiscoveryTimeout,
}

impl From<FlowFailure> for FlowFailureFfi {
    fn from(f: FlowFailure) -> Self {
        match f {
            FlowFailure::KeyClaimTimeout => FlowFailureFfi::KeyClaimTimeout,
            FlowFailure::NatFailed => FlowFailureFfi::NatFailed,
            FlowFailure::NatTimeout => FlowFailureFfi::NatTimeout,
            FlowFailure::DiscoveryTimeout => FlowFailureFfi::DiscoveryTimeout,
        }
    }
}

/// An event surfaced to Dart.
///
/// Simple variants (`Connected`, `Ready`, `Disconnected`,
/// `EstablishmentFailed`) carry typed fields. The verbose variants
/// (`Message`, `Datagram`) carry the wire verb and the raw bytes; a
/// Dart consumer that needs the typed message calls `decode_message`
/// (a later milestone) with the raw payload.
pub enum NodeEventFfi {
    Connected {
        peer: Vec<u8>,
    },
    Ready {
        peer: Vec<u8>,
        kt_status: KtStatusFfi,
    },
    EstablishmentFailed {
        peer: Vec<u8>,
        failure: FlowFailureFfi,
    },
    Disconnected {
        peer: Vec<u8>,
    },
    Message {
        peer: Vec<u8>,
        tier: u8,
        verb: String,
        raw: Vec<u8>,
    },
    Datagram {
        peer: Vec<u8>,
        verb: String,
        raw: Vec<u8>,
    },
    Error {
        peer: Option<Vec<u8>>,
        message: String,
    },
}

impl NodeEventFfi {
    fn from_rust(event: NodeEvent) -> Self {
        match event {
            NodeEvent::Connected { peer } => NodeEventFfi::Connected {
                peer: peer.to_vec(),
            },
            NodeEvent::Ready { peer, kt_status } => NodeEventFfi::Ready {
                peer: peer.to_vec(),
                kt_status: kt_status.into(),
            },
            NodeEvent::EstablishmentFailed { peer, failure } => {
                NodeEventFfi::EstablishmentFailed {
                    peer: peer.to_vec(),
                    failure: failure.into(),
                }
            }
            NodeEvent::Disconnected { peer } => NodeEventFfi::Disconnected {
                peer: peer.to_vec(),
            },
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

/// A running QUIP node, exposed across the FFI boundary as an opaque
/// handle.
pub struct NodeHandle {
    inner: tokio::sync::Mutex<CoreNode>,
    events: std::sync::Mutex<Option<mpsc::Receiver<NodeEvent>>>,
    runtime: tokio::runtime::Handle,
}

impl NodeHandle {
    /// Bind a new QUIP node.
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

    /// The node's NodeId, as 32 raw bytes.
    pub async fn local_node_id(&self) -> Vec<u8> {
        self.inner.lock().await.local_node_id().to_vec()
    }

    /// The address the node's QUIC endpoint is bound to.
    pub async fn local_addr(&self) -> FfiResult<String> {
        self.inner
            .lock()
            .await
            .local_addr()
            .map(|a| a.to_string())
            .map_err(FfiError::from)
    }

    /// Dial a remote node. Returns the peer's NodeId as 32 raw bytes.
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

    /// Initiate a graceful shutdown of the node.
    pub async fn shutdown(&self) {
        self.inner.lock().await.shutdown();
    }
}