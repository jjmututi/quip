//! FFI surface for the QUIP node.
//!
//! Every public function or type in this module is exposed to Dart
//! through `flutter_rust_bridge`. The generated Dart code lives in
//! `lib/src/rust/` after running `flutter_rust_bridge_codegen generate`.
//!
//! # Scope
//!
//! M10.1 exposes the minimum surface needed to prove the boundary:
//! bind a node, read its `NodeId`, shut it down. The event stream,
//! trust policy, and content helpers land in later milestones.

use quip_core::time::{Clock, SystemClock, Timestamp};
use quip_node::{NodeConfig, Node as CoreNode};
use quip_net::crypto::Ed25519Signer;
use std::net::SocketAddr;
use std::sync::Arc;

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
            message: format!("invalid bind address: {e}"),
        }
    }
}

/// The type FRB returns to Dart as the result of `bind`.
pub type FfiResult<T> = Result<T, FfiError>;

/// A running QUIP node, exposed across the FFI boundary as an opaque
/// handle.
///
/// Dart holds a reference to this object; the underlying Rust `Node`
/// is owned by the handle and dropped when the Dart object is
/// garbage-collected or when `shutdown()` is called explicitly.
///
/// The inner node is wrapped in `Arc` so the handle can be cloned
/// without moving the endpoint, and so a future milestone can hand
/// the same node to multiple Dart-side consumers.
pub struct NodeHandle {
    inner: Arc<CoreNode>,
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
        let node = CoreNode::bind(config).await?;
        Ok(NodeHandle {
            inner: Arc::new(node),
        })
    }

    /// The node's `NodeId` — its Ed25519 public key, as 32 raw bytes.
    ///
    /// Dart receives this as a `Uint8List`. The value never changes
    /// for the lifetime of the node.
    pub fn local_node_id(&self) -> Vec<u8> {
        self.inner.local_node_id().to_vec()
    }

    /// The address the node's QUIC endpoint is bound to.
    ///
    /// Useful when `bind_addr` used port 0 and the OS chose the port.
    pub fn local_addr(&self) -> FfiResult<String> {
        self.inner
            .local_addr()
            .map(|a| a.to_string())
            .map_err(FfiError::from)
    }

    /// Initiate a graceful shutdown of the node.
    ///
    /// Closes the endpoint; in-flight peer tasks exit on their next
    /// poll. `Drop` on the `NodeHandle` does the same thing, so
    /// calling this is optional — it exists for callers that want an
    /// explicit shutdown before the Dart GC runs.
    pub fn shutdown(&self) {
        self.inner.shutdown();
    }
}