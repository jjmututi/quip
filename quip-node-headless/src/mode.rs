//! Resolve a `Config` into a running node.
//!
//! `NodeConfig` carries no store (see `quip-node/src/config.rs`), so
//! the binary builds the store and passes it to a generic
//! `run_with_store` function. Development selects `MemoryBlobStore`,
//! Production selects `FileBlobStore`; the two monomorphisations are
//! the only place the two modes diverge.

use std::sync::Arc;

use quip_core::time::{Clock, SystemClock};
use quip_net::crypto::Ed25519Signer;
use quip_node::{Node, NodeConfig};
use quip_storage::blob::BlobStore;
use quip_storage::QuipStore;

use crate::config::{Config, Mode, PeerConfig};

/// What `run` needs after the store has been chosen.
pub struct NodePlan {
    pub config: NodeConfig,
    pub peers: Vec<PeerConfig>,
    pub trust_at_start: Vec<[u8; 32]>,
}

impl NodePlan {
    /// Build the `NodeConfig` from a resolved `Config`.
    pub fn from_config(config: &Config) -> quip_net::Result<NodePlan> {
        let signer = Ed25519Signer::from_seed(&config.seed);
        let now = SystemClock.now();
        let node_config = NodeConfig::new(config.bind, Arc::new(signer), now)?
            .with_capabilities(config.capabilities)
            .with_auto_serve_pins(config.auto_serve_pins)
            .with_relay_capable(config.relay_capable)
            .with_force_relay(config.force_relay);
        Ok(NodePlan {
            config: node_config,
            peers: config.peers.clone(),
            trust_at_start: config.trust_at_start.clone(),
        })
    }
}

/// Run the node with `store`.
///
/// Generic over the store type because `Node<B>` is; the mode decides
/// which store `main` passes.
pub async fn run_with_store<B>(plan: NodePlan, store: QuipStore<B>) -> quip_net::Result<()>
where
    B: BlobStore + Send + Sync + 'static,
{
    let mut node = Node::bind_with_store(plan.config, store).await?;
    let addr = node.local_addr()?;
    tracing::info!(addr = %addr, "node listening");

    for peer in &plan.peers {
        match node.connect(peer.addr, &peer.server_name).await {
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(?peer.addr, error = %e, "bootstrap dial failed");
            }
        }
    }

    // Trust-at-start is parsed and validated but not yet consumed; M9.6c
    // defines what trusting a peer at startup means. Recording the intent
    // here is the honest thing to do with the field.
    if !plan.trust_at_start.is_empty() {
        tracing::warn!(
            count = plan.trust_at_start.len(),
            "trust_at_start is parsed but not yet consumed; M9.6c consumes it"
        );
    }

    crate::shutdown::run_until_signal(&mut node).await
}

/// Run the node in the mode `config` names.
pub async fn run(config: Config) -> quip_net::Result<()> {
    let plan = NodePlan::from_config(&config)?;
    match config.mode {
        Mode::Development => run_with_store(plan, QuipStore::new()).await,
        Mode::Production => {
            let path = config
                .store_path
                .as_ref()
                .expect("Production config validated store_path");
            let blob_store = quip_storage::FileBlobStore::new(path).map_err(|e| {
                quip_net::Error::Transport(format!("cannot open store at {}: {e}", path.display()))
            })?;
            run_with_store(plan, QuipStore::with_backend(blob_store)).await
        }
    }
}
