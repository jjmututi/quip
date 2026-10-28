//! Graceful shutdown.
//!
//! `Node`'s `Drop` aborts every peer task; this module's job is to
//! reach that `Drop` from a signal rather than from a panic.

use quip_node::Node;
use quip_storage::blob::BlobStore;

/// Resolve on SIGINT (ctrl-c) or, on unix, SIGTERM.
///
/// `tokio::signal::ctrl_c` listens for SIGINT only. A VPS's
/// `systemd stop` sends SIGTERM, so ctrl-c alone would leave the
/// process dying without running `Node`'s `Drop` — the peer tasks
/// would be torn down by the kernel, not by the node. See
/// `docs/M9.7-design.md` §3.
async fn signal_received() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "cannot install SIGTERM handler; ctrl-c only");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Run until a shutdown signal, draining events.
///
/// On a signal the node is shut down and this returns `Ok(())`, so
/// `main` can exit 0 and the `Node` drops, aborting every peer task.
///
/// `witness_ring` is the configured ring; its members are seeded as
/// `Trusted` at first contact (see [`seed_ring_member`]).
pub async fn run_until_signal<B>(
    node: &mut Node<B>,
    witness_ring: &[[u8; 32]],
) -> quip_net::Result<()>
where
    B: BlobStore + Send + Sync + 'static,
{
    tokio::select! {
        _ = signal_received() => {
            tracing::info!("shutdown signal received; stopping node");
            node.shutdown();
            Ok(())
        }
        result = run_event_loop(node, witness_ring) => result,
    }
}

/// M9.6c: the configured witness ring is the operator's trust anchor.
/// The seed is applied here, after the trust policy has observed the
/// peer's Key Claim (`Node::connect` calls
/// `TrustPolicy::observe_claim` before it emits `NodeEvent::Connected`,
/// `quip-node/src/lib.rs:691`–`:699`), because
/// `TrustPolicy::record_decision` returns false against an empty policy
/// — a boot-time seed would be a silent no-op. A ring member is
/// `Trusted`, not `Verified`; `Verified` follows M9.6a's first-seen
/// window once the statements flow.
///
/// Returns whether the decision was recorded. A peer that already has a
/// decision is left alone: an operator's explicit `Untrusted` must not
/// be overwritten by the config, and a reconnecting ring member does not
/// need re-seeding.
async fn seed_ring_member<B>(
    node: &Node<B>,
    witness_ring: &[[u8; 32]],
    peer: &[u8; 32],
    trust: quip_node::trust::PeerTrust,
) -> bool
where
    B: BlobStore + Send + Sync + 'static,
{
    if !witness_ring.iter().any(|member| member == peer) {
        return false;
    }
    if trust != quip_node::trust::PeerTrust::Unknown {
        tracing::debug!(
            peer = %hex::encode(peer),
            ?trust,
            "ring member already has a trust decision; not re-seeding"
        );
        return false;
    }
    let accepted = node
        .trust_peer(peer, quip_node::trust::PeerTrust::Trusted)
        .await;
    tracing::info!(
        peer = %hex::encode(peer),
        accepted,
        "seeded configured ring member as Trusted"
    );
    accepted
}

async fn run_event_loop<B>(node: &mut Node<B>, witness_ring: &[[u8; 32]]) -> quip_net::Result<()>
where
    B: BlobStore + Send + Sync + 'static,
{
    loop {
        match node.poll().await {
            Ok(events) => {
                for e in events {
                    if let quip_node::NodeEvent::Connected { peer, trust } = &e {
                        seed_ring_member(node, witness_ring, peer, *trust).await;
                    }
                    tracing::debug!(?e, "node event");
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "event poll failed");
                return Err(e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use quip_core::time::{Clock, SystemClock};
    use quip_net::crypto::Ed25519Signer;
    use quip_node::trust::{PeerTrust, TrustPolicy};

    /// The seed point is first contact because `record_decision` needs an
    /// observed claim. If this ever passes before `observe_claim`, the
    /// seed could move to load time and `docs/M9.6c-design.md` §1a would
    /// need revisiting — which is the point of pinning it.
    #[test]
    fn seed_requires_an_observed_claim() {
        let signer = Ed25519Signer::from_seed(&[9u8; 32]);
        let now = SystemClock.now();
        let claim = quip_node::make_key_claim(&signer, now).expect("claim");
        let peer = claim.node_id;

        let mut policy = TrustPolicy::new();
        assert!(
            !policy.record_decision(&peer, PeerTrust::Trusted, now),
            "record_decision must refuse a peer with no stored claim; \
             this is why M9.6c seeds at first contact rather than at load"
        );

        policy.observe_claim(claim, now);
        assert!(
            policy.record_decision(&peer, PeerTrust::Trusted, now),
            "after observe_claim the decision is recorded"
        );
        assert_eq!(policy.trust_of(&peer), PeerTrust::Trusted);
    }
}
