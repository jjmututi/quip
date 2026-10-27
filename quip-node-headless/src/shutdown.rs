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
pub async fn run_until_signal<B>(node: &mut Node<B>) -> quip_net::Result<()>
where
    B: BlobStore + Send + Sync + 'static,
{
    tokio::select! {
        _ = signal_received() => {
            tracing::info!("shutdown signal received; stopping node");
            node.shutdown();
            Ok(())
        }
        result = run_event_loop(node) => result,
    }
}

async fn run_event_loop<B>(node: &mut Node<B>) -> quip_net::Result<()>
where
    B: BlobStore + Send + Sync + 'static,
{
    loop {
        match node.poll().await {
            Ok(events) => {
                for e in events {
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
