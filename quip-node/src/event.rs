//! Node events surfaced to the application.
//!
//! [`NodeEvent`] is the single event type a running [`Node`] emits.
//! It is produced by the peer tasks and drained by [`Node::poll`] or,
//! on the FFI boundary, by the Dart-facing event stream.
//!
//! The enum lives in its own module rather than in the crate root so
//! that the root stays focused on the [`Node`] type itself. It is
//! re-exported from the crate root, so `use quip_node::NodeEvent;`
//! works as before.
//!
//! [`Node`]: crate::Node
//! [`Node::poll`]: crate::Node::poll

use quip_core::dvv::NodeId;
use quip_net::establishment::{FlowFailure, KtStatus};
use quip_net::frame::Tier;
use quip_net::message::Message;
use quip_net::Error;

use crate::trust::PeerTrust;

/// An event surfaced to the application.
///
/// Events are generation-scoped internally: a task whose slot has been
/// superseded by a newer connection for the same `NodeId` is aborted
/// before it can emit, so the application never observes two live
/// generations for one peer. `NodeEvent` does not carry the
/// [`PeerSlot`](crate::PeerSlot) on the wire; applications that need
/// the current generation for a peer can call
/// [`Node::peer_slot`](crate::Node::peer_slot).
#[derive(Debug)]
pub enum NodeEvent {
    /// A peer completed the §4 handshake and §16 Key Claim exchange.
    ///
    /// The peer is reachable from `send_to` at this point; the
    /// establishment flow still has to run before T2/T3 traffic is
    /// appropriate. That completion is signalled by
    /// [`NodeEvent::Ready`].
    ///
    /// `trust` is the policy's view of the peer's Key Claim at the
    /// moment the event fired. A first-seen peer is
    /// [`PeerTrust::Unknown`]; the application is expected to call
    /// [`Node::trust_peer`](crate::Node::trust_peer) to accept or deny
    /// it.
    Connected {
        /// The peer's NodeId, as claimed.
        peer: NodeId,
        /// The policy's current trust level for the peer.
        trust: PeerTrust,
    },
    /// The establishment flow reached `Ready`.
    ///
    /// `kt_status` is the trust level the flow computed from the
    /// witness discovery. `trust` is the combined policy + flow view
    /// of the peer.
    Ready {
        /// The peer.
        peer: NodeId,
        /// KT status at the moment the flow completed.
        kt_status: KtStatus,
        /// The policy's current trust level for the peer.
        trust: PeerTrust,
    },
    /// The establishment flow failed before reaching `Ready`.
    ///
    /// The peer task terminates and [`NodeEvent::Disconnected`]
    /// follows. The transport connection is closed.
    EstablishmentFailed {
        /// The peer.
        peer: NodeId,
        /// Why the flow failed.
        failure: FlowFailure,
        /// The policy's current trust level for the peer.
        trust: PeerTrust,
    },
    /// A peer disconnected.
    Disconnected {
        /// The peer's NodeId.
        peer: NodeId,
        /// The policy's current trust level for the peer at the
        /// moment of disconnection. The store retains this value, so
        /// a reconnect sees the same trust.
        trust: PeerTrust,
    },
    /// The peer's trust level changed.
    ///
    /// Fires when the application calls
    /// [`Node::trust_peer`](crate::Node::trust_peer), when a claim
    /// mismatch demotes a peer to `Untrusted`, or when the flow
    /// promotes a `Trusted` peer to `Verified`.
    PeerTrustChanged {
        /// The peer.
        peer: NodeId,
        /// The new trust level.
        trust: PeerTrust,
    },
    /// A framed message arrived from `peer` on `tier`.
    ///
    /// Verbs covered by
    /// [`NodeConfig::auto_serve_pins`](crate::NodeConfig::auto_serve_pins)
    /// do not surface here. §12 NAT verbs do not surface here either;
    /// they are routed into the node's DHT client.
    Message {
        /// The peer that sent it.
        peer: NodeId,
        /// Tier the message arrived on.
        tier: Tier,
        /// Decoded message.
        msg: Message,
    },
    /// A T3 datagram arrived from `peer`.
    Datagram {
        /// The peer that sent it.
        peer: NodeId,
        /// Decoded message.
        msg: Message,
    },
    /// An error occurred on a peer connection, or globally.
    Error {
        /// Peer the error is associated with, if any.
        peer: Option<NodeId>,
        /// The error.
        error: Error,
    },
}
