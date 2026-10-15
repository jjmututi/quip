//! Peer registry: the node's view of its connected peers.
//!
//! [`Registry`] owns the active [`PeerHandle`]s and the persistent
//! generation counters that keep [`PeerSlot`]s unique across
//! reconnects. It is deliberately ignorant of the rest of the node —
//! it knows nothing about the DHT, the store, or the transport. The
//! one cross-cutting concern, mirroring a lifecycle transition into
//! the DHT routing table, lives in `lib.rs`'s `set_peer_lifecycle`,
//! which calls [`Registry::set_lifecycle`] and then updates the DHT.

use quip_core::dvv::NodeId;
use quip_net::message::Message;

use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

use crate::peer::{PeerLifecycle, PeerSlot};

/// A registered peer connection.
struct PeerHandle {
    /// The current connection generation for this peer.
    slot: PeerSlot,
    /// Outbound queue for the peer task driving this generation.
    outbound: mpsc::Sender<Message>,
    /// Connection lifecycle for this generation.
    ///
    /// The peer task is the single writer; every transition flows
    /// through `set_peer_lifecycle`, which validates the edge
    /// against §2a via [`PeerLifecycle::transition_to`]. A new slot
    /// starts at `Established`, because a [`PeerSlot`] is allocated
    /// only after the §4 handshake completes — the peer's `NodeId`
    /// is not known before then — so `Connecting` is not observable
    /// at the slot level.
    lifecycle: PeerLifecycle,
}

/// Per-node registry of active peer handles and generation counters.
///
/// The two maps live behind one lock so that "allocate a new slot,
/// replace the handle" is a single atomic step with respect to any
/// other `register` call for the same `NodeId`. This is what makes a
/// concurrent reconnect deterministic: whoever takes the lock second
/// wins, and the first task's slot is no longer current.
///
/// The generation counter is **persistent**. It is never reset when a
/// peer disconnects, because resetting would allow a slot value to be
/// reused and break the "stale slot cannot match" invariant.
pub(crate) struct Registry {
    /// Active peer handles, keyed by logical NodeId.
    peers: BTreeMap<NodeId, PeerHandle>,
    /// Persistent per-NodeId generation counter. Incremented every
    /// time a new `PeerSlot` is allocated for the NodeId. Never
    /// reset, so a slot value is never reused within a `Node`'s
    /// lifetime.
    generations: BTreeMap<NodeId, u64>,
}

impl Registry {
    pub(crate) fn new() -> Self {
        Self {
            peers: BTreeMap::new(),
            generations: BTreeMap::new(),
        }
    }

    /// Allocate a fresh slot for `peer`, replace any existing handle,
    /// and return the new slot plus the previous handle if any.
    ///
    /// The new handle starts in [`PeerLifecycle::Established`]: a
    /// [`PeerSlot`] is allocated only after the §4 handshake has
    /// completed, so `Connecting` is not observable at the slot
    /// level.
    ///
    /// The generation counter uses `wrapping_add`: reaching
    /// `u64::MAX` connections for a single peer would require a
    /// connection rate no deployed node will ever see, and a panic
    /// in the accept loop is worse than an astronomically unlikely
    /// reuse.
    fn register(
        &mut self,
        peer: NodeId,
        outbound: mpsc::Sender<Message>,
    ) -> (PeerSlot, Option<PeerHandle>) {
        let counter = self.generations.entry(peer).or_insert(0);
        *counter = counter.wrapping_add(1);
        let slot = PeerSlot::new(peer, *counter);
        let old = self.peers.insert(
            peer,
            PeerHandle {
                slot,
                outbound,
                lifecycle: PeerLifecycle::Established,
            },
        );
        (slot, old)
    }

    /// True if `slot` is the currently-registered slot for its peer.
    pub(crate) fn is_current(&self, slot: &PeerSlot) -> bool {
        self.peers
            .get(&slot.node_id)
            .map(|h| h.slot == *slot)
            .unwrap_or(false)
    }

    /// Apply a lifecycle transition for `slot` if it is still current.
    ///
    /// The edge is validated against §2a via
    /// [`PeerLifecycle::transition_to`]. A rejected edge is a caller
    /// bug and leaves the state unchanged; a stale slot is a silent
    /// no-op. Returns `true` if the transition was applied.
    pub(crate) fn set_lifecycle(&mut self, slot: &PeerSlot, to: PeerLifecycle) -> bool {
        if let Some(h) = self.peers.get_mut(&slot.node_id) {
            if h.slot == *slot && h.lifecycle.transition_to(to).is_ok() {
                h.lifecycle = to;
                return true;
            }
        }
        false
    }

    /// Slots of peers that are currently routing-eligible.
    ///
    /// §3 of `docs/M9.5b-design.md`: physical connection existence and
    /// routing eligibility are distinct. The predicate is
    /// [`PeerLifecycle::is_routing_eligible`].
    pub(crate) fn routing_eligible_slots(&self) -> Vec<PeerSlot> {
        self.peers
            .values()
            .filter(|h| h.lifecycle.is_routing_eligible())
            .map(|h| h.slot)
            .collect()
    }

    /// Remove the entry for `slot` if it is current; return whether
    /// anything was removed.
    fn remove_if_current(&mut self, slot: &PeerSlot) -> bool {
        if self.is_current(slot) {
            self.peers.remove(&slot.node_id);
            true
        } else {
            false
        }
    }

    /// Clone the outbound sender for `peer`, if it is registered.
    pub(crate) fn outbound_of(&self, peer: &NodeId) -> Option<mpsc::Sender<Message>> {
        self.peers.get(peer).map(|h| h.outbound.clone())
    }

    /// Every registered peer's `NodeId`, in map order.
    pub(crate) fn peer_ids(&self) -> Vec<NodeId> {
        self.peers.keys().copied().collect()
    }

    /// The current connection generation for `peer`, if registered.
    pub(crate) fn peer_slot(&self, peer: &NodeId) -> Option<PeerSlot> {
        self.peers.get(peer).map(|h| h.slot)
    }

    /// The current lifecycle state for `peer`, if registered.
    pub(crate) fn peer_lifecycle(&self, peer: &NodeId) -> Option<PeerLifecycle> {
        self.peers.get(peer).map(|h| h.lifecycle)
    }
}

/// Shared registry behind the same lock the node's `peers` handle
/// uses.
pub(crate) type PeerRegistry = Arc<Mutex<Registry>>;

/// Peer tasks keyed by logical NodeId. The slot is stored alongside
/// the handle so a task's cleanup path can verify that the entry it
/// sees is its own before removing it.
pub(crate) type TaskMap = Arc<Mutex<BTreeMap<NodeId, (PeerSlot, JoinHandle<()>)>>>;

/// Allocate a slot for a new connection and abort any previous task
/// for the same `NodeId`.
///
/// Returns the new slot. The caller must insert the returned
/// `JoinHandle` into the task map once it has spawned its task.
pub(crate) async fn register_peer(
    peers: &PeerRegistry,
    peer_tasks: &TaskMap,
    peer: NodeId,
    outbound: mpsc::Sender<Message>,
) -> PeerSlot {
    let slot = {
        let mut reg = peers.lock().await;
        let (slot, _old) = reg.register(peer, outbound);
        slot
    };
    // Abort the previous task if there is one. We take the entry
    // out of the map first so that a subsequent insert by the caller
    // replaces it deterministically.
    if let Some((_old_slot, old_task)) = peer_tasks.lock().await.remove(&peer) {
        old_task.abort();
    }
    slot
}

/// Remove a peer task's registry entries on exit.
///
/// The peer handle and the task-map entry are both removed only if
/// `slot` is still the current generation for its peer. A stale task
/// — whose slot was superseded by a newer connection before it
/// finished — leaves the newer task's state alone.
pub(crate) async fn unregister_peer(
    peers: &PeerRegistry,
    peer_tasks: &TaskMap,
    peer: &NodeId,
    slot: &PeerSlot,
) {
    let removed = {
        let mut reg = peers.lock().await;
        reg.remove_if_current(slot)
    };
    if removed {
        let mut tasks = peer_tasks.lock().await;
        let is_ours = tasks
            .get(peer)
            .map(|(s, _)| s == slot)
            .unwrap_or(false);
        if is_ours {
            tasks.remove(peer);
        }
    }
}

