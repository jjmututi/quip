//! Flow-control frames (spec §11).
//!
//! Flow-control frames ride on T1/T2 streams as regular QUIP messages but
//! are consumed by the backpressure layer rather than dispatched to the
//! application. They share the wire path (varint length prefix + QUIP-CBOR)
//! with application verbs, so the driver tries [`dispatch_flow`] first on
//! T1/T2 and falls through to [`crate::message::dispatch`] on `None`.
//!
//! # Wire form
//!
//! The spec §11 lists three frames but does not give a CDDL. This module
//! uses:
//!
//! ```text
//! FlowFrame = [ "quip-v1", "flow", kind: uint, ? window_bytes: uint ]
//! ```
//!
//! with `kind` one of [`BLOCK_KIND`], [`UNBLOCK_KIND`], or
//! [`WINDOW_KIND`]. `window_bytes` is present iff `kind == WINDOW_KIND`.
//!
//! # Direction
//!
//! All three frames are sent by the *receiver* of a stream to the *sender*.
//! `BLOCK` and `UNBLOCK` gate further writes; `WINDOW` advertises how many
//! more bytes the receiver can accept. A [`FlowStateMachine`] tracks both
//! directions for one stream: `send` (our writes, updated by frames the
//! peer sends us) and `recv` (the peer's writes, updated when we send
//! frames to the peer).

use crate::codec::{envelope, fields, verb_of};
use crate::error::{Error, Result};
use alloc::vec::Vec;
use quip_core::cbor::{decode, encode, CborValue};

/// Wire kind discriminant for `BLOCK`.
pub const BLOCK_KIND: u64 = 0x01;
/// Wire kind discriminant for `UNBLOCK`.
pub const UNBLOCK_KIND: u64 = 0x02;
/// Wire kind discriminant for `WINDOW`.
pub const WINDOW_KIND: u64 = 0x03;

/// A flow-control frame.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FlowFrame {
    /// Receiver cannot accept more data.
    Block,
    /// Receiver is ready to accept data.
    Unblock,
    /// Receiver advertises available capacity in bytes.
    Window {
        /// Bytes the receiver can currently accept.
        bytes: u64,
    },
}

impl FlowFrame {
    /// Wire kind discriminant.
    pub const fn kind(&self) -> u64 {
        match self {
            FlowFrame::Block => BLOCK_KIND,
            FlowFrame::Unblock => UNBLOCK_KIND,
            FlowFrame::Window { .. } => WINDOW_KIND,
        }
    }

    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut f = alloc::vec![CborValue::Int(self.kind() as i128)];
        if let FlowFrame::Window { bytes } = self {
            f.push(CborValue::Int(*bytes as i128));
        }
        Ok(encode(&envelope("flow", f))?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "flow" {
            return Err(Error::BadFrame("not a flow frame"));
        }
        let f = fields(&v, "flow")?;
        if f.is_empty() || f.len() > 2 {
            return Err(Error::BadFrame("flow arity"));
        }
        let kind = match &f[0] {
            CborValue::Int(n) if *n >= 0 => *n as u64,
            _ => return Err(Error::BadFrame("flow kind must be a uint")),
        };
        match (kind, f.len()) {
            (BLOCK_KIND, 1) => Ok(FlowFrame::Block),
            (UNBLOCK_KIND, 1) => Ok(FlowFrame::Unblock),
            (WINDOW_KIND, 2) => {
                let bytes = match &f[1] {
                    CborValue::Int(n) if *n >= 0 => *n as u64,
                    _ => return Err(Error::BadFrame("window bytes must be a uint")),
                };
                Ok(FlowFrame::Window { bytes })
            }
            (BLOCK_KIND, _) | (UNBLOCK_KIND, _) => {
                Err(Error::BadFrame("BLOCK/UNBLOCK take no payload"))
            }
            (WINDOW_KIND, _) => Err(Error::BadFrame("WINDOW requires a byte count")),
            _ => Err(Error::BadFrame("unknown flow frame kind")),
        }
    }
}

/// Try to parse `bytes` as a flow frame.
///
/// Returns:
/// - `Some(Ok(frame))` if `bytes` is a well-formed flow frame.
/// - `Some(Err(..))` if `bytes` is a malformed flow frame (verb is
///   `"flow"` but the body is wrong).
/// - `None` if `bytes` is a valid QUIP message whose verb is not `"flow"`,
///   meaning the caller should fall through to application dispatch.
///
/// Non-CBOR bytes and messages with a wrong prefix return `Some(Err(..))`
/// — those are hard errors either way.
pub fn dispatch_flow(bytes: &[u8]) -> Option<Result<FlowFrame>> {
    let value = match decode(bytes) {
        Ok(v) => v,
        Err(e) => return Some(Err(e.into())),
    };
    match verb_of(&value) {
        Ok("flow") => Some(FlowFrame::from_bytes(bytes)),
        Ok(_) => None,
        Err(e) => Some(Err(e)),
    }
}

// -------------------------------------------------------------------------
// State machine
// -------------------------------------------------------------------------

/// Whether a direction is currently accepting data.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FlowState {
    /// Writes permitted (subject to advertised capacity).
    Ready,
    /// Writes blocked until the peer sends `UNBLOCK` or a positive `WINDOW`.
    Blocked,
}

/// Per-direction state.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct DirectionState {
    state: FlowState,
    capacity: u64,
}

impl DirectionState {
    const fn ready() -> Self {
        Self {
            state: FlowState::Ready,
            capacity: u64::MAX,
        }
    }
}

/// Per-stream flow state.
///
/// Tracks two independent directions:
///
/// - **send**: governs bytes *we* write to the stream. Updated by the
///   peer's inbound `BLOCK` / `UNBLOCK` / `WINDOW` frames.
/// - **recv**: governs bytes *the peer* writes to the stream. Updated
///   when we emit outbound `BLOCK` / `UNBLOCK` / `WINDOW` frames.
///
/// The state machine does not own a wire handle; it is a pure data
/// structure. Callers update it from [`FlowFrame`] values they receive or
/// send, and consult it before writing.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FlowStateMachine {
    send: DirectionState,
    recv: DirectionState,
}

impl FlowStateMachine {
    /// A fresh state machine: both directions Ready, capacity unbounded
    /// until the peer or we advertise otherwise.
    pub const fn new() -> Self {
        Self {
            send: DirectionState::ready(),
            recv: DirectionState::ready(),
        }
    }

    // ---- send direction: our writes, peer's frames ----

    /// Current send-side state.
    pub const fn send_state(&self) -> FlowState {
        self.send.state
    }

    /// Bytes the peer has told us it can currently accept. `u64::MAX`
    /// means "unbounded until the peer says otherwise".
    pub const fn send_capacity(&self) -> u64 {
        self.send.capacity
    }

    /// True when we may write at least one byte.
    pub const fn can_send(&self) -> bool {
        matches!(self.send.state, FlowState::Ready) && self.send.capacity > 0
    }

    /// True when we may write exactly `n` bytes.
    pub const fn can_send_n(&self, n: u64) -> bool {
        matches!(self.send.state, FlowState::Ready) && n <= self.send.capacity
    }

    /// Try to reserve `n` bytes against the send-side capacity.
    ///
    /// Returns `true` and consumes `n` bytes of capacity on success,
    /// `false` and consumes nothing on failure. Callers that need a
    /// structured error (with a tier) should map the `false` at their
    /// level, where the tier is known.
    pub fn try_reserve_send(&mut self, n: u64) -> bool {
        if !self.can_send_n(n) {
            return false;
        }
        self.send.capacity -= n;
        true
    }

    /// Apply a frame the peer sent us. Updates the send direction.
    pub fn apply_remote(&mut self, frame: FlowFrame) {
        match frame {
            FlowFrame::Block => {
                self.send.state = FlowState::Blocked;
                self.send.capacity = 0;
            }
            FlowFrame::Unblock => {
                self.send.state = FlowState::Ready;
                // Capacity is whatever the last WINDOW said; if none has
                // arrived, restore the unbounded default.
                if self.send.capacity == 0 {
                    self.send.capacity = u64::MAX;
                }
            }
            FlowFrame::Window { bytes } => {
                self.send.capacity = bytes;
                if bytes > 0 {
                    self.send.state = FlowState::Ready;
                }
            }
        }
    }

    // ---- recv direction: peer's writes, our frames ----

    /// Current recv-side state.
    pub const fn recv_state(&self) -> FlowState {
        self.recv.state
    }

    /// Bytes we have advertised as acceptable. `u64::MAX` means unbounded.
    pub const fn recv_capacity(&self) -> u64 {
        self.recv.capacity
    }

    /// Record that we have sent `BLOCK` to the peer.
    pub fn local_block(&mut self) {
        self.recv.state = FlowState::Blocked;
        self.recv.capacity = 0;
    }

    /// Record that we have sent `UNBLOCK` to the peer.
    pub fn local_unblock(&mut self) {
        self.recv.state = FlowState::Ready;
        if self.recv.capacity == 0 {
            self.recv.capacity = u64::MAX;
        }
    }

    /// Record that we have sent a `WINDOW` frame advertising `bytes`.
    pub fn local_window(&mut self, bytes: u64) {
        self.recv.capacity = bytes;
        if bytes > 0 {
            self.recv.state = FlowState::Ready;
        }
    }
}

impl Default for FlowStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_kind_values_match_spec() {
        assert_eq!(BLOCK_KIND, 0x01);
        assert_eq!(UNBLOCK_KIND, 0x02);
        assert_eq!(WINDOW_KIND, 0x03);
        assert_eq!(FlowFrame::Block.kind(), 0x01);
        assert_eq!(FlowFrame::Unblock.kind(), 0x02);
        assert_eq!(FlowFrame::Window { bytes: 0 }.kind(), 0x03);
    }

    #[test]
    fn block_roundtrip() {
        let f = FlowFrame::Block;
        assert_eq!(FlowFrame::from_bytes(&f.to_bytes().unwrap()).unwrap(), f);
    }

    #[test]
    fn unblock_roundtrip() {
        let f = FlowFrame::Unblock;
        assert_eq!(FlowFrame::from_bytes(&f.to_bytes().unwrap()).unwrap(), f);
    }

    #[test]
    fn window_roundtrip() {
        let f = FlowFrame::Window { bytes: 65_536 };
        assert_eq!(FlowFrame::from_bytes(&f.to_bytes().unwrap()).unwrap(), f);
    }

    #[test]
    fn window_zero_roundtrips() {
        // A zero-byte WINDOW is legal; it re-asserts capacity without
        // unblocking.
        let f = FlowFrame::Window { bytes: 0 };
        assert_eq!(FlowFrame::from_bytes(&f.to_bytes().unwrap()).unwrap(), f);
    }

    #[test]
    fn window_without_bytes_is_rejected() {
        let msg = envelope("flow", alloc::vec![CborValue::Int(WINDOW_KIND as i128)]);
        let bytes = encode(&msg).unwrap();
        assert!(FlowFrame::from_bytes(&bytes).is_err());
    }

    #[test]
    fn block_with_bytes_is_rejected() {
        let msg = envelope(
            "flow",
            alloc::vec![CborValue::Int(BLOCK_KIND as i128), CborValue::Int(1)],
        );
        let bytes = encode(&msg).unwrap();
        assert!(FlowFrame::from_bytes(&bytes).is_err());
    }

    #[test]
    fn unknown_kind_is_rejected() {
        let msg = envelope("flow", alloc::vec![CborValue::Int(99)]);
        let bytes = encode(&msg).unwrap();
        assert!(FlowFrame::from_bytes(&bytes).is_err());
    }

    #[test]
    fn dispatch_flow_returns_none_for_other_verbs() {
        // A well-formed non-flow message must yield None so the caller
        // falls through to application dispatch.
        let msg = envelope("set", alloc::vec![CborValue::Int(1)]);
        let bytes = encode(&msg).unwrap();
        assert!(dispatch_flow(&bytes).is_none());
    }

    #[test]
    fn dispatch_flow_returns_some_for_flow() {
        let bytes = FlowFrame::Block.to_bytes().unwrap();
        assert!(matches!(dispatch_flow(&bytes), Some(Ok(FlowFrame::Block))));
    }

    #[test]
    fn dispatch_flow_errors_on_malformed_flow() {
        // Right verb, wrong body.
        let msg = envelope("flow", alloc::vec![CborValue::Int(99)]);
        let bytes = encode(&msg).unwrap();
        assert!(matches!(dispatch_flow(&bytes), Some(Err(_))));
    }

    #[test]
    fn dispatch_flow_errors_on_garbage() {
        assert!(matches!(dispatch_flow(&[0xff, 0xff, 0xff]), Some(Err(_))));
    }

    // ---- state machine ----

    #[test]
    fn fresh_state_machine_is_ready_unbounded() {
        let m = FlowStateMachine::new();
        assert_eq!(m.send_state(), FlowState::Ready);
        assert_eq!(m.recv_state(), FlowState::Ready);
        assert_eq!(m.send_capacity(), u64::MAX);
        assert!(m.can_send());
    }

    #[test]
    fn block_transitions_send_to_blocked() {
        let mut m = FlowStateMachine::new();
        m.apply_remote(FlowFrame::Block);
        assert_eq!(m.send_state(), FlowState::Blocked);
        assert!(!m.can_send());
        assert!(!m.try_reserve_send(1));
    }

    #[test]
    fn unblock_restores_send() {
        let mut m = FlowStateMachine::new();
        m.apply_remote(FlowFrame::Block);
        m.apply_remote(FlowFrame::Unblock);
        assert_eq!(m.send_state(), FlowState::Ready);
        assert!(m.can_send());
    }

    #[test]
    fn window_sets_send_capacity() {
        let mut m = FlowStateMachine::new();
        m.apply_remote(FlowFrame::Window { bytes: 1024 });
        assert_eq!(m.send_capacity(), 1024);
        assert!(m.can_send());
    }

    #[test]
    fn window_of_zero_blocks_writes() {
        let mut m = FlowStateMachine::new();
        m.apply_remote(FlowFrame::Window { bytes: 0 });
        assert!(!m.can_send());
        assert!(!m.try_reserve_send(1));
    }

    #[test]
    fn reserve_send_consumes_capacity() {
        let mut m = FlowStateMachine::new();
        m.apply_remote(FlowFrame::Window { bytes: 100 });
        assert!(m.try_reserve_send(30));
        assert_eq!(m.send_capacity(), 70);
        assert!(m.try_reserve_send(70));
        assert_eq!(m.send_capacity(), 0);
        assert!(!m.try_reserve_send(1));
    }

    #[test]
    fn reserve_send_all_or_nothing() {
        let mut m = FlowStateMachine::new();
        m.apply_remote(FlowFrame::Window { bytes: 100 });
        assert!(!m.try_reserve_send(101));
        assert_eq!(m.send_capacity(), 100, "no capacity should have been used");
    }

    #[test]
    fn unblock_after_zero_window_restores_unbounded() {
        let mut m = FlowStateMachine::new();
        m.apply_remote(FlowFrame::Window { bytes: 0 });
        assert!(!m.can_send());
        m.apply_remote(FlowFrame::Unblock);
        assert!(m.can_send());
        assert_eq!(m.send_capacity(), u64::MAX);
    }

    #[test]
    fn block_then_window_with_positive_bytes_unblocks() {
        // A peer that blocks and then advertises capacity is signalling
        // that it can accept data again. This is the natural way to
        // replace "BLOCK followed by UNBLOCK" with a single WINDOW.
        let mut m = FlowStateMachine::new();
        m.apply_remote(FlowFrame::Block);
        assert!(!m.can_send());
        m.apply_remote(FlowFrame::Window { bytes: 512 });
        assert!(m.can_send());
        assert_eq!(m.send_capacity(), 512);
    }

    #[test]
    fn local_block_updates_recv_state() {
        let mut m = FlowStateMachine::new();
        m.local_block();
        assert_eq!(m.recv_state(), FlowState::Blocked);
        assert_eq!(m.recv_capacity(), 0);
    }

    #[test]
    fn local_unblock_restores_recv_state() {
        let mut m = FlowStateMachine::new();
        m.local_block();
        m.local_unblock();
        assert_eq!(m.recv_state(), FlowState::Ready);
    }

    #[test]
    fn local_window_sets_recv_capacity() {
        let mut m = FlowStateMachine::new();
        m.local_window(4096);
        assert_eq!(m.recv_capacity(), 4096);
        assert_eq!(m.recv_state(), FlowState::Ready);
    }

    #[test]
    fn directions_are_independent() {
        let mut m = FlowStateMachine::new();
        m.local_block();
        assert_eq!(m.recv_state(), FlowState::Blocked);
        assert_eq!(m.send_state(), FlowState::Ready, "send unaffected");
        assert!(m.can_send());

        m.apply_remote(FlowFrame::Block);
        assert_eq!(m.send_state(), FlowState::Blocked);
        assert_eq!(m.recv_state(), FlowState::Blocked);
    }
} 