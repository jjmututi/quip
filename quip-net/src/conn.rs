//! Connection lifecycle (spec §11, §12, §15).
//!
//! [`Connection`] is a pure state container: it holds the negotiated
//! capabilities, per-tier stream counts, and per-stream flow-control
//! state. It does not touch a socket or a QUIC handle. The transport
//! driver (M5) owns the QUIC connection and calls into `Connection` for
//! the bookkeeping.

use crate::codec::{envelope, fields, verb_of};
use crate::constants::{HANDSHAKE_TIMEOUT_MS, T0_MAX_STREAMS};
use crate::error::{Error, Result};
use crate::flow::{FlowFrame, FlowStateMachine};
use crate::frame::Tier;
use crate::handshake::{Capabilities, Handshake};
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use quip_core::cbor::{decode, encode, CborValue};
use quip_core::time::Timestamp;

/// Connection configuration.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct QuipNetConfig {
    /// Capabilities to offer.
    pub capabilities: Capabilities,
    /// Max T1 streams.
    pub max_sync_streams: usize,
    /// Max T2 streams.
    pub max_bulk_streams: usize,
}

impl Default for QuipNetConfig {
    fn default() -> Self {
        Self {
            capabilities: Capabilities::baseline(),
            max_sync_streams: crate::constants::T1_MAX_STREAMS,
            max_bulk_streams: crate::constants::T2_MAX_STREAMS,
        }
    }
}

/// Connection phase.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConnectionPhase {
    /// Handshake not yet exchanged.
    Handshaking,
    /// Application streams live.
    Established,
    /// Connection is draining.
    Draining,
    /// Connection closed.
    Closed,
}

/// A QUIP-over-QUIC connection (transport-owned state only).
pub struct Connection {
    config: QuipNetConfig,
    handshake: Handshake,
    phase: ConnectionPhase,
    agreed: Option<Capabilities>,
    opened: [usize; 4],
    received: u64,
    /// Per-stream flow-control state, keyed by QUIC stream ID.
    ///
    /// Populated when a T1/T2 stream is opened and torn down when it
    /// closes. The driver (M5) consults `flow_state` before writing and
    /// calls `apply_flow_frame` when it receives a `"flow"` message.
    flows: BTreeMap<u64, FlowStateMachine>,
}

/// Action returned by [`Connection::note_bytes_received`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BackpressureAction {
    received: u64,
    blocked: bool,
}

impl BackpressureAction {
    /// Total bytes received so far.
    pub fn received(&self) -> u64 {
        self.received
    }

    /// True once any bytes flowed.
    pub fn backpressure_applied(&self) -> bool {
        self.received > 0
    }

    /// True when the connection must shed load.
    pub fn must_shed(&self) -> bool {
        self.blocked
    }
}

impl Connection {
    /// Create as handshake initiator.
    pub fn new_initiator(config: QuipNetConfig) -> Self {
        let handshake = Handshake::new(config.capabilities);
        Self {
            config,
            handshake,
            phase: ConnectionPhase::Handshaking,
            agreed: None,
            opened: [0; 4],
            received: 0,
            flows: BTreeMap::new(),
        }
    }

    /// Create as responder.
    pub fn new_responder(config: QuipNetConfig) -> Self {
        Self::new_initiator(config)
    }

    /// Current phase.
    pub fn phase(&self) -> ConnectionPhase {
        self.phase
    }

    /// Local handshake bytes for QUIC stream 0.
    pub fn handshake_bytes(&self) -> Result<Vec<u8>> {
        self.handshake.to_bytes()
    }

    /// True when `bytes` decode as a handshake array.
    pub fn is_quip_handshake(bytes: &[u8]) -> bool {
        Handshake::from_bytes(bytes).is_ok()
    }

    /// Process a remote handshake; transitions to `Established`.
    pub fn on_handshake(&mut self, bytes: &[u8], _now: Timestamp) -> Result<Capabilities> {
        if self.phase != ConnectionPhase::Handshaking {
            return Err(Error::Handshake("handshake already done"));
        }
        let remote = Handshake::from_bytes(bytes)?;
        let agreed = self.handshake.negotiate(&remote)?;
        self.agreed = Some(agreed);
        self.phase = ConnectionPhase::Established;
        Ok(agreed)
    }

    /// Negotiated capabilities (`None` before handshake).
    pub fn agreed(&self) -> Option<Capabilities> {
        self.agreed
    }

    /// Track received bytes.
    pub fn note_bytes_received(&mut self, n: u64, _now: Timestamp) -> BackpressureAction {
        self.received = self.received.saturating_add(n);
        BackpressureAction {
            received: self.received,
            blocked: false,
        }
    }

    /// Open a stream on `tier`, enforcing per-tier caps.
    ///
    /// The returned value is a **count**, not a QUIC stream ID. The caller
    /// opens the QUIC stream via the runtime and passes the actual stream
    /// ID to [`crate::frame::StreamId::kind`] for tier validation.
    pub fn open_stream(&mut self, tier: Tier) -> Result<u64> {
        let idx = tier as usize;
        let cap = match tier {
            Tier::Ctrl => T0_MAX_STREAMS,
            Tier::Sync => self.config.max_sync_streams,
            Tier::Bulk => self.config.max_bulk_streams,
            Tier::Event => crate::constants::T3_MAX_DATAGRAMS,
        };
        if self.opened[idx] >= cap {
            return Err(Error::FlowBlocked {
                tier: tier as u8,
                limit: cap,
            });
        }
        self.opened[idx] += 1;
        Ok(self.opened[idx] as u64)
    }

    /// Close one stream on `tier`.
    pub fn close_stream(&mut self, tier: Tier) {
        let idx = tier as usize;
        self.opened[idx] = self.opened[idx].saturating_sub(1);
    }

    /// Handshake timeout in ms.
    pub fn handshake_timeout() -> u64 {
        HANDSHAKE_TIMEOUT_MS
    }

    /// Encode a protocol error message.
    ///
    /// Wire form (spec §14): `["quip-v1", "error", code, message_id, text]`.
    pub fn error_bytes(code: quip_core::ErrorCode, id: u64, text: &str) -> Vec<u8> {
        let msg = envelope(
            "error",
            alloc::vec![
                CborValue::Int(code as i128),
                CborValue::Int(id as i128),
                CborValue::String(text.to_string()),
            ],
        );
        encode(&msg).unwrap_or_default()
    }

    /// Decode a protocol error message.
    ///
    /// Returns `(code, message_id, text)`.
    pub fn parse_error(bytes: &[u8]) -> Result<(u64, u64, String)> {
        let v = decode(bytes)?;
        let verb = verb_of(&v)?;
        if verb != "error" {
            return Err(Error::BadFrame("not an error"));
        }
        let f = fields(&v, "error")?;
        if f.len() != 3 {
            return Err(Error::BadFrame("error arity"));
        }
        let code = match &f[0] {
            CborValue::Int(n) if *n >= 0 && *n <= u8::MAX as i128 => *n as u64,
            _ => return Err(Error::BadFrame("error code must be a small uint")),
        };
        let id = match &f[1] {
            CborValue::Int(n) if *n >= 0 => *n as u64,
            _ => return Err(Error::BadFrame("error id must be a uint")),
        };
        let text = match &f[2] {
            CborValue::String(s) => s.clone(),
            _ => return Err(Error::BadFrame("error text must be a string")),
        };
        Ok((code, id, text))
    }

    // ---- Per-stream flow control (§11) ----

    /// Register a new flow state for `stream` in the Ready/Unbounded state.
    ///
    /// Called by the driver when a T1 or T2 stream is opened. Calling this
    /// for a stream that already has flow state is a no-op, so a retry
    /// after a partial open does not clobber advertised capacity.
    pub fn register_flow_stream(&mut self, stream: u64) {
        self.flows.entry(stream).or_default();
    }

    /// Drop flow state for `stream`.
    pub fn unregister_flow_stream(&mut self, stream: u64) {
        self.flows.remove(&stream);
    }

    /// Read-only view of the flow state for `stream`, if registered.
    pub fn flow_state(&self, stream: u64) -> Option<&FlowStateMachine> {
        self.flows.get(&stream)
    }

    /// Mutable view of the flow state for `stream`, if registered.
    pub fn flow_state_mut(&mut self, stream: u64) -> Option<&mut FlowStateMachine> {
        self.flows.get_mut(&stream)
    }

    /// Apply an inbound flow frame to `stream`'s state.
    ///
    /// Returns [`Error::BadStream`] if `stream` has no registered flow
    /// state — a flow frame for an unknown stream is a protocol error.
    pub fn apply_flow_frame(&mut self, stream: u64, frame: FlowFrame) -> Result<()> {
        let state = self
            .flows
            .get_mut(&stream)
            .ok_or(Error::BadStream("flow frame for unregistered stream"))?;
        state.apply_remote(frame);
        Ok(())
    }

    /// Reserve `n` bytes for an outbound write on `stream`.
    ///
    /// Returns [`Error::BadStream`] if the stream has no flow state, or
    /// [`Error::FlowBlocked`] if the peer has blocked writes or advertised
    /// insufficient capacity. On failure, no capacity is consumed.
    pub fn reserve_send(&mut self, stream: u64, n: u64) -> Result<()> {
        let state = self
            .flows
            .get_mut(&stream)
            .ok_or(Error::BadStream("write to unregistered stream"))?;
        if state.try_reserve_send(n) {
            return Ok(());
        }
        // Derive the tier from the stream ID for the error. If the stream
        // ID is unreserved, fall back to `0` (Ctrl); the caller receives a
        // structured error either way.
        let tier = crate::frame::StreamId(stream)
            .tier()
            .map(|t| t as u8)
            .unwrap_or(0);
        Err(Error::FlowBlocked {
            tier,
            limit: n as usize,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::FlowState;
    use quip_core::ErrorCode;

    #[test]
    fn error_roundtrip_includes_prefix() {
        let bytes = Connection::error_bytes(ErrorCode::ProfileMismatch, 42, "no common");
        let (code, id, text) = Connection::parse_error(&bytes).unwrap();
        assert_eq!(code, ErrorCode::ProfileMismatch as u64);
        assert_eq!(id, 42);
        assert_eq!(text, "no common");
    }

    #[test]
    fn error_bytes_start_with_quip_prefix() {
        let bytes = Connection::error_bytes(ErrorCode::Violation, 1, "x");
        let v = quip_core::cbor::decode(&bytes).unwrap();
        let CborValue::Array(items) = v else {
            panic!("expected array");
        };
        assert_eq!(items[0], CborValue::String("quip-v1".into()));
        assert_eq!(items[1], CborValue::String("error".into()));
    }

    #[test]
    fn flow_streams_are_tracked_per_id() {
        let mut c = Connection::new_initiator(QuipNetConfig::default());
        c.register_flow_stream(4);
        c.register_flow_stream(8);
        assert!(c.flow_state(4).is_some());
        assert!(c.flow_state(8).is_some());
        assert!(c.flow_state(12).is_none());
        c.unregister_flow_stream(4);
        assert!(c.flow_state(4).is_none());
    }

    #[test]
    fn applying_flow_frame_updates_state() {
        let mut c = Connection::new_initiator(QuipNetConfig::default());
        c.register_flow_stream(4);
        c.apply_flow_frame(4, FlowFrame::Block).unwrap();
        assert_eq!(c.flow_state(4).unwrap().send_state(), FlowState::Blocked);
    }

    #[test]
    fn flow_frame_for_unregistered_stream_errors() {
        let mut c = Connection::new_initiator(QuipNetConfig::default());
        assert!(matches!(
            c.apply_flow_frame(4, FlowFrame::Block),
            Err(Error::BadStream(_))
        ));
    }

    #[test]
    fn reserve_send_honours_flow_state() {
        let mut c = Connection::new_initiator(QuipNetConfig::default());
        c.register_flow_stream(4);
        c.apply_flow_frame(4, FlowFrame::Window { bytes: 100 })
            .unwrap();
        c.reserve_send(4, 60).unwrap();
        assert!(matches!(
            c.reserve_send(4, 60),
            Err(Error::FlowBlocked { tier: 1, .. })
        ));
        c.reserve_send(4, 40).unwrap();
    }

    #[test]
    fn reserve_send_for_unregistered_stream_errors() {
        let mut c = Connection::new_initiator(QuipNetConfig::default());
        assert!(matches!(
            c.reserve_send(4, 1),
            Err(Error::BadStream(_))
        ));
    }

    #[test]
    fn register_flow_stream_is_idempotent() {
        let mut c = Connection::new_initiator(QuipNetConfig::default());
        c.register_flow_stream(4);
        c.apply_flow_frame(4, FlowFrame::Window { bytes: 100 })
            .unwrap();
        c.register_flow_stream(4); // should not reset
        assert_eq!(c.flow_state(4).unwrap().send_capacity(), 100);
    }

    #[test]
    fn blocked_stream_rejects_reserve() {
        let mut c = Connection::new_initiator(QuipNetConfig::default());
        c.register_flow_stream(8);
        c.apply_flow_frame(8, FlowFrame::Block).unwrap();
        assert!(matches!(
            c.reserve_send(8, 1),
            Err(Error::FlowBlocked { tier: 2, .. })
        ));
    }
}