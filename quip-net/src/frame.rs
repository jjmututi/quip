//! QUIC stream tiers and message framing (spec §11–§12).
//!
//! Wire form on reliable streams (T0/T1/T2):
//!
//! ```text
//! +------------------+----------------------------------+
//! | varint           | QUIP-CBOR object                 |
//! | length (1-8 B)   | ["quip-v1", ...]                 |
//! +------------------+----------------------------------+
//! ```
//!
//! On T3 (EVENT) there is no framing: each QUIC DATAGRAM carries exactly
//! one QUIP-CBOR object (RFC 9221).
//!
//! Streams are classified by their **reserved QUIC stream ID** (spec §11),
//! not by QUIC's own low-bit convention: stream 0 is the Control Stream,
//! stream 4 is SYNC, and streams 8, 12, 16, … are BULK. Stream IDs 1, 2, 3,
//! 5, 6, 7 and anything not a multiple of 4 at or above 8 are unreserved
//! and MUST be rejected.

use crate::constants::{MAX_DGRAM_BYTES, MAX_MESSAGE_SIZE};
use crate::error::{Error, Result};
use alloc::vec::Vec;

/// Transport tier (spec §12).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Tier {
    /// T0 CTRL — handshake, governance, discovery (stream 0).
    Ctrl = 0,
    /// T1 SYNC — DVV deltas, RBSR, pin queries (stream 4).
    Sync = 1,
    /// T2 BULK — large transfers on dedicated streams (8, 12, 16, …).
    Bulk = 2,
    /// T3 EVENT — unreliable datagrams (`emit`, `pin_announce`).
    Event = 3,
}

/// Legacy numeric aliases (spec tables use T0–T3).
pub const T0: u8 = Tier::Ctrl as u8;
/// T1 SYNC tier discriminant.
pub const T1: u8 = Tier::Sync as u8;
/// T2 BULK tier discriminant.
pub const T2: u8 = Tier::Bulk as u8;
/// T3 EVENT tier discriminant.
pub const T3: u8 = Tier::Event as u8;

impl Tier {
    /// Inverse of `tier as u8`; useful when a wire-adjacent API carries a
    /// tier discriminant.
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Tier::Ctrl),
            1 => Ok(Tier::Sync),
            2 => Ok(Tier::Bulk),
            3 => Ok(Tier::Event),
            _ => Err(Error::BadFrame("unknown tier discriminant")),
        }
    }

    /// True for the unreliable datagram tier.
    pub fn is_datagram(self) -> bool {
        matches!(self, Tier::Event)
    }

    /// Per-tier payload ceiling in bytes (spec §11, §12).
    ///
    /// On T0/T1/T2 the ceiling is the 64 KiB message cap; on T3 it is the
    /// QUIC DATAGRAM MTU bound.
    pub fn max_payload(self) -> usize {
        match self {
            Tier::Event => MAX_DGRAM_BYTES,
            _ => MAX_MESSAGE_SIZE,
        }
    }
}

/// Classification of a stream ID.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum StreamKind {
    /// The single bidirectional Control Stream (QUIC stream 0).
    Ctrl,
    /// The bidirectional SYNC stream (QUIC stream 4).
    Sync,
    /// A bidirectional BULK stream (QUIC streams 8, 12, 16, …).
    Bulk,
}

impl StreamKind {
    /// Corresponding transport tier.
    pub fn tier(self) -> Tier {
        match self {
            StreamKind::Ctrl => Tier::Ctrl,
            StreamKind::Sync => Tier::Sync,
            StreamKind::Bulk => Tier::Bulk,
        }
    }
}

/// Newtype QUIC stream ID with reserved-ID validation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(pub u64);

/// The Control Stream (T0, QUIC stream 0).
pub const CTRL_STREAM: StreamId = StreamId(0);

/// The single SYNC stream (T1, QUIC stream 4).
pub const SYNC_STREAM: StreamId = StreamId(4);

/// Reserved Control Stream ID (spec §11).
pub const CTRL_STREAM_ID: u64 = 0;

/// Reserved SYNC stream ID (spec §11).
pub const SYNC_STREAM_ID: u64 = 4;

/// Maximum streams per tier before backpressure (spec §12).
///
/// Mirrors the `*_MAX_*` constants in [`crate::constants`]; keep both in
/// sync. Indexed by `tier as usize` (Ctrl=0, Sync=1, Bulk=2, Event=3).
pub const MAX_STREAMS_PER_TIER: [usize; 4] = [
    crate::constants::T0_MAX_STREAMS,
    crate::constants::T1_MAX_STREAMS,
    crate::constants::T2_MAX_STREAMS,
    crate::constants::T3_MAX_DATAGRAMS,
];

impl StreamId {
    /// Classify a stream ID by its reserved value (spec §11).
    ///
    /// T0 = 0, T1 = 4, T2 = every client-initiated bidirectional stream ID
    /// starting at 8 (i.e. multiples of 4). Anything else is unreserved.
    pub fn kind(self) -> Result<StreamKind> {
        match self.0 {
            0 => Ok(StreamKind::Ctrl),
            4 => Ok(StreamKind::Sync),
            n if n >= 8 && n % 4 == 0 => Ok(StreamKind::Bulk),
            _ => Err(Error::BadStream("unreserved stream id")),
        }
    }

    /// Tier of this stream.
    pub fn tier(self) -> Result<Tier> {
        Ok(self.kind()?.tier())
    }

    /// True for the Control Stream.
    pub fn is_ctrl(self) -> bool {
        self.0 == 0
    }
}

// -------------------------------------------------------------------------
// Varint (QUIC-style, 1 / 2 / 4 / 8 bytes)
// -------------------------------------------------------------------------

/// Encode `value` as a QUIC-style variable-length integer.
///
/// The two high bits of the first byte select the total width:
/// `00` → 1 byte (values < 64), `01` → 2 bytes (< 2^14),
/// `10` → 4 bytes (< 2^30), `11` → 8 bytes (< 2^62).
///
/// Returns [`Error::BadFrame`] if `value >= 2^62`.
pub fn encode_varint(value: u64, out: &mut Vec<u8>) -> Result<()> {
    if value < 64 {
        out.push(value as u8);
    } else if value < 16_384 {
        let bytes = ((value as u16) | 0x4000).to_be_bytes();
        out.extend_from_slice(&bytes);
    } else if value < 1_073_741_824 {
        let bytes = ((value as u32) | 0x8000_0000).to_be_bytes();
        out.extend_from_slice(&bytes);
    } else if value < (1u64 << 62) {
        let bytes = (value | 0xC000_0000_0000_0000).to_be_bytes();
        out.extend_from_slice(&bytes);
    } else {
        return Err(Error::BadFrame("varint exceeds 2^62-1"));
    }
    Ok(())
}

/// Total width in bytes of the varint whose first byte is `first_byte`.
///
/// Never fails: every `u8` maps to a valid width.
pub fn varint_len(first_byte: u8) -> usize {
    1usize << (first_byte >> 6)
}

/// Decode a QUIC-style varint from the front of `buf`, returning
/// `(value, bytes_consumed)`.
///
/// Returns [`Error::BadFrame`] if `buf` is shorter than the varint's declared
/// width. Callers doing incremental reassembly should check
/// `buf.len() >= varint_len(buf[0])` first — see [`try_deframe`].
pub fn decode_varint(buf: &[u8]) -> Result<(u64, usize)> {
    let first = *buf.first().ok_or(Error::BadFrame("varint: empty buffer"))?;
    let len = varint_len(first);
    if buf.len() < len {
        return Err(Error::BadFrame("varint: truncated"));
    }
    let mut value = (first & 0x3f) as u64;
    for &b in &buf[1..len] {
        value = (value << 8) | b as u64;
    }
    Ok((value, len))
}

// -------------------------------------------------------------------------
// Message framing
// -------------------------------------------------------------------------

/// Encode one QUIP message for a reliable stream (T0/T1/T2).
///
/// Prepends the shortest-form varint length. On T3 use the payload directly:
/// no length prefix is present, and one CBOR object is one datagram.
pub fn encode_message(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > MAX_MESSAGE_SIZE {
        return Err(Error::TooLarge {
            size: payload.len(),
            max: MAX_MESSAGE_SIZE,
        });
    }
    let mut out = Vec::with_capacity(payload.len() + 8);
    encode_varint(payload.len() as u64, &mut out)?;
    out.extend_from_slice(payload);
    Ok(out)
}

/// Try to extract one framed message from the front of `buf`.
///
/// Returns:
/// - `Ok(Some((message, consumed)))` when a full message is available.
///   `message` is the CBOR payload (length prefix already stripped) and
///   `consumed` is the number of framed bytes the caller should advance by.
/// - `Ok(None)` when `buf` holds only a prefix of an incomplete message.
///   The caller reads more bytes and retries.
/// - `Err(..)` when the declared length exceeds [`MAX_MESSAGE_SIZE`].
///
/// The caller owns the buffer; this function never allocates and never
/// copies the payload.
pub fn try_deframe(buf: &[u8]) -> Result<Option<(&[u8], usize)>> {
    let Some(&first) = buf.first() else {
        return Ok(None);
    };
    let header_len = varint_len(first);
    if buf.len() < header_len {
        return Ok(None);
    }
    let (len, _) = decode_varint(buf)?;
    let len = len as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(Error::TooLarge {
            size: len,
            max: MAX_MESSAGE_SIZE,
        });
    }
    let total = header_len + len;
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some((&buf[header_len..total], total)))
}

/// Drain every complete message from `buf`, returning the messages and the
/// trailing incomplete bytes.
///
/// Convenience wrapper around [`try_deframe`] for hosts that prefer a single
/// call over an incremental loop.
pub fn deframe_all(buf: &[u8]) -> Result<(Vec<Vec<u8>>, Vec<u8>)> {
    let mut messages = Vec::new();
    let mut cursor = 0usize;
    while let Some((msg, consumed)) = try_deframe(&buf[cursor..])? {
        messages.push(msg.to_vec());
        cursor += consumed;
    }
    Ok((messages, buf[cursor..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_widths() {
        assert_eq!(varint_len(0x00), 1);
        assert_eq!(varint_len(0x3f), 1);
        assert_eq!(varint_len(0x40), 2);
        assert_eq!(varint_len(0x7f), 2);
        assert_eq!(varint_len(0x80), 4);
        assert_eq!(varint_len(0xbf), 4);
        assert_eq!(varint_len(0xc0), 8);
        assert_eq!(varint_len(0xff), 8);
    }

    #[test]
    fn varint_roundtrip_boundaries() {
        for v in [0u64, 1, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824, (1u64 << 62) - 1] {
            let mut buf = Vec::new();
            encode_varint(v, &mut buf).unwrap();
            let (back, used) = decode_varint(&buf).unwrap();
            assert_eq!(back, v, "value {v}");
            assert_eq!(used, buf.len(), "length {v}");
            assert_eq!(used, varint_len(buf[0]), "width vs first byte for {v}");
        }
    }

    #[test]
    fn varint_rejects_out_of_range() {
        let mut buf = Vec::new();
        assert!(encode_varint(1u64 << 62, &mut buf).is_err());
        assert!(encode_varint(u64::MAX, &mut buf).is_err());
    }

    #[test]
    fn stream_classification() {
        assert_eq!(StreamId(0).kind().unwrap(), StreamKind::Ctrl);
        assert_eq!(StreamId(4).kind().unwrap(), StreamKind::Sync);
        assert_eq!(StreamId(8).kind().unwrap(), StreamKind::Bulk);
        assert_eq!(StreamId(12).kind().unwrap(), StreamKind::Bulk);
        assert_eq!(StreamId(16).kind().unwrap(), StreamKind::Bulk);
        // Reserved / unreserved rejected.
        for bad in [1u64, 2, 3, 5, 6, 7, 9, 10, 11, 13, 101] {
            assert!(StreamId(bad).kind().is_err(), "stream {bad}");
        }
    }

    #[test]
    fn message_roundtrip() {
        let payload = b"[\"quip-v1\",\"ping\"]";
        let framed = encode_message(payload).unwrap();
        let (msg, consumed) = try_deframe(&framed).unwrap().unwrap();
        assert_eq!(msg, payload);
        assert_eq!(consumed, framed.len());
    }

    #[test]
    fn deframe_needs_more_bytes_returns_none() {
        let framed = encode_message(b"hello").unwrap();
        // Every strict prefix must yield Ok(None), never an error.
        for cut in 0..framed.len() {
            assert!(
                try_deframe(&framed[..cut]).unwrap().is_none(),
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn deframe_rejects_oversized_length() {
        // Forge a 4-byte varint declaring 1 MiB.
        let mut buf = Vec::new();
        encode_varint(1_048_576, &mut buf).unwrap();
        assert!(matches!(
            try_deframe(&buf),
            Err(Error::TooLarge { .. })
        ));
    }

    #[test]
    fn deframe_all_handles_pipelined_messages() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&encode_message(b"one").unwrap());
        stream.extend_from_slice(&encode_message(b"two").unwrap());
        stream.extend_from_slice(&encode_message(b"three").unwrap());
        // Trailing partial message.
        stream.extend_from_slice(&encode_message(b"four").unwrap()[..1]);
        let (msgs, rest) = deframe_all(&stream).unwrap();
        assert_eq!(msgs, vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]);
        assert_eq!(rest.len(), 1);
    }
}