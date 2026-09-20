//! BULK-plane transfers (T2, spec section 14.3).
//!
//! A sender splits a payload into `send_chunk` frames; a receiver
//! reassembles them and verifies the result against the CID announced in
//! `send_start`. Spec §8 requires receivers to verify the hash of the
//! received payload against its CID, so the production entry point is
//! [`BulkReceiver::reassemble_verified`]; [`BulkReceiver::reassemble`]
//! exists as a low-level primitive and MUST NOT be used in production
//! without an out-of-band check.

use crate::codec::{as_bytes, as_u64, envelope, fields, verb_of};
use crate::constants::MAX_CHUNK_BYTES;
use crate::error::{Error, Result};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use quip_core::cbor::{decode, encode, CborValue};
use quip_core::cid::{CidOrV1, HashAlgo};
use quip_storage::{verify_content, ContentHasher};

/// Default chunk payload size.
pub const CHUNK_SIZE: usize = MAX_CHUNK_BYTES;

/// BULK transfer configuration.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BulkTransferConfig {
    /// Chunk payload size in bytes.
    pub chunk_size: usize,
}

impl Default for BulkTransferConfig {
    fn default() -> Self {
        Self { chunk_size: CHUNK_SIZE }
    }
}

// -------------------------------------------------------------------------
// Sender
// -------------------------------------------------------------------------

/// Outgoing BULK transfer: splits a payload into `send_chunk` frames.
#[derive(Clone, Debug)]
pub struct BulkSender {
    resource_id: Vec<u8>,
    payload: Vec<u8>,
    cid: CidOrV1,
    config: BulkTransferConfig,
    next_seq: u64,
    started: bool,
    done: bool,
}

impl BulkSender {
    /// Create a sender for `payload` announced under `cid`.
    pub fn new(
        resource_id: Vec<u8>,
        payload: Vec<u8>,
        cid: CidOrV1,
        config: BulkTransferConfig,
    ) -> Self {
        Self {
            resource_id,
            payload,
            cid,
            config,
            next_seq: 0,
            started: false,
            done: false,
        }
    }

    /// Encode `send_start`; call once before chunks.
    ///
    /// Wire form (spec §14.3):
    /// `["send_start", resource_id, total_size, hash, cid, ?hash_algo]`.
    /// The legacy `hash` slot duplicates the CID digest (deprecated but
    /// still on the wire).
    pub fn send_start(&mut self) -> Result<Vec<u8>> {
        if self.started {
            return Err(Error::Transfer("send_start already emitted"));
        }
        self.started = true;
        let digest = self.cid.digest().to_vec();
        let msg = envelope(
            "send_start",
            alloc::vec![
                CborValue::Bytes(self.resource_id.clone()),
                CborValue::Int(self.payload.len() as i128),
                CborValue::Bytes(digest),
                self.cid.to_cbor(),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Next `send_chunk`, or `None` when the payload is exhausted.
    pub fn next_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        if !self.started {
            return Err(Error::Transfer("send_start required first"));
        }
        if self.done {
            return Ok(None);
        }
        let offset = self.next_seq as usize * self.config.chunk_size;
        if offset >= self.payload.len() {
            self.done = true;
            return Ok(None);
        }
        let end = (offset + self.config.chunk_size).min(self.payload.len());
        let msg = envelope(
            "send_chunk",
            alloc::vec![
                CborValue::Bytes(self.resource_id.clone()),
                CborValue::Int(self.next_seq as i128),
                CborValue::Int(offset as i128),
                CborValue::Bytes(self.payload[offset..end].to_vec()),
            ],
        );
        self.next_seq += 1;
        if end == self.payload.len() {
            self.done = true;
        }
        Ok(Some(encode(&msg)?))
    }

    /// Encode `send_complete`.
    ///
    /// Wire form (spec §14.3):
    /// `["send_complete", resource_id, final_hash, ?cid]`.
    /// `final_hash` duplicates the CID digest; the trailing `cid` is
    /// optional per the spec CDDL.
    pub fn send_complete(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "send_complete",
            alloc::vec![
                CborValue::Bytes(self.resource_id.clone()),
                CborValue::Bytes(self.cid.digest().to_vec()),
                self.cid.to_cbor(),
            ],
        );
        Ok(encode(&msg)?)
    }
}

// -------------------------------------------------------------------------
// Receiver
// -------------------------------------------------------------------------

/// Incoming BULK transfer: reassembles `send_chunk` frames.
#[derive(Clone, Debug, Default)]
pub struct BulkReceiver {
    expected: Option<(Vec<u8>, usize, CidOrV1)>,
    chunks: BTreeMap<u64, Vec<u8>>,
    received: usize,
}

impl BulkReceiver {
    /// Create an empty receiver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Handle one decoded wire message; returns `true` when complete.
    pub fn ingest_bytes(&mut self, bytes: &[u8]) -> Result<bool> {
        let value = decode(bytes)?;
        let verb = verb_of(&value)?;
        match verb {
            "send_start" => {
                let f = fields(&value, "send_start")?;
                if f.len() != 4 && f.len() != 5 {
                    return Err(Error::Transfer("send_start arity"));
                }
                let rid = as_bytes(&f[0])?;
                let total = as_u64(&f[1])? as usize;
                // f[2] is the legacy `hash` slot (deprecated, duplicates CID digest).
                let cid = CidOrV1::from_cbor(&f[3])?;
                self.expected = Some((rid, total, cid));
                self.chunks.clear();
                self.received = 0;
                Ok(false)
            }
            "send_chunk" => {
                let f = fields(&value, "send_chunk")?;
                if f.len() != 4 {
                    return Err(Error::Transfer("send_chunk arity"));
                }
                let seq = as_u64(&f[1])?;
                let chunk = as_bytes(&f[3])?;
                if chunk.len() > MAX_CHUNK_BYTES {
                    return Err(Error::Transfer("chunk too large"));
                }
                if self.chunks.insert(seq, chunk.clone()).is_none() {
                    self.received += chunk.len();
                }
                Ok(self.is_complete())
            }
            "send_complete" => {
                let f = fields(&value, "send_complete")?;
                if f.len() != 2 && f.len() != 3 {
                    return Err(Error::Transfer("send_complete arity"));
                }
                // f[0] is resource_id, f[1] is final_hash; optional f[2] is cid.
                Ok(self.is_complete())
            }
            _ => Err(Error::UnknownVerb(alloc::string::ToString::to_string(verb))),
        }
    }

    /// True when all expected bytes arrived.
    pub fn is_complete(&self) -> bool {
        match &self.expected {
            Some((_, total, _)) => self.received >= *total && *total > 0,
            None => false,
        }
    }

    /// Reassemble in sequence order, **without** verifying against the CID.
    ///
    /// This is the low-level primitive. Production callers MUST use
    /// [`Self::reassemble_verified`], which verifies the reassembled bytes
    /// against the CID from `send_start` as required by spec §8.
    ///
    /// Returns the concatenation of chunks `0..total` as announced in
    /// `send_start`. Errors if `send_start` has not been seen or a
    /// sequence number is missing.
    pub fn reassemble(&self) -> Result<Vec<u8>> {
        let (_, total, _) = self
            .expected
            .as_ref()
            .ok_or(Error::Transfer("no send_start"))?;
        let mut out = Vec::with_capacity(*total);
        let mut seq = 0u64;
        while out.len() < *total {
            let chunk = self
                .chunks
                .get(&seq)
                .ok_or(Error::Transfer("missing chunk"))?;
            out.extend_from_slice(chunk);
            seq += 1;
        }
        out.truncate(*total);
        Ok(out)
    }

    /// Reassemble and verify the result against the announced CID.
    ///
    /// On success the returned bytes are the payload that hashed to the
    /// CID in `send_start`. A mismatch is rejected with
    /// [`quip_storage::Error::CidMismatch`] wrapped as [`Error::Storage`],
    /// which maps to `E_CID_MISMATCH` (0x0C) on the wire (spec §8).
    ///
    /// # Algorithm selection
    ///
    /// For a tagged [`CidOrV1::V1`], the hash algorithm comes from the CID
    /// itself and `negotiated` is ignored. For a raw [`CidOrV1::Raw`], the
    /// algorithm comes from the connection's `hash_algo` handshake
    /// extension, which the caller passes as `negotiated` (spec §8).
    pub fn reassemble_verified(
        &self,
        negotiated: HashAlgo,
        hasher: &impl ContentHasher,
    ) -> Result<Vec<u8>> {
        let bytes = self.reassemble()?;
        let cid = self.cid().ok_or(Error::Transfer("no send_start"))?;
        verify_content(&cid, &bytes, negotiated, hasher)?;
        Ok(bytes)
    }

    /// Expected CID announced in `send_start`.
    pub fn cid(&self) -> Option<CidOrV1> {
        self.expected.as_ref().map(|(_, _, c)| *c)
    }

    /// Expected total payload size in bytes.
    pub fn total_size(&self) -> Option<usize> {
        self.expected.as_ref().map(|(_, t, _)| *t)
    }

    /// Resource name announced in `send_start`.
    pub fn resource_id(&self) -> Option<&[u8]> {
        self.expected.as_ref().map(|(r, _, _)| r.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Deterministic fake hasher: digest = XOR-fold of payload bytes,
    /// seeded per algorithm so SHA-256 and BLAKE3 produce distinct values.
    struct FakeHasher;

    impl ContentHasher for FakeHasher {
        fn digest(&self, algo: HashAlgo, payload: &[u8]) -> Option<[u8; 32]> {
            let seed = match algo {
                HashAlgo::Sha256 => 0x11,
                HashAlgo::Blake3 => 0x22,
            };
            let mut out = [0u8; 32];
            for (i, b) in payload.iter().enumerate() {
                out[i % 32] ^= b ^ seed;
            }
            Some(out)
        }
    }

    /// Compute the raw CID that `FakeHasher` would produce for `payload`.
    fn cid_for(payload: &[u8], algo: HashAlgo) -> CidOrV1 {
        let digest = FakeHasher.digest(algo, payload).unwrap();
        CidOrV1::Raw(quip_core::cid::Cid::new(digest))
    }

    /// Feed `messages` through a fresh receiver and return it.
    fn ingest_all(messages: &[Vec<u8>]) -> BulkReceiver {
        let mut r = BulkReceiver::new();
        for m in messages {
            r.ingest_bytes(m).unwrap();
        }
        r
    }

    #[test]
    fn verified_reassemble_accepts_matching_payload() {
        let payload = b"the quick brown fox jumps over the lazy dog".to_vec();
        let cid = cid_for(&payload, HashAlgo::Sha256);
        let mut sender = BulkSender::new(
            b"res".to_vec(),
            payload.clone(),
            cid,
            BulkTransferConfig::default(),
        );
        let mut msgs = vec![sender.send_start().unwrap()];
        while let Some(c) = sender.next_chunk().unwrap() {
            msgs.push(c);
        }
        msgs.push(sender.send_complete().unwrap());

        let r = ingest_all(&msgs);
        let bytes = r.reassemble_verified(HashAlgo::Sha256, &FakeHasher).unwrap();
        assert_eq!(bytes, payload);
    }

    #[test]
    fn verified_reassemble_rejects_mismatched_payload() {
        // Send a CID for the wrong payload. Reassemble + verify must fail.
        let real = b"correct payload".to_vec();
        let wrong = b"tampered payload".to_vec();
        let cid = cid_for(&real, HashAlgo::Sha256);

        let mut sender = BulkSender::new(
            b"res".to_vec(),
            wrong,
            cid,
            BulkTransferConfig::default(),
        );
        let mut msgs = vec![sender.send_start().unwrap()];
        while let Some(c) = sender.next_chunk().unwrap() {
            msgs.push(c);
        }
        msgs.push(sender.send_complete().unwrap());

        let r = ingest_all(&msgs);
        let err = r
            .reassemble_verified(HashAlgo::Sha256, &FakeHasher)
            .unwrap_err();
        assert!(
            matches!(err, Error::Storage(quip_storage::Error::CidMismatch)),
            "expected CidMismatch, got {err:?}"
        );
    }

    #[test]
    fn verified_reassemble_honours_negotiated_algorithm_for_raw_cids() {
        // A raw CID carries no algorithm; the negotiated value decides.
        // Compute the CID under SHA-256, then verify with BLAKE3 as the
        // negotiated algorithm — the digests differ, so verification must
        // fail.
        let payload = b"some bytes".to_vec();
        let cid = cid_for(&payload, HashAlgo::Sha256);
        let mut sender = BulkSender::new(
            b"res".to_vec(),
            payload,
            cid,
            BulkTransferConfig::default(),
        );
        let mut msgs = vec![sender.send_start().unwrap()];
        while let Some(c) = sender.next_chunk().unwrap() {
            msgs.push(c);
        }
        msgs.push(sender.send_complete().unwrap());

        let r = ingest_all(&msgs);
        // SHA-256 negotiated: succeeds.
        assert!(r
            .reassemble_verified(HashAlgo::Sha256, &FakeHasher)
            .is_ok());
        // BLAKE3 negotiated: fails because the digest differs.
        assert!(matches!(
            r.reassemble_verified(HashAlgo::Blake3, &FakeHasher),
            Err(Error::Storage(quip_storage::Error::CidMismatch))
        ));
    }

    #[test]
    fn verified_reassemble_without_send_start_errors() {
        let r = BulkReceiver::new();
        assert!(matches!(
            r.reassemble_verified(HashAlgo::Sha256, &FakeHasher),
            Err(Error::Transfer("no send_start"))
        ));
    }

    #[test]
    fn multi_chunk_payload_verifies() {
        // Force multiple chunks by using a small config.
        let payload: Vec<u8> = (0..100u8).collect();
        let cid = cid_for(&payload, HashAlgo::Sha256);
        let cfg = BulkTransferConfig { chunk_size: 8 };
        let mut sender = BulkSender::new(b"res".to_vec(), payload.clone(), cid, cfg);

        let mut msgs = vec![sender.send_start().unwrap()];
        while let Some(c) = sender.next_chunk().unwrap() {
            msgs.push(c);
        }
        msgs.push(sender.send_complete().unwrap());

        let r = ingest_all(&msgs);
        assert_eq!(r.total_size(), Some(100));
        let bytes = r.reassemble_verified(HashAlgo::Sha256, &FakeHasher).unwrap();
        assert_eq!(bytes, payload);
    }

    #[test]
    fn reassemble_low_level_returns_bytes_without_checking() {
        // The unverified path must produce the same bytes as the verified
        // path on a valid transfer, and must still produce bytes on a
        // mismatched one (it is the caller's job to verify).
        let real = b"correct payload".to_vec();
        let cid = cid_for(&real, HashAlgo::Sha256);
        let mut sender = BulkSender::new(
            b"res".to_vec(),
            b"tampered".to_vec(),
            cid,
            BulkTransferConfig::default(),
        );
        let mut msgs = vec![sender.send_start().unwrap()];
        while let Some(c) = sender.next_chunk().unwrap() {
            msgs.push(c);
        }
        msgs.push(sender.send_complete().unwrap());

        let r = ingest_all(&msgs);
        let bytes = r.reassemble().unwrap();
        assert_eq!(bytes, b"tampered");
    }

    #[test]
    fn resource_id_and_total_size_are_exposed() {
        let payload = b"abc".to_vec();
        let cid = cid_for(&payload, HashAlgo::Sha256);
        let mut sender =
            BulkSender::new(b"my-resource".to_vec(), payload, cid, BulkTransferConfig::default());
        let start = sender.send_start().unwrap();
        let r = ingest_all(&[start]);
        assert_eq!(r.resource_id(), Some(b"my-resource".as_slice()));
        assert_eq!(r.total_size(), Some(3));
    }
}