//! Content-addressed blob storage.
//!
//! Spec §8 and App. A.3: a CID is the SHA-256 or BLAKE3 digest of the payload, so
//! bytes are addressed by their digest and never by a name the writer chooses.
//! A [`BlobStore`] is a dumb key/value backend; verification lives in
//! [`crate::store::QuipStore`], which hashes before writing and after
//! reading.
//!
//! Blobs are keyed by the **digest**, not by the tagged/raw form: both algorithms
//! produce 32-byte digests, and the digest is the content identity. The record's
//! CID form is preserved as it was stored, so a peer that migrates a raw CID to
//! CIDv1 (spec §8.1 migration rule) simply overwrites the record with the tagged
//! form.

use crate::codec::{as_bytes, as_u64, expect_key, parse_map};
use crate::error::{Error, Result};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use quip_core::cbor::CborValue;
use quip_core::cid::{CidOrV1, HashAlgo};
use quip_core::time::Timestamp;

const BLOB_RECORD_KEYS: &[&str] = &["cid", "bytes", "stored_at"];

/// A stored blob: its CID form, its bytes, and when it was written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobRecord {
    /// The CID as it was presented to [`BlobStoreMut::put`].
    pub cid: CidOrV1,
    /// The payload bytes.
    pub bytes: Vec<u8>,
    /// Local receipt time.
    pub stored_at: Timestamp,
}

impl BlobRecord {
    /// Encode to a CBOR map for snapshots.
    pub fn to_cbor(&self) -> CborValue {
        CborValue::Map(alloc::vec![
            (CborValue::String("cid".into()), self.cid.to_cbor()),
            (
                CborValue::String("bytes".into()),
                CborValue::Bytes(self.bytes.clone()),
            ),
            (
                CborValue::String("stored_at".into()),
                CborValue::Int(self.stored_at.as_millis() as i128),
            ),
        ])
    }

    /// Decode a [`BlobRecord::to_cbor`] map.
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        let map = parse_map(value, BLOB_RECORD_KEYS)?;
        Ok(BlobRecord {
            cid: CidOrV1::from_cbor(expect_key(&map, "cid", "missing cid")?)?,
            bytes: as_bytes(expect_key(&map, "bytes", "missing bytes")?)?,
            stored_at: Timestamp::from_millis(as_u64(expect_key(
                &map,
                "stored_at",
                "missing stored_at",
            )?)?),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Public read-only view
// ─────────────────────────────────────────────────────────────────────────

/// Read-only view of a content-addressed byte store.
///
/// Writes are not exposed through this trait. The public write path is
/// [`crate::store::QuipStore::put_content`], which
/// verifies the payload against the CID and enforces quarantine policy.
/// The one named exception is
/// [`crate::store::QuipStore::restore_blob`],
/// documented as a trusted-input shortcut.
pub trait BlobStore {
    /// Fetch the bytes for `cid`, or `None` if the digest is not held.
    fn get(&self, cid: &CidOrV1) -> Result<Option<Vec<u8>>>;

    /// True if the digest is held.
    fn has(&self, cid: &CidOrV1) -> bool;

    /// Number of stored blobs.
    fn len(&self) -> usize;

    /// Sum of the payload sizes, in bytes.
    fn total_bytes(&self) -> u64;

    /// True when nothing is stored.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Snapshot every record, ordered by digest.
    fn list(&self) -> Result<Vec<BlobRecord>>;

    /// Local receipt time recorded for `cid`.
    fn stored_at(&self, cid: &CidOrV1) -> Option<Timestamp>;

    /// The CID form currently held for `cid`'s digest.
    fn cid_form(&self, cid: &CidOrV1) -> Option<CidOrV1>;

    /// The recorded hash algorithm, if the record was stored in tagged form.
    fn algo(&self, cid: &CidOrV1) -> Option<HashAlgo>;
}

// ─────────────────────────────────────────────────────────────────────────
// Crate-internal write view (sealed)
// ─────────────────────────────────────────────────────────────────────────

/// Sealing supertrait for [`BlobStoreMut`].
///
/// Because this module is private, `Sealed` cannot be named or implemented
/// outside `quip-storage`, even though the trait itself is declared `pub`.
/// This is the standard sealed-trait pattern: it lets `BlobStoreMut` appear
/// in public bounds (avoiding `private_bounds`) while preventing third-party
/// implementations.
mod sealed {
    /// Cannot be implemented outside this crate.
    pub trait Sealed {}

    impl Sealed for super::MemoryBlobStore {}

    #[cfg(feature = "std")]
    impl Sealed for crate::file::FileBlobStore {}
}

/// Write access to a blob store.
///
/// Sealed: the trait is public so that
/// `impl<B: BlobStoreMut> QuipStore<B>` can appear on the public
/// [`crate::store::QuipStore`] type without triggering Rust's
/// `private_bounds` lint, but the `sealed::Sealed` supertrait cannot be
/// implemented outside this crate. Only [`MemoryBlobStore`] and (with
/// `std`) [`crate::file::FileBlobStore`] implement it.
///
/// Downstream users do **not** call these methods directly. The public
/// write path is
/// [`crate::store::QuipStore::put_content`]; the
/// one named exception is
/// [`crate::store::QuipStore::restore_blob`].
pub trait BlobStoreMut: BlobStore + sealed::Sealed {
    /// Store `bytes` under `cid`, replacing any existing record with the
    /// same digest. Enforces the byte budget.
    fn put(&mut self, cid: &CidOrV1, bytes: Vec<u8>, now: Timestamp) -> Result<()>;

    /// Store `bytes` under `cid` without enforcing the byte budget.
    ///
    /// Used only by the snapshot-restore path: the input is trusted, and
    /// silently dropping records would make restore lossy.
    fn put_trusted(&mut self, cid: &CidOrV1, bytes: Vec<u8>, now: Timestamp) -> Result<()>;

    /// Drop the record for `cid`, returning whether something was removed.
    fn remove(&mut self, cid: &CidOrV1) -> Result<bool>;

    /// Remove everything.
    fn clear(&mut self) -> Result<()>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    cid: CidOrV1,
    bytes: Vec<u8>,
    stored_at: Timestamp,
}

/// In-memory [`BlobStore`].
///
/// Available in `no_std + alloc`. Entries are held in a `BTreeMap` keyed by
/// digest, so iteration order is deterministic — convenient for tests and for
/// snapshot diffing.
#[derive(Clone, Debug)]
pub struct MemoryBlobStore {
    entries: BTreeMap<[u8; 32], Entry>,
    total_bytes: u64,
    max_bytes: Option<u64>,
}

impl MemoryBlobStore {
    /// Empty store with no byte budget.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            total_bytes: 0,
            max_bytes: None,
        }
    }

    /// Empty store bounded to `max` payload bytes.
    ///
    /// A `put` that would exceed the budget fails with
    /// [`Error::CapacityExceeded`] rather than evicting: unlike pins, content is
    /// addressed by digest, so silently dropping it would break pin promises.
    pub fn with_max_bytes(max: u64) -> Self {
        Self {
            max_bytes: Some(max),
            ..Self::new()
        }
    }

    /// The current byte budget, if any.
    pub fn max_bytes(&self) -> Option<u64> {
        self.max_bytes
    }

    /// Set or clear the byte budget.
    pub fn set_max_bytes(&mut self, max: Option<u64>) {
        self.max_bytes = max;
    }
}

impl Default for MemoryBlobStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BlobStore for MemoryBlobStore {
    fn get(&self, cid: &CidOrV1) -> Result<Option<Vec<u8>>> {
        Ok(self.entries.get(cid.digest()).map(|e| e.bytes.clone()))
    }

    fn has(&self, cid: &CidOrV1) -> bool {
        self.entries.contains_key(cid.digest())
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    fn list(&self) -> Result<Vec<BlobRecord>> {
        Ok(self
            .entries
            .values()
            .map(|e| BlobRecord {
                cid: e.cid,
                bytes: e.bytes.clone(),
                stored_at: e.stored_at,
            })
            .collect())
    }

    fn stored_at(&self, cid: &CidOrV1) -> Option<Timestamp> {
        self.entries.get(cid.digest()).map(|e| e.stored_at)
    }

    fn cid_form(&self, cid: &CidOrV1) -> Option<CidOrV1> {
        self.entries.get(cid.digest()).map(|e| e.cid)
    }

    fn algo(&self, cid: &CidOrV1) -> Option<HashAlgo> {
        self.entries.get(cid.digest()).and_then(|e| e.cid.algo())
    }
}

impl BlobStoreMut for MemoryBlobStore {
    fn put(&mut self, cid: &CidOrV1, bytes: Vec<u8>, now: Timestamp) -> Result<()> {
        let key = *cid.digest();
        let new_len = bytes.len() as u64;
        let old_len = self
            .entries
            .get(&key)
            .map(|e| e.bytes.len() as u64)
            .unwrap_or(0);
        if let Some(max) = self.max_bytes {
            let projected = self.total_bytes.saturating_sub(old_len) + new_len;
            if projected > max {
                return Err(Error::CapacityExceeded {
                    table: "blob",
                    limit: max,
                });
            }
        }
        self.total_bytes = self.total_bytes.saturating_sub(old_len) + new_len;
        self.entries.insert(
            key,
            Entry {
                cid: *cid,
                bytes,
                stored_at: now,
            },
        );
        Ok(())
    }

    fn put_trusted(&mut self, cid: &CidOrV1, bytes: Vec<u8>, now: Timestamp) -> Result<()> {
        let key = *cid.digest();
        let new_len = bytes.len() as u64;
        let old_len = self
            .entries
            .get(&key)
            .map(|e| e.bytes.len() as u64)
            .unwrap_or(0);
        self.total_bytes = self.total_bytes.saturating_sub(old_len) + new_len;
        self.entries.insert(
            key,
            Entry {
                cid: *cid,
                bytes,
                stored_at: now,
            },
        );
        Ok(())
    }

    fn remove(&mut self, cid: &CidOrV1) -> Result<bool> {
        match self.entries.remove(cid.digest()) {
            Some(entry) => {
                self.total_bytes = self.total_bytes.saturating_sub(entry.bytes.len() as u64);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn clear(&mut self) -> Result<()> {
        self.entries.clear();
        self.total_bytes = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use quip_core::cid::{Cid, CidV1};

    fn cid(b: u8) -> CidOrV1 {
        CidOrV1::Raw(Cid([b; 32]))
    }

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    #[test]
    fn put_get_remove() {
        let mut store = MemoryBlobStore::new();
        assert!(store.is_empty());
        store.put(&cid(1), vec![1, 2, 3], now()).unwrap();
        assert_eq!(store.get(&cid(1)).unwrap().unwrap(), vec![1, 2, 3]);
        assert!(store.has(&cid(1)));
        assert_eq!(store.len(), 1);
        assert_eq!(store.total_bytes(), 3);
        assert_eq!(store.stored_at(&cid(1)), Some(now()));
        assert!(store.remove(&cid(1)).unwrap());
        assert!(!store.remove(&cid(1)).unwrap());
        assert!(store.is_empty());
        assert_eq!(store.total_bytes(), 0);
    }

    #[test]
    fn same_digest_is_same_content() {
        let mut store = MemoryBlobStore::new();
        // Raw and tagged forms of one digest address the same payload.
        store.put(&cid(7), vec![9], now()).unwrap();
        let tagged = CidOrV1::V1(CidV1 {
            hash_algo: HashAlgo::Blake3,
            digest: [7u8; 32],
        });
        assert!(store.has(&tagged));
        assert_eq!(store.algo(&tagged), None);
        // Re-storing in tagged form migrates the record (spec §8.1).
        store.put(&tagged, vec![9, 9], now()).unwrap();
        assert_eq!(store.algo(&tagged), Some(HashAlgo::Blake3));
        assert_eq!(store.cid_form(&tagged), Some(tagged));
        assert_eq!(store.len(), 1);
        assert_eq!(store.total_bytes(), 2);
    }

    #[test]
    fn oversize_put_is_rejected_without_eviction() {
        let mut store = MemoryBlobStore::with_max_bytes(4);
        store.put(&cid(1), vec![1, 2, 3, 4], now()).unwrap();
        let err = store.put(&cid(2), vec![5], now()).unwrap_err();
        assert!(matches!(
            err,
            Error::CapacityExceeded {
                table: "blob",
                limit: 4
            }
        ));
        assert!(!store.has(&cid(2)));
        assert_eq!(store.len(), 1);
        // Replacing an existing record is accounted, not added.
        store.put(&cid(1), vec![1, 1], now()).unwrap();
        assert_eq!(store.total_bytes(), 2);
    }

    #[test]
    fn put_trusted_ignores_byte_budget() {
        let mut store = MemoryBlobStore::with_max_bytes(4);
        store.put(&cid(1), vec![1, 2, 3, 4], now()).unwrap();
        // put would reject; put_trusted accepts.
        store.put_trusted(&cid(2), vec![5, 6, 7, 8], now()).unwrap();
        assert!(store.has(&cid(2)));
        assert_eq!(store.total_bytes(), 8);
    }

    #[test]
    fn list_is_digest_ordered() {
        let mut store = MemoryBlobStore::new();
        store.put(&cid(2), vec![2], now()).unwrap();
        store.put(&cid(1), vec![1], now()).unwrap();
        let listed = store.list().unwrap();
        assert_eq!(listed[0].cid, cid(1));
        assert_eq!(listed[1].cid, cid(2));
        store.clear().unwrap();
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn blob_record_cbor_roundtrip() {
        let record = BlobRecord {
            cid: cid(5),
            bytes: vec![1, 2, 3, 4],
            stored_at: now(),
        };
        let cbor = record.to_cbor();
        let bytes = quip_core::cbor::encode(&cbor).unwrap();
        let decoded_val = quip_core::cbor::decode(&bytes).unwrap();
        let decoded = BlobRecord::from_cbor(&decoded_val).unwrap();
        assert_eq!(record, decoded);
    }
}