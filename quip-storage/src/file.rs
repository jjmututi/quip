//! Filesystem-backed blob store.
//!
//! Available when the `std` feature is enabled.

use crate::blob::{BlobRecord, BlobStore, BlobStoreMut};
use crate::codec::{as_u64, expect_key, parse_map};
use crate::error::{Error, Result};
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use quip_core::cbor::CborValue;
use quip_core::cid::{CidOrV1, HashAlgo};
use quip_core::time::Timestamp;

const META_KEYS: &[&str] = &["cid", "stored_at"];

fn hex_digest(digest: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in digest {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

#[derive(Clone, Debug)]
struct MetaEntry {
    cid: CidOrV1,
    stored_at: Timestamp,
    len: u64,
}

/// Filesystem-backed [`BlobStore`].
///
/// Stores raw payload bytes in `{digest}.data` files and metadata (the CID form
/// and stored timestamp) in `{digest}.meta` files. Maintains an in-memory index
/// for deterministic iteration and constant-time existence checks.
#[derive(Debug)]
pub struct FileBlobStore {
    root: PathBuf,
    entries: BTreeMap<[u8; 32], MetaEntry>,
    total_bytes: u64,
    max_bytes: Option<u64>,
}

impl FileBlobStore {
    /// Open or create a blob store at `root`.
    pub fn new(root: impl AsRef<Path>) -> Result<Self> {
        Self::with_max_bytes(root, None)
    }

    /// Open or create a blob store at `root` with a payload byte budget.
    pub fn with_max_bytes(root: impl AsRef<Path>, max_bytes: Option<u64>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(|e| Error::Io(e.to_string()))?;

        let mut store = Self {
            root,
            entries: BTreeMap::new(),
            total_bytes: 0,
            max_bytes,
        };
        store.reload_index()?;
        Ok(store)
    }

    /// The root directory containing blob files.
    pub fn path(&self) -> &Path {
        &self.root
    }

    /// Scan directory and rebuild in-memory index.
    fn reload_index(&mut self) -> Result<()> {
        self.entries.clear();
        self.total_bytes = 0;

        let read_dir = fs::read_dir(&self.root).map_err(|e| Error::Io(e.to_string()))?;
        for entry in read_dir {
            let entry = entry.map_err(|e| Error::Io(e.to_string()))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("meta") {
                let meta_bytes = fs::read(&path).map_err(|e| Error::Io(e.to_string()))?;
                let cbor = quip_core::cbor::decode(&meta_bytes)
                    .map_err(|e| Error::Io(e.to_string()))?;
                let map = parse_map(&cbor, META_KEYS)?;
                let cid = CidOrV1::from_cbor(expect_key(&map, "cid", "missing cid")?)?;
                let stored_at = Timestamp::from_millis(as_u64(expect_key(
                    &map,
                    "stored_at",
                    "missing stored_at",
                )?)?);

                let data_path = path.with_extension("data");
                if data_path.exists() {
                    let len = fs::metadata(&data_path)
                        .map_err(|e| Error::Io(e.to_string()))?
                        .len();
                    self.total_bytes += len;
                    self.entries.insert(
                        *cid.digest(),
                        MetaEntry {
                            cid,
                            stored_at,
                            len,
                        },
                    );
                }
            }
        }
        Ok(())
    }

    fn data_path(&self, digest: &[u8; 32]) -> PathBuf {
        self.root.join(format!("{}.data", hex_digest(digest)))
    }

    fn meta_path(&self, digest: &[u8; 32]) -> PathBuf {
        self.root.join(format!("{}.meta", hex_digest(digest)))
    }

    /// Shared write path for `put` and `put_trusted`.
    fn write_record(
        &mut self,
        key: &[u8; 32],
        cid: &CidOrV1,
        bytes: Vec<u8>,
        now: Timestamp,
        new_len: u64,
        old_len: u64,
    ) -> Result<()> {
        let data_p = self.data_path(key);
        let meta_p = self.meta_path(key);

        fs::write(&data_p, &bytes).map_err(|e| Error::Io(e.to_string()))?;

        let meta_cbor = CborValue::Map(alloc::vec![
            (CborValue::String("cid".into()), cid.to_cbor()),
            (
                CborValue::String("stored_at".into()),
                CborValue::Int(now.as_millis() as i128),
            ),
        ]);
        let meta_bytes =
            quip_core::cbor::encode(&meta_cbor).map_err(|e| Error::Io(e.to_string()))?;
        fs::write(&meta_p, meta_bytes).map_err(|e| Error::Io(e.to_string()))?;

        self.total_bytes = self.total_bytes.saturating_sub(old_len) + new_len;
        self.entries.insert(
            *key,
            MetaEntry {
                cid: *cid,
                stored_at: now,
                len: new_len,
            },
        );
        Ok(())
    }
}

impl BlobStore for FileBlobStore {
    fn get(&self, cid: &CidOrV1) -> Result<Option<Vec<u8>>> {
        let key = cid.digest();
        if !self.entries.contains_key(key) {
            return Ok(None);
        }
        let p = self.data_path(key);
        match fs::read(p) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Io(e.to_string())),
        }
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
        let mut list = Vec::with_capacity(self.entries.len());
        for (key, meta) in &self.entries {
            let bytes = fs::read(self.data_path(key)).map_err(|e| Error::Io(e.to_string()))?;
            list.push(BlobRecord {
                cid: meta.cid,
                bytes,
                stored_at: meta.stored_at,
            });
        }
        Ok(list)
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

impl BlobStoreMut for FileBlobStore {
    fn put(&mut self, cid: &CidOrV1, bytes: Vec<u8>, now: Timestamp) -> Result<()> {
        let key = *cid.digest();
        let new_len = bytes.len() as u64;
        let old_len = self.entries.get(&key).map(|e| e.len).unwrap_or(0);

        if let Some(max) = self.max_bytes {
            let projected = self.total_bytes.saturating_sub(old_len) + new_len;
            if projected > max {
                return Err(Error::CapacityExceeded {
                    table: "blob",
                    limit: max,
                });
            }
        }
        self.write_record(&key, cid, bytes, now, new_len, old_len)
    }

    fn put_trusted(&mut self, cid: &CidOrV1, bytes: Vec<u8>, now: Timestamp) -> Result<()> {
        let key = *cid.digest();
        let new_len = bytes.len() as u64;
        let old_len = self.entries.get(&key).map(|e| e.len).unwrap_or(0);
        self.write_record(&key, cid, bytes, now, new_len, old_len)
    }

    fn remove(&mut self, cid: &CidOrV1) -> Result<bool> {
        let key = cid.digest();
        if let Some(entry) = self.entries.remove(key) {
            self.total_bytes = self.total_bytes.saturating_sub(entry.len);
            let _ = fs::remove_file(self.data_path(key));
            let _ = fs::remove_file(self.meta_path(key));
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn clear(&mut self) -> Result<()> {
        for key in self.entries.keys() {
            let _ = fs::remove_file(self.data_path(key));
            let _ = fs::remove_file(self.meta_path(key));
        }
        self.entries.clear();
        self.total_bytes = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quip_core::cid::Cid;

    fn cid(b: u8) -> CidOrV1 {
        CidOrV1::Raw(Cid([b; 32]))
    }

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    #[test]
    fn file_blob_store_lifecycle() {
        let tmp = std::env::temp_dir().join("quip_file_blob_test_1");
        let _ = fs::remove_dir_all(&tmp);

        let mut store = FileBlobStore::new(&tmp).unwrap();
        assert!(store.is_empty());
        assert_eq!(store.total_bytes(), 0);

        store.put(&cid(1), vec![10, 20, 30], now()).unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(store.total_bytes(), 3);
        assert!(store.has(&cid(1)));
        assert_eq!(store.get(&cid(1)).unwrap().unwrap(), vec![10, 20, 30]);

        // Reopen store from disk
        drop(store);
        let mut reopened = FileBlobStore::new(&tmp).unwrap();
        assert_eq!(reopened.len(), 1);
        assert_eq!(reopened.total_bytes(), 3);
        assert!(reopened.has(&cid(1)));
        assert_eq!(reopened.get(&cid(1)).unwrap().unwrap(), vec![10, 20, 30]);

        // Remove
        assert!(reopened.remove(&cid(1)).unwrap());
        assert!(!reopened.has(&cid(1)));
        assert_eq!(reopened.len(), 0);

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn file_put_trusted_ignores_byte_budget() {
        let tmp = std::env::temp_dir().join("quip_file_blob_test_2");
        let _ = fs::remove_dir_all(&tmp);

        let mut store = FileBlobStore::with_max_bytes(&tmp, Some(4)).unwrap();
        store.put(&cid(1), vec![1, 2, 3, 4], now()).unwrap();
        // put would reject; put_trusted accepts.
        store.put_trusted(&cid(2), vec![5, 6, 7, 8], now()).unwrap();
        assert!(store.has(&cid(2)));

        let _ = fs::remove_dir_all(&tmp);
    }
}