//! Resource directory for location hints.
//!
//! Implements cached state for `resource_announce` and `query_resource`
//! (spec §14.5, App. A.6).
//!
//! Mutable resources are synced via DVVs, but peers discover current content
//! locations by querying resource announcements. Announcements are valid for up to
//! [`MAX_ANNOUNCEMENT_AGE_S`] (24 hours).

use crate::codec::{as_bytes, as_node_ids, as_u64, expect_key, parse_map};
use crate::constants::{DEFAULT_RESOURCE_CAPACITY, MAX_ANNOUNCEMENT_AGE_S};
use crate::error::{Error, Result};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use quip_core::cbor::CborValue;
use quip_core::cid::CidOrV1;
use quip_core::dvv::NodeId;
use quip_core::time::Timestamp;

const ANNOUNCEMENT_KEYS: &[&str] = &[
    "resource_id",
    "latest_cid",
    "witness_ring",
    "dht_locations",
    "relay_locations",
    "received_at",
];

/// A cached resource location announcement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceAnnouncement {
    /// Application-defined resource name.
    pub resource_id: Vec<u8>,
    /// The current CID or CIDv1 of the resource.
    pub latest_cid: CidOrV1,
    /// Witness ring node IDs for this resource.
    pub witness_ring: Vec<NodeId>,
    /// DHT nodes that can serve the resource.
    pub dht_locations: Vec<NodeId>,
    /// Relay nodes for NAT-hosted peers.
    pub relay_locations: Vec<NodeId>,
    /// Local timestamp when this announcement was received/stored.
    pub received_at: Timestamp,
}

impl ResourceAnnouncement {
    /// Age of the announcement in seconds relative to `now`.
    pub fn age_seconds(&self, now: Timestamp) -> u64 {
        now.as_millis()
            .saturating_sub(self.received_at.as_millis())
            .checked_div(1_000)
            .unwrap_or(0)
    }

    /// True if the announcement is older than `max_age_seconds`.
    pub fn is_stale(&self, now: Timestamp, max_age_seconds: u64) -> bool {
        self.age_seconds(now) > max_age_seconds
    }

    /// Encode to a CBOR map for snapshot serialization.
    pub fn to_cbor(&self) -> CborValue {
        let ring: Vec<CborValue> = self
            .witness_ring
            .iter()
            .map(|n| CborValue::Bytes(n.to_vec()))
            .collect();
        let dht: Vec<CborValue> = self
            .dht_locations
            .iter()
            .map(|n| CborValue::Bytes(n.to_vec()))
            .collect();
        let relay: Vec<CborValue> = self
            .relay_locations
            .iter()
            .map(|n| CborValue::Bytes(n.to_vec()))
            .collect();

        CborValue::Map(alloc::vec![
            (
                CborValue::String("resource_id".into()),
                CborValue::Bytes(self.resource_id.clone()),
            ),
            (
                CborValue::String("latest_cid".into()),
                self.latest_cid.to_cbor(),
            ),
            (CborValue::String("witness_ring".into()), CborValue::Array(ring)),
            (CborValue::String("dht_locations".into()), CborValue::Array(dht)),
            (
                CborValue::String("relay_locations".into()),
                CborValue::Array(relay),
            ),
            (
                CborValue::String("received_at".into()),
                CborValue::Int(self.received_at.as_millis() as i128),
            ),
        ])
    }

    /// Decode from a CBOR map.
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        let map = parse_map(value, ANNOUNCEMENT_KEYS)?;
        Ok(ResourceAnnouncement {
            resource_id: as_bytes(expect_key(&map, "resource_id", "missing resource_id")?)?,
            latest_cid: CidOrV1::from_cbor(expect_key(&map, "latest_cid", "missing latest_cid")?)?,
            witness_ring: as_node_ids(expect_key(
                &map,
                "witness_ring",
                "missing witness_ring",
            )?)?,
            dht_locations: as_node_ids(expect_key(
                &map,
                "dht_locations",
                "missing dht_locations",
            )?)?,
            relay_locations: as_node_ids(expect_key(
                &map,
                "relay_locations",
                "missing relay_locations",
            )?)?,
            received_at: Timestamp::from_millis(as_u64(expect_key(
                &map,
                "received_at",
                "missing received_at",
            )?)?),
        })
    }
}

/// Directory caching known resource location hints.
#[derive(Clone, Debug)]
pub struct ResourceDirectory {
    announcements: BTreeMap<Vec<u8>, ResourceAnnouncement>,
    capacity: usize,
    max_age_seconds: u64,
}

impl ResourceDirectory {
    /// Create a directory with standard capacity and max age.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_RESOURCE_CAPACITY)
    }

    /// Create a directory with custom capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            announcements: BTreeMap::new(),
            capacity: capacity.max(1),
            max_age_seconds: MAX_ANNOUNCEMENT_AGE_S,
        }
    }

    /// Configured capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Maximum age in seconds before an announcement is considered stale.
    pub fn max_age_seconds(&self) -> u64 {
        self.max_age_seconds
    }

    /// Set the maximum age before staleness.
    pub fn set_max_age_seconds(&mut self, max_age_seconds: u64) {
        self.max_age_seconds = max_age_seconds;
    }

    /// Total number of announcements held.
    pub fn len(&self) -> usize {
        self.announcements.len()
    }

    /// True if no announcements are held.
    pub fn is_empty(&self) -> bool {
        self.announcements.is_empty()
    }

    /// Clear all announcements.
    pub fn clear(&mut self) {
        self.announcements.clear();
    }

    /// Store or update a resource announcement.
    ///
    /// If capacity is reached, stale entries are swept first. If still full,
    /// [`Error::CapacityExceeded`] is returned.
    pub fn announce(&mut self, ann: ResourceAnnouncement, now: Timestamp) -> Result<()> {
        let key = &ann.resource_id;
        if !self.announcements.contains_key(key) && self.announcements.len() >= self.capacity {
            self.sweep_stale(now);
            if self.announcements.len() >= self.capacity {
                return Err(Error::CapacityExceeded {
                    table: "resource",
                    limit: self.capacity as u64,
                });
            }
        }
        self.announcements.insert(ann.resource_id.clone(), ann);
        Ok(())
    }

    /// Look up an announcement by `resource_id`, regardless of staleness.
    pub fn get(&self, resource_id: &[u8]) -> Option<&ResourceAnnouncement> {
        self.announcements.get(resource_id)
    }

    /// Look up an announcement by `resource_id`, returning [`Error::Stale`] if stale
    /// or [`Error::NotFound`] if absent.
    pub fn get_fresh(&self, resource_id: &[u8], now: Timestamp) -> Result<&ResourceAnnouncement> {
        let ann = self.announcements.get(resource_id).ok_or(Error::NotFound)?;
        let age = ann.age_seconds(now);
        if age > self.max_age_seconds {
            Err(Error::Stale {
                age_seconds: age,
                max_age_seconds: self.max_age_seconds,
            })
        } else {
            Ok(ann)
        }
    }

    /// Answer a `query_resource` lookup (spec §14.5).
    ///
    /// Returns `None` if the announcement is absent, stale, or does not match
    /// the optional `cid` filter.
    pub fn query(
        &self,
        resource_id: &[u8],
        cid: Option<&CidOrV1>,
        now: Timestamp,
    ) -> Option<&ResourceAnnouncement> {
        let ann = self.announcements.get(resource_id)?;
        if ann.is_stale(now, self.max_age_seconds) {
            return None;
        }
        if let Some(c) = cid {
            if ann.latest_cid.digest() != c.digest() {
                return None;
            }
        }
        Some(ann)
    }

    /// Remove an announcement for `resource_id`.
    pub fn remove(&mut self, resource_id: &[u8]) -> bool {
        self.announcements.remove(resource_id).is_some()
    }

    /// Sweep announcements that exceed `max_age_seconds`.
    pub fn sweep_stale(&mut self, now: Timestamp) -> usize {
        let max_age = self.max_age_seconds;
        let before = self.announcements.len();
        self.announcements.retain(|_, ann| !ann.is_stale(now, max_age));
        before - self.announcements.len()
    }

    /// All stored announcements.
    pub fn all_announcements(&self) -> impl Iterator<Item = &ResourceAnnouncement> {
        self.announcements.values()
    }

    /// Restore announcements from an iterator, respecting capacity.
    pub fn restore<I: IntoIterator<Item = ResourceAnnouncement>>(&mut self, announcements: I) {
        for ann in announcements {
            if self.announcements.len() < self.capacity
                || self.announcements.contains_key(&ann.resource_id)
            {
                self.announcements.insert(ann.resource_id.clone(), ann);
            }
        }
    }

    /// Insert announcements verbatim **without** enforcing capacity.
    ///
    /// Crate-internal: used only by the snapshot-restore path.
    pub(crate) fn restore_exact<I: IntoIterator<Item = ResourceAnnouncement>>(
        &mut self,
        announcements: I,
    ) {
        for ann in announcements {
            self.announcements.insert(ann.resource_id.clone(), ann);
        }
    }

    /// Serialize to CBOR array for snapshots.
    pub fn to_cbor(&self) -> CborValue {
        let items: Vec<CborValue> = self.announcements.values().map(|a| a.to_cbor()).collect();
        CborValue::Array(items)
    }

    /// Deserialize from CBOR array.
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        let CborValue::Array(items) = value else {
            return Err(Error::Core(quip_core::Error::BadEncoding(
                "directory must be an array",
            )));
        };
        let mut dir = Self::new();
        for item in items {
            let ann = ResourceAnnouncement::from_cbor(item)?;
            dir.announcements.insert(ann.resource_id.clone(), ann);
        }
        Ok(dir)
    }
}

impl Default for ResourceDirectory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use quip_core::cid::Cid;

    fn cid(b: u8) -> CidOrV1 {
        CidOrV1::Raw(Cid([b; 32]))
    }

    fn dummy_ann(id: &[u8], cid_byte: u8, received_at_ms: u64) -> ResourceAnnouncement {
        ResourceAnnouncement {
            resource_id: id.to_vec(),
            latest_cid: cid(cid_byte),
            witness_ring: vec![[1; 32]],
            dht_locations: vec![[2; 32]],
            relay_locations: vec![],
            received_at: Timestamp::from_millis(received_at_ms),
        }
    }

    #[test]
    fn announce_query_and_staleness() {
        let mut dir = ResourceDirectory::new();
        dir.set_max_age_seconds(60); // 60s max age

        let ann = dummy_ann(b"profile", 1, 10_000);
        dir.announce(ann, Timestamp::from_millis(10_000)).unwrap();

        // Fresh query
        let q = dir.query(b"profile", None, Timestamp::from_millis(20_000));
        assert!(q.is_some());
        assert_eq!(q.unwrap().latest_cid, cid(1));

        // CID filter
        assert!(dir
            .query(b"profile", Some(&cid(1)), Timestamp::from_millis(20_000))
            .is_some());
        assert!(dir
            .query(b"profile", Some(&cid(2)), Timestamp::from_millis(20_000))
            .is_none());

        // Stale query (> 60s)
        let stale_t = Timestamp::from_millis(80_000); // 70s later
        assert!(dir.query(b"profile", None, stale_t).is_none());
        assert!(matches!(
            dir.get_fresh(b"profile", stale_t),
            Err(Error::Stale { .. })
        ));

        // Sweep removes stale
        assert_eq!(dir.sweep_stale(stale_t), 1);
        assert!(dir.is_empty());
    }

    #[test]
    fn cbor_roundtrip() {
        let mut dir = ResourceDirectory::new();
        dir.announce(dummy_ann(b"doc", 9, 1_000), Timestamp::from_millis(1_000))
            .unwrap();

        let cbor = dir.to_cbor();
        let bytes = quip_core::cbor::encode(&cbor).unwrap();
        let decoded = quip_core::cbor::decode(&bytes).unwrap();
        let back = ResourceDirectory::from_cbor(&decoded).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back.get(b"doc").unwrap().latest_cid, cid(9));
    }

    #[test]
    fn restore_exact_ignores_capacity() {
        let mut dir = ResourceDirectory::with_capacity(1);
        dir.restore_exact(alloc::vec![
            dummy_ann(b"a", 1, 0),
            dummy_ann(b"b", 2, 0),
        ]);
        assert_eq!(dir.len(), 2);
    }
}