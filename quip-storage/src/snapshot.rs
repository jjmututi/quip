//! Full-store snapshot serialization using canonical QUIP-CBOR.
//!
//! Provides self-contained persistence without `serde` dependencies.

use crate::blob::BlobRecord;
use crate::codec::{as_array, as_timestamp, as_u64, expect_key, parse_map};
use crate::directory::ResourceAnnouncement;
use crate::error::{Error, Result};
use crate::pins::PinRecord;
use alloc::vec::Vec;
use quip_core::cbor::CborValue;
use quip_core::messages::{DelegationCertificate, DerivativeLink, QuarantineNotice, TrustedCidRegistration};
use quip_core::time::Timestamp;

/// Current snapshot format version.
pub const SNAPSHOT_VERSION: u64 = 1;

const SNAPSHOT_KEYS: &[&str] = &[
    "version",
    "created_at",
    "pins",
    "blobs",
    "quarantine",
    "trusted_cids",
    "delegations",
    "derivative_links",
    "resources",
];

/// Full point-in-time state of a [`crate::store::QuipStore`].
#[derive(Clone, Debug, PartialEq)]
pub struct Snapshot {
    /// Format version; must equal [`SNAPSHOT_VERSION`].
    pub version: u64,
    /// When the snapshot was generated.
    pub created_at: Timestamp,
    /// Held pins.
    pub pins: Vec<PinRecord>,
    /// Stored blob records.
    pub blobs: Vec<BlobRecord>,
    /// Active quarantine notices.
    pub quarantine: Vec<QuarantineNotice>,
    /// Registered Trusted CIDs.
    pub trusted_cids: Vec<TrustedCidRegistration>,
    /// Governance delegation certificates.
    pub delegations: Vec<DelegationCertificate>,
    /// Derivative links.
    pub derivative_links: Vec<DerivativeLink>,
    /// Cached resource location hints.
    pub resources: Vec<ResourceAnnouncement>,
}

impl Snapshot {
    /// Create an empty snapshot with current [`SNAPSHOT_VERSION`].
    pub fn new(created_at: Timestamp) -> Self {
        Self {
            version: SNAPSHOT_VERSION,
            created_at,
            pins: Vec::new(),
            blobs: Vec::new(),
            quarantine: Vec::new(),
            trusted_cids: Vec::new(),
            delegations: Vec::new(),
            derivative_links: Vec::new(),
            resources: Vec::new(),
        }
    }

    /// Encode snapshot into canonical CBOR.
    pub fn to_cbor(&self) -> CborValue {
        let pins: Vec<CborValue> = self.pins.iter().map(|p| p.to_cbor()).collect();
        let blobs: Vec<CborValue> = self.blobs.iter().map(|b| b.to_cbor()).collect();
        let quar: Vec<CborValue> = self.quarantine.iter().map(|q| q.to_cbor()).collect();
        let tcids: Vec<CborValue> = self.trusted_cids.iter().map(|t| t.to_cbor()).collect();
        let dels: Vec<CborValue> = self.delegations.iter().map(|d| d.to_cbor()).collect();
        let links: Vec<CborValue> = self.derivative_links.iter().map(|l| l.to_cbor()).collect();
        let res: Vec<CborValue> = self.resources.iter().map(|r| r.to_cbor()).collect();

        CborValue::Map(alloc::vec![
            (CborValue::String("version".into()), CborValue::Int(self.version as i128)),
            (
                CborValue::String("created_at".into()),
                CborValue::Int(self.created_at.as_millis() as i128),
            ),
            (CborValue::String("pins".into()), CborValue::Array(pins)),
            (CborValue::String("blobs".into()), CborValue::Array(blobs)),
            (CborValue::String("quarantine".into()), CborValue::Array(quar)),
            (CborValue::String("trusted_cids".into()), CborValue::Array(tcids)),
            (CborValue::String("delegations".into()), CborValue::Array(dels)),
            (CborValue::String("derivative_links".into()), CborValue::Array(links)),
            (CborValue::String("resources".into()), CborValue::Array(res)),
        ])
    }

    /// Decode snapshot from canonical CBOR.
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        let map = parse_map(value, SNAPSHOT_KEYS)?;
        let version = as_u64(expect_key(&map, "version", "missing version")?)?;
        if version != SNAPSHOT_VERSION {
            return Err(Error::VersionMismatch {
                found: version,
                expected: SNAPSHOT_VERSION,
            });
        }
        let created_at = as_timestamp(expect_key(&map, "created_at", "missing created_at")?)?;

        let pin_arr = as_array(expect_key(&map, "pins", "missing pins")?)?;
        let mut pins = Vec::with_capacity(pin_arr.len());
        for p in pin_arr {
            pins.push(PinRecord::from_cbor(p)?);
        }

        let blob_arr = as_array(expect_key(&map, "blobs", "missing blobs")?)?;
        let mut blobs = Vec::with_capacity(blob_arr.len());
        for b in blob_arr {
            blobs.push(BlobRecord::from_cbor(b)?);
        }

        let quar_arr = as_array(expect_key(&map, "quarantine", "missing quarantine")?)?;
        let mut quarantine = Vec::with_capacity(quar_arr.len());
        for q in quar_arr {
            quarantine.push(QuarantineNotice::from_cbor(q)?);
        }

        let tcid_arr = as_array(expect_key(&map, "trusted_cids", "missing trusted_cids")?)?;
        let mut trusted_cids = Vec::with_capacity(tcid_arr.len());
        for t in tcid_arr {
            trusted_cids.push(TrustedCidRegistration::from_cbor(t)?);
        }

        let del_arr = as_array(expect_key(&map, "delegations", "missing delegations")?)?;
        let mut delegations = Vec::with_capacity(del_arr.len());
        for d in del_arr {
            delegations.push(DelegationCertificate::from_cbor(d)?);
        }

        let link_arr = as_array(expect_key(&map, "derivative_links", "missing derivative_links")?)?;
        let mut derivative_links = Vec::with_capacity(link_arr.len());
        for l in link_arr {
            derivative_links.push(DerivativeLink::from_cbor(l)?);
        }

        let res_arr = as_array(expect_key(&map, "resources", "missing resources")?)?;
        let mut resources = Vec::with_capacity(res_arr.len());
        for r in res_arr {
            resources.push(ResourceAnnouncement::from_cbor(r)?);
        }

        Ok(Snapshot {
            version,
            created_at,
            pins,
            blobs,
            quarantine,
            trusted_cids,
            delegations,
            derivative_links,
            resources,
        })
    }

    /// Encode snapshot directly to canonical CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        quip_core::cbor::encode(&self.to_cbor()).map_err(Error::Core)
    }

    /// Decode snapshot directly from CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let value = quip_core::cbor::decode(bytes).map_err(Error::Core)?;
        Self::from_cbor(&value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quip_core::cid::Cid;
    use quip_core::cid::CidOrV1;

    fn cid(b: u8) -> CidOrV1 {
        CidOrV1::Raw(Cid([b; 32]))
    }

    #[test]
    fn snapshot_empty_roundtrip() {
        let snap = Snapshot::new(Timestamp::from_millis(1_700_000_000_000));
        let bytes = snap.to_bytes().unwrap();
        let back = Snapshot::from_bytes(&bytes).unwrap();
        assert_eq!(snap, back);
    }

    #[test]
    fn snapshot_with_data_roundtrip() {
        let mut snap = Snapshot::new(Timestamp::from_millis(1_700_000_000_000));
        snap.pins.push(PinRecord {
            resource_id: b"test".to_vec(),
            cid: cid(1),
            pinned_at: Timestamp::from_millis(100),
            ttl_seconds: 60,
            ref_count: 1,
            local: true,
        });
        snap.blobs.push(BlobRecord {
            cid: cid(1),
            bytes: alloc::vec![1, 2, 3],
            stored_at: Timestamp::from_millis(100),
        });

        let bytes = snap.to_bytes().unwrap();
        let back = Snapshot::from_bytes(&bytes).unwrap();
        assert_eq!(snap, back);
    }

    #[test]
    fn snapshot_version_mismatch_rejected() {
        let mut snap = Snapshot::new(Timestamp::from_millis(100));
        snap.version = 99;
        let cbor = snap.to_cbor();
        let err = Snapshot::from_cbor(&cbor).unwrap_err();
        assert!(matches!(
            err,
            Error::VersionMismatch {
                found: 99,
                expected: SNAPSHOT_VERSION
            }
        ));
    }
}
