//! High-level QUIP storage facade.
//!
//! Composes content-addressed blobs, pins, quarantine, governance, and resource
//! discovery, enforcing cross-cutting protocol rules:
//!
//! - Content is verified against CID digests on both write and read.
//! - Content under active quarantine is blocked from being read, announced, or
//!   discovered via queries (spec §7.2).
//! - Stale resource announcements are filtered (spec §14.5).
//! - Snapshotting exports the unified persistent state in canonical QUIP-CBOR.
//!
//! ## The one write path
//!
//! The primitive blob write is [`BlobStoreMut::put`], which lives on a
//! crate-internal trait and is not reachable from outside this crate. The
//! public write path is [`QuipStore::put_content`], which verifies the payload
//! against the computed CID and enforces quarantine policy. The single named
//! exception is [`QuipStore::restore_blob`], documented as a trusted-input
//! shortcut for the snapshot-restore path.

use crate::blob::{BlobStore, BlobStoreMut, MemoryBlobStore};
use crate::constants::{
    DEFAULT_PIN_TTL_S, DEFAULT_QUARANTINE_CAPACITY, DEFAULT_RESOURCE_CAPACITY,
    DERIVATIVE_LINK_CAPACITY, MAX_ANNOUNCEMENT_AGE_S,
};
use crate::directory::{ResourceAnnouncement, ResourceDirectory};
use crate::error::{Error, Result};
use crate::governance::GovernanceStore;
use crate::hash::{compute_cid, verify_content, ContentHasher};
use crate::pins::{PinRecord, PinTable};
use crate::quarantine::QuarantineStore;
use crate::snapshot::Snapshot;
use alloc::vec::Vec;
use quip_core::cid::{CidOrV1, HashAlgo};
use quip_core::constants::{GOV_CAPACITY, PIN_CAPACITY};
use quip_core::dvv::NodeId;
use quip_core::messages::{
    DelegationCertificate, DerivativeLink, PinEntry, QuarantineNotice,
    TrustedCidRegistration,
};
use quip_core::time::Timestamp;

/// Formatting preference for generated Content Identifiers.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CidTagging {
    /// Raw 32-byte digest ([`CidOrV1::Raw`]).
    Raw,
    /// Tagged CIDv1 with explicit hash algorithm ([`CidOrV1::V1`]).
    V1,
}

/// Configuration settings for [`QuipStore`].
#[derive(Clone, Debug)]
pub struct StoreConfig {
    /// Maximum number of pins held in the pin table.
    pub pin_capacity: usize,
    /// Maximum number of active quarantine notices.
    pub quarantine_capacity: usize,
    /// Maximum number of registered Trusted CIDs.
    pub tcid_capacity: usize,
    /// Maximum number of derivative links.
    pub derivative_capacity: usize,
    /// Maximum number of cached resource announcements.
    pub resource_capacity: usize,
    /// Maximum age in seconds before a resource announcement is stale.
    pub max_announcement_age_s: u64,
    /// Default TTL in seconds when a pin has `ttl = 0`.
    pub default_pin_ttl_s: u64,
    /// When true, quarantined CIDs cannot be fetched or announced.
    pub enforce_quarantine: bool,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            pin_capacity: PIN_CAPACITY,
            quarantine_capacity: DEFAULT_QUARANTINE_CAPACITY,
            tcid_capacity: GOV_CAPACITY,
            derivative_capacity: DERIVATIVE_LINK_CAPACITY,
            resource_capacity: DEFAULT_RESOURCE_CAPACITY,
            max_announcement_age_s: MAX_ANNOUNCEMENT_AGE_S,
            default_pin_ttl_s: DEFAULT_PIN_TTL_S,
            enforce_quarantine: true,
        }
    }
}

/// Summary of records swept during a maintenance cycle.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SweepSummary {
    /// Expired pins removed.
    pub expired_pins: usize,
    /// Expired quarantine notices removed.
    pub expired_quarantines: usize,
    /// Expired governance delegations removed.
    pub expired_delegations: usize,
    /// Stale resource announcements removed.
    pub stale_resources: usize,
}

/// Unified QUIP storage node.
#[derive(Clone, Debug)]
pub struct QuipStore<B = MemoryBlobStore> {
    blobs: B,
    pins: PinTable,
    quarantine: QuarantineStore,
    governance: GovernanceStore,
    directory: ResourceDirectory,
    config: StoreConfig,
}

impl QuipStore<MemoryBlobStore> {
    /// Create a new in-memory store with default configuration.
    pub fn new() -> Self {
        Self::with_config(StoreConfig::default())
    }

    /// Create a new in-memory store with explicit configuration.
    pub fn with_config(config: StoreConfig) -> Self {
        Self::with_backend_and_config(MemoryBlobStore::new(), config)
    }
}

impl Default for QuipStore<MemoryBlobStore> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: BlobStoreMut> QuipStore<B> {
    /// Create a store with a custom blob backend and default configuration.
    pub fn with_backend(backend: B) -> Self {
        Self::with_backend_and_config(backend, StoreConfig::default())
    }

    /// Create a store with a custom blob backend and explicit configuration.
    pub fn with_backend_and_config(backend: B, config: StoreConfig) -> Self {
        let mut pins = PinTable::with_capacity(config.pin_capacity);
        pins.set_default_ttl_seconds(config.default_pin_ttl_s);

        let quarantine = QuarantineStore::with_capacity(config.quarantine_capacity);
        let governance =
            GovernanceStore::with_capacities(config.tcid_capacity, config.derivative_capacity);
        let mut directory = ResourceDirectory::with_capacity(config.resource_capacity);
        directory.set_max_age_seconds(config.max_announcement_age_s);

        Self {
            blobs: backend,
            pins,
            quarantine,
            governance,
            directory,
            config,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Read + non-blob accessors + snapshot export.
// ─────────────────────────────────────────────────────────────────────────

impl<B: BlobStore> QuipStore<B> {
    /// Store configuration.
    pub fn config(&self) -> &StoreConfig {
        &self.config
    }

    /// Reference to the underlying blob store (read-only).
    pub fn blobs(&self) -> &B {
        &self.blobs
    }

    /// Reference to the pin table.
    pub fn pins(&self) -> &PinTable {
        &self.pins
    }

    /// Mutable reference to the pin table.
    pub fn pins_mut(&mut self) -> &mut PinTable {
        &mut self.pins
    }

    /// Reference to the quarantine store.
    pub fn quarantine(&self) -> &QuarantineStore {
        &self.quarantine
    }

    /// Mutable reference to the quarantine store.
    pub fn quarantine_mut(&mut self) -> &mut QuarantineStore {
        &mut self.quarantine
    }

    /// Reference to the governance store.
    pub fn governance(&self) -> &GovernanceStore {
        &self.governance
    }

    /// Mutable reference to the governance store.
    pub fn governance_mut(&mut self) -> &mut GovernanceStore {
        &mut self.governance
    }

    /// Reference to the resource directory.
    pub fn directory(&self) -> &ResourceDirectory {
        &self.directory
    }

    /// Mutable reference to the resource directory.
    pub fn directory_mut(&mut self) -> &mut ResourceDirectory {
        &mut self.directory
    }

    // ── Blobs (reads) ────────────────────────────────────────────────────

    /// Fetch payload bytes for `cid`, checking quarantine and verifying integrity.
    ///
    /// If quarantined, returns [`Error::Quarantined`].
    /// If not held, returns [`Error::NotFound`].
    /// If held bytes do not match the expected digest, returns [`Error::CidMismatch`].
    pub fn get_content(
        &self,
        cid: &CidOrV1,
        negotiated: HashAlgo,
        hasher: &impl ContentHasher,
        now: Timestamp,
    ) -> Result<Vec<u8>> {
        if self.config.enforce_quarantine && self.quarantine.is_quarantined(cid, now) {
            return Err(Error::Quarantined);
        }
        let bytes = self.blobs.get(cid)?.ok_or(Error::NotFound)?;
        verify_content(cid, &bytes, negotiated, hasher)?;
        Ok(bytes)
    }

    /// True if the blob for `cid` is held locally and not quarantined.
    pub fn has_content(&self, cid: &CidOrV1, now: Timestamp) -> bool {
        if self.config.enforce_quarantine && self.quarantine.is_quarantined(cid, now) {
            return false;
        }
        self.blobs.has(cid)
    }

    // ── Pins ─────────────────────────────────────────────────────────────

    /// Accept or refresh a local pin for immutable content.
    pub fn pin(
        &mut self,
        resource_id: &[u8],
        cid: &CidOrV1,
        ttl_seconds: u64,
        now: Timestamp,
    ) -> &PinRecord {
        self.pins.pin(resource_id, cid, ttl_seconds, now)
    }

    /// Drop a pin for a resource or a specific CID.
    pub fn unpin(&mut self, resource_id: &[u8], cid: Option<&CidOrV1>) -> usize {
        self.pins.unpin(resource_id, cid)
    }

    /// Query held pins.
    pub fn query_pins(
        &self,
        resource_id: Option<&[u8]>,
        cid: Option<&CidOrV1>,
        now: Timestamp,
    ) -> Vec<PinEntry> {
        self.pins.query(resource_id, cid, now)
    }

    // ── Quarantine ───────────────────────────────────────────────────────

    /// Record a validated quarantine notice.
    pub fn apply_quarantine_notice(
        &mut self,
        notice: QuarantineNotice,
        now: Timestamp,
    ) -> Result<()> {
        self.quarantine.add_notice(notice, now)
    }

    /// True if `cid` is quarantined at `now`.
    pub fn is_quarantined(&self, cid: &CidOrV1, now: Timestamp) -> bool {
        self.quarantine.is_quarantined(cid, now)
    }

    // ── Governance ───────────────────────────────────────────────────────

    /// Register a Trusted CID.
    pub fn register_tcid(&mut self, reg: TrustedCidRegistration) -> Result<()> {
        self.governance.register_tcid(reg)
    }

    /// Add a delegation certificate.
    pub fn add_delegation(&mut self, cert: DelegationCertificate) -> Result<()> {
        self.governance.add_delegation(cert)
    }

    /// Add a derivative link.
    pub fn add_derivative_link(&mut self, link: DerivativeLink) -> Result<()> {
        self.governance.add_derivative_link(link)
    }

    /// Check authorization for a node on a Trusted CID.
    pub fn is_authorized(
        &self,
        trusted_cid: &CidOrV1,
        node: &NodeId,
        permission: u64,
        now: Timestamp,
    ) -> bool {
        self.governance
            .is_authorized(trusted_cid, node, permission, now)
    }

    // ── Resource Discovery ───────────────────────────────────────────────

    /// Store a resource announcement, rejecting quarantined targets.
    pub fn announce_resource(
        &mut self,
        ann: ResourceAnnouncement,
        now: Timestamp,
    ) -> Result<()> {
        if self.config.enforce_quarantine
            && self.quarantine.is_quarantined(&ann.latest_cid, now)
        {
            return Err(Error::Quarantined);
        }
        self.directory.announce(ann, now)
    }

    /// Query for a resource announcement, filtering out quarantined CIDs.
    pub fn query_resource(
        &self,
        resource_id: &[u8],
        cid: Option<&CidOrV1>,
        now: Timestamp,
    ) -> Option<&ResourceAnnouncement> {
        let ann = self.directory.query(resource_id, cid, now)?;
        if self.config.enforce_quarantine
            && self.quarantine.is_quarantined(&ann.latest_cid, now)
        {
            return None;
        }
        Some(ann)
    }

    // ── Maintenance ──────────────────────────────────────────────────────

    /// Sweep expired pins, quarantine notices, delegations, and stale resource hints.
    pub fn sweep(&mut self, now: Timestamp) -> SweepSummary {
        SweepSummary {
            expired_pins: self.pins.sweep_expired(now),
            expired_quarantines: self.quarantine.sweep_expired(now),
            expired_delegations: self.governance.sweep_expired_delegations(now),
            stale_resources: self.directory.sweep_stale(now),
        }
    }

    // ── Snapshot (export) ────────────────────────────────────────────────

    /// Export store state to a [`Snapshot`].
    pub fn snapshot(&self, now: Timestamp) -> Result<Snapshot> {
        let blobs = self.blobs.list()?;
        let pins: Vec<PinRecord> = self.pins.records().cloned().collect();
        let quarantine: Vec<QuarantineNotice> = self.quarantine.notices().cloned().collect();
        let trusted_cids: Vec<TrustedCidRegistration> =
            self.governance.registrations().cloned().collect();
        let mut delegations = Vec::new();
        for tcid in &trusted_cids {
            for del in self.governance.get_delegations(&tcid.cid) {
                delegations.push(del.clone());
            }
        }
        let derivative_links = self.governance.derivative_links().to_vec();
        let resources: Vec<ResourceAnnouncement> =
            self.directory.all_announcements().cloned().collect();

        Ok(Snapshot {
            version: crate::snapshot::SNAPSHOT_VERSION,
            created_at: now,
            pins,
            blobs,
            quarantine,
            trusted_cids,
            delegations,
            derivative_links,
            resources,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Write impl block — bounded on the crate-internal `BlobStoreMut`.
// ─────────────────────────────────────────────────────────────────────────

impl<B: BlobStoreMut> QuipStore<B> {
    /// Store raw payload bytes after verifying their digest and quarantine status.
    ///
    /// Computes the CID using `algo` and `hasher`. If quarantine enforcement is
    /// enabled and the CID is quarantined, returns [`Error::Quarantined`].
    ///
    /// This is the **sole public write path** for content. There is one named
    /// exception, [`Self::restore_blob`].
    pub fn put_content(
        &mut self,
        payload: Vec<u8>,
        algo: HashAlgo,
        tagging: CidTagging,
        hasher: &impl ContentHasher,
        now: Timestamp,
    ) -> Result<CidOrV1> {
        let raw_cid = compute_cid(algo, &payload, hasher)?;
        let cid = match tagging {
            CidTagging::Raw => CidOrV1::Raw(raw_cid),
            CidTagging::V1 => CidOrV1::V1(raw_cid.with_algo(algo)),
        };

        if self.config.enforce_quarantine && self.quarantine.is_quarantined(&cid, now) {
            return Err(Error::Quarantined);
        }

        self.blobs.put(&cid, payload, now)?;
        Ok(cid)
    }

    /// Restore a blob from trusted input without CID verification.
    ///
    /// This is the **one named exception** to the rule that writes go through
    /// [`Self::put_content`]. It exists for the snapshot-restore path and for
    /// callers that have verified the digest out of band.
    ///
    /// Passing bytes that do not match `cid` corrupts the store's integrity
    /// invariant. The caller is responsible for the correctness of `cid`.
    /// Quarantine policy is still enforced: a quarantined CID cannot be
    /// restored while `enforce_quarantine` is on.
    ///
    /// The byte budget is **not** enforced: restore is a trusted-input
    /// operation, and silently dropping records would make restore lossy.
    pub fn restore_blob(
        &mut self,
        cid: &CidOrV1,
        bytes: Vec<u8>,
        stored_at: Timestamp,
    ) -> Result<()> {
        if self.config.enforce_quarantine
            && self.quarantine.is_quarantined(cid, stored_at)
        {
            return Err(Error::Quarantined);
        }
        self.blobs.put_trusted(cid, bytes, stored_at)
    }

    /// Drop the payload for `cid`.
    pub fn remove_content(&mut self, cid: &CidOrV1) -> Result<bool> {
        self.blobs.remove(cid)
    }

    /// Restore store state from a [`Snapshot`].
    ///
    /// The snapshot is treated as trusted input: capacity limits on the pin
    /// table, governance store, quarantine store, and resource directory are
    /// **not** enforced. Call [`Self::sweep`] or resize the store afterwards
    /// if the snapshot exceeds local limits.
    ///
    /// The only errors that can occur are I/O errors from a file-backed blob
    /// store and quarantine rejections on individual blobs.
    pub fn restore_snapshot(&mut self, snapshot: Snapshot) -> Result<()> {
        self.blobs.clear()?;
        for b in snapshot.blobs {
            self.restore_blob(&b.cid, b.bytes, b.stored_at)?;
        }
        self.pins.restore_exact(snapshot.pins);
        self.quarantine.clear();
        self.quarantine.restore_exact(snapshot.quarantine);
        self.governance.clear();
        self.governance.restore_exact(
            snapshot.trusted_cids,
            snapshot.delegations,
            snapshot.derivative_links,
        );
        self.directory.clear();
        self.directory.restore_exact(snapshot.resources);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use quip_core::messages::{IndividualRingSig, RingSignature};

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

    fn dummy_quarantine(target: CidOrV1) -> QuarantineNotice {
        QuarantineNotice {
            trusted_cid: target,
            affected_cids: vec![target],
            reason: "test".into(),
            timestamp: Timestamp::from_millis(100),
            valid_until: Timestamp::from_millis(0),
            ring_signature: RingSignature::Individual(IndividualRingSig {
                signatures: vec![[0xaa; 64]],
                signers: vec![[0x01; 32]],
            }),
        }
    }

    #[test]
    fn full_quip_store_flow() {
        let mut store = QuipStore::new();
        let now = Timestamp::from_millis(1_700_000_000_000);

        let cid = store
            .put_content(
                b"hello quip".to_vec(),
                HashAlgo::Sha256,
                CidTagging::V1,
                &FakeHasher,
                now,
            )
            .unwrap();

        assert_eq!(store.blobs().len(), 1);
        assert!(store.has_content(&cid, now));

        let fetched = store
            .get_content(&cid, HashAlgo::Sha256, &FakeHasher, now)
            .unwrap();
        assert_eq!(fetched, b"hello quip");

        // Pin it
        store.pin(b"docs/readme", &cid, 0, now);
        assert_eq!(store.pins().len(), 1);

        // Quarantine it
        store
            .apply_quarantine_notice(dummy_quarantine(cid), now)
            .unwrap();
        assert!(store.is_quarantined(&cid, now));

        // When quarantined, get_content and has_content block
        assert_eq!(
            store.get_content(&cid, HashAlgo::Sha256, &FakeHasher, now),
            Err(Error::Quarantined)
        );
        assert!(!store.has_content(&cid, now));

        // Announcing quarantined resource fails
        let ann = ResourceAnnouncement {
            resource_id: b"docs/readme".to_vec(),
            latest_cid: cid,
            witness_ring: vec![],
            dht_locations: vec![],
            relay_locations: vec![],
            received_at: now,
        };
        assert_eq!(store.announce_resource(ann, now), Err(Error::Quarantined));
    }

    #[test]
    fn snapshot_and_restore() {
        let mut store = QuipStore::new();
        let now = Timestamp::from_millis(1_700_000_000_000);

        let cid = store
            .put_content(
                b"persisted bytes".to_vec(),
                HashAlgo::Sha256,
                CidTagging::Raw,
                &FakeHasher,
                now,
            )
            .unwrap();
        store.pin(b"asset", &cid, 3600, now);

        let snap = store.snapshot(now).unwrap();
        assert_eq!(snap.blobs.len(), 1);
        assert_eq!(snap.pins.len(), 1);

        let mut restored = QuipStore::new();
        restored.restore_snapshot(snap).unwrap();

        assert_eq!(restored.blobs().len(), 1);
        assert_eq!(restored.pins().len(), 1);
        assert_eq!(
            restored
                .get_content(&cid, HashAlgo::Sha256, &FakeHasher, now)
                .unwrap(),
            b"persisted bytes"
        );
    }

    #[test]
    fn restore_snapshot_preserves_records_beyond_capacity() {
        // Fill a store, snapshot it, then restore into a store configured
        // with a smaller capacity. The restore must not silently drop
        // records: capacity limits are for steady-state operation, not for
        // trusted-input restore.
        let mut src = QuipStore::new();
        let now = Timestamp::from_millis(1_700_000_000_000);
        for i in 0..5u8 {
            let cid = src
                .put_content(
                    alloc::vec![i; 4],
                    HashAlgo::Sha256,
                    CidTagging::Raw,
                    &FakeHasher,
                    now,
                )
                .unwrap();
            src.pin(&[i], &cid, 0, now);
        }
        let snap = src.snapshot(now).unwrap();

        let small_config = StoreConfig {
            pin_capacity: 2,
            ..StoreConfig::default()
        };
        let mut dst = QuipStore::with_config(small_config);
        dst.restore_snapshot(snap).unwrap();
        // Capacity was not enforced during restore: all 5 pins are present.
        assert_eq!(dst.pins().len(), 5);
        // A subsequent capacity change trims down.
        dst.pins_mut().set_capacity(2);
        assert_eq!(dst.pins().len(), 2);
    }
}