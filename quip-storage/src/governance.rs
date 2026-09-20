//! Content governance store.
//!
//! Implements the state behind Trusted CIDs (spec §7.1), delegation certificates
//! (spec §7.1), and derivative linking (spec §7.3).

use crate::codec::{as_array, optional_key, parse_map};
use crate::constants::DERIVATIVE_LINK_CAPACITY;
use crate::error::{Error, Result};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use quip_core::cbor::CborValue;
use quip_core::cid::CidOrV1;
use quip_core::constants::GOV_CAPACITY;
use quip_core::dvv::NodeId;
use quip_core::messages::{DelegationCertificate, DerivativeLink, TrustedCidRegistration};
use quip_core::time::Timestamp;

const GOVERNANCE_KEYS: &[&str] = &["trusted_cids", "delegations", "derivative_links"];

/// Persistent store for Trusted CID registrations, delegations, and derivative links.
#[derive(Clone, Debug)]
pub struct GovernanceStore {
    trusted_cids: BTreeMap<[u8; 32], TrustedCidRegistration>,
    delegations: BTreeMap<[u8; 32], Vec<DelegationCertificate>>,
    derivative_links: Vec<DerivativeLink>,
    tcid_capacity: usize,
    derivative_capacity: usize,
}

impl GovernanceStore {
    /// Create a new governance store with protocol defaults ([`GOV_CAPACITY`] and
    /// [`DERIVATIVE_LINK_CAPACITY`]).
    pub fn new() -> Self {
        Self::with_capacities(GOV_CAPACITY, DERIVATIVE_LINK_CAPACITY)
    }

    /// Create with explicit capacities.
    pub fn with_capacities(tcid_capacity: usize, derivative_capacity: usize) -> Self {
        Self {
            trusted_cids: BTreeMap::new(),
            delegations: BTreeMap::new(),
            derivative_links: Vec::new(),
            tcid_capacity: tcid_capacity.max(1),
            derivative_capacity: derivative_capacity.max(1),
        }
    }

    /// Number of registered Trusted CIDs.
    pub fn tcid_count(&self) -> usize {
        self.trusted_cids.len()
    }

    /// Total number of derivative links.
    pub fn derivative_count(&self) -> usize {
        self.derivative_links.len()
    }

    /// True if no Trusted CIDs or derivative links are held.
    pub fn is_empty(&self) -> bool {
        self.trusted_cids.is_empty() && self.derivative_links.is_empty()
    }

    /// Clear all governance state.
    pub fn clear(&mut self) {
        self.trusted_cids.clear();
        self.delegations.clear();
        self.derivative_links.clear();
    }

    // -------------------------------------------------------------------------
    // Trusted CID Registration
    // -------------------------------------------------------------------------

    /// Register a Trusted CID.
    ///
    /// # Errors
    ///
    /// [`Error::CapacityExceeded`] if `tcid_capacity` is reached and the CID
    /// is not already registered.
    pub fn register_tcid(&mut self, reg: TrustedCidRegistration) -> Result<()> {
        let key = *reg.cid.digest();
        if !self.trusted_cids.contains_key(&key) && self.trusted_cids.len() >= self.tcid_capacity {
            return Err(Error::CapacityExceeded {
                table: "governance",
                limit: self.tcid_capacity as u64,
            });
        }
        self.trusted_cids.insert(key, reg);
        Ok(())
    }

    /// Look up a Trusted CID registration by CID or CIDv1.
    pub fn get_tcid(&self, cid: &CidOrV1) -> Option<&TrustedCidRegistration> {
        self.trusted_cids.get(cid.digest())
    }

    /// Remove a Trusted CID and all its associated delegations.
    pub fn remove_tcid(&mut self, cid: &CidOrV1) -> bool {
        let key = cid.digest();
        let removed = self.trusted_cids.remove(key).is_some();
        self.delegations.remove(key);
        self.derivative_links
            .retain(|link| link.trusted_cid.digest() != key);
        removed
    }

    /// Iterate over all Trusted CID registrations.
    pub fn registrations(&self) -> impl Iterator<Item = &TrustedCidRegistration> {
        self.trusted_cids.values()
    }

    // -------------------------------------------------------------------------
    // Delegations
    // -------------------------------------------------------------------------

    /// Add a delegation certificate for a registered Trusted CID.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] if the `trusted_cid` has not been registered.
    pub fn add_delegation(&mut self, cert: DelegationCertificate) -> Result<()> {
        let key = *cert.trusted_cid.digest();
        if !self.trusted_cids.contains_key(&key) {
            return Err(Error::NotFound);
        }
        let list = self.delegations.entry(key).or_default();
        // Replace existing delegation for the same delegate if present, or append.
        if let Some(pos) = list.iter().position(|d| d.delegate == cert.delegate) {
            list[pos] = cert;
        } else {
            list.push(cert);
        }
        Ok(())
    }

    /// Get all delegations for a Trusted CID.
    pub fn get_delegations<'a>(
        &'a self,
        trusted_cid: &CidOrV1,
    ) -> impl Iterator<Item = &'a DelegationCertificate> {
        self.delegations
            .get(trusted_cid.digest())
            .map(|v| v.as_slice())
            .unwrap_or(&[])
            .iter()
    }

    /// Check whether `node` is authorized for `permission` on `trusted_cid` at `now`.
    ///
    /// An entity is authorized if:
    /// 1. It is the recorded owner of the Trusted CID registration; OR
    /// 2. It holds a valid delegation certificate active at `now` covering all
    ///    requested permission bits (`(cert.permissions & permission) == permission`).
    pub fn is_authorized(
        &self,
        trusted_cid: &CidOrV1,
        node: &NodeId,
        permission: u64,
        now: Timestamp,
    ) -> bool {
        let Some(reg) = self.get_tcid(trusted_cid) else {
            return false;
        };
        if reg.owner == *node {
            return true;
        }
        if let Some(list) = self.delegations.get(trusted_cid.digest()) {
            for cert in list {
                if cert.delegate == *node
                    && cert.is_valid_at(now)
                    && (cert.permissions & permission) == permission
                {
                    return true;
                }
            }
        }
        false
    }

    /// Enforce authorization, returning [`Error::NotAuthorized`] or [`Error::NotFound`].
    pub fn check_authorized(
        &self,
        trusted_cid: &CidOrV1,
        node: &NodeId,
        permission: u64,
        now: Timestamp,
    ) -> Result<()> {
        if self.get_tcid(trusted_cid).is_none() {
            return Err(Error::NotFound);
        }
        if self.is_authorized(trusted_cid, node, permission, now) {
            Ok(())
        } else {
            Err(Error::NotAuthorized)
        }
    }

    /// Sweep expired delegation certificates, returning how many were removed.
    /// Entries whose delegation list becomes empty are also removed.
    pub fn sweep_expired_delegations(&mut self, now: Timestamp) -> usize {
        let mut removed = 0;
        self.delegations.retain(|_, list| {
            let before = list.len();
            list.retain(|c| c.is_valid_at(now));
            removed += before - list.len();
            !list.is_empty()
        });
        removed
    }

    // -------------------------------------------------------------------------
    // Derivative Linking
    // -------------------------------------------------------------------------

    /// Record a derivative link.
    ///
    /// # Errors
    ///
    /// [`Error::CapacityExceeded`] if `derivative_capacity` is reached.
    pub fn add_derivative_link(&mut self, link: DerivativeLink) -> Result<()> {
        let target_d = link.derivative_cid.digest();
        let target_t = link.trusted_cid.digest();
        // Overwrite if exact link exists
        if let Some(pos) = self.derivative_links.iter().position(|l| {
            l.derivative_cid.digest() == target_d && l.trusted_cid.digest() == target_t
        }) {
            self.derivative_links[pos] = link;
            return Ok(());
        }
        if self.derivative_links.len() >= self.derivative_capacity {
            return Err(Error::CapacityExceeded {
                table: "governance",
                limit: self.derivative_capacity as u64,
            });
        }
        self.derivative_links.push(link);
        Ok(())
    }

    /// Look up all derivative links for a given Trusted CID.
    pub fn derivatives_for(&self, trusted_cid: &CidOrV1) -> Vec<&DerivativeLink> {
        let d = trusted_cid.digest();
        self.derivative_links
            .iter()
            .filter(|l| l.trusted_cid.digest() == d)
            .collect()
    }

    /// Look up the Trusted CID linked to `derivative_cid`, if any.
    pub fn trusted_cid_for_derivative(&self, derivative_cid: &CidOrV1) -> Option<&CidOrV1> {
        let d = derivative_cid.digest();
        self.derivative_links
            .iter()
            .find(|l| l.derivative_cid.digest() == d)
            .map(|l| &l.trusted_cid)
    }

    /// All stored derivative links.
    pub fn derivative_links(&self) -> &[DerivativeLink] {
        &self.derivative_links
    }

    // -------------------------------------------------------------------------
    // Serialization
    // -------------------------------------------------------------------------

    /// Serialize governance state to CBOR for snapshots.
    pub fn to_cbor(&self) -> CborValue {
        let tcids: Vec<CborValue> = self.trusted_cids.values().map(|r| r.to_cbor()).collect();
        let mut dels: Vec<CborValue> = Vec::new();
        for list in self.delegations.values() {
            for d in list {
                dels.push(d.to_cbor());
            }
        }
        let links: Vec<CborValue> = self.derivative_links.iter().map(|l| l.to_cbor()).collect();

        CborValue::Map(alloc::vec![
            (CborValue::String("trusted_cids".into()), CborValue::Array(tcids)),
            (CborValue::String("delegations".into()), CborValue::Array(dels)),
            (CborValue::String("derivative_links".into()), CborValue::Array(links)),
        ])
    }

    /// Deserialize governance state from CBOR.
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        let map = parse_map(value, GOVERNANCE_KEYS)?;
        let mut store = Self::new();

        if let Some(val) = optional_key(&map, "trusted_cids") {
            for item in as_array(val)? {
                let reg = TrustedCidRegistration::from_cbor(item)?;
                let _ = store.register_tcid(reg);
            }
        }
        if let Some(val) = optional_key(&map, "delegations") {
            for item in as_array(val)? {
                let cert = DelegationCertificate::from_cbor(item)?;
                let _ = store.add_delegation(cert);
            }
        }
        if let Some(val) = optional_key(&map, "derivative_links") {
            for item in as_array(val)? {
                let link = DerivativeLink::from_cbor(item)?;
                let _ = store.add_derivative_link(link);
            }
        }
        Ok(store)
    }

    /// Insert registrations, delegations, and derivative links verbatim
    /// **without** enforcing capacity.
    ///
    /// Crate-internal: used only by the snapshot-restore path. The input is
    /// trusted; silently dropping records would be a data-loss bug, so this
    /// bypasses the capacity checks that [`Self::register_tcid`] and
    /// [`Self::add_derivative_link`] enforce.
    pub(crate) fn restore_exact(
        &mut self,
        trusted_cids: impl IntoIterator<Item = TrustedCidRegistration>,
        delegations: impl IntoIterator<Item = DelegationCertificate>,
        derivative_links: impl IntoIterator<Item = DerivativeLink>,
    ) {
        for reg in trusted_cids {
            self.trusted_cids.insert(*reg.cid.digest(), reg);
        }
        for cert in delegations {
            self.delegations
                .entry(*cert.trusted_cid.digest())
                .or_default()
                .push(cert);
        }
        for link in derivative_links {
            self.derivative_links.push(link);
        }
    }
}

impl Default for GovernanceStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;
    use quip_core::cid::Cid;

    fn cid(b: u8) -> CidOrV1 {
        CidOrV1::Raw(Cid([b; 32]))
    }

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    #[test]
    fn registration_and_authorization() {
        let mut store = GovernanceStore::new();
        let owner = nid(1);
        let delegate = nid(2);
        let stranger = nid(3);
        let tcid = cid(10);

        let reg = TrustedCidRegistration {
            cid: tcid,
            app_metadata: vec![("title".to_string(), CborValue::String("Song".into()))],
            owner,
            timestamp: Timestamp::from_millis(1_000),
            signature: [0xaa; 64],
        };
        store.register_tcid(reg).unwrap();
        assert_eq!(store.tcid_count(), 1);

        let now = Timestamp::from_millis(2_000);
        // Owner is authorized for any permission
        assert!(store.is_authorized(&tcid, &owner, 0b111, now));
        assert!(!store.is_authorized(&tcid, &delegate, 0b001, now));
        assert!(!store.is_authorized(&tcid, &stranger, 0b001, now));

        // Add delegation for delegate with permission 0b010 valid [1500, 3000)
        let cert = DelegationCertificate {
            trusted_cid: tcid,
            delegate,
            permissions: 0b010,
            valid_from: Timestamp::from_millis(1_500),
            valid_until: Timestamp::from_millis(3_000),
            owner_signature: [0xbb; 64],
        };
        store.add_delegation(cert).unwrap();

        assert!(store.is_authorized(&tcid, &delegate, 0b010, now));
        // Missing bit 0b001
        assert!(!store.is_authorized(&tcid, &delegate, 0b011, now));
        // Expired at 3000
        assert!(!store.is_authorized(&tcid, &delegate, 0b010, Timestamp::from_millis(3_000)));

        assert_eq!(store.sweep_expired_delegations(Timestamp::from_millis(3_000)), 1);
    }

    #[test]
    fn sweep_removes_empty_delegation_lists() {
        let mut store = GovernanceStore::new();
        let tcid = cid(10);
        store
            .register_tcid(TrustedCidRegistration {
                cid: tcid,
                app_metadata: vec![],
                owner: nid(1),
                timestamp: Timestamp::from_millis(1_000),
                signature: [0xaa; 64],
            })
            .unwrap();
        store
            .add_delegation(DelegationCertificate {
                trusted_cid: tcid,
                delegate: nid(2),
                permissions: 0b001,
                valid_from: Timestamp::from_millis(0),
                valid_until: Timestamp::from_millis(1_000),
                owner_signature: [0xbb; 64],
            })
            .unwrap();
        assert_eq!(
            store.sweep_expired_delegations(Timestamp::from_millis(2_000)),
            1
        );
        // The now-empty delegation list is removed.
        assert_eq!(store.get_delegations(&tcid).count(), 0);
        // Inserting a fresh delegation still works.
        store
            .add_delegation(DelegationCertificate {
                trusted_cid: tcid,
                delegate: nid(3),
                permissions: 0b001,
                valid_from: Timestamp::from_millis(0),
                valid_until: Timestamp::from_millis(3_000),
                owner_signature: [0xcc; 64],
            })
            .unwrap();
        assert_eq!(store.get_delegations(&tcid).count(), 1);
    }

    #[test]
    fn derivative_links() {
        let mut store = GovernanceStore::new();
        let tcid = cid(10);
        let deriv = cid(20);

        let link = DerivativeLink {
            trusted_cid: tcid,
            derivative_cid: deriv,
            app_data: vec![],
            link_type: "phash".into(),
            timestamp: Timestamp::from_millis(1_000),
            reporter: nid(9),
            signature: [0xcc; 64],
        };
        store.add_derivative_link(link).unwrap();

        assert_eq!(store.derivative_count(), 1);
        assert_eq!(store.trusted_cid_for_derivative(&deriv), Some(&tcid));
        assert_eq!(store.derivatives_for(&tcid).len(), 1);
    }

    #[test]
    fn restore_exact_ignores_capacity_and_registration_order() {
        let mut store = GovernanceStore::with_capacities(1, 1);
        // Delegation references a tcid that doesn't exist in the store yet.
        // restore_exact must insert both without the order mattering.
        store.restore_exact(
            alloc::vec![
                TrustedCidRegistration {
                    cid: cid(1),
                    app_metadata: vec![],
                    owner: nid(1),
                    timestamp: Timestamp::from_millis(0),
                    signature: [0xaa; 64],
                },
                TrustedCidRegistration {
                    cid: cid(2),
                    app_metadata: vec![],
                    owner: nid(2),
                    timestamp: Timestamp::from_millis(0),
                    signature: [0xaa; 64],
                },
            ],
            alloc::vec![DelegationCertificate {
                trusted_cid: cid(1),
                delegate: nid(3),
                permissions: 0b001,
                valid_from: Timestamp::from_millis(0),
                valid_until: Timestamp::from_millis(1_000),
                owner_signature: [0xbb; 64],
            }],
            alloc::vec![],
        );
        assert_eq!(store.tcid_count(), 2);
        assert_eq!(store.get_delegations(&cid(1)).count(), 1);
    }

    #[test]
    fn cbor_roundtrip() {
        let mut store = GovernanceStore::new();
        let reg = TrustedCidRegistration {
            cid: cid(10),
            app_metadata: vec![],
            owner: nid(1),
            timestamp: Timestamp::from_millis(1_000),
            signature: [0xaa; 64],
        };
        store.register_tcid(reg).unwrap();
        let cbor = store.to_cbor();
        let bytes = quip_core::cbor::encode(&cbor).unwrap();
        let decoded = quip_core::cbor::decode(&bytes).unwrap();
        let back = GovernanceStore::from_cbor(&decoded).unwrap();
        assert_eq!(back.tcid_count(), 1);
        assert!(back.get_tcid(&cid(10)).is_some());
    }
}