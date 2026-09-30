# QUIP — Roadmap

Implementation milestones for the reference implementation of
[draft-mututi-quip-03](./draft-mututi-quip-03.xml).

## How to read this file

Milestones are numbered `M1`–`M8` in dependency order, with dot
sub-milestones where a milestone split during execution (`M6.1`,
`M4b.1`). The code cites its own milestone in comments; the **Tag
index** at the bottom is the reverse mapping.

**Statuses are evidence-based.** A milestone is *landed* only when the
code exists, is wired into the crate root, and its tests pass under
`cargo test --workspace --all-features`. "Drafted but not verified" is
not a status this file recognises.

**This file and the code must not drift.** When a milestone lands,
update its row and the tag index in the same commit.

---

## Status at a glance

| Milestone | Scope | Status |
|---|---|---|
| M1 | Foundation: dispatch, codec, frame, error, constants | landed |
| M2 | Coral DHT state: routing, cluster, witness discovery | landed |
| M3 | NAT traversal: codecs, state machine, driver, connection flow, sealer | landed |
| M4 | BFT consensus: wire codecs, round core, view change, checkpointing | landed |
| M5 | QUIC transport: endpoint, handshake, T0/T1/T2/T3 I/O | landed |
| M6 | Integration: §16 flow, test vectors, CI | landed |
| M7 | Hardening: rate limits, caches, quarantine, state machines | landed |
| M8 | Range fetch: bao verified streaming | landed |
| Spec pass | S1–S7 and D4 resolved in the draft | landed |
| Spec pass | S8 (`bft_state_transfer` ring signature scope) | open, spec-only |

Every code milestone is landed. §16 runs end-to-end through step 8.
The only open items are S8 (text-only) and four small deferred items
listed under **Open items**.

---

## Build status

All crates compile, every test passes, clippy and rustdoc are silent
under `-D warnings`, and the `no_std` build works:

```
cargo test --workspace --all-features                    601 unit + 3 doc, exit 0
cargo clippy --workspace --all-targets --all-features    clean, -D warnings
cargo doc --workspace --all-features --no-deps           clean
RUSTDOCFLAGS="-D warnings" cargo doc ...                 clean
cargo build -p quip-core -p quip-storage -p quip-net \
    --no-default-features                                clean
```

All five commands run in `.github/workflows/ci.yml` on every push,
plus a `vectors` job that regenerates `test-vectors/` and fails if the
working tree changed.

### Verification baseline

```bash
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --all-features --no-deps
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps
cargo build -p quip-core -p quip-storage -p quip-net --no-default-features
```

Baseline on `main`:

```
quip-core      74 passed
quip-net      470 passed
quip-storage   57 passed
doc-tests       3 passed (one per crate)
             ~601 unit tests, 0 failed — clippy clean, rustdoc clean, no_std clean
```

---

## M1 — Foundation — LANDED

The dispatcher, codec closure, frame format, error codes, and shared
constants every other module builds on.

`quip-core`: `address`, `cbor`, `cid`, `constants`, `dvv`, `error`,
`messages`, `time`. `quip-net`: `codec`, `frame`, `error`,
`constants`, `dispatch`.

**Evidence:** the full `quip-core` suite (74 tests) and the
`frame`/`codec` test groups.

---

## M2 — Coral DHT state — LANDED

Cluster self-organisation, XOR-distance routing, witness discovery, and
the in-memory state a driver consults.

- `cluster.rs` — `ClusterLevel`, `ClusterInfo`, acceptance (§13.2),
  merge (§13.4), split (§13.5), size estimation (§13.6).
- `dht.rs` — `RttClass`, `LookupProgress`, `LookupState`,
  `WitnessRingCache`, cluster-level discriminants.
- `coral.rs` — wire codecs for `coral_lookup`, `lookup_response`,
  `spillover`, `cross_path_validation`, `cross_path_result`;
  XOR-distance selection and cross-path consensus.
- `discovery.rs` — `WitnessDiscovery` state machine driving §5.3.2.

**Evidence:** `cluster::tests`, `dht::tests`, `coral::tests`,
`discovery::tests`.

---

## M3 — NAT traversal (§12) — LANDED

- **Wire codecs (`M3.1`).** `nat_wire.rs` defines `Address`,
  `Candidate`, `RelayEntry`, and the four top-level messages:
  `connectivity_announce`, `candidate_announce`, `relay_discovery`,
  `relay_response`. Signing follows §10.1.
- **State machine + driver (`M3.2`).** `nat.rs` holds `AddressState`
  (most-consistent external address, NAT-type inference from 3
  observers), `CandidateTable`, `RelayManager` (§12.2 selection
  order), `HolePunchSession`, and the `NatTraversal` façade.
  `nat_driver.rs` holds the `DhtClient` trait, `DhtResult`,
  `NullDhtClient`, and `NatDriver::poll()`. Outbound arms that need
  an `Endpoint` or a `Signer` forward to the application as
  `NatEvent`s.
- **Relay emission (`M3.3`).** `NatTraversal::poll` runs a four-phase
  per-session ladder (probe direct candidates; wait out the
  collection window; emit `RequestRelays` once with a fresh
  `request_id`; time out). `on_relay_response` correlates by both
  `request_id` and `target`. `AddressState::port_preservation`
  replaces a hardcoded `true`.
- **Driver-side handlers (`M3.4`).** `NatApplication` trait
  (`probe_candidate`, `send_relay_discovery`, `on_nat_event`);
  `NatDriver::build_relay_discovery`; `NatDriver::dispatch_event`;
  `poll_and_dispatch` convenience.
- **Connection-establishment orchestration (`M3.5`).**
  `establishment.rs` (distinct from `flow.rs`, which owns per-stream
  flow-control frames). `ConnectionFlow` sequences §16 phases:
  `AwaitHandshake → AwaitKeyClaim → NatTraversal → WitnessDiscovery
  → Ready(KtStatus)`, with `Failed(FlowFailure)` reachable via
  timeout. `FlowAction` carries the next step: `Send`,
  `StartNatTraversal`, `StartWitnessDiscovery`, `Ready`, `Failed`.
  KT status computed from accumulated `AnnounceWitness`: 4+
  non-expired ⇒ `Verified`, else `Pending`. A failed discovery
  yields `Ready(Pending)`.
- **Residuals (`M3.6`).** Adaptive re-announce (§12.1) via
  `AddressState::observe_at` + `NatTraversal::current_reannounce_percent`.
  Multi-hop relay chains via `RelayManager::best_chain` and
  `build_chain_recursive`, sealing each hop's `traffic_key ||
  CBOR(trailing chain)`. Relay-announce rate limit via a per-peer
  `RelayAnnounceWindow`.
- **Concrete sealer.** `relay_hpke.rs` implements `RelayHopSealer`:
  HPKE `mode_base`, `DHKEM(X25519, HKDF-SHA256)` / `HKDF-SHA256` /
  `ChaCha20Poly1305`, `info = "QUIP-relay-hop-v1"`, empty `aad`. The
  recipient key is the Ed25519→X25519 birational map of `relay_id`,
  exposed as `ed25519_to_x25519`. Behind the `hpke` feature (off by
  default; `full` enables it).

**Evidence:** `nat::tests`, `nat_wire::tests`, `nat_driver::tests`,
`establishment::tests`, `relay_hpke::tests`.

---

## M4 — BFT consensus (§5.3.4, §5.3.4.1) — LANDED

- **Wire codecs (`M4a`).** `bft.rs` defines all eight messages with
  `to_bytes` / `from_bytes` / `signing_payload` / `verify`. `Operation`
  is a real struct (`kind: tstr`, `subject: bytes`, `body: any`).
  `BftPreprepare::compute_digest` recomputes
  `SHA-256(ring_id || view || sequence || QUIP-CBOR(operation))` with
  8-byte big-endian view and sequence; `verify_digest` and
  `verify_full` enforce it. Wired into `message.rs`.
- **Round core (`M4b.1`).** `bft_driver.rs` runs the four-phase
  protocol in a single view. `RingMembership` holds members in
  canonical NodeId order (S3); `primary_for(v)` is
  `members[v mod |R|]`; `quorum()` is `n - f`. `BftHandler` is the
  application-side apply hook. `RoundState` and `try_advance` drive
  each quorum transition exactly once.
- **View change (`M4b.2`).** `start_view_change` broadcasts a
  `bft_view_change` for `view + 1`. `on_view_change` discards
  superseded votes before signature verification, joins a
  peer-initiated view change, ignores votes for a different target.
  `on_new_view` verifies the sender is the primary for the target
  view, verifies the primary signature, decodes each enclosed
  view-change message, resolves each signer by trial verification
  against the ring (`find_view_change_signer`, O(|R|) per message),
  enforces distinct signers, adopts on quorum.
- **Checkpointing and state transfer (`M4b.3`).** `BftHandler` gains
  `state_digest()`, `state_bytes()`, `apply_state()` with
  conservative defaults. `apply_current` triggers a checkpoint every
  `CHECKPOINT_INTERVAL`; `start_checkpoint()` is public.
  `on_checkpoint` collects witness signatures over
  `(sequence, state_digest)` and promotes to stable at quorum;
  stability is checked against `stable_checkpoint`, not
  `checkpoint_sequence`, so a checkpoint at sequence 0 is not
  mistaken for one already held. `request_state_transfer` emits a
  `bft_state_transfer` with empty state and empty ring signature;
  `on_state_transfer` dispatches on whether the ring signature is
  empty and installs a verified response.

**Evidence:** `bft::tests`, `bft_driver::tests`.

---

## M5 — QUIC transport (§11, §12, §16) — LANDED

`transport.rs` binds QUIP to QUIC via `quinn`.

- `Endpoint` for server and client, ALPN `"quip"`, no-op TLS
  verifier (identity comes from the Key Claim exchange).
- `ConnectionDriver` lifecycle: `Connecting → KeyClaimExchanging →
  Established → Closed`. T0 handshake and §16 Key Claim exchange run
  inline before the read tasks spawn.
- Per-tier send halves (T0/T1), per-resource T2 streams held for the
  connection's lifetime; read halves moved into tasks feeding a
  shared `mpsc::Sender<Event>`.
- Four read loops: T0, T1, T2-accept, T3-datagram. `Event` enum:
  `Frame`, `Datagram`, `BulkStreamOpened`, `ControlConnected`,
  `Error`.

**Evidence:** 16 tests in `transport::tests` over a real QUIC
handshake pair.

---

## M6 — Integration + vectors + CI — LANDED

- **§16 integration (`M6.1`).** Five tests, one per stage 4–8:
  `bulk_full_transfer_verifies_cid`,
  `fetch_range_round_trip_with_proof`,
  `governance_register_tcid_round_trips`,
  `bft_consensus_sequence_round_trips`,
  `cross_path_validation_round_trips`. Stages 1–3 covered by the
  pre-existing transport tests. Two non-test changes were needed:
  `Endpoint` holds a `QuipNetConfig`; `ConnectionDriver` keeps the
  receive half of every outbound T2 stream alive.
- **Signing vectors (`M6.2`).** `test-vectors/` holds
  `key_claim.json`, `witness_statement.json`,
  `individual_ring_sig.json`, `frost_ring_sig.json`. Generated by
  `cargo xtask generate-vectors`. A CI job regenerates and diffs.
- **CI (`M6.3`).** `.github/workflows/ci.yml` runs five independent
  jobs: `test`, `clippy`, `doc`, `no_std`, `vectors`.

---

## M7 — Hardening (§11, §19.4) — LANDED

- **Rate limiting.** `ConnectionDriver` enforces inbound limits per
  peer NodeId via `RateLimiter`. T2 (bulk) exempt; pre-handshake
  unbounded. Per-connection scope.
- **Bao chunk-tree cache.** `bao_cache.rs` holds bao *outboards*
  (~6.25% of a resource) keyed by BLAKE3 digest. LRU, bounded.
  `extract_proof_cached` serves from the cache on a hit.
  `ExtractedProof::recomputed` signals §8.2's rate-limit case.
- **Quarantine on range.** `range::QuarantineCheck` implemented for
  `quip_storage::QuarantineStore`; `NoQuarantine` for deployments
  without the primitive. `serve_range` and `RangeResponder` consult
  the policy and return `E_QUARANTINED`.
- **Range length cap.** `RangeResponder::serve` binds cache,
  quarantine policy, and negotiated `max_range_length`.
- **T1 SYNC state machine.** `sync_stream.rs` models six states and
  their transitions; the transport driver consults it.
- **Connection throttling.** `backoff::BackoffTracker<K>`;
  `dht::WitnessLoad` caps concurrent ring participation at 10. The
  transport driver records per-peer errors into a
  `BackoffTracker<NodeId>`.
- **DoS bounds.** `split_range` plans multi-request fetches;
  concurrent inbound T2 streams capped at `T2_MAX_STREAMS` via a
  `Semaphore`.
- **Flow control.** `flow.rs` codec and state machine (§11).
- **Pin eviction.** `quip-storage/src/pins.rs` evicts by lowest
  `ref_count` then age.

---

## M8 — Range fetch — LANDED

`range.rs` defines `fetch_range` and `range_response`;
`bao_support::extract_proof` and `verify_response` are behind the
`crypto` feature.

- BLAKE3 only. `is_blake3` checks the CID; SHA-256 CIDs rejected.
- `MAX_RANGE_IN_SINGLE_RESPONSE` caps a response at
  `(MAX_MESSAGE_SIZE - 1024) / 2`.
- Range bounds checked before encoding.

**Evidence:** `range::tests` (30 tests: 6 codec, 3 quarantine-policy,
21 in `bao_tests`, 9 of which exercise the M7 cached path).

---

## Spec pass

Seven points where the draft left a choice, plus one numeric mismatch
and one open revision.

- **S1 — `RelayHop.encrypted_key`.** §12.2 defines HPKE `mode_base`,
  `DHKEM(X25519, HKDF-SHA256)` / `HKDF-SHA256` / `ChaCha20Poly1305`,
  `info = "QUIP-relay-hop-v1"`, empty `aad`.
- **S2 — QUIC path validation.** §12.3 documents the
  application-owned `Endpoint` path.
- **S3 — View-change ordering.** §5.3.4 pins ring order to canonical
  NodeId order; primary for `v` is `members[v mod |R|]`.
- **S4 — `bft_state_transfer.state` contents.** §5.3.4.1 requires the
  state to be opaque, digest-bound
  (`checkpoint_digest = SHA-256(state)`), deterministically
  decodable, and to encode the DVV, view, sequence, and
  post-checkpoint operations at minimum.
- **S5 — Handshake framing.** §4 specifies self-delimiting CBOR
  without the varint prefix. Buffer cap is `MAX_HANDSHAKE_BYTES`
  (4096).
- **S6 — Target echo in `relay_response`.** §12.2 requires
  `request_id: bytes .size 16` on `RelayDiscovery`, echoed with
  `target` on `RelayResponse`.
- **S7 — `NAT_TYPE_*` numeric values.** §12.1 carries a normative
  table matching `nat_wire.rs`.
- **D4 — `T2_MAX_STREAMS`.** §19.4 says 256; `constants.rs` was 16.
  Aligned.
- **S8 — `bft_state_transfer` ring signature scope — OPEN.** §5.3.4.1
  says the `ring_signature` covers the state transfer's own signing
  payload. A responder cannot produce a fresh quorum ring signature
  without an extra round trip the spec does not describe. The
  implementation treats the ring signature as the collection of
  `bft_checkpoint` signatures that made the checkpoint stable, and
  verifies it against the `bft_checkpoint` payload for
  `(ring_id, checkpoint_sequence, checkpoint_digest)`. **Spec
  revision required**, text-only: §5.3.4.1 should either describe
  the extra round or adopt the checkpoint-signatures interpretation.

---

## Tag index

Milestone citations in the source. Update both when a tag moves.

| Location | Tag | Refers to |
|---|---|---|
| `quip-net/src/lib.rs` | M1, M2 | module description |
| `quip-net/src/nat.rs` (`RelayHopSealer`) | M3.3 | relay-hop HPKE interface |
| `quip-net/src/nat.rs` (`build_chain_recursive`) | M3.6 | multi-hop chain builder |
| `quip-net/src/nat.rs` (`NatTraversal::poll`) | M3.3 | four-phase session ladder |
| `quip-net/src/nat.rs` (`on_relay_response`) | M3.3 | request_id + target correlation |
| `quip-net/src/nat.rs` (`generate_request_id`) | M3.3 | 16-byte request-id derivation |
| `quip-net/src/nat.rs` (`AddressState::port_preservation`) | M3.3 | replaces hardcoded `true` |
| `quip-net/src/nat.rs` (`AddressState::observe_at`) | M3.6 | timestamped observation, churn history |
| `quip-net/src/nat.rs` (`current_reannounce_percent`) | M3.6 | churn-adaptive §12.1 percent |
| `quip-net/src/nat.rs` (`RelayAnnounceWindow`) | M3.6 | per-peer §19.4 window |
| `quip-net/src/nat_driver.rs` (`NatApplication`) | M3.4 | probe + relay-discovery handlers |
| `quip-net/src/nat_driver.rs` (`dispatch_event`) | M3.4 | event routing |
| `quip-net/src/establishment.rs:1` | M3.5 | §16 connection flow |
| `quip-net/src/relay_hpke.rs:1` | M3.6 | concrete relay-hop HPKE sealer |
| `quip-net/src/bft_driver.rs:1` | M4b.1–M4b.3 | BFT round core, view change, checkpointing |
| `quip-net/src/bft_driver.rs` (`RingMembership`) | M4b.1 | canonical-order membership, quorum, primary rotation |
| `quip-net/src/bft_driver.rs` (`BftHandler`) | M4b.1, M4b.3 | apply hook + state hooks |
| `quip-net/src/bft_driver.rs` (`start_view_change`) | M4b.2 | view-change initiation |
| `quip-net/src/bft_driver.rs` (`on_new_view`) | M4b.2 | new-view acceptance and adoption |
| `quip-net/src/bft_driver.rs` (`start_checkpoint`) | M4b.3 | checkpoint emission |
| `quip-net/src/bft_driver.rs` (`on_state_transfer`) | M4b.3 | state transfer request/response |
| `quip-net/src/bft_driver.rs` (`verify_checkpoint_ring_sig`) | M4b.3 | S8 interpretation of the ring signature |
| `quip-net/src/transport.rs:3` | M5 | status header |
| `quip-net/src/transport.rs` (M5.2–M5.4 test groups) | M5 | handshake/capability, T0/T1/T3, Key Claim |
| `quip-net/src/transport.rs` (M6.1 section) | M6.1 | §16 integration tests |
| `quip-net/src/transport.rs` (M7 section) | M7 | rate limiting |
| `quip-net/src/conn.rs:6` | M5 | driver owns the QUIC connection |
| `quip-net/src/conn.rs:66` | M5 | driver consults `flow_state` |
| `quip-net/src/handshake.rs:562` | M8 | negotiated-set re-encode hot path |
| `quip-net/src/cluster.rs:108` | M2b.1 | `ClusterInfo` after signature verification |
| `quip-net/src/bft.rs` (module docs) | M4b | opaque `new_view` contents verified by the driver |
| `quip-net/src/bao_cache.rs:1` | M7 | cached bao chunk trees |
| `quip-net/src/range.rs` (`extract_proof_cached`) | M7 | cached proof path |
| `quip-net/src/range.rs` (`serve_range`) | M7 | quarantine policy |
| `quip-net/src/range.rs` (`extract_proof`) | M8 | uncached proof builder |
| `quip-net/src/backoff.rs:1` | M7 | per-key exponential backoff |
| `quip-net/src/sync_stream.rs:1` | M7 | T1 SYNC state machine |
| `quip-net/src/dht.rs` (`WitnessLoad`) | M7 | witness ring participation cap |
| `quip-net/src/range.rs` (`split_range`) | M7 | client-side range splitting |
| `quip-net/src/range.rs` (`RangeResponder`) | M7 | responder with cap + quarantine |
| `quip-net/src/test_support.rs:1` | — | test-only `FakeSigner` |

The code subdivides NAT work as `M3a` / `M3b.1` / `M3b.2` / `M3b.3`
and BFT work as `M4a` / `M4b`. The M3 section above numbers the later
work `M3.3`–`M3.6`; those tags appear in commits but not uniformly in
the source. `M3b.3` is retired — its only `TODO`
(`port_preservation`) landed with M3.3.

**Not yet tagged but milestone-owned:** `flow.rs` (M7), `rate.rs`
(M7), `discovery.rs` (M2), `coral.rs` (M2), `message.rs` BFT arms
(M4), `bft.rs` (M4), `xtask/` (M6.2), `.github/workflows/ci.yml`
(M6.3). Tagging on the next touch is cheap.

---

## Open items

Every code milestone is landed. What remains:

1. **S8 spec revision.** Text-only. Decide whether §5.3.4.1
   describes the extra round trip a fresh quorum ring signature
   would require, or whether it adopts the checkpoint-signatures
   interpretation the implementation uses. Until this lands, the
   code and the draft disagree on what
   `bft_state_transfer.ring_signature` covers.
2. **Prepared-operation carry-forward on view change.** The new
   primary does not yet re-propose operations prepared in an earlier
   view; `bft_new_view.prepared_messages` is emitted empty. Needs a
   `prepared: BTreeMap<sequence, (Operation, Digest, view, sig)>` on
   the driver and a re-propose path in `adopt_view`.
3. **Checkpoint carry-forward on view change.**
   `bft_new_view.checkpoint_messages` is emitted empty. Same shape as
   (2): the driver already retains `stable_checkpoint`, but
   `maybe_emit_new_view` does not encode it.
4. **FROST ring signature verification** in
   `verify_checkpoint_ring_sig`. Requires a group public key on the
   ring; the driver does not hold one today. The individual-signature
   path is complete.
5. **Release tag.** `git tag v0.1.0-m6 && git push origin
   v0.1.0-m6`, then update to `v0.1.0` once S8 lands.
6. **GitHub metadata.** Repository description and topics.

None of items 1–4 block the demo path. §16 runs end-to-end.

---

## Housekeeping

### Done
- `git init` and first push; branch `main` at
  `github.com/jjmututi/quip`.
- `LICENSE-MIT` and `LICENSE-APACHE`, matching `MIT OR Apache-2.0`
  in every manifest.
- `.gitignore` with `target/`.
- CI workflow at `.github/workflows/ci.yml`.
- Draft at repository root.
- Each crate's `lib.rs` links to this file (see `## Roadmap` in the
  module docs).
- `quip-core/quip-core.txt` and `quip-core/crate_dump.sh` deleted.
- `README.md` at repository root.