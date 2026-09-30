# QUIP — Roadmap

Implementation milestones for the reference implementation of
[draft-mututi-quip-03](./draft-mututi-quip-03.xml).

## How to read this file

Milestones are numbered `M1`–`M8` in dependency order. Sub-milestones use a
dot: `M6.1`, `M6.2`. The code cites its own milestone in comments so that a
reader can find the plan from the source; the **Tag index** at the bottom is
the reverse mapping.

**Statuses are evidence-based.** A milestone is *landed* only when the code
exists, is wired into the crate root, and its tests pass under
`cargo test --workspace --all-features`. "Drafted but not verified" is not a
status this file recognises.

**This file and the code must not drift.** When a milestone lands, update its
row and the tag index in the same commit.

---

## Status at a glance

| Milestone | Scope | Status |
|---|---|---|
| M1 | Foundation: dispatch, codec, frame, error, constants | landed |
| M2 | Coral DHT state: routing, cluster, witness discovery | landed |
| M3 | NAT traversal: codecs, state machine, driver, connection flow | landed; M3.6 sealer outstanding |
| M4 | BFT consensus: wire codecs (M4a), driver (M4b) | landed |
| M5 | QUIC transport: endpoint, handshake, T0/T1/T2/T3 I/O | landed |
| M6 | Integration: §16 flow, test vectors, CI | landed |
| M7 | Hardening: rate limits, caches, quarantine, state machines | landed |
| M8 | Range fetch: bao verified streaming | landed |
| Spec pass | S1–S7 and D4 pinned in the draft | landed; S1 sealer impl is code work |

**Demo-critical list is complete.** The §16 flow runs end-to-end through
step 8. M4b's consensus driver is the last known gap.

---

## Build status

All crates compile, every test passes, clippy and rustdoc are silent under
`-D warnings`, and the `no_std` build works:

```
cargo test --workspace --all-features                    601 unit + 3 doc, exit 0
cargo clippy --workspace --all-targets --all-features    clean, -D warnings
cargo doc --workspace --all-features --no-deps           clean
RUSTDOCFLAGS="-D warnings" cargo doc ...                 clean
cargo build -p quip-core -p quip-storage -p quip-net \
    --no-default-features                                clean
```

All five commands run in `.github/workflows/ci.yml` on every push, plus a
`vectors` job that regenerates `test-vectors/` and fails if the working tree
changed.

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
constants that every other module builds on.

### Contents
- `quip-core`: `address`, `cbor`, `cid`, `constants`, `dvv`, `error`,
  `messages`, `time`.
- `quip-net`: `codec`, `frame`, `error`, `constants`, `dispatch`.

### Evidence
The full `quip-core` test suite (74 tests) and the `frame`/`codec` test
groups in `quip-net`.

---

## M2 — Coral DHT state — LANDED

Cluster self-organisation, XOR-distance routing, witness discovery, and the
in-memory state that a driver consults.

### Contents
- `cluster.rs`: `ClusterLevel`, `ClusterInfo`, acceptance test (§13.2),
  merge decision (§13.4), split decision (§13.5), size estimation (§13.6).
- `dht.rs`: `RttClass`, `LookupProgress`, `LookupState`, `WitnessRingCache`,
  cluster-level discriminants.
- `coral.rs`: wire codecs for `coral_lookup`, `lookup_response`, `spillover`,
  `cross_path_validation`, `cross_path_result`; XOR-distance selection and
  cross-path consensus.
- `discovery.rs`: `WitnessDiscovery` state machine driving the §5.3.2
  algorithm.

### Evidence
`cluster::tests`, `dht::tests`, `coral::tests`, `discovery::tests`.

---

## M3 — NAT traversal (§12) — LANDED

### M3.1 — Wire codecs — LANDED
`nat_wire.rs` defines `Address`, `Candidate`, `RelayEntry`, and the four
top-level messages: `connectivity_announce`, `candidate_announce`,
`relay_discovery`, `relay_response`. Signing convention follows §10.1.

### M3.2 — State machine + driver — LANDED
- `nat.rs`: `AddressState` (most-consistent external address, NAT-type
  inference from 3 observers), `CandidateTable` (priority class, TTL
  pruning, session binding), `RelayManager` (§12.2 selection order),
  `HolePunchSession`, `NatTraversal` façade with `Outbound`/`NatEvent`.
- `nat_driver.rs`: `DhtClient` trait, `DhtResult`, `NullDhtClient`,
  `NatDriver<D>::poll()`. Outbound arms that need an `Endpoint` or a
  `Signer` forward to the application as `NatEvent`s.

### M3.3 — Relay emission — LANDED
- `NatTraversal::poll` runs a four-phase per-session ladder: probe any
  unprobed direct candidate; wait out the candidate collection window;
  emit `RequestRelays` exactly once with a fresh `request_id`; time the
  session out if relay discovery goes unanswered.
- `on_relay_response` correlates by both `request_id` and `target`
  (§12.2) and emits `NatEvent::RelayPathAvailable`.
- `generate_request_id` derives a 16-byte value from the local NodeId
  prefix plus a monotonic counter.
- `AddressState::port_preservation` replaces the hardcoded `true` in
  `emit_connectivity_announce`.
- `RelayHopSealer` trait and a first `build_relay_chain` that seals a
  single hop with the HPKE scheme fixed by §12.2. The signature and
  hop-construction were extended in M3.6 to support multi-hop chains;
  the trait itself is unchanged.

### M3.4 — Driver-side handlers — LANDED
- `NatApplication` trait: `probe_candidate`, `send_relay_discovery`,
  `on_nat_event`.
- `NatDriver::build_relay_discovery` signs the §12.2 message shape.
- `NatDriver::dispatch_event` routes an emitted `NatEvent` to the
  application; observation-only events reach `on_nat_event`.
- `NatDriver::poll_and_dispatch` is the convenience wrapper.

### M3.5 — Connection-establishment orchestration — LANDED
- `establishment.rs` (distinct from `flow.rs`, which owns per-stream
  flow-control frames). `ConnectionFlow` sequences §16 phases:
  `AwaitHandshake → AwaitKeyClaim → NatTraversal → WitnessDiscovery →
  Ready(KtStatus)`, with `Failed(FlowFailure)` reachable via timeout.
- `FlowAction` tells the caller what to do next: `Send(Box<Message>)`,
  `StartNatTraversal`, `StartWitnessDiscovery`, `Ready`, `Failed`.
- KT status computed from accumulated `AnnounceWitness` messages: 4+
  non-expired statements ⇒ `Verified`, otherwise `Pending`. A failed
  witness discovery yields `Ready(Pending)` rather than a failed flow.
- Timeouts: 10 s (Key Claim), 30 s (NAT), 30 s (discovery). All three
  are implementation choices.

### M3.6 — Residuals

Three of four landed.

**Landed:**
- **Adaptive re-announce (§12.1).** `AddressState` gains
  `observe_at(observer, addr, now)` alongside the original 2-arg
  `observe`; the latter delegates with a zero timestamp so existing
  callers compile. `observe_at` records a bounded history of
  external-address changes. `NatTraversal::current_reannounce_percent`
  maps a 1-hour churn window to 90 / 80 / 50 %; `poll` uses it in
  place of the fixed `NatConfig::reannounce_interval_ms`.
- **Multi-hop relay chains (§12.2).** `RelayManager::best_chain`
  returns up to `max_hops` relays that declare the target, ordered by
  the same criteria as `best_for`. `RelayHop` and `RelayChain` gain
  CBOR codecs. `build_relay_chain(target, target_addr, max_hops,
  ttl_s, traffic_key, sealer)` builds the chain from the last hop
  backwards via the free function `build_chain_recursive`; each
  earlier hop's HPKE plaintext is `traffic_key || CBOR(trailing
  chain)`.
- **Relay-announce rate limit (§19.4).** `NatTraversal` keeps a
  per-peer `RelayAnnounceWindow` (100 relay-capable announces per
  minute). `on_connectivity_announce` consults it before offering the
  announce to the `RelayManager`; excess announces are dropped
  silently.

**Outstanding:**
1. **S1 concrete sealer.** `RelayHopSealer` has no production impl.
   HPKE `mode_base`, `DHKEM(X25519, HKDF-SHA256)` / `HKDF-SHA256` /
   `ChaCha20Poly1305`, `info = "QUIP-relay-hop-v1"`, empty `aad`; the
   recipient key is the Ed25519→X25519 birational map of `relay_id`.
   Belongs in `quip-net/src/crypto.rs` behind the `crypto` feature, or
   a new `hpke` feature. Multi-hop chains now construct correctly at
   the state-machine level but cannot be sealed without this impl.

---

## M4 — BFT consensus (§5.3.4, §5.3.4.1) — LANDED

### M4a — Wire codecs — LANDED
`bft.rs` defines all eight messages (`BftPreprepare`, `BftPrepare`,
`BftPrecommit`, `BftCommit`, `BftViewChange`, `BftNewView`, `BftCheckpoint`,
`BftStateTransfer`) with `to_bytes`/`from_bytes`/`signing_payload`, plus
`verify(signer, verifier)`.

Two corrections from drafting are in the code:
- `Operation` is a real struct (`kind: tstr`, `subject: bytes`,
  `body: any`), not an opaque `CborValue` newtype.
- `BftPreprepare::compute_digest` recomputes
  `SHA-256(ring_id || view || sequence || QUIP-CBOR(operation))` with
  8-byte big-endian view and sequence; `verify_digest` and `verify_full`
  enforce it.

Wired into `message.rs` with verb, tier, capability, and dispatch arms.

### M4b.1 — Round core — LANDED
`bft_driver.rs` runs the four-phase protocol in a single view:
preprepare → prepare (quorum) → precommit (quorum) → commit (quorum)
→ apply.

- `RingMembership` holds members in canonical NodeId order (S3 pinned
  this); `primary_for(v)` is `members[v mod |R|]`; `quorum()` is
  `n - f` where `f = (n - 1) / 3`.
- `BftHandler` is the application-side apply hook, called exactly once
  per sequence on commit quorum.
- `BftDriver` holds a `Signer` and a `Verifier`; both are value types.
- The four-phase ladder (`RoundState`) is driven by `try_advance`,
  which fires each quorum transition exactly once and emits the
  corresponding event.

### M4b.2 — View change — LANDED
A witness that suspects the primary calls
`BftDriver::start_view_change()`. The driver broadcasts a
`bft_view_change` for `view + 1` and starts collecting. When a member
has quorum votes *and* is the primary for the target view, it emits a
`bft_new_view` carrying the collected votes and adopts.

- `on_view_change` discards superseded votes (target view ≤ current
  view) before signature verification; joins a peer-initiated view
  change if none is in progress; ignores votes for a different target.
- `on_new_view` verifies the sender is the primary for `msg.view`, the
  primary signature, and each enclosed view-change message; resolves
  each signer by trial verification against the ring (the wire type
  carries no signer NodeId); enforces distinct signers; adopts on
  quorum.
- `find_view_change_signer` is the trial-verification helper; O(|R|)
  per message, acceptable for the ring sizes this protocol supports.

### M4b.3 — Checkpointing and state transfer — LANDED
- `BftHandler` gains `state_digest()`, `state_bytes()`, and
  `apply_state()`, all with conservative defaults so existing handlers
  compile unchanged.
- `BftDriver::apply_current` triggers a checkpoint every
  `CHECKPOINT_INTERVAL` sequences. `start_checkpoint()` is public so
  callers can force one (e.g. before shutdown).
- `on_checkpoint` collects witness signatures over
  `(sequence, state_digest)`. A quorum promotes the checkpoint to
  stable and retains the signatures. Stability is checked against
  `stable_checkpoint`, not `checkpoint_sequence`, so a checkpoint at
  sequence 0 is not mistaken for one already held.
- `request_state_transfer()` emits a `bft_state_transfer` with the
  driver's known sequence, empty state, and an empty ring signature.
  `on_state_transfer` dispatches on whether the ring signature is
  empty: a request gets a response if the responder has a newer
  stable checkpoint; a response is verified, has its digest checked
  against the transmitted state, is installed via the handler, and
  advances the driver's sequence.
- `verify_checkpoint_ring_sig` verifies each signature against the
  `bft_checkpoint` payload for
  `(ring_id, checkpoint_sequence, checkpoint_digest)`, not the state
  transfer's own signing payload. See S8.

### M4b — Out of scope (deferred)

- **Prepared-operation carry-forward on view change.** The new
  primary does not yet re-propose operations that were prepared in an
  earlier view. `bft_new_view.prepared_messages` is emitted empty.
- **Checkpoint carry-forward on view change.**
  `bft_new_view.checkpoint_messages` is emitted empty.
- **FROST ring signature verification** in
  `verify_checkpoint_ring_sig`. The individual-signature path is
  complete; the FROST path returns `false` and the caller rejects the
  transfer.

---

## M5 — QUIC transport (§11, §12, §16) — LANDED

`transport.rs` binds QUIP to QUIC via `quinn`.

### Contents
- `Endpoint` for server and client, with ALPN `"quip"` and a no-op TLS
  verifier (identity comes from the Key Claim exchange, not the certificate).
- `ConnectionDriver`: lifecycle `Connecting → KeyClaimExchanging →
  Established → Closed`.
- T0 handshake + §16 Key Claim exchange driven inline before the read tasks
  spawn.
- Per-tier send halves (T0/T1) and per-resource T2 streams held for the
  connection's lifetime; read halves moved into tasks feeding a shared
  `mpsc::Sender<Event>`.
- Four read loops: T0, T1, T2-accept, T3-datagram.
- `Event` enum: `Frame`, `Datagram`, `BulkStreamOpened`, `ControlConnected`,
  `Error`.

### Evidence
16 tests in `transport::tests`, over a real QUIC handshake pair.

---

## M6 — Integration + vectors + CI — LANDED

### M6.1 — §16 full-flow integration tests — LANDED
Five tests in `transport.rs`, one per §16 stage 4–8:

| Test | Stage |
|---|---|
| `bulk_full_transfer_verifies_cid` | 4 — bulk with CID verification |
| `fetch_range_round_trip_with_proof` | 5 — bao proof verification |
| `governance_register_tcid_round_trips` | 6 — governance verbs on T0 |
| `bft_consensus_sequence_round_trips` | 7 — BFT quorum messages on T0 |
| `cross_path_validation_round_trips` | 8 — cross-path validation |

Stages 1–3 covered by the pre-existing transport tests.

Two non-test changes were needed:
- `Endpoint` holds a `QuipNetConfig`; `ServerConfig`/`ClientConfig` gained
  `capabilities`. The server previously had nowhere to advertise a
  non-baseline set, so `merkle_range` and `governance` could not be
  negotiated in tests.
- `ConnectionDriver` keeps the receive half of every outbound T2 stream
  alive. Dropping it sent STOP_SENDING, tearing down the peer's read side
  and silently dropping frames still in flight.

### M6.2 — Signing vectors (§10.1) — LANDED
Four vectors in `test-vectors/`: `key_claim.json`, `witness_statement.json`,
`individual_ring_sig.json`, `frost_ring_sig.json`. FROST uses a real 5-of-7
aggregate with deterministic nonces.

Generated by `cargo xtask generate-vectors`. `xtask/` depends on
`frost-ed25519` as a dev-dependency only. A CI job regenerates and diffs.

### M6.3 — CI — LANDED
`.github/workflows/ci.yml` runs five independent jobs: `test`, `clippy`,
`doc`, `no_std`, `vectors`.

---

## M7 — Hardening (§11, §19.4) — LANDED

Ten items. All landed.

### Landed
- **Rate limiting (§19.4).** `ConnectionDriver` enforces inbound limits per
  peer NodeId via `RateLimiter`. `Frame` and `Datagram` events are checked
  after the Key Claim exchange; over-budget events become
  `Event::Error { error: RateLimit }`. T2 (bulk) exempt. Pre-handshake
  unbounded. Per-connection scope (shared budgets across connections need
  the limiter hoisted above the driver).
- **Bao chunk-tree cache (§8.2, App. A.4).** `quip-net/src/bao_cache.rs`
  holds bao *outboards* — the parent nodes alone, about 6.25% of a
  resource against ~106% for the combined encoding — keyed by BLAKE3
  digest. LRU, bounded by `max_entries` / `max_bytes` / `max_entry_bytes`;
  no TTL, because an outboard is immutable.
  `range::bao_support::extract_proof_cached` serves a proof from the
  cached tree on a hit and falls back to `extract_proof` for a tree too
  large to hold. `ExtractedProof::recomputed` is the signal §8.2 asks for
  when it says a recomputing responder SHOULD rate-limit.
- **Quarantine on range (§8.2, §19.3).** `range::QuarantineCheck` is the
  policy boundary; it is implemented for
  `quip_storage::QuarantineStore` so the range path and the whole-resource
  path cannot disagree. `range::NoQuarantine` covers deployments that do
  not support the governance primitive. `bao_support::serve_range` and
  `bao_support::RangeResponder` both consult the policy before touching
  the cache and return `E_QUARANTINED` on a hit.
- **Range length cap — call site (§8.2).** `bao_support::RangeResponder`
  binds the cache, the quarantine policy, and the peer's negotiated
  `max_range_length` into a single `serve` method: length first,
  quarantine second, `extract_proof_cached` third.
- **T1 SYNC stream state machine (§11).**
  `quip-net/src/sync_stream.rs` models the six states (`Initial`,
  `Syncing`, `RbsrSyncing`, `RangeFetching`, `Idle`, `Error`) and their
  transitions. The transport driver consults it, feeding inbound T1
  requests via `SyncStream::classify_verb` and advancing to `Idle` on
  the next successful T1 write while busy.
- **Connection throttling (§19.4).** `backoff::BackoffTracker<K>` is a
  per-key exponential backoff with the §19.4 defaults (1 s base, 60 s
  cap, 10 000 keys). `dht::WitnessLoad` caps concurrent witness-ring
  participation at `DEFAULT_MAX_RINGS` = 10, per §19.4. The transport
  driver records per-peer errors into a `BackoffTracker<NodeId>` and
  exposes it for the caller's retry policy.
- **DoS bounds (§19.4).** `range::split_range` plans multi-request
  fetches for resources larger than the single-response cap. The
  transport driver caps concurrent inbound T2 streams at
  `T2_MAX_STREAMS` per connection using a `Semaphore`, so a peer that
  opens more than the cap gets QUIC-level backpressure.
- **Flow control frames (§11).** `flow.rs` codec and state machine.
- **Pin eviction.** `quip-storage/src/pins.rs` evicts by lowest
  `ref_count` then age.
- **Range length cap — codec half.** `FetchRange::check_length` exists.

### Size
~1500–2000 lines.

---

## M8 — Range fetch — LANDED

`range.rs` defines `fetch_range` and `range_response`, with
`bao_support::extract_proof` and `bao_support::verify_response` behind the
`crypto` feature.

### Constraints
- BLAKE3 only. `is_blake3` checks the CID; SHA-256 CIDs are rejected.
- `MAX_RANGE_IN_SINGLE_RESPONSE` caps a single response at
  `(MAX_MESSAGE_SIZE - 1024) / 2`.
- Range bounds checked before encoding; oversized payloads rejected.

### Evidence
`range::tests` (30 tests: 6 codec, 3 quarantine-policy, and 21 in
`bao_tests`, of which 9 exercise the M7 cached path).

The cached path is a responder-side cost optimisation, not part of M8's wire
surface: `extract_proof_cached` produces byte-identical proofs to
`extract_proof`, which `cached_and_uncached_proofs_are_byte_identical` pins.

---

## Spec pass — LANDED

Seven points where the draft left a choice, plus one code/spec numeric
mismatch. All eight are now resolved in `draft-mututi-quip-03.xml`.

- **S1 — `RelayHop.encrypted_key`.** §12.2 now defines HPKE `mode_base`,
  `DHKEM(X25519, HKDF-SHA256)` / `HKDF-SHA256` / `ChaCha20Poly1305`,
  `info = "QUIP-relay-hop-v1"`, empty `aad`. The recipient key is the
  Ed25519→X25519 birational map of `relay_id`. **Code follow-up:** the
  concrete sealer is M3.6 item 1; `build_relay_chain` is single-hop until
  it lands.
- **S2 — QUIC path validation.** §12.3 now documents the application-owned
  `Endpoint` path: the driver signals a probe, the application dials a
  fresh connection with the same ALPN, reports back. Probe connections are
  not retained. `NatDriver` forwards `NatEvent::ProbeRequested`; M3.4
  routes it.
- **S3 — View-change ordering.** §5.3.4 pins ring order to canonical
  NodeId order (bytewise lexicographic); primary for view `v` is
  `members[v mod |R|]`. Reachable-subset handling for DEGRADED mode is
  specified.
- **S4 — `bft_state_transfer.state` contents.** §5.3.4.1 now requires the
  state to be opaque, digest-bound (`checkpoint_digest = SHA-256(state)`),
  deterministically decodable by the same application, and to encode the
  DVV, current view and sequence, and post-checkpoint operations at
  minimum.
- **S5 — Handshake framing.** §4 now specifies the handshake as
  self-delimiting CBOR without the varint prefix; every subsequent message
  on the control stream carries the prefix. Buffer cap is
  `MAX_HANDSHAKE_BYTES` (4096).
- **S6 — Target echo in `relay_response`.** §12.2 now requires a
  `request_id: bytes .size 16` on `RelayDiscovery`, echoed along with
  `target` on `RelayResponse`. **Code follow-up:** landed in M3.3 and
  M3.4.
- **S7 — `NAT_TYPE_*` numeric values.** §12.1 now carries a normative
  table matching `nat_wire.rs` (`UNKNOWN`=0, `OPEN`=1, `CONE`=2,
  `RESTRICTED`=3, `SYMMETRIC`=4).
- **D4 — `T2_MAX_STREAMS`.** §19.4 says 256; `constants.rs` was 16.
  Aligned the constant to the spec.
- **S8 — `bft_state_transfer` ring signature scope.** §5.3.4.1 says the
  `ring_signature` covers the state transfer's own signing payload. A
  responder cannot produce a fresh quorum ring signature without an
  extra round trip the spec does not describe. The implementation
  treats the ring signature as the collection of `bft_checkpoint`
  signatures that made the checkpoint stable, and verifies it against
  the `bft_checkpoint` payload for
  `(ring_id, checkpoint_sequence, checkpoint_digest)`. **Spec
  revision required**, text-only: §5.3.4.1 should either describe the
  extra round or adopt the checkpoint-signatures interpretation.

---

## Tag index

Milestone citations in the source. Update both when a tag moves.

| Location | Tag | Refers to |
|---|---|---|
| `quip-net/src/lib.rs` | M1, M2 | module description |
| `quip-net/src/nat.rs:11` | M3a | legacy NAT types removed from this file |
| `quip-net/src/nat.rs:32` | M3a | NAT flavour + hole punching |
| `quip-net/src/nat.rs:346` | M3b.1 | configuration |
| `quip-net/src/nat.rs:391` | M3b.1 | address discovery (§12.1) |
| `quip-net/src/nat.rs:510` | M3b.1 | candidate table (§12.3) |
| `quip-net/src/nat.rs:634` | M3b.1 | sessions + driver-facing types |
| `quip-net/src/nat.rs` (`RelayHopSealer`) | M3.3 | relay-hop HPKE interface (§12.2) |
| `quip-net/src/nat.rs` (`build_chain_recursive`) | M3.6 | multi-hop chain builder |
| `quip-net/src/nat.rs` (`NatTraversal::poll`) | M3.3 | four-phase session ladder |
| `quip-net/src/nat.rs` (`on_relay_response`) | M3.3 | request_id + target correlation |
| `quip-net/src/nat.rs` (`generate_request_id`) | M3.3 | 16-byte request-id derivation |
| `quip-net/src/nat.rs` (`AddressState::port_preservation`) | M3.3 | replaces hardcoded `true` |
| `quip-net/src/nat.rs` (`AddressState::observe_at`) | M3.6 | timestamped observation, churn history |
| `quip-net/src/nat.rs` (`current_reannounce_percent`) | M3.6 | churn-adaptive §12.1 percent |
| `quip-net/src/nat.rs` (`RelayAnnounceWindow`) | M3.6 | per-peer §19.4 window |
| `quip-net/src/nat_driver.rs:148` | M3b.2 | send on the one connection passed in |
| `quip-net/src/nat_driver.rs` (`NatApplication`) | M3.4 | probe + relay-discovery handlers |
| `quip-net/src/nat_driver.rs` (`dispatch_event`) | M3.4 | event routing |
| `quip-net/src/establishment.rs:1` | M3.5 | §16 connection flow |
| `quip-net/src/bft_driver.rs:1` | M4b.1–M4b.3 | BFT round core, view change, checkpointing |
| `quip-net/src/bft_driver.rs` (`RingMembership`) | M4b.1 | canonical-order membership, quorum, primary rotation |
| `quip-net/src/bft_driver.rs` (`BftHandler`) | M4b.1, M4b.3 | apply hook + state hooks |
| `quip-net/src/bft_driver.rs` (`BftDriver::start_view_change`) | M4b.2 | view-change initiation |
| `quip-net/src/bft_driver.rs` (`BftDriver::on_new_view`) | M4b.2 | new-view acceptance and adoption |
| `quip-net/src/bft_driver.rs` (`BftDriver::start_checkpoint`) | M4b.3 | checkpoint emission |
| `quip-net/src/bft_driver.rs` (`BftDriver::on_state_transfer`) | M4b.3 | state transfer request/response |
| `quip-net/src/bft_driver.rs` (`verify_checkpoint_ring_sig`) | M4b.3 | S8 interpretation of the ring signature |
| `quip-net/src/lib.rs` (establishment re-export) | M3.5 | module wiring |
| `quip-net/src/transport.rs:3` | M5 | status header |
| `quip-net/src/transport.rs` (M5.2–M5.4 test groups) | M5 | handshake/capability, T0/T1/T3, Key Claim |
| `quip-net/src/transport.rs` (M6.1 section) | M6.1 | §16 integration tests |
| `quip-net/src/transport.rs` (M7 section) | M7 | rate limiting |
| `quip-net/src/conn.rs:6` | M5 | driver owns the QUIC connection |
| `quip-net/src/conn.rs:66` | M5 | driver consults `flow_state` |
| `quip-net/src/handshake.rs:562` | M8 | negotiated-set re-encode hot path |
| `quip-net/src/cluster.rs:108` | M2b.1 | `ClusterInfo` after signature verification |
| `quip-net/src/bft.rs` (module docs) | M4b | opaque `new_view` contents verified by the driver |
| `quip-net/src/bao_cache.rs:1` | M7 | cached bao chunk trees (§8.2, App. A.4) |
| `quip-net/src/range.rs:374` | M7 | `extract_proof_cached` |
| `quip-net/src/range.rs:447` | M7 | `serve_range` — quarantine policy (§8.2, §19.3) |
| `quip-net/src/range.rs:677` | M7 | cached-path and quarantine tests |
| `quip-net/src/range.rs:324` | M8 | `extract_proof` — uncached proof builder |
| `quip-net/src/backoff.rs:1` | M7 | per-key exponential backoff (§19.4) |
| `quip-net/src/sync_stream.rs:1` | M7 | T1 SYNC state machine (§11) |
| `quip-net/src/dht.rs` (WitnessLoad) | M7 | witness ring participation cap (§19.4) |
| `quip-net/src/range.rs` (`split_range`) | M7 | client-side range splitting (§19.4) |
| `quip-net/src/range.rs` (`RangeResponder`) | M7 | responder with cap + quarantine |
| `quip-net/src/test_support.rs:1` | — | test-only `FakeSigner`; not milestone-owned |

The code subdivides the NAT work as `M3a` / `M3b.1` / `M3b.2` / `M3b.3`, and
the BFT work as `M4a` / `M4b`. The M3 section above numbers the later work
`M3.3` (relay emission), `M3.4` (driver handlers), `M3.5` (connection flow),
and `M3.6` (residuals); these tags appear in commits but not (yet) in the
source. `M3a` = `M3.1`; `M3b.1`–`M3b.2` = `M3.2`. The `M3b.3` tag is retired
— its only `TODO` (`port_preservation`) landed with M3.3.

**Not yet tagged but milestone-owned:** `flow.rs` (M7), `range.rs`
(M8 — its M7 cached path is tagged above), `rate.rs` (M7), `discovery.rs`
(M2), `coral.rs` (M2), `message.rs` BFT arms (M4), `bft.rs` (M4),
`xtask/` (M6.2), `.github/workflows/ci.yml` (M6.3). Tagging on the next
touch is cheap.

---

## Suggested order

M6, M7, M8, and the spec pass have landed. M3.3–M3.5 have landed since the
last revision of this file. The remaining work, in dependency order:

1. **Update this file** (this commit).
2. **M4b.1 — BFT round core.** Preprepare / prepare / precommit / commit,
   the `BftDriver` skeleton, the `BftHandler` trait, and `RingMembership`.
   The largest remaining item; split the view-change and checkpointing
   halves out as M4b.2 and M4b.3.
3. **S1 concrete sealer.** Small and bounded. The last wire-format gap
   on the relay path; multi-hop chains now build but cannot be sealed
   without it. Can be done in parallel with M4b.
4. **M4b.2 — View change.** `bft_view_change` / `bft_new_view` handling,
   primary rotation, `prepared_messages` verification.
5. **M4b.3 — Checkpointing and state transfer.** Checkpoint collection
   to 5-of-7, `bft_state_transfer` request/response, apply-and-resume.

Do not start M4b before the tree is green. A 2,500-line consensus state
machine landing into a tree that has not exercised its own rate limiter is
how the M3b build break happened.

---

## Housekeeping

### Done
- `git init` and first push; branch `main` at
  `github.com/jjmututi/quip`.
- `LICENSE-MIT` and `LICENSE-APACHE`, matching `MIT OR Apache-2.0` in every
  manifest.
- `.gitignore` with `target/`.
- CI workflow at `.github/workflows/ci.yml`.
- Draft at repository root.
- `fix_bcp14.py` at repository root — one-shot script that normalizes
  non-keyword `<bcp14>` tags to `<strong>`. Keep or remove on the next
  draft touch.

### Outstanding
- **Decide `quip-core/quip-core.txt` and `quip-core/crate_dump.sh`.** The
  dump is a 68 KB concatenation regenerated by the script; keeping either
  in-tree means every source diff includes a stale copy.
- **README.md.** The repository root currently has no README.
- **Repo description and topics** on GitHub.
- **Tag the demo state.** `git tag v0.1.0-m6 && git push origin v0.1.0-m6`.
- **A `<link>` from each crate's `lib.rs` to this file**, so milestone tags
  are discoverable from the source.