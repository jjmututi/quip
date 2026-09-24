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
| M3 | NAT traversal: wire codecs, state machine, driver wiring | M3.1–M3.2 landed; M3.3 not started |
| M4 | BFT consensus: wire codecs (M4a), driver (M4b) | M4a landed; M4b not started |
| M5 | QUIC transport: endpoint, handshake, T0/T1/T2/T3 I/O | landed |
| M6 | Integration: §16 flow, test vectors, CI | landed |
| M7 | Hardening: rate limits, caches, quarantine, state machines | 5 of 10 landed |
| M8 | Range fetch: bao verified streaming | landed |

**Demo-critical list is complete.** The §16 flow runs end-to-end through
step 8. M3b's relay emission and M4b's consensus driver are the two known
gaps; both are post-demo.

---

## Build status

All crates compile, every test passes, clippy and rustdoc are silent under
`-D warnings`, and the `no_std` build works:

```
cargo test --workspace --all-features                    488 unit + 3 doc, exit 0
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

Baseline on `main` at commit `d7191e4`, plus the M7 bao cache:

```
quip-core      74 passed
quip-net      357 passed
quip-storage   57 passed
doc-tests       3 passed (one per crate)
             488 unit tests, 0 failed — clippy clean, rustdoc clean, no_std clean
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

## M3 — NAT traversal (§12)

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

### M3.3 — Outstanding
- **Relay emission.** `Outbound::RequestRelays` is handled but
  `Outbound::DiscoverRelays` is defined yet emitted nowhere. The state
  machine never asks for relays today, so `RelayManager` is only fed by
  `connectivity_announce`.
- **Re-announce scheduler (§12.1).** TTL 600 s, re-announce 480 s, adaptive
  50–90 %. `last_announce` exists but nothing schedules.
- **`port_preservation` inference.** Hardcoded `true` at `nat.rs:1108`;
  should be inferred from observation consistency.
- **Relay chaining beyond one hop.** `build_relay_chain` produces a single
  hop and leaves `encrypted_key` empty (see **S1**).
- **Relay rate limit and LRU eviction.** Capacity bound exists; the
  100/min rate limit and eviction under `RELAY_CAPACITY` do not.

---

## M4 — BFT consensus (§5.3.4, §5.3.4.1)

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

### M4b — Driver — not started
The consensus state machine a witness ring runs: view, sequence, prepared
certificates, stable checkpoints. Ring *formation* is M2, not here.

**Deliverables:**
- `bft_driver.rs` — `BftDriver` with `poll()` and an outbound message queue.
- `BftHandler` trait to apply operations to the DVV.
- `RingMembership` view mapping position → NodeId for primary rotation.
- Verify the contents of `bft_new_view`'s opaque
  `view_change_messages`, `prepared_messages`, and `checkpoint_messages`
  (the carry-forward from M4a).

**Message flow:** preprepare → prepare (5/7) → precommit (5/7) → commit
(5/7) → apply to DVV.

**Critical operations** MUST NOT proceed in DEGRADED mode: rotation,
revocation, witness membership, ownership transfer, and Trusted CID
registrations requiring witness validation.

**DEGRADED mode** entered at 3–4 reachable witnesses
(`DEGRADED_QUORUM` = 3). MUST log and alert if it persists > 5 minutes.

**View changes:** new primary is the next node in the ring (ordering
undefined — see **S3**). `bft_new_view` MUST contain at least
`VIEW_CHANGE_QUORUM` = 5 valid view-change messages plus full encoded
preprepare messages.

**Checkpointing:** every `CHECKPOINT_INTERVAL` = 100 rounds, collect to
5-of-7 for the same `state_digest`. Lagging witness requests
`bft_state_transfer` with its checkpoint sequence; peer responds with state
plus a `RingSignature`; lagging witness verifies and resumes.

**Size:** ~2000–2500 lines.

**Spec gaps:** S3 (ring order), S4 (`bft_state_transfer.state` contents).

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

## M7 — Hardening (§11, §19.4)

Ten items. Five landed, five outstanding.

### Landed
- **Rate limiting (§19.4).** `ConnectionDriver` enforces inbound limits per
  peer NodeId via `RateLimiter`. `Frame` and `Datagram` events are checked
  after the Key Claim exchange; over-budget events become
  `Event::Error { error: RateLimit }`. T2 (bulk) exempt. Pre-handshake
  unbounded. Per-connection scope (shared budgets across connections need
  the limiter hoisted above the driver).
- **Bao chunk-tree cache (§8.2, App. A.4).** `quip-net/src/bao_cache.rs` holds
  bao *outboards* — the parent nodes alone, about 6.25% of a resource against
  ~106% for the combined encoding — keyed by BLAKE3 digest. LRU, bounded by
  `max_entries` / `max_bytes` / `max_entry_bytes`; no TTL, because an outboard
  is immutable. `range::bao_support::extract_proof_cached` serves a proof from
  the cached tree on a hit and falls back to `extract_proof` for a tree too
  large to hold. `ExtractedProof::recomputed` is the signal §8.2 asks for when
  it says a recomputing responder SHOULD rate-limit. Proofs are byte-identical
  to the uncached path, so the client and the wire format are unchanged.
- **Flow control frames (§11).** `flow.rs` codec and state machine; already
  landed during M5.
- **Pin eviction.** `quip-storage/src/pins.rs` evicts by lowest `ref_count`
  then age.
- **Range length cap — codec half.** `FetchRange::check_length` exists.

### Outstanding
1. **Quarantine on range (§8.2, §19.3).** A quarantined CID MUST NOT be
   served via `range_response`, even when the requester knows the CID.
   `range.rs` has no check. `extract_proof_cached` is the natural home for
   it, since the CID is already a parameter.
2. **Range length cap — call site.** `check_length` is called only by its
   own unit test. The driver must reject over-cap requests with
   `E_RANGE_INVALID`, using the peer's negotiated `max_range_length`.
3. **T1 SYNC stream state machine (§11).** Not modelled: `INITIAL`,
   `SYNCING`, `RBSR_SYNCING`, `RANGE_FETCHING`, `IDLE`, `ERROR`.
4. **Connection throttling.** Witness ring load cap `MAX_CAPACITY` = 10;
   exponential backoff on repeated errors (capped 60 s).
5. **DoS bounds.** Per-connection memory bound; split range responses that
   exceed `MAX_MESSAGE_SIZE`.

### D4 (reconcile against the draft)
`T2_MAX_STREAMS = 16` in `constants.rs`; §19.4 says 256.

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

## Spec gaps

Seven points where the draft leaves a choice the implementation had to make.
Two affect the wire format.

- **S1 — `RelayHop.encrypted_key`.** Encryption scheme unnamed. Presumably
  ECDH + X25519 + AEAD. Until pinned, `build_relay_chain` is single-hop.
- **S2 — QUIC path validation.** §12.3 says connectivity checks use QUIC
  path validation but not how a driver with no `Endpoint` performs one.
- **S3 — View-change ordering.** "The next node in the ring" — next in what
  order? Presumably canonical NodeId order.
- **S4 — `bft_state_transfer.state` contents.** Field is `bytes`; the draft
  does not say what is in it.
- **S5 — Handshake framing.** Whether the §4 handshake carries the varint
  length prefix that every other reliable-stream message uses.
- **S6 — Target echo in `relay_response`.** The current implementation
  correlates out-of-band; the draft should either require the echo or
  permit out-of-band correlation.
- **S7 — `NAT_TYPE_*` numeric values.** Pinned in `nat_wire.rs`
  (`NAT_TYPE_UNKNOWN`/`OPEN`/`CONE`/`RESTRICTED`/`SYMMETRIC`); §12.1 gives
  the numbers in prose only.

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
| `quip-net/src/nat.rs:1090` | M3b.3 | `TODO`: infer `port_preservation` |
| `quip-net/src/nat_driver.rs:148` | M3b.2 | send on the one connection passed in |
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

The code subdivides the NAT work as `M3a` / `M3b.1` / `M3b.2` / `M3b.3`, and
the BFT work as `M4a` / `M4b`. The status table and the M3 section above
collapse these to `M3.1`–`M3.3` (`M3a` = `M3.1`; `M3b.1`–`M3b.2` = `M3.2`;
`M3b.3` = `M3.3`). This index cites the code's tags, since it is defined as
the reverse mapping *from* the source.

**Not yet tagged but milestone-owned:** `flow.rs` (M7), `range.rs`
(M8 — its M7 cached path is tagged above), `rate.rs` (M7), `discovery.rs`
(M2), `coral.rs` (M2), `message.rs` BFT arms (M4), `bft.rs` (M4),
`xtask/` (M6.2), `.github/workflows/ci.yml` (M6.3). Tagging on the next
touch is cheap.

---

## Suggested order

M6 landed. The remaining work:

1. **M7 items 1–2.** Quarantine on range, then the range length cap at the
   call site. Two small commits, each independently testable, each closing a
   spec reference. This is the natural stopping point before a public
   release. Both want the driver-side range responder that M3.3 and M6.1
   leave open, and neither is blocked by it: `extract_proof_cached` already
   takes the CID and `FetchRange::check_length` already takes the peer's
   negotiated maximum.
2. **Spec updates S1–S7.** Text-only. S5 and S6 affect the wire format;
   the rest are clarifications.
3. **M3.3 completion.** Relay emission, re-announce scheduler, candidate
   probing. Unlocks §16 steps 9–14 for integration coverage.
4. **M4b — BFT driver.** Largest remaining item. Landing after M7 means
   the driver joins a codebase that already enforces its rate limits and
   has a settled T1 state machine.
5. **M7 items 3–5.** T1 state machine, throttling, DoS bounds.

Do not start M4b before M7 items 1–2. A 2,500-line consensus state machine
landing into a tree that has not exercised its own rate limiter is how the
M3b build break happened.

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

### Outstanding
- **Decide `quip-core/quip-core.txt` and `quip-core/crate_dump.sh`.** The
  dump is a 68 KB concatenation regenerated by the script; keeping either
  in-tree means every source diff includes a stale copy.
- **README.md.** The repository root currently has no README.
- **Repo description and topics** on GitHub.
- **Tag the demo state.** `git tag v0.1.0-m6 && git push origin v0.1.0-m6`.
- **A `<link>` from each crate's `lib.rs` to this file**, so milestone tags
  are discoverable from the source.