# QUIP — Roadmap

Implementation milestones for the reference implementation of
[draft-mututi-quip-03](./draft-mututi-quip-03.xml).

## How to read this file

Milestones are identified as `M<n>`, with sub-milestones `M<n><letter>` and
sub-sub `M<n><letter>.<k>`. The code cites its own milestones in comments so
that a reader can find the plan from the source; this file is the index for
those citations, and the **Tag index** at the bottom is the authoritative
mapping from code location to milestone.

**Statuses are evidence-based.** A milestone is *landed* only when the code
exists, is wired into the crate root, and its tests pass under
`cargo test --workspace --all-features`. "Drafted but not verified" is not a
status this file recognises.

**This file and the tags must not drift.** If you move a milestone, update
both. The M3b build break documented below happened because a refactor landed
in two files while three dependents kept compiling against the old shape.

**Sections are ordered by execution priority, not by number.** M7 and M4b are
first now that M6 has landed; M3b's remaining work and the defect register
follow. The M4a, M5, and M8 records are kept as historical context.

---

## Status at a glance

| Milestone | Scope | Status | Evidence |
|---|---|---|---|
| M2 | Coral DHT + NAT in-memory state | landed | `nat.rs`, `dht.rs` |
| M2b.1 | Cluster info / membership state | landed | `cluster.rs` |
| M3a | NAT wire codecs (§12) | landed | `nat_wire.rs` |
| M3b.1 | NAT state machine (§12.1–§12.3) | landed | `nat.rs`, `AddressState`, `CandidateTable` |
| M3b.2 | NAT driver wiring | landed (relay emission outstanding) | `nat_driver.rs`, builds clean |
| M3b.3 | Candidate probing, relay signing | not started | 1 `TODO(M3b.3)` at `nat.rs:1108` |
| M5 | QUIC transport driver (§11, §12, §16) | landed | `transport.rs`, 16 tests over a real QUIC handshake pair |
| M4a | BFT wire codecs (§5.3.4) | landed | `bft.rs`, 39 tests |
| **M6.1** | **§16 full-flow integration tests** | **landed** | `transport.rs`, 5 new tests |
| **M6.2** | **Signing test vectors (§10.1)** | **landed** | `test-vectors/`, `xtask/` |
| **M6.3** | **CI** | **landed** | `.github/workflows/ci.yml`, 5 jobs |
| M4b | BFT driver (§5.3.4) | not started | no `bft_driver.rs` |
| M7 | Hardening (§11, §19.4) | partially landed early | see M7 |
| M8 | Range fetch / bao verified streaming | landed | `range.rs` |

**Demo-critical list is complete.** M6.1, M6.2, M6.3, and the parts of M3b
touching §16 steps 9–14 are the last remaining items before the reference
implementation is demo-ready. M3b's relay emission is the one gap in that set.

---

## Build status

**Green.** All three crates compile, every test passes, clippy and rustdoc are
silent under `-D warnings`, and the `no_std` build works:

```
cargo check --workspace --all-features                   clean, no warnings
cargo test --workspace --all-features                    458 unit + 3 doc, exit 0
cargo clippy --workspace --all-features --all-targets    clean, -D warnings
cargo doc --workspace --all-features --no-deps           clean
RUSTDOCFLAGS="-D warnings" cargo doc ...                 clean
cargo build -p quip-core -p quip-storage -p quip-net \
    --no-default-features                                clean
```

All five commands are in `.github/workflows/ci.yml` and run on every push.

### Resolved: the M3b build break

Kept as a record, because the reason it happened is the reason M6.3 landed
before M6.1.

For one revision `quip-net` did not compile on **any** feature combination —
5 errors with default features, 11 under `--all-features --all-targets`.

**Root cause.** The M3a refactor moved `RelayEntry` and the other NAT wire
types from `nat.rs` into `nat_wire.rs`, and changed two signatures in `nat.rs`:

- `RelayManager::offer(entry: RelayEntry, target: Option<NodeId>)` — was
  `offer(from: NodeId, to: NodeId)`.
- `NatTraversal::on_relay_response(response, target: NodeId, now)` — gained
  the `target` parameter.

Three dependents kept compiling against the old shapes:

1. `nat.rs`'s own `use crate::nat_wire::{..}` list — missing `RelayEntry`.
2. `nat.rs`'s test `relay_manager_finds_and_bounds` — still called the
   two-`NodeId` shape. This was masked by the unresolved type and only
   surfaced once the import was fixed.
3. `nat_driver.rs` — `poll()`'s `match` was non-exhaustive
   (`Outbound::ProbeCandidate` and `Outbound::RequestRelays` had been added
   after the driver was written), and two `on_relay_response` calls omitted
   `target`.

**Resolution, now in the tree.** `DhtResult::Relays` carries the target,
`NatTraversal::on_relay_response_unattributed` handles responses that cannot be
correlated, `NatDriver::on_peer_message` takes
`relay_target: Option<NodeId>`, and the two uncovered `Outbound` arms forward
to the application as `NatEvent::ProbeRequested` and
`NatEvent::RelayDiscoveryRequested`.

**The lesson.** A refactor in two files left three dependents stale, and
nothing in the project was capable of saying so. M6.3 landed and closed that
gap; the workflow would have failed on the commit that caused the break.

---

## Verification baseline

Run all five after any change; the first two are the gate for this file's
status claims.

```bash
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --all-features --no-deps
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps
cargo build -p quip-core -p quip-storage -p quip-net --no-default-features
```

Current baseline, verified on `main` at commit `3a52c0b`:

```
quip-core      74 passed
quip-net      327 passed
quip-storage   57 passed
doc-tests       3 passed (one per crate)
             458 unit tests, 0 failed — clippy clean, rustdoc clean, no_std clean
```

The CI workflow (`.github/workflows/ci.yml`) runs an equivalent set of five
jobs on every push, plus a `vectors` job that regenerates `test-vectors/` and
fails if the working tree changed.

---

## M3b — NAT driver (§12.1, §12.2, §12.3)

**Status: M3b.1 landed · M3b.2 landed, with relay emission outstanding · M3b.3 not started**

### Scope
Peer-facing NAT traversal: address discovery, candidate exchange, connectivity
probing, relay fallback. Does **not** include the Coral DHT client itself —
that sits behind a trait the driver calls into.

### M3b.1 — state machine — LANDED
`nat.rs` carries `AddressState` (most-consistent external address, NAT-type
inference from 3 observers), `CandidateTable` (priority class, TTL pruning,
session binding), `RelayManager` (§12.2 selection order: XOR distance, then
available capacity, then cost, then reliability), `HolePunchSession`, and the
`NatTraversal` façade with `Outbound`/`NatEvent`. Tests cover open/symmetric
inference, stale pruning, host-before-relayed ordering, and hop limits.

### M3b.2 — driver wiring — LANDED
`nat_driver.rs` defines the `DhtClient` trait, `DhtResult` (whose `Relays`
variant threads the discovery target the wire drops — see **D5**),
`NullDhtClient`, and `NatDriver<D>::poll()`. The two `Outbound` arms the
original driver predated (`ProbeCandidate`, `RequestRelays`) forward to the
application as `NatEvent`s rather than executing in the driver. What remains:

- **Emit the relay requests.** `Outbound::RequestRelays` is handled by the
  driver but `Outbound::DiscoverRelays` is *defined* yet emitted nowhere. The
  state machine never asks for relays today, so `RelayManager` is only ever
  fed by `connectivity_announce`.
- **§12.1 re-announce scheduler** (TTL 600 s, re-announce 480 s; adaptive
  50–90 %). `last_announce` exists on `NatTraversal` but nothing schedules.

### M3b.3 — not started
- `nat.rs:1108` carries the workspace's **only** `TODO`: `port_preservation`
  is hardcoded `true` and should be inferred from observation consistency.
- Relay chaining beyond one hop. `build_relay_chain` currently produces a
  single hop and leaves `encrypted_key` empty, because the encryption scheme
  is undefined (see **S1**).
- Relay rate limit (100 connections/min per NodeId) and LRU eviction under
  `RELAY_CAPACITY` (the capacity bound exists; the rate limit does not).

### Dependencies
M3a (landed), M2b.1 (landed), and the `DhtClient` trait. **The gating design
question is answered: define the trait, ship a null impl, take no concrete DHT
dependency.**

### Risks
The driver compiles and the state machine is exercised, but nothing yet
*drives* it end to end: no relay request is ever emitted and no probe is ever
answered, so `NatTraversal` stays in its initial state in a real deployment.
M3b is only *partly* demo-critical (§16 steps 9–14); the demo path itself is
complete through M6.1 without it.

---

## M4a — BFT wire codecs (§5.3.4, §5.3.4.1) — LANDED

**Status: landed and verified.** `quip-net/src/bft.rs`, 39 tests passing.

Both corrections flagged during drafting are in the code:

- **`Operation` is a real struct**, not an opaque `CborValue` newtype —
  `kind: tstr`, `subject: bytes`, `body: any`, with `to_cbor`/`from_cbor`/
  `encoded_len`.
- **The pre-prepare digest is recomputed.** `BftPreprepare::compute_digest`
  implements `SHA-256(ring_id || view || sequence ||
  QUIP-CBOR-encode(operation))` with `view`/`sequence` as 8-byte big-endian;
  `verify_digest` and `verify_full` enforce it.

Also present: all eight messages (`BftPreprepare`, `BftPrepare`,
`BftPrecommit`, `BftCommit`, `BftViewChange`, `BftNewView`, `BftCheckpoint`,
`BftStateTransfer`) with `to_bytes`/`from_bytes`/`signing_payload`, and
`verify(signer: &NodeId, ..)` taking the signer explicitly since the messages
carry no signer field. Wired into `message.rs` with `verb()`,
`required_tier()` (`Tier::Ctrl` for all eight), `required_capability()`
(the two `bft_checkpoint`-gated ones only), `to_bytes()`, and `dispatch()`.

### Carry-forward
`bft.rs`'s module docs note that `BftNewView`'s `view_change_messages`,
`prepared_messages`, and `checkpoint_messages` are opaque `[* bytes]`; the
codec preserves them verbatim and verifying their contents is M4b.

### Dependencies
None.

---

## M6 — Integration + test vectors — LANDED

**Status: M6.1, M6.2, and M6.3 all landed.**

### M6.1 — Full-flow integration tests — LANDED
Five tests in `quip-net/src/transport.rs`, one per §16 stage 4–8:

| Test | §16 stage |
|---|---|
| `bulk_full_transfer_verifies_cid` | 4 — `send_start` / `send_chunk` / `send_complete` with CID verification |
| `fetch_range_round_trip_with_proof` | 5 — `fetch_range` / `range_response` with bao proof verification |
| `governance_register_tcid_round_trips` | 6 — governance verbs on T0 |
| `bft_consensus_sequence_round_trips` | 7 — BFT preprepare/prepare/precommit/commit on T0 |
| `cross_path_validation_round_trips` | 8 — cross-path validation on T0 |

Stages 1–3 are covered by the existing transport tests
(`handshake_exchange_negotiates_capabilities`,
`key_claims_are_exchanged_and_stored`, `send_receive_on_t1`/`_t3`).

Two non-test changes were needed to make stages 4–5 testable:

- **`Endpoint` holds a `QuipNetConfig`.** `ServerConfig` and `ClientConfig`
  gained a `capabilities: Capabilities` field. Before this, the server side
  had nowhere to advertise a non-baseline capability set, so `merkle_range`
  and `governance` could not be negotiated in tests.
- **`ConnectionDriver` keeps the receive half of every outbound T2 stream
  alive.** Dropping it sent STOP_SENDING to the peer, tearing down the peer
  read side and silently dropping frames still in flight. This was the root
  cause of the bulk test seeing only `BulkStreamOpened`.

The bulk test sends its entire transfer before the server begins polling,
because BULK is a streaming protocol with no natural turn-taking; an earlier
structure that polled between client sends raced against read-task scheduling
under load.

### M6.2 — Signing test vectors (§10.1) — LANDED
Four vectors under `test-vectors/`, one per §10.1 case:

- `key_claim.json` — self-signed `KeyClaim`
- `witness_statement.json` — witness-signed `WitnessStatement`
- `individual_ring_sig.json` — 5-signer `IndividualRingSig`
- `frost_ring_sig.json` — real 5-of-7 FROST aggregate, deterministic nonces

Generated by `cargo xtask generate-vectors`. `xtask/` depends on
`frost-ed25519` as a dev-dependency only. A CI job (`vectors`) regenerates and
diffs, failing if the vectors are stale after a codec change.

The FROST case landed, closing the open question the previous revision of this
file flagged as possibly unachievable.

### M6.3 — CI — LANDED
`.github/workflows/ci.yml` runs five jobs, each independent:

| Job | Command |
|---|---|
| `test` | `cargo test --workspace --all-features --locked` |
| `clippy` | `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` |
| `doc` | `cargo doc --workspace --all-features --no-deps --locked` with `RUSTDOCFLAGS=-D warnings` |
| `no_std` | `cargo build -p quip-core -p quip-storage -p quip-net --no-default-features --locked` |
| `vectors` | `cargo xtask generate-vectors` + `git diff --exit-code test-vectors/` |

The `clippy` job uses `--all-targets` (the original M6.3 wording omitted it;
without it the test modules are not linted).

### Dependencies
M6.1 depends on M4a (landed) and M8 (landed). Full §16 coverage of steps 9–16
also needs M3b.3. M6.2 depends on M4a (landed). M6.3 is unblocked.

---

## M4b — BFT driver (§5.3.4, §5.3.4.1) — not started

**Status: not started.** No `bft_driver.rs`. The largest outstanding item.

### Scope
The consensus state machine a witness ring runs. Not ring *formation* — that
is M2b. This is the per-ring state: view, sequence, prepared certificates,
stable checkpoints.

### Message flow (§5.3.4)
1. Primary proposes (PRE-PREPARE)
2. Witnesses respond (PREPARE) — 5 of 7
3. Witnesses commit to prepare (PRECOMMIT) — 5 of 7
4. Witnesses finalize (COMMIT) — 5 of 7
5. Apply operation to DVV

### Optimistic execution
Eligible operations (~95 % of writes) apply to the DVV immediately and
witnesses verify in the background; BFT runs only on conflict. Eligibility:
does not change ring membership, no rotation/revocation, no ownership
transfer, and the peer is `KT_VERIFIED`. Pending-status peers MAY write but
MUST await BFT confirmation. An optimistically-applied conflict is resolved
deterministically by DVV merge; the ring is involved only if the conflict is
not causally resolvable.

### Critical operations
MUST NOT proceed in DEGRADED mode: key rotation, key revocation, witness
membership changes, resource ownership transfers, and Trusted CID
registrations requiring witness validation. Queue until 5-of-7 is restored.

### DEGRADED mode
Entered at 3–4 reachable witnesses (`DEGRADED_QUORUM` = 3), tolerates only
f=1. Regular operations MAY continue with degraded guarantees. MUST log and
alert if DEGRADED persists > 5 minutes.

### View changes
Triggered on primary suspicion; the new primary is the next node in the ring
(ordering undefined — see **S3**). `bft_view_change` carries quorum
certificates for prepared messages plus the latest stable checkpoint.
`bft_new_view` MUST contain at least `VIEW_CHANGE_QUORUM` = 5 valid
view-change messages plus full encoded `preprepare` messages for operations
prepared in earlier views.

### Checkpointing (§5.3.4.1)
Every `CHECKPOINT_INTERVAL` = 100 rounds a witness sends `bft_checkpoint`;
witnesses collect to 5-of-7 for the same `state_digest`; the stable
checkpoint is recorded. View-change messages include the latest stable
checkpoint to bound replay. A lagging witness requests `bft_state_transfer`
with its checkpoint sequence; a peer responds with state plus a
`RingSignature`; the lagging witness verifies and resumes.

### Deliverables
- `quip-net/src/bft_driver.rs` — `BftDriver` with `poll()` and an outbound
  message queue.
- Per-ring state, a `BftHandler` trait to apply operations to the DVV, and a
  `RingMembership` view mapping position → NodeId for primary rotation.
- Tests: full 5-of-7 commit, view change on primary failure, checkpoint
  convergence, state transfer, DEGRADED entry and exit.
- Also fulfil the M4a carry-forward: verify the contents of
  `bft_new_view`'s opaque `view_change_messages`, `prepared_messages`, and
  `checkpoint_messages`.

### Dependencies
M4a (landed). A DVV application path that M4b calls into.

### Spec gaps
**S3** (ring order), **S4** (`bft_state_transfer.state` contents), and the
M2b interface for "how does the driver learn current ring membership".

### Size
~2000–2500 lines. As many edge cases as the transport driver.

---

## M7 — Hardening (§11, §19.4) — PARTIALLY LANDED EARLY

**Status: roughly half this list was already built during M5/M8.** The
completed items are listed first so they are not redone.

### Already done
- **Flow control frames.** `flow.rs` has the codec (`BLOCK_KIND` 0x01,
  `UNBLOCK_KIND` 0x02, `WINDOW_KIND` 0x03, `FlowFrame`, `dispatch_flow`) *and*
  the state machine (`FlowStateMachine` with `local_block`, `local_unblock`,
  `local_window`, `apply_remote`, `try_reserve_send`). All re-exported from
  `lib.rs`.
- **Pin eviction.** `quip-storage/src/pins.rs` evicts by lowest `ref_count`
  then age, with the test `eviction_prefers_low_ref_count_then_age`.
- **Range length cap — codec half.** `FetchRange::check_length` exists.

### Outstanding
- **Rate limiting (§19.4, §12.2, §12.3, §13.8).** `rate.rs` is complete
  (`RateLimiter`, `BucketConfig`, `OperationKind`) but has **zero enforcement
  points** — the only reference outside `rate.rs` is the `lib.rs` re-export.
  Wire it to: T0/T1 1000 ops/min per NodeId (100 burst); pin announcements
  100/min; governance 100/min; spillover 10/min with a 5-minute blacklist on
  exceed; relay connections 100/min; range request bytes 64 MB/min per
  connection; range tree recomputation, rate-limited per NodeId.
- **T1 SYNC stream state machine (§11).** Not modelled anywhere: no
  `INITIAL` / `SYNCING` / `RBSR_SYNCING` / `RANGE_FETCHING` / `IDLE` /
  `ERROR` states.
- **bao encoding cache (§A.4).** `extract_proof` re-encodes the whole payload
  O(n) per call; §A.4 says implementations SHOULD cache the chunk tree
  alongside the blob, and calls recomputation a CPU amplification vector.
  Needs a `BaoCache` keyed by CID.
- **Quarantine enforcement on range fetching (§8.2, §19.3).** A quarantined
  CID MUST NOT be served via `range_response` even when the requester knows
  the CID; SHOULD reject with `E_QUARANTINED`. `range.rs` has no quarantine
  check at all.
- **Range length cap — call-site half.** `check_length` is called only by its
  own unit test. A request exceeding the negotiated `max_range_length` MUST be
  rejected with `E_RANGE_INVALID` at the driver.
- **Connection throttling.** Witness ring load cap `MAX_CAPACITY` = 10 rings
  is in the spec and absent from the code. Exponential backoff on repeated
  errors (capped 60 s) does not exist.
- **DoS bounds.** Per-connection memory bound; split range responses that
  would exceed `MAX_MESSAGE_SIZE`.

### Reconcile against the draft
**D4** — the T2 per-connection stream cap is `T2_MAX_STREAMS = 16` in
`constants.rs`, while §19.4 says 256. One of the two is wrong.

### Dependencies
M6 (landed) provides the integration harness that exercises these.

### Size
~1500–2000 lines spread across several modules.

---

## Defect register

### D1 — Coral cluster-level discriminants — RESOLVED
Commit `51fcc51` inverted `LOCAL_CLUSTER` and `GLOBAL_CLUSTER` in `dht.rs` to
match §13 (Local = 2, Regional = 1, Global = 0) and `ClusterLevel`. The
`assert_ne!`-only test was replaced with an `assert_eq!` test on the spec
values, plus the original distinctness check kept alongside.

### D2 — `quip-net` `no_std` build — RESOLVED
Commit `0a95fb6` added `use alloc::vec;` to `discovery.rs`. The `no_std` job
in CI now passes. Every crate's `lib.rs` advertises `no_std + alloc`, and
that contract now holds.

### D3 — Handshake framing is undefined, and works by accident
§4 says only that the handshake is "a CBOR array defined by the following
CDDL" — it never says whether the array carries the varint length prefix that
every other reliable-stream message uses.

The code sends it **raw** (`transport.rs`, no `encode_message`) and reads it
by pulling **one byte at a time** until `Handshake::from_bytes` succeeds. So
T0's first message is self-delimiting by trial parse, while every subsequent
message is length-prefixed. It works because a varint prefix byte in front of
a CBOR array normally fails to parse *as an array*, so the trial loop skips
past it.

Severity: high for interoperability. Two peers running this implementation
can never expose it. Resolve as **S5**.

### D4 — T2 stream cap disagrees with the spec
`T2_MAX_STREAMS = 16` in `quip-net/src/constants.rs`; §19.4 says 256. See M7.

### D5 — `relay_response` cannot be attributed to a target — RESOLVED IN CODE
`RelayDiscovery` carries `{requester, target, max_hops, timestamp,
signature}`; `RelayResponse` carries `{requester, relays, timestamp,
signature}` and drops the target. `target` is threaded through
`DhtResult::Relays` and `on_peer_message`, with
`on_relay_response_unattributed` as the fallback. Worth still pinning in the
draft as **S6**.

### D6 — Dead function that broke the `no_std` build — RESOLVED
Commit `0a95fb6` deleted `sync.rs`'s `error_text`, which had no callers and
discarded its own `id` parameter.

### D7 — No version control, no licence files — RESOLVED
Repository initialised; nine commits on `main`. `LICENSE-MIT` and
`LICENSE-APACHE` added, matching the `MIT OR Apache-2.0` declared in every
manifest. `.gitignore` committed with `target/`. Pushed to
`github.com/jjmututi/quip`.

The stale `quip-core/target/` and `quip-core/Cargo.lock` from the pre-workspace
era were removed before the initial import.

**Still outstanding:** decide the fate of `quip-core/quip-core.txt` and
`quip-core/crate_dump.sh` (see Housekeeping).

---

## Spec gaps

Questions the draft leaves open that the implementation currently answers by
choice, and which should be resolved in the text.

- **S1 — `RelayHop.encrypted_key`.** "Encrypted with the next hop's public
  key", but the scheme is never named. Presumably ECDH + X25519 + AEAD. Until
  it is pinned, `build_relay_chain` cannot go past one hop and leaves the
  field empty.
- **S2 — How the driver obtains QUIC path validation.** §12.3 says
  connectivity checks use QUIC path validation but not how a driver with no
  `Endpoint` performs one. In practice: open a throwaway connection per
  candidate. Say so.
- **S3 — View-change ordering.** "The new primary is the next node in the
  ring" — next in what order? Presumably canonical NodeId order.
- **S4 — `bft_state_transfer.state` contents.** The field is `bytes`; the
  draft does not say what is in it. Presumably serialised DVV plus whatever
  application state the ring tracks.
- **S5 — Handshake framing.** State explicitly whether the handshake carries
  the varint length prefix (see **D3**).
- **S6 — Target echo in `relay_response`.** Either add the target to the
  message or state that responders and requesters must correlate out-of-band
  (see **D5**).
- **S7 — `NAT_TYPE_*` numeric values.** These are now pinned in
  `nat_wire.rs` (`NAT_TYPE_UNKNOWN`/`OPEN`/`CONE`/`RESTRICTED`/`SYMMETRIC`),
  but §12.1 gives the numbers in prose only. Lift the table into one place in
  the draft.

---

## Tag index

Every milestone citation in the source, so the code and this file cannot drift
apart silently. If you add a tag, add it here.

**Note on positions.** `transport.rs` grew by ~500 lines in M6.1, so tag
positions in that file have shifted. The values below reflect the tree at
commit `3a52c0b`; re-grep if you move a tagged region.

| Location | Tag | Refers to |
|---|---|---|
| `quip-net/src/lib.rs:16` | M2, M3 | `nat` / `dht` module description |
| `quip-net/src/nat.rs:11` | M3a | legacy NAT types removed from this file |
| `quip-net/src/nat.rs:32` | M3a | NAT flavour + hole punching |
| `quip-net/src/nat.rs:1150` | M3a | test group |
| `quip-net/src/nat.rs:346` | M3b.1 | configuration |
| `quip-net/src/nat.rs:391` | M3b.1 | address discovery (§12.1) |
| `quip-net/src/nat.rs:510` | M3b.1 | candidate table (§12.3) |
| `quip-net/src/nat.rs:634` | M3b.1 | sessions + driver-facing types |
| `quip-net/src/nat.rs:1198` | M3b.1 | test group |
| `quip-net/src/nat.rs:1108` | M3b.3 | `TODO`: infer `port_preservation` |
| `quip-net/src/nat_driver.rs:153` | M3b.2 | send on the one connection passed in |
| `quip-net/src/transport.rs:3` | M5 | "M5 complete" status header |
| `quip-net/src/transport.rs:~1247` | M5.2 | handshake/capability test group |
| `quip-net/src/transport.rs:~1324` | M5.3 | T0/T1/T3 send-receive test group |
| `quip-net/src/transport.rs:~1484` | M5.4 | Key Claim test group |
| `quip-net/src/transport.rs` (M6.1 section) | M6.1 | §16 integration tests |
| `quip-net/src/conn.rs:6` | M5 | driver owns the QUIC connection |
| `quip-net/src/conn.rs:66` | M5 | driver consults `flow_state` |
| `quip-net/src/handshake.rs:562` | M8 | negotiated-set re-encode hot path |
| `quip-net/src/cluster.rs:109` | M2b.1 | `ClusterInfo` after signature verification |
| `quip-net/src/bft.rs` (module docs) | M4b | opaque `new_view` contents verified by the driver |

**M0, M1, M4, M6, and M7 are cited nowhere in the code.** Their definitions
live only in this file. Either tag them when their work lands or accept that
the numbering has holes at those positions.

**Not yet tagged but milestone-owned:** `flow.rs` (M7, landed early),
`range.rs` (M8 + M7), `rate.rs` (M7, unwired), `discovery.rs` (M2b),
`coral.rs` (M2), `message.rs` BFT arms (M4a), `bft.rs` (M4a), `xtask/` (M6.2),
`.github/workflows/ci.yml` (M6.3). Tagging these on the next touch is cheap
and makes the index complete.

---

## Suggested order

M6 is complete. The remaining work is post-demo and can be taken in any order
that suits; the sequence below reflects dependency and risk.

1. **M7 — hardening, starting with rate limiting.** `rate.rs` is complete but
   has zero call sites. Wiring it is the highest-value single item on the
   remaining list: it closes a §19.4 gap, exercises a module that no test
   currently reaches in anger, and each enforcement point is independently
   verifiable. The bao cache, quarantine on range, and the T1 stream state
   machine follow.

2. **Spec updates S1–S7.** Cheap, text-only, and closes the gap between the
   draft and the code. S5 (handshake framing) and S6 (`relay_response` target)
   are the ones that affect the wire format; the rest are clarifications.

3. **M3b.2 completion.** Emit `Outbound::DiscoverRelays` from the state
   machine, add the §12.1 re-announce scheduler, and finish M3b.3's candidate
   probing. This unlocks §16 steps 9–14 for integration coverage.

4. **M4b — BFT driver.** Largest remaining item at ~2000–2500 lines. Landing
   it after M7 means the driver is added to a codebase that already enforces
   its rate limits and has a settled T1 state machine.

Do not start M4b before M7. A 2,500-line consensus state machine landing into
a tree that has not exercised its own rate limiter is how the M3b break
happened.

---

## Housekeeping

### Done
- **`git init` and first push.** Nine commits on `main` at
  `github.com/jjmututi/quip`. See D7.
- **`LICENSE-MIT` + `LICENSE-APACHE`**, matching the `MIT OR Apache-2.0`
  declared in all three manifests.
- **`.gitignore`** with `target/`.
- **`quip-core/target/` and `quip-core/Cargo.lock`** deleted before the
  initial import.
- **Draft at repository root.** `draft-mututi-quip-03.xml` versioned alongside
  the code.
- **CI workflow** at `.github/workflows/ci.yml`.

### Outstanding
- **Decide the fate of `quip-core/quip-core.txt` and
  `quip-core/crate_dump.sh`.** The dump is a 68 KB concatenation of the crate
  and is regenerated by the script; keeping either in-tree means the diff of
  every source change includes a stale copy. Either commit both with a note
  that the dump is regenerated, or remove both and rely on `cargo doc` and the
  Git history.
- **Add repo description and topics** on GitHub. Suggested: description "QUIP
  reference implementation — a brokerless federation protocol over QUIC";
  topics `quic`, `p2p`, `federation`, `rust`, `ietf`, `dht`, `bft`,
  `content-addressing`.
- **Tag the M6.1 state.** `git tag v0.1.0-m6 && git push origin v0.1.0-m6`
  marks the commit where the demo-critical list closed. Any future regression
  can be diagnosed against it.
- **A `<link>` from each crate's `lib.rs` to this file** would make the
  milestone tags discoverable from the source rather than only the reverse.