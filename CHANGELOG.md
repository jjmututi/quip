# QUIP — Changelog

A running record of every landed milestone in the QUIP reference
implementation of [draft-mututi-quip-03](./draft-mututi-quip-03.xml),
plus the current state of the workspace and the known gaps.

**Statuses are evidence-based.** A milestone is *landed* only when the
code exists, is wired into the crate root, and its tests pass under
`cargo test --workspace --all-features`. "Drafted but not verified" is
not a status this file recognises.

---

## Current state

Every protocol-level milestone (M1–M8) is landed. The application
layer (M9.x) is in progress: M9.1 through M9.5a are landed, M9.5b is
not started. The interface layer (M10.x) has begun: M10.1 through
M10.3 are landed. §16 runs end-to-end through step 8 across the
protocol crates; the `Node` type composes them into a runnable peer;
a Dart client can bind a node, subscribe to its event stream, and
make explicit trust decisions about its peers.

The protocol skeleton is complete. What remains is concentrated in
two places: making the boundaries rigorous (BFT execution semantics,
view-change certificates, identity types, membership) and making the
distributed parts withstand hostile conditions (adversarial
simulation, bounded queues, adversarial routing models).

### Build status

All crates compile, every test passes, clippy and rustdoc are silent
under `-D warnings`, and the `no_std` build works:

```
cargo test --workspace --all-features                    626 unit + 4 doc, exit 0
cargo clippy --workspace --all-targets --all-features    clean, -D warnings
cargo doc --workspace --all-features --no-deps           clean
RUSTDOCFLAGS="-D warnings" cargo doc ...                 clean
cargo build -p quip-core -p quip-storage -p quip-net \
    --no-default-features                                clean
```

All five commands run in `.github/workflows/ci.yml` on every push,
plus a `vectors` job that regenerates `test-vectors/` and fails if the
working tree changed.

`quip-node` is not part of the `no_std` build: it depends on `tokio`,
`std`, and the `quic` feature of `quip-net`.

### Toolchain

The workspace pins Rust to 1.99.0 via `rust-toolchain.toml`, and every
CI job passes `toolchain: "1.99.0"` to `actions-rust-lang/setup-rust-toolchain`.
The pin exists because `setup-rust-toolchain` resolves `stable` at run
time, so CI drifts ahead of the local toolchain whenever a new stable
ships. This last happened between 1.95.0 (local) and 1.99.0 (CI), when
rustdoc widened `redundant_explicit_links` and flagged ~30 intra-doc
links that the older toolchain silently accepted. Pinning defers the
next drift to a deliberate bump.

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
quip-net      471 passed
quip-storage   57 passed
quip-node      37 passed
quip-node-ffi   0 passed
doc-tests       4 passed (one per crate)
             ~626 unit tests, 0 failed — clippy clean, rustdoc clean, no_std clean
```

### Status at a glance

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
| M9.1 | `quip-node`: endpoint bind, accept loop, peer tasks, event stream | landed |
| M9.2 | `quip-node`: `QuipStore` integration, pin auto-serve, clock injection | landed |
| M9.3 | `quip-node`: `ConnectionFlow` integration | folded into M9.4b |
| M9.4a | `quip-node`: live `DhtClient` over the node's peer connections | landed |
| M9.4b | `quip-node`: `ConnectionFlow` integration | landed |
| M9.5a | `quip-node`: shared Coral discovery wired into the flow | landed |
| M9.5b | `quip-node`: real `NatDriver` + cluster merge/split | not started |
| M9.5b-c | `quip-node`: M9.5b shared contracts (frozen) | landed |
| M9.6 | `quip-node`: witness accumulation and trust bootstrap | not started |
| M10.1 | `quip-node-ffi`: bind and query a node from Dart | landed |
| M10.2 | `quip-node-ffi`: event stream across the FFI boundary | landed |
| M10.3 | `quip-node-ffi`: explicit trust policy and peer trust events | landed |
| M10.4 | `quip-node-ffi`: platform signer shim | not started |
| M10.5 | `quip-node-ffi`: end-to-end verification on Android | not started |
| M11 | Browser substrate: local gateway, content layer, trust anchors | not started |
| BFT-A | BFT correctness: `apply()` contract, prepared/checkpoint carry-forward | not started |
| BFT-V | BFT validation: adversarial network simulator, property tests | not started |
| N-Hard | Network hardening: bounded queues, peer generation, adversarial routing | not started |
| Spec | Membership boundaries and pin authorization model | not started |

---

## Landed milestones

### M1 — Foundation — LANDED

The dispatcher, codec closure, frame format, error codes, and shared
constants every other module builds on.

`quip-core`: `address`, `cbor`, `cid`, `constants`, `dvv`, `error`,
`messages`, `time`. `quip-net`: `codec`, `frame`, `error`,
`constants`, `dispatch`.

Tests: the full `quip-core` suite (74 tests) and the `frame`/`codec`
test groups.

### M2 — Coral DHT state — LANDED

Cluster self-organisation, XOR-distance routing, witness discovery,
and the in-memory state a driver consults.

- `cluster.rs` — `ClusterLevel`, `ClusterInfo`, acceptance (§13.2),
  merge (§13.4), split (§13.5), size estimation (§13.6).
- `dht.rs` — `RttClass`, `LookupProgress`, `LookupState`,
  `WitnessRingCache`, cluster-level discriminants.
- `coral.rs` — wire codecs for `coral_lookup`, `lookup_response`,
  `spillover`, `cross_path_validation`, `cross_path_result`;
  XOR-distance selection and cross-path consensus.
- `discovery.rs` — `WitnessDiscovery` state machine driving §5.3.2.

Tests: `cluster::tests`, `dht::tests`, `coral::tests`,
`discovery::tests`.

### M3 — NAT traversal (§12) — LANDED

- **Wire codecs (`M3.1`).** `nat_wire.rs` defines `Address`,
  `Candidate`, `RelayEntry`, and the four top-level messages:
  `connectivity_announce`, `candidate_announce`, `relay_discovery`,
  `relay_response`. Signing follows §10.1.
- **State machine + driver (`M3.2`).** `nat.rs` holds `AddressState`
  (most-consistent external address, NAT-type inference from 3
  observers), `CandidateTable`, `RelayManager` (§12.2 selection
  order), `HolePunchSession`, and the `NatTraversal` façade.
  `nat_driver.rs` holds the `DhtClient` trait, `DhtResult`,
  `NullDhtClient`, and `NatDriver::poll()`.
- **Relay emission (`M3.3`).** `NatTraversal::poll` runs a four-phase
  per-session ladder. `on_relay_response` correlates by both
  `request_id` and `target`. `AddressState::port_preservation`
  replaces a hardcoded `true`.
- **Driver-side handlers (`M3.4`).** `NatApplication` trait;
  `NatDriver::build_relay_discovery`; `NatDriver::dispatch_event`;
  `poll_and_dispatch` convenience.
- **Connection-establishment orchestration (`M3.5`).**
  `establishment.rs` (distinct from `flow.rs`, which owns per-stream
  flow-control frames). `ConnectionFlow` sequences §16 phases:
  `AwaitHandshake → AwaitKeyClaim → NatTraversal → WitnessDiscovery
  → Ready(KtStatus)`, with `Failed(FlowFailure)` reachable via
  timeout. `resume_from_key_claim` (added in the M9 series) starts
  the flow at `NatTraversal` for callers whose transport performs the
  §4/§16 exchanges inline.
- **Residuals (`M3.6`).** Adaptive re-announce (§12.1) via
  `AddressState::observe_at` + `NatTraversal::current_reannounce_percent`.
  Multi-hop relay chains via `RelayManager::best_chain` and
  `build_chain_recursive`.
- **Concrete sealer.** `relay_hpke.rs` implements `RelayHopSealer`:
  HPKE `mode_base`, `DHKEM(X25519, HKDF-SHA256)` / `HKDF-SHA256` /
  `ChaCha20Poly1305`, `info = "QUIP-relay-hop-v1"`, empty `aad`.

Tests: `nat::tests`, `nat_wire::tests`, `nat_driver::tests`,
`establishment::tests`, `relay_hpke::tests`.

### M4 — BFT consensus (§5.3.4, §5.3.4.1) — LANDED

- **Wire codecs (`M4a`).** `bft.rs` defines all eight messages with
  `to_bytes` / `from_bytes` / `signing_payload` / `verify`. `Operation`
  is a real struct. `BftPreprepare::compute_digest` recomputes
  `SHA-256(ring_id || view || sequence || QUIP-CBOR(operation))` with
  8-byte big-endian view and sequence.
- **Round core (`M4b.1`).** `bft_driver.rs` runs the four-phase
  protocol in a single view. `RingMembership` holds members in
  canonical NodeId order (S3); `primary_for(v)` is
  `members[v mod |R|]`; `quorum()` is `n - f`. `BftHandler` is the
  application-side apply hook.
- **View change (`M4b.2`).** `start_view_change` broadcasts a
  `bft_view_change` for `view + 1`. `on_new_view` verifies the sender
  is the primary for the target view, verifies the primary signature,
  decodes each enclosed view-change message, resolves each signer by
  trial verification against the ring.
- **Checkpointing and state transfer (`M4b.3`).** `BftHandler` gains
  `state_digest()`, `state_bytes()`, `apply_state()`. `on_checkpoint`
  collects witness signatures over `(sequence, state_digest)` and
  promotes to stable at quorum. `request_state_transfer` emits a
  `bft_state_transfer`; `on_state_transfer` dispatches on whether the
  ring signature is empty and installs a verified response.

Tests: `bft::tests`, `bft_driver::tests`.

**Known incomplete**: the `apply()` contract permits post-commit
failure; prepared and checkpoint carry-forward are absent. See BFT-A.

### M5 — QUIC transport (§11, §12, §16) — LANDED

`transport.rs` binds QUIP to QUIC via `quinn`.

- `Endpoint` for server and client, ALPN `"quip"`, no-op TLS
  verifier (identity comes from the Key Claim exchange).
- `ConnectionDriver` lifecycle: `Connecting → KeyClaimExchanging →
  Established → Closed`. T0 handshake and §16 Key Claim exchange run
  inline before the read tasks spawn.
- Per-tier send halves (T0/T1), per-resource T2 streams held for the
  connection's lifetime; read halves moved into tasks feeding a
  shared `mpsc::Sender<Event>`.
- Four read loops: T0, T1, T2-accept, T3-datagram.

Tests: 16 tests in `transport::tests` over a real QUIC handshake pair.

### M6 — Integration + vectors + CI — LANDED

- **§16 integration (`M6.1`).** Five tests, one per stage 4–8.
- **Signing vectors (`M6.2`).** `test-vectors/` holds
  `key_claim.json`, `witness_statement.json`,
  `individual_ring_sig.json`, `frost_ring_sig.json`. Generated by
  `cargo xtask generate-vectors`.
- **CI (`M6.3`).** `.github/workflows/ci.yml` runs five independent
  jobs: `test`, `clippy`, `doc`, `no_std`, `vectors`.

### M7 — Hardening (§11, §19.4) — LANDED

- **Rate limiting.** `ConnectionDriver` enforces inbound limits per
  peer NodeId via `RateLimiter`. T2 (bulk) exempt.
- **Bao chunk-tree cache.** `bao_cache.rs` holds bao outboards keyed
  by BLAKE3 digest. LRU, bounded.
- **Quarantine on range.** `QuarantineCheck` implemented for
  `QuarantineStore`; `NoQuarantine` for deployments without the
  primitive.
- **Range length cap.** `RangeResponder::serve` binds cache,
  quarantine policy, and negotiated `max_range_length`.
- **T1 SYNC state machine.** `sync_stream.rs` models six states.
- **Connection throttling.** `backoff::BackoffTracker<K>`;
  `dht::WitnessLoad` caps concurrent ring participation at 10.
- **DoS bounds.** `split_range` plans multi-request fetches;
  concurrent inbound T2 streams capped at `T2_MAX_STREAMS`.
- **Flow control.** `flow.rs` codec and state machine (§11).
- **Pin eviction.** `quip-storage/src/pins.rs` evicts by lowest
  `ref_count` then age.

**Known incomplete**: `T2_MAX_STREAMS` in the draft was 256;
`constants.rs` had 16 (D4, aligned). The DHT handle uses unbounded
channels; bounding and coalescing is N-Hard.

### M8 — Range fetch — LANDED

`range.rs` defines `fetch_range` and `range_response`;
`bao_support::extract_proof` and `verify_response` are behind the
`crypto` feature.

- BLAKE3 only. `is_blake3` checks the CID; SHA-256 CIDs rejected.
- `MAX_RANGE_IN_SINGLE_RESPONSE` caps a response at
  `(MAX_MESSAGE_SIZE - 1024) / 2`.
- Range bounds checked before encoding.

Tests: `range::tests` (30 tests: 6 codec, 3 quarantine-policy, 21 in
`bao_tests`, 9 of which exercise the M7 cached path).

### M9.1 — `quip-node` transport integration — LANDED

- `NodeConfig::new` derives a signed `KeyClaim` from a `Signer`.
- `Node::bind` spawns an accept loop; each accepted
  `ConnectionDriver` is driven through the §4/§16 handshake and
  handed to a peer task.
- `Node::connect` dials, drives the handshake inline, and returns
  the peer's `NodeId`.
- `Node::poll` drains the event channel with a short timeout.
- `Node::send_to` routes a `Message` to a peer's outbound queue.
- `Node::shutdown` closes the endpoint; `Drop` aborts the accept task
  and every peer task.

Tests: `two_nodes_connect`, `two_nodes_exchange_messages`,
`send_to_unknown_peer_errors`, `local_addr_is_bound`,
`peers_snapshot_grows_after_connect`, `drop_releases_peer_tasks`.

### M9.2 — `quip-node` store integration — LANDED

- `Node<B>` owns an `Arc<Mutex<QuipStore<B>>>` shared across peer
  tasks.
- Direct store helpers: `put_content`, `get_content`, `pin`,
  `unpin`, `query_pins`, `store()`.
- With `auto_serve_pins` on (default), inbound `pin`, `unpin`, and
  `query_pins` are applied to the store inside the peer task and do
  not surface as `NodeEvent::Message`.
- `register_tcid`, `delegation`, and `derivative_link` are
  deliberately not auto-served.
- **Clock injection.** `NodeConfig::clock` is a `SharedClock`
  defaulting to `SystemClock`; tests inject a `ManualClock`.

Tests: `put_and_get_content_round_trip`,
`peer_query_pins_is_auto_served`, `peer_pin_is_applied_to_store`, and
the doctest.

**Known incomplete**: pin authorization model. Whether §14 means "any
connected peer may persist" or "the resource owner may" is not
settled. See Spec.

### M9.3 — `quip-node` ConnectionFlow integration — FOLDED INTO M9.4b

Deferred. Running the §16 `ConnectionFlow` at the node layer without
a real `NatDriver` and `DhtClient` can only drive the NAT phase to a
hardcoded success and the witness-discovery phase to a hardcoded
failure, yielding `Ready(Pending)` for every connection regardless of
what is actually true. The `ConnectionFlow::resume_from_key_claim`
constructor was added to `quip-net` in preparation; the node consumes
it in M9.4b.

### M9.4a — `quip-node` live DhtClient — LANDED

`quip-node/src/dht.rs` adds a live `DhtClient` on top of the node's
existing T0 connections.

- `LiveDht` implements `quip_net::nat_driver::DhtClient`. The three
  publish verbs broadcast to every connected peer. The two lookup
  verbs are documented no-ops.
- A `DhtHandle` bundles the shared `LiveDht` with a clone of the
  inbound channel.
- A router task drains the DHT's outbound queue and forwards each
  message to every connected peer.
- §12 NAT verbs on T0 are intercepted in the peer steady loop before
  the pin auto-serve path: `dht_result_from` verifies the signature
  and the claimed NodeId, and only on success is the result enqueued.
- `NodeConfig::new` now advertises `NAT_TRAVERSAL` and
  `DHT_DISCOVERY` so §12 verbs pass the transport's capability gate.

Tests: `dht_publish_connectivity_reaches_peer`,
`dht_routing_table_lists_peers`, `dht_publish_with_no_peers_is_a_noop`,
`dht_forged_connectivity_is_dropped`.

**Known incomplete**: broadcast is used where XOR-distance routing
would be correct; the routing table holds direct peers only; lookups
are no-ops. See M9.5b.

### M9.4b — `quip-node` ConnectionFlow integration — LANDED

Each peer task now runs a `ConnectionFlow` between the inline §4/§16
handshake and the steady-state loop.

- `run_establishment` resumes the flow at `NatTraversal` via
  `ConnectionFlow::resume_from_key_claim`, using a session identifier
  derived symmetrically from the two NodeIds (`local[0..16] XOR
  remote[0..16]`).
- The NAT phase concludes from the live transport: the handshake
  proves direct connectivity. M9.5b replaces this with a real
  `NatDriver` waiting on `NatEvent::DirectPathEstablished`.
- The witness phase concludes as "not attempted". The flow translates
  that into `Ready(Pending)` per §16 step 18.
- `NodeEvent::Ready { peer, kt_status }` fires on success;
  `NodeEvent::EstablishmentFailed { peer, failure }` fires on failure
  and is followed by `NodeEvent::Disconnected`.
- `DhtHandle` is refactored to `Clone` and to implement `DhtClient`
  directly, with a `std::sync::Mutex` for its shared state.
- `Node::dht()` returns a `DhtHandle` clone rather than holding a
  lock.

Tests: `ready_fires_after_connect`,
`dht_handle_clone_shares_routing_table`, and the existing connection
tests (all now traverse the flow).

**Known incomplete**: NAT phase is a placeholder; witness phase is a
placeholder; both defer to M9.5b/M9.6.

### M9.5a — `quip-node` shared Coral discovery — LANDED

`quip-node/src/discovery.rs` adds a `DiscoveryHandle` that wraps
`WitnessDiscovery<Ed25519Signer>` behind an `Arc<Mutex<…>>`.

- The flow's witness phase runs the real state machine. Each peer
  task starts a discovery for its remote, sends a signed
  `coral_lookup`, ingests the response, and either completes with
  `Ready(Verified)` (4+ witnesses) or falls back to
  `Ready(Pending)`.
- The node is both a Coral client and a Coral server. Inbound
  `coral_lookup` / `spillover` requests are answered with signed
  responses. M9.5a's responder answers with no witnesses and no
  consensus, which is honest — the node holds no
  `WitnessStatement`s yet.
- `NodeConfig` gains a `signer: SharedSigner` field
  (`Arc<Ed25519Signer>`, not `Arc<dyn Signer>`).
- `Node::discovery()` returns a `DiscoveryHandle` clone.

**Scope note.** In a two-node network neither side holds witnesses,
so both peers reach `Ready(Pending)`. The machinery is real; a larger
network with actual witness statements reaches `Ready(Verified)`.

**Known limitation.** The establishment-time discovery wait uses a
wall-clock deadline (5 s), not the injected `Clock`. A frozen
`ManualClock` would otherwise hang the phase forever.

Tests: `ready_via_shared_discovery_on_both_sides`,
`discovery_local_node_id_matches_node`,
`discovery_clones_share_state`, plus the unit tests in
`quip-node::discovery`.

**Known incomplete**: witness accumulation. See M9.6.

### M9.5b-c — shared contracts — LANDED

The shared contracts for M9.5b's NAT and cluster integration tracks
are frozen. The NAT and cluster tracks run in parallel against these
contracts. Two gates were closed before freezing: §13.2's acceptance
rule and `ConnectionFlow`'s failure semantics.

**Peer identity and generation.** `NodeId` identifies a logical node;
`PeerSlot` identifies its active connection generation. Events are
generation-scoped: an event from an obsolete `PeerSlot` must not
mutate current routing or cluster state. `quinn::Connection::stable_id()`
is the candidate for the generation identifier, subject to
verification against the pinned Quinn version; an explicit per-peer
counter is the fallback.

**Lifecycle transitions.**

```
Connecting  → Established
Established → NatDirect | NatRelayed | Failed
NatDirect  ↔ NatRelayed
NatDirect | NatRelayed → Failed
Any nonterminal state  → Closing
Failed, Closing → terminal for this PeerSlot
```

Recovery after `Failed` or `Closing` creates a new `PeerSlot`.
Discovery failure does not transition the lifecycle:
`on_discovery_failed()` yields `Ready(Pending)`, which the node
treats as successful establishment. Witness status (`Pending` /
`Verified`) and application trust (`Unknown` / `Trusted` /
`Untrusted` / `Revoked`) are independent dimensions, not lifecycle
states.

**Routing-table record.** Keyed by logical `NodeId`, each active
record associated with its current `PeerSlot`. Physical connection
existence and routing eligibility are distinct. The NAT track sets
eligibility when a peer reaches an eligible direct or relayed state;
the lifecycle and cleanup path clears it on failure, closure, or
replacement.

**Cluster-membership eligibility.** Membership is a subset of
routing-table peers. §13.2 requires the cluster-joining decision to
pass a 90th-percentile RTT test using a minimum 20-sample procedure;
the sample requirement binds the acceptance decision, not individual
members. `ClusterState::is_acceptable` enforces
`ACCEPTANCE_MIN_SAMPLES`. A peer with missing RTT data does not count
toward the sample minimum and does not independently satisfy the
acceptance test.

**RTT observations.** `ConnectionDriver::rtt() -> Option<Duration>`
in `quip-net`, reading the Quinn RTT statistic. `Option` because the
statistic may not be populated before the first sample.

**NAT session coordination.** Reuse the deterministic
`derive_session_id(local, remote)` in `quip-node`. Both endpoints
derive the same session identifier from the same logical peer
identities, independent of endpoint ordering and independent of
connection generation.

**Verification record.** Two gates were closed before freezing:

- §13.2 (draft): requires 90th-percentile RTT at or below the
  cluster threshold, with a recommended minimum of 20 samples. The
  sample requirement binds the acceptance decision, not per-member
  history.
- `ConnectionFlow` (quip-net/src/establishment.rs): discovery
  failure yields `Ready(Pending)`, not `Failed`. Confirmed by
  reading `on_discovery_failed()` and the node's
  `run_discovery_phase`.

**Still open** (gates 3–7 from the design): `PeerSlot` ownership and
generation identity, lifecycle transitions as code, routing-table
record semantics, routing-eligibility transitions, and the shared
types plus RTT accessor. These are the next commit; the NAT and
cluster tracks may proceed once they are in code.

### M10.1 — `quip-node-ffi` bind and query — LANDED

`quip-node-ffi` is a new workspace member. It exposes a `NodeHandle`
to Dart through `flutter_rust_bridge` 2.13.0. The FFI boundary is
proven end to end: a Dart CLI loads the Rust `cdylib`, binds a node
via a static async method, reads its bound address and NodeId, and
shuts down cleanly.

- `NodeHandle::bind(bindAddr, seed) -> Future<NodeHandle>` — binds
  a QUIC endpoint; `seed` is a 32-byte Ed25519 seed.
- `NodeHandle::localAddr() -> Future<String>` — the bound address.
- `NodeHandle::localNodeId() -> Future<Uint8List>` — 32 raw bytes.
- `NodeHandle::shutdown() -> Future<void>`.
- `FfiError` is the single error type the boundary exposes;
  underlying `quip_net::Error` and `quip_node` errors fold into a
  human-readable message.

The codegen is FRB v2 with codegen mode. Generated Dart lands in
`lib/src/rust/`, which is gitignored; the Rust shim
(`quip-node-ffi/src/frb_generated.rs`) is committed.

**Toolchain note.** The crate is pure-Dart compatible: the FRB
runtime has a `RustLib.init(externalLibrary: ExternalLibrary.open(path))`
path for CLIs that don't use the Flutter engine. The 2 GB Flutter SDK
download is not required for M10.1 or M10.2.

Tests: `bin/smoke.dart` prints a bound NodeId and exits cleanly.

### M10.2 — `quip-node-ffi` event stream — LANDED

A Dart consumer can subscribe to a node's event stream. The Rust side
drains the internal `mpsc::Receiver<NodeEvent>` into an FRB
`StreamSink<NodeEventFfi>`; the Dart side receives a `Stream` of
freezed-sealed classes it can pattern-match on.

- `quip-node` gains `Node::take_events()` so the FFI layer can own
  the receiver rather than competing with `Node::poll`. `poll` now
  returns an error if called after `take_events`.
- `NodeEventFfi` variants: `Connected`, `Ready`,
  `EstablishmentFailed`, `Disconnected`, `Message`, `Datagram`,
  `Error`. The first four carry typed fields; `Message` and
  `Datagram` carry `verb: String` + `raw: Vec<u8>`; a typed decoder
  lands in a later milestone.
- `KtStatusFfi` and `FlowFailureFfi` mirror the `quip-net` enums.
- `NodeHandle::subscribe_events(sink: StreamSink<NodeEventFfi>)`
  spawns a drain task on FRB's runtime. Runtime handling: `bind`
  captures `Handle::current()` while inside FRB's runtime;
  `subscribe_events` uses the captured handle, since `tokio::spawn`
  from a Dart-called sync method panics with "no reactor running".
- The pubspec adds `freezed`, `freezed_annotation`, and
  `build_runner`. `build_runner` is pinned below 2.15.2 to keep the
  analyzer version compatible with `freezed` 3.x.

**Known limitation.** The FRB-generated `frb_generated.web.dart`
uses an `inline-class` language feature that the current Dart
analyzer refuses to parse. The `.io.dart` backend is unaffected;
Linux and Android builds are clean. Web target support would need an
analysis_options change.

Tests: `bin/smoke_events.dart` shows both nodes reaching
`Ready(Pending)` through the FFI event stream, with peer IDs
matching across both nodes' events.

### M10.3 — `quip-node-ffi` explicit trust policy — LANDED

A first-seen peer is `Unknown` and stays there until the application
calls `Node::trust_peer(peer, Trusted)`. Nothing auto-escalates. This
is the SSH `StrictHostKeyChecking=ask` model: the node records the
claim on contact, and the trust decision belongs to the application
(or the user behind it).

Two independent axes:

- **Policy**: `Unknown` / `Trusted` / `Untrusted` / `Revoked`,
  decided by the local store and explicit calls.
- **Flow**: `Pending` / `Verified`, decided by the §16
  witness-discovery phase from 4+ independent witnesses.

`Verified` is never set by the application; only the flow promotes
a `Trusted` peer to `Verified`. `Revoked` is terminal — a subsequent
`trust_peer(Trusted)` returns `true` (the call is processed) but the
policy short-circuits to `Revoked` on any query.

Peer-related events carry the current trust level. A
`PeerTrustChanged` event fires only when the level actually changes,
and carries the resulting state rather than the requested decision
— so a re-trust attempt on a tombstoned peer emits nothing rather
than emitting a misleading `Trusted`.

- `quip-node/src/trust.rs` (new): `PeerTrust`, `StoredClaim`,
  `TrustPolicy`.
- `quip-node/src/lib.rs`: `pub mod trust;`, trust handle on `Node`,
  claim observation at the two `Connected` emission sites,
  promotion at `Ready(Verified)`, `Node::trust_peer` /
  `Node::peer_trust` / `Node::trust_snapshot`.
- `quip-node-ffi/src/api.rs`: `PeerTrustFfi`, `trust` field on peer
  events, `PeerTrustChanged`, `trust_peer` / `peer_trust`.
- `quip-node-ffi/bin/smoke_trust.dart` (new): acceptance test
  covering first-contact `Unknown`, explicit escalation, the
  `Verified`-is-not-settable rule, and revocation terminality.

**Known incomplete**: the identity boundary is still collapsed. The
transport produces a claimed `NodeId`, and `Node::connect` exposes
it as a plain `NodeId`; `AuthenticatedPeer` / `TrustedPeer` are not
distinct types. See Spec.

Tests: `peer_stays_unknown_until_decided`, `trust_change_emits_event`,
`revocation_is_terminal`, plus the unit tests in `quip-node::trust`.

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
  state to be opaque, digest-bound, deterministically decodable, and
  to encode the DVV, view, sequence, and post-checkpoint operations
  at minimum.
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

## Outstanding work

Organized by the axis it belongs to — correctness, network
completion, validation, protocol design, or release discipline —
rather than by milestone number. The status table above names the
same items under their phase labels (BFT-A, BFT-V, N-Hard, Spec,
M9.5b, M9.6, M10.4, M10.5, M11).

### BFT correctness (BFT-A)

1. **`apply()` contract.** `BftHandler::apply(...) -> Result<()>`
   currently permits a post-commit failure: replica A applies an
   operation successfully, replica B returns `Err`, the driver emits
   `ApplyFailed` on B and advances the sequence on both. Two honest
   replicas now disagree about state while both believe consensus
   progressed, which breaks the invariant BFT exists to provide.

   Three resolutions are defensible:

   - **(a)** Make `apply` infallible by contract. Applications must
     validate before the operation enters consensus.
   - **(b)** Validate operations deterministically before consensus,
     so `apply` cannot fail on committed operations.
   - **(c)** Make the execution result part of the consensus
     decision — commit the state transition, not the request.

   The reference implementation has not chosen. Current code does
   none of the three and documents the gap.

2. **Prepared-operation carry-forward on view change.** The new
   primary does not re-propose operations prepared in an earlier
   view; `bft_new_view.prepared_messages` is emitted empty. A proper
   view change must carry a prepared certificate so the operation
   remains eligible for commitment.

3. **Checkpoint carry-forward on view change.**
   `bft_new_view.checkpoint_messages` is emitted empty. The driver
   already retains `stable_checkpoint`, but `maybe_emit_new_view`
   does not encode it. Same shape as (2).

4. **FROST ring signature verification** in
   `verify_checkpoint_ring_sig`. Requires a group public key on the
   ring; the driver does not hold one today. The individual-
   signature path is complete.

5. **S8 spec revision.** Text-only. Decide whether §5.3.4.1
   describes the extra round trip a fresh quorum ring signature
   would require, or whether it adopts the checkpoint-signatures
   interpretation the implementation uses.

### BFT validation (BFT-V)

6. **Adversarial network simulator.** A deterministic test harness
   with delivery policies — `drop`, `duplicate`, `reorder`, `delay`,
   `partition`, `heal`, `replay`, `byzantine(sender, message)` — so
   BFT can be tested against hostile schedules rather than
   cooperative ones. The current `pump()` helper propagates until
   quiescence; real distributed-systems bugs live in the schedules
   that never reach quiescence.

7. **Property tests over safety invariants.** Once the simulator
   exists, assert invariants rather than expected traces:

   - no two honest replicas commit conflicting operations for the
     same `(ring, view, sequence)`;
   - no honest replica regresses its committed sequence;
   - committed digests agree across honest replicas;
   - old-view messages cannot corrupt new-view state;
   - invalid membership cannot produce quorum;
   - invalid signatures cannot advance state.

   This is more valuable than another hundred happy-path tests.

8. **Model checking of the BFT state machine.** The state space
   (`view`, `sequence`, `phase`, prepared/precommit/commit
   certificates, view-change votes, checkpoint) is small enough to
   model-check. Enumerate message permutations, duplication,
   omission, crashes, and Byzantine messages; assert safety and
   liveness. Multi-week effort, but it is the confidence-building
   work for the protocol's most ambitious component.

### Network hardening (N-Hard)

9. **Peer lifecycle race.** The peer registry is keyed by `NodeId`
   alone. Two connections from the same NodeId can race during
   cleanup, and the first's teardown can remove the second's live
   entry. Fix: `PeerSlot { connection_id, handle }`, with cleanup
   conditional on the connection identity. Small, self-contained,
   blocks nothing. (Frozen in M9.5b-c; implementation pending.)

10. **Bounded DHT queues.** `DhtHandle` uses unbounded channels for
    both inbound and outbound. An authenticated peer can flood the
    queue faster than the application drains it, and memory becomes
    the backpressure mechanism — not what a protocol with §19.4
    DoS bounds wants. Replace with bounded channels and an explicit
    policy: coalesce by `NodeId` for announcements (latest-wins),
    drop newest or drop oldest for other kinds, per-peer limits.
    This is a hardening issue, not a forging issue — the messages
    are already signature-verified.

11. **Adversarial DHT routing model.** A DHT is not hard because
    hash-to-bucket is hard; it's hard because an adversary controls
    which nodes you see, which answer, which are close, and which
    witnesses you select. The Coral layer needs explicit answers to
    Sybil resistance, eclipse resistance, routing-table poisoning,
    lookup termination, lookup amplification, inconsistent witness
    responses, stale witness statements, adversarial churn, and
    split-brain cluster membership. The existing `ClusterInfo` and
    routing structures are a foundation; they are not the answer.

### Protocol design (Spec)

12. **Membership boundaries.** The relationship between "QUIP
    peer," "Coral routing member," "witness candidate," "witness
    ring member," and "BFT ring member" is not specified. The
    protocol lets those sets coincide by accident; a dynamic Coral
    makes that worse. This needs a design document and a section in
    the draft. Especially: how does a changing DHT become a stable
    BFT membership, given that an attacker can influence the DHT?

13. **Pin authorization model.** §14's intent for `pin` / `unpin`
    is not specified: does any connected peer have the authority to
    make a resource persistent on my store, or is persistence an
    owner-authorized operation? The current node auto-serves on
    connection identity, which may or may not be correct. Fix: an
    explicit `PinAuthorization` enum at the node boundary, with the
    policy chosen by the application.

14. **Claimed / authenticated / trusted identity types.** The
    transport produces a claimed `NodeId`; `Node::connect` exposes
    it as a plain `NodeId`. That collapses three distinct concepts
    into one primitive. Downstream paths (`dht_result_from`, NAT)
    re-verify, so this is an API-safety issue rather than a live
    vulnerability — but the type boundary should be made explicit
    before the FFI surface freezes around the current shape.
    Proposed: `PeerClaim` → `AuthenticatedPeer` → `TrustedPeer`,
    with `TrustPolicy` operating above `AuthenticatedPeer`.

15. **Name hints as signed keyword sets.** A hint is a signed
    keyword set — optional primary label, required keywords,
    optional category, optional app metadata — embedded in the Coral
    value blob for a resource announcement. The Coral lookup key is
    `SHA-256(NFC(sorted_keywords) || category)`. Hints are not
    lookup keys; the lookup returns a candidate set, and the client
    filters candidates through its own `TrustPolicy`. The protocol
    cannot prevent key occupation in the DHT; the resolution layer
    filters it.

16. **Trust precedes registration.** `register_tcid` is gated on
    `Trusted` or `Verified` in the receiver's `TrustPolicy`. The
    gate is checked in the peer steady loop before dispatch; a
    rejected registration is answered with `E_NOT_AUTHORIZED` rather
    than dropped silently. Trusted peers gain access to the
    governance verbs; untrusted peers do not.

17. **Open questions from items 15 and 16.**

    - Untrusted candidates in hint resolution: show with a marker,
      or hide entirely?
    - Storage-only `register_tcid` from `Unknown` peers: record for
      later evaluation, or reject outright?
    - Trust gate on `pin` / `unpin`: currently accepts from any
      connected peer; should it match the `register_tcid` gate?
    - Witness statement trust filtering: the discovery path ingests
      witness statements without consulting `TrustPolicy`, but
      `Verified` status is what trust filtering produces, so there
      is a circularity to resolve.

### Application layer (M9)

18. **M9.5b — real `NatDriver` + cluster merge/split.** Wire a
    per-peer `NatDriver` into the flow so the NAT phase concludes
    from a real `NatEvent::DirectPathEstablished` rather than from
    the transport being up. Exchange actual candidates, perform
    probing, distinguish direct / relayed / failed connectivity,
    and propagate an explicit `NatStatus`. Run `ClusterState`
    merge/split against the routing table. Replace `LiveDht`'s
    lookup no-ops with real Coral lookups and the DHT router's
    broadcast with XOR-distance routing. Shared contracts frozen in
    M9.5b-c; implementation gates 3–7 still open.

19. **M9.6 — witness accumulation and trust bootstrap.** The
    responder currently answers with no witnesses; when the node
    accumulates `WitnessStatement`s from its peers, the responder
    returns real rings and `Ready(Verified)` becomes reachable in a
    network with at least four independent witnesses. The
    bootstrapping problem is real: a two-node network can never
    reach `Verified`, because verification requires third parties.

### Interface layer (M10)

20. **M10.4 — platform signer shim.** A `SignerBackend` trait in
    `quip-node` and one implementation per platform: Kotlin/JNI for
    Android, Swift for iOS, C ABI for Linux/Windows. Hardware-backed
    Ed25519 is available on Android 13+ with TEE or StrongBox,
    absent in the iOS Secure Enclave (P-256 only), and software-only
    on Linux. The shim exposes the fallback as a first-class case
    and reports which backing a key uses. The trait belongs in
    `quip-node`, not `quip-node-ffi`, because a hardware-backed key
    cannot be coerced into `Ed25519Signer::from_seed`'s
    `[u8; 32]` shape — the private bytes never exist.

21. **M10.5 — end-to-end verification on Android.** The smoke tests
    from M10.1 through M10.3 re-run against an Android device,
    exercising the platform signer shim.

### Browser substrate (M11)

22. **No rendering format.** The browser substrate renders standard
    web formats (HTML, CSS, JS, images, media) via the existing
    browser engine. QUIP does not define a markup language. Its
    contribution is the resolver, the address scheme, and the trust
    chrome around the content. This is a design constraint, not an
    open question.

23. **Local gateway.** A `quip-daemon` or FFI-exposed server that
    answers `http://localhost:PORT/quip/<cid>` and
    `http://localhost:PORT/hint/<name>`, so any existing browser can
    resolve QUIP content without a bespoke browser. This is the tier
    that makes the "standards for content distribution" story real:
    URL shape, content-type negotiation, trust-policy enforcement,
    all reachable from a Firefox tab.

24. **Content layer.** Trusted CID wiring (inbound `register_tcid` →
    verify → policy → `GovernanceStore`), the CBOR value-blob schema
    for what responders publish as Coral values (see Spec item 15),
    and the name-hint mechanism.

25. **Content-type metadata.** How does a CID acquire a MIME type?
    Options: pin-time metadata (cleanest, mirrors IPFS's
    `Content-Disposition`), byte sniffing, or address hints. Needed
    before the gateway can be useful for anything but downloads.

26. **VPS tier.** A user-controlled always-on anchor. Not a new
    protocol layer: the same headless build, deployed differently.
    Acts as rendezvous point, relay candidate, availability anchor,
    and custodian of witness statements. Also the mechanism by which
    a mobile client can be woken for sync — the VPS is a push
    provider, using APNs and FCM as notification-only channels.

### FFI / API stabilization

27. **Node lifecycle.** Duplicate connections, reconnect behavior,
    shutdown ordering, FFI-safe ownership and lifetimes. The FFI
    surface should not be frozen until the identity type boundary
    (item 14) and the peer generation race (item 9) are resolved.

28. **`NodeEventFfi::Message` decoding.** `Message` and `Datagram`
    carry `verb: String` + `raw: Vec<u8>`; a typed decoder
    (`decodeMessage(raw)`) is needed so Dart consumers do not
    reimplement CBOR parsing.

29. **Test-vector synchronization.** `test-vectors/` currently holds
    signing vectors. Once S8 is resolved, regenerate the vectors to
    cover the state-transfer interpretation and any other wire shape
    affected by the spec pass.

### Housekeeping

30. **Release tag.** `git tag v0.1.0-m10.3 && git push origin
    v0.1.0-m10.3`, then `v0.1.0` once S8 and BFT-A land.

31. **GitHub metadata.** Repository description and topics. The
    README currently links to this file; the repo description is
    still blank.

32. **Move the `Send + Sync` bound onto `quip_core::time::Clock`.**
    The bound currently sits on `quip-node`'s `SharedClock` alias
    because widening the trait is a breaking change. Every
    reasonable clock satisfies the stronger bound; the alias should
    eventually become unnecessary.

33. **Draft contribution log.** The reference implementation was
    developed against earlier drafts; the resolutions that became
    revision 03 are documented in the spec-pass section above. A
    short paragraph in the draft's doc history — one line per
    resolution, no reference to the reference implementation —
    would close the loop between what the draft now says and why.

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
| `quip-net/src/establishment.rs` (`resume_from_key_claim`) | M9.4b | flow started at `NatTraversal` |
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
| `quip-node/src/lib.rs:1` | M9.1–M9.4a | `Node` type, store integration, clock injection, DHT routing |
| `quip-node/src/lib.rs` (`NodeConfig`) | M9.1, M9.2, M9.4a | node configuration, clock, and capabilities |
| `quip-node/src/lib.rs` (`Node::bind`) | M9.1 | server bind + accept loop |
| `quip-node/src/lib.rs` (`Node::connect`) | M9.1, M9.4a | dial + inline handshake + DHT note_peer |
| `quip-node/src/lib.rs` (`Node::store` and direct helpers) | M9.2 | store access and pin API |
| `quip-node/src/lib.rs` (`try_auto_serve_pins`) | M9.2 | pin/unpin/query_pins auto-serve |
| `quip-node/src/lib.rs` (`dht_router_task`) | M9.4a | broadcast DHT outbound to peers |
| `quip-node/src/lib.rs` (`run_peer_loop` DHT branch) | M9.4a | intercept §12 NAT verbs |
| `quip-node/src/dht.rs:1` | M9.4a | live `DhtClient` |
| `quip-node/src/dht.rs` (`LiveDht`) | M9.4a | DHT client implementation |
| `quip-node/src/dht.rs` (`DhtHandle`) | M9.4a | node-owned DHT handle |
| `quip-node/src/dht.rs` (`PeerRecord`) | M9.4a | routing-table entry shape |
| `quip-node/src/dht.rs` (`dht_result_from`) | M9.4a | §12 verb verification and conversion |
| `quip-node/src/lib.rs` (`run_establishment`) | M9.4b | §16 flow driven per peer |
| `quip-node/src/lib.rs` (`derive_session_id`) | M9.4b | symmetric session-id derivation |
| `quip-node/src/lib.rs` (`peer_run`) | M9.4b | establishment + steady-state entry point |
| `quip-node/src/dht.rs` (`DhtHandle` impl `DhtClient`) | M9.4b | shared handle as DhtClient |
| `quip-node/src/discovery.rs:1` | M9.5a | shared Coral discovery client |
| `quip-node/src/discovery.rs` (`DiscoveryHandle`) | M9.5a | shared handle |
| `quip-node/src/discovery.rs` (`respond_to_lookup`) | M9.5a | Coral server role |
| `quip-node/src/discovery.rs` (`respond_to_spillover`) | M9.5a | spillover server role |
| `quip-node/src/lib.rs` (`run_discovery_phase`) | M9.5a | flow witness phase driver |
| `quip-node/src/lib.rs` (`make_lookup_paths`) | M9.5a | path selection |
| `quip-node/src/lib.rs` (`handle_discovery_event`) | M9.5a | Coral verb routing |
| `quip-node/src/lib.rs` (`NodeConfig::signer`) | M9.5a | shared Ed25519 signer |
| `quip-node/src/lib.rs` (`Node::take_events`) | M10.2 | receiver hand-off for the FFI layer |
| `quip-node/src/trust.rs:1` | M10.3 | trust policy |
| `quip-node/src/trust.rs` (`PeerTrust`) | M10.3 | five-level trust enum |
| `quip-node/src/trust.rs` (`TrustPolicy`) | M10.3 | stored claims and decisions |
| `quip-node/src/lib.rs` (`Node::trust_peer`) | M10.3 | explicit trust decision API |
| `quip-node/src/lib.rs` (`Node::peer_trust`) | M10.3 | trust query API |
| `quip-node/src/lib.rs` (`Node::trust_snapshot`) | M10.3 | trust store snapshot |
| `quip-node-ffi/src/api.rs:1` | M10.1–M10.3 | FFI surface |
| `quip-node-ffi/src/api.rs` (`NodeHandle`) | M10.1–M10.3 | Dart-facing handle |
| `quip-node-ffi/src/api.rs` (`NodeEventFfi`) | M10.2, M10.3 | Dart-facing event enum |
| `quip-node-ffi/src/api.rs` (`KtStatusFfi`, `FlowFailureFfi`) | M10.2 | mirrored enums |
| `quip-node-ffi/src/api.rs` (`PeerTrustFfi`) | M10.3 | mirrored trust enum |
| `quip-node-ffi/bin/smoke.dart` | M10.1 | bind-and-query acceptance test |
| `quip-node-ffi/bin/smoke_events.dart` | M10.2 | event-stream acceptance test |
| `quip-node-ffi/bin/smoke_trust.dart` | M10.3 | trust-policy acceptance test |

The code subdivides NAT work as `M3a` / `M3b.1` / `M3b.2` / `M3b.3`
and BFT work as `M4a` / `M4b`. The M3 section above numbers the later
work `M3.3`–`M3.6`; those tags appear in commits but not uniformly in
the source. `M3b.3` is retired — its only `TODO`
(`port_preservation`) landed with M3.3.

**Not yet tagged but milestone-owned:** `flow.rs` (M7), `rate.rs`
(M7), `discovery.rs` (M2, consumed in M9.5a), `coral.rs` (M2, to be
consumed in M9.5b), `message.rs` BFT arms (M4), `bft.rs` (M4),
`xtask/` (M6.2), `.github/workflows/ci.yml` (M6.3). Tagging on the
next touch is cheap.