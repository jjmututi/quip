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
layer (M9.x) runs through M9.6b: M9.1 through M9.6b are landed, with
M9.6c (trust bootstrap), M9.7 (headless binary) and M9.8 (peer address
book) next. The interface layer (M10.x) has begun: M10.1 through M10.3
are landed. §16 runs end-to-end through step 8 across
the protocol crates; the `Node` type composes them into a runnable
peer; a Dart client can bind a node, subscribe to its event stream,
and make explicit trust decisions about its peers; the node now
allocates a distinct generation slot per connection so a reconnect
cannot corrupt routing or cluster state, and it tracks a per-slot
connection lifecycle whose `NatDirect` / `NatRelayed` states define
routing eligibility. `NatRelayed` is producible at the state-machine
level: a session whose direct candidates fail and whose relay use
succeeds emits `RelayedPathEstablished`, the counterpart of
`DirectPathEstablished`. The peer task now drives a per-peer
`NatDriver`, so the §16 NAT phase concludes from a `NatEvent` the
driver emitted rather than from a hardcoded reading of the transport.
Candidate exchange between peers is now live: an empty-list
`candidate_announce` addressed to a specific peer pulls that peer's
candidates for the session. The node's signer is threaded into the
peer task, so §12 NAT verbs the peer sends — candidate announces,
relay discoveries — carry real signatures and are accepted by the
receiving peer's `dht_result_from`. The relayed branch is now
reachable end-to-end: a node whose direct candidates all fail sends
a signed `relay_discovery`, a `relay_capable` peer answers with a
signed `relay_response`, and the requester's lifecycle concludes
`PeerLifecycle::NatRelayed`. Inbound §12 verbs during the NAT phase
are verified by `dht_result_from` before reaching the state machine.
The node now samples each peer connection's RTT into its routing
table and derives a cluster member set from the routing-eligible
peers that fall within the cluster's §13.2 threshold. Mesh verbs are
routed by XOR distance to the `GATEWAY_ROUTER_COUNT` closest
eligible peers rather than broadcast to every connected peer. Witness
accumulation is now live: a running node stores `WitnessStatement`s
node-wide, serves them from the Coral responder, and — for the first
time — feeds them to its own `ConnectionFlow`, so `Ready(Verified)` is
reachable in a network with four independent, first-seen-matured
witnesses. The issuance policy that produces those statements is still
a labelled placeholder: the draft's first-issuance rule landed in
`71b52dc`, but the implementation keeps M9.6a's policy until a
milestone owns replacing it.

The protocol skeleton is complete. What remains is concentrated in
two places: making the boundaries rigorous (BFT execution semantics,
view-change certificates, identity types, membership) and making the
distributed parts withstand hostile conditions (adversarial
simulation, bounded queues, adversarial routing models).

The application layer's headless deployment shape — a `quip-node`
binary running without Flutter — is the substrate the VPS tier,
bootstrap nodes, and witness rings depend on. It lands as M9.7 after
the M9.5b-c and M9.6 work that gives it something real to do.

### Build status

All crates compile, every test passes, clippy and rustdoc are silent
under `-D warnings`, and the `no_std` build works:

```
cargo test --workspace --all-features                    ~770 unit + 4 doc, exit 0
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

Baseline on `main` after M9.6b:

```
quip-core      74 passed
quip-net      506 passed
quip-storage   57 passed
quip-node     133 passed
quip-node-ffi   0 passed
doc-tests       4 passed (one per crate)
             ~770 unit tests, 0 failed — clippy clean, rustdoc clean, no_std clean
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
| Spec pass | S8 (`bft_state_transfer` ring signature scope) | decided, draft text landed |
| Spec pass | S9–S10 (initial witness issuance; verifier independence) | decided, draft text landed |
| Spec pass | S11–S16 (split attempt episode; expiry filter; quorum as `n - f`; pending split attempts; the state-transfer digest pair; authenticating the transferred state) | resolved, draft text landed |
| M9.1 | `quip-node`: endpoint bind, accept loop, peer tasks, event stream | landed |
| M9.2 | `quip-node`: `QuipStore` integration, pin auto-serve, clock injection | landed |
| M9.3 | `quip-node`: `ConnectionFlow` integration | folded into M9.4b |
| M9.4a | `quip-node`: live `DhtClient` over the node's peer connections | landed |
| M9.4b | `quip-node`: `ConnectionFlow` integration | landed |
| M9.5a | `quip-node`: shared Coral discovery wired into the flow | landed |
| M9.5b-a | M9.5b design: peer lifecycle, routing, cluster-membership contracts | landed |
| M9.5b-b | `quip-node`: `PeerSlot`, `PeerLifecycle`, `ConnectionDriver::rtt()` | landed |
| M9.5b-c | `quip-node`: routing eligibility, cluster-member identity, `RelayedPathEstablished`, `NatDriver` in the peer task, signed candidate exchange, real probe, relay path, cluster membership and XOR routing; cluster split execution deferred to M9.6b | landed |
| M9.6a | `quip-node`: witness accumulation, store, responder, issuance policy | landed |
| M9.6b | `quip-node`: cluster-info exchange and split execution | landed |
| M9.6b (merge) | `quip-node`: cluster merging (§13.4) | landed |
| M9.6c | `quip-node`: trust bootstrap | not started |
| M9.7 | `quip-node-headless`: binary, config file, deployment | not started |
| M9.8 | `quip-node`: peer address book and bootstrap | not started |
| M10.1 | `quip-node-ffi`: bind and query a node from Dart | landed |
| M10.2 | `quip-node-ffi`: event stream across the FFI boundary | landed |
| M10.3 | `quip-node-ffi`: explicit trust policy and peer trust events | landed |
| M10.4 | `quip-node-ffi`: platform signer shim | not started |
| M10.5 | `quip-node-ffi`: end-to-end verification on Android | not started |
| M11 | Browser substrate: local gateway, content layer, trust anchors | not started |
| BFT-A | BFT correctness: `apply()` contract, prepared/checkpoint carry-forward | not started |
| BFT-V | BFT validation: adversarial network simulator, property tests | not started |
| N-Hard | Network hardening: bounded queues, peer generation, adversarial routing | in progress |
| Pre-6b | `quip-node`: hoist the inbound dispatch into one phase-parameterised function | landed |
| Spec | Category 3 design items: membership boundaries, pin authorization, identity types, name hints, §13.5 split episode | not started |
| Conformance | Conformance matrix (draft ↔ code ↔ tests) in `docs/conformance-matrix.md`: nine-field schema (History added at `ece3e58`), eighteen rows, and a scope statement naming what the matrix covers and what it does not. The decisive query returns zero rows over the eighteen rows that exist; the draft's unrowed statements are inventoried in the matrix's "What follows" section, not judged. The §5.3.4/§5.3.4.1 pass added rows 14–18: the transfer's two digests (row 14, `PASS` once the code gained `state_hash`), preprepare digest, new-view quorum, ring-signature validation (`PASS`), and degraded-mode admission (row 18, `FAIL` — no gate) | in progress |

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

**Known incomplete**: the DHT handle uses unbounded channels;
bounding and coalescing is N-Hard.

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
are no-ops. See M9.5b-c.

### M9.4b — `quip-node` ConnectionFlow integration — LANDED

Each peer task now runs a `ConnectionFlow` between the inline §4/§16
handshake and the steady-state loop.

- `run_establishment` resumes the flow at `NatTraversal` via
  `ConnectionFlow::resume_from_key_claim`, using a session identifier
  derived symmetrically from the two NodeIds (`local[0..16] XOR
  remote[0..16]`).
- The NAT phase concludes from the live transport: the handshake
  proves direct connectivity. M9.5b-c replaces this with a real
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
placeholder; both defer to M9.5b-c and M9.6.

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

### M9.5b-a — M9.5b design contracts — LANDED

`docs/M9.5b-design.md` freezes the shared contracts that the NAT and
cluster integration tracks of M9.5b depend on. Written before either
track starts, so the two can proceed in parallel without drifting.

Four contracts:

- **`PeerSlot` generation identity.** A `PeerSlot` identifies a
  particular connection generation for a logical `NodeId`. Events
  from an obsolete generation cannot mutate current routing or
  cluster state.
- **`PeerLifecycle` transitions.** `Connecting → Established`;
  `Established → NatDirect | NatRelayed | Failed`; a path change
  between `NatDirect` and `NatRelayed` does not recreate the
  connection; any nonterminal state can reach `Closing`; `Failed`
  and `Closing` are terminal for a given slot.
- **Routing-table record.** Keyed by `NodeId`, associated with the
  active `PeerSlot`, with routing eligibility distinct from
  physical connection existence.
- **Cluster-membership eligibility.** Follows draft §13.2: the
  cluster-joining decision requires the 90th-percentile RTT at or
  below the cluster's threshold, using the specified 20-sample
  procedure. The sample requirement binds the acceptance decision,
  not individual members.

Three dimensions are kept separate: connection lifecycle, witness
verification (`Pending` / `Verified`), and application trust
(`Unknown` / `Trusted` / `Untrusted` / `Revoked`). A peer can be
`NatDirect` with `Pending` witness status and `Unknown` application
trust without a lifecycle variant for that combination.

Discovery failure does not transition the connection lifecycle.
`ConnectionFlow::on_discovery_failed()` yields `Ready(Pending)`,
which the node treats as successful establishment.

Verified against the current draft (§13.2) and the `quip-net`
sources (`establishment.rs`, `cluster.rs`) before landing. The
implementation of the shared types and the `ConnectionDriver::rtt()`
accessor is M9.5b-b.

**Post-M9.5b-b documentation correction.** After M9.5b-b landed the
shared types and the RTT accessor, the design doc's status header
and §7 gate list were updated in a follow-up `docs:` commit to
match reality. The header now reads "Partially landed: gates 3, 4,
and 7 closed by M9.5b-b; gates 5 and 6 open," gates 3, 4, and 7 in
§7 are struck through with citations to the code that closed them,
and §1, §2a, and §5 point at `quip-node/src/peer.rs` and
`quip-net/src/transport.rs` as the normative source for the
contracts the code now carries. Gates 5 and 6 remain open; §3, §4,
§6, §8, and §9 are unchanged. Two forward-dependency notes were
added: §1 references Spec item 14 (identity types), and §3
references Spec item 12 (membership boundaries). The document
remains the authoritative contract for M9.5b until the milestone
completes.

**Post-M9.5b-c documentation correction.** After M9.5b-c gates 5 and
6 landed, the design doc's status header, §2a, §3, §4, and §7 were
updated in the same commit. The header now reads "Gates 3–7 closed;
the integration work those gates unblock … pending." §2a gains a
"Landed (M9.5b-c gates 5 and 6)" note describing lifecycle as a live
state variable. §3 gains a "Landed" note describing the
routing-eligible set and the cluster-member identity. §4 gains a
"Landed (partial)" note distinguishing identity (defined) from
derivation (pending). §7 gates 5 and 6 are struck through with
citations to the code that closed them; the "Remaining" paragraph is
rewritten to name the M9.5b-c integration work.

### M9.5b-b — `quip-node` peer generation, lifecycle vocabulary, RTT accessor — LANDED

The M9.5b-a contracts become code. This milestone introduces the
types the NAT and cluster tracks of M9.5b-c consume, plus the
`ConnectionDriver` accessor §13.2's acceptance test needs.

- **`quip-node/src/peer.rs` (new).** `PeerSlot { node_id, generation }`
  is the logical `NodeId` plus a per-`Node` `u64` that increments on
  every new connection for that identity and is never reset, so a
  slot value is never reused. `PeerLifecycle` encodes the §2a
  transition table as a tested type: `can_transition` is total, and
  the disallowed edges — including `Connecting → Failed` — are
  covered by explicit unit tests.
- **`quip-node/src/lib.rs`.** `Node` gains a `Registry` holding peer
  handles and the persistent generation counters behind one mutex.
  `register_peer` allocates a fresh slot, inserts the new handle,
  and aborts the previous task's `JoinHandle`; `unregister_peer`
  removes a task's entries only if its slot is still current, so a
  superseded generation cannot clobber its successor's state.
  `peer_run` takes the slot and performs two `is_current` checks —
  one on entry, one after the establishment flow — before entering
  the steady loop. The public API gains `Node::peer_slot`, so an
  application that caches per-peer state can detect a reconnect.
- **`quip-node/src/dht.rs`.** `PeerRecord` gains a `slot: PeerSlot`.
  `note_peer(peer, slot, addr, now)` always records the calling
  generation; `forget_peer(peer, slot)` only removes the record if
  the slot matches. A stale generation's cleanup is a no-op against
  a live record.
- **`quip-net/src/transport.rs`.** `ConnectionDriver::rtt() ->
  Option<Duration>` returns `None` until the driver has confirmed a
  real sample. Quinn reports an RTT *estimate* from connection
  creation — never zero, never absent — so the accessor cannot use
  "check for zero." Instead, the driver captures Quinn's smoothed
  RTT at handshake completion as a baseline and flips an internal
  `rtt_sampled` flag the first time the value moves by more than
  `RTT_SAMPLE_EPSILON = 1 ms`. Until then, `rtt()` returns `None`,
  which is exactly what §13.2's cluster acceptance test needs:
  missing observations must not count toward the required sample
  minimum, and must not independently satisfy the test.

**Deliberately not in this milestone.** `PeerLifecycle` is defined
and tested but not yet a live state variable on the flow;
`run_establishment` still reads `FlowPhase` directly. Wiring the
lifecycle into the flow is meaningful only with a real `NatDriver`,
so it belongs to M9.5b-c. `NodeEvent` does not carry the slot;
stale-event suppression happens inside the peer task, and the
application sees at most one live generation per `NodeId` because
the previous task is aborted on takeover.

Tests: `peer_slot_increments_across_reconnects`,
`dht_forget_peer_is_slot_scoped`, `rtt_is_none_before_handshake`,
`rtt_is_absent_or_plausible_after_handshake`, plus the unit tests in
`quip-node::peer` and `quip-node::dht`.

### M9.5b-c (part 2) — `NatRelayed` outcome: `RelayedPathEstablished` — LANDED

The design note's §2a table admits `PeerLifecycle::NatRelayed` as a
transition from `Established`, but until this commit nothing
produced it: the state machine had no event for "the NAT phase
concluded without a direct path." This commit adds the producer.

- **`quip-net/src/nat.rs`.** `NatEvent` gains a
  `RelayedPathEstablished { peer, session_id, relay }` variant.
  `NatTraversal::on_relay_result(session_id, relay_id, success, now)`
  is the sole producer: on success it records the outcome on the
  session, records a relay-manager success against the relay, and
  queues `RelayedPathEstablished`; on failure it records a
  relay-manager failure and removes the relay from the session's
  candidate list. `SessionState` gains a
  `relay_outcome: Option<NodeId>` field; a session with
  `relay_outcome` set is skipped by `NatTraversal::poll`, so a
  concluded relayed session cannot be re-processed.
- **`quip-net/src/nat_driver.rs`.** `NatDriver::on_relay_result` is a
  passthrough to the state machine. The application calls it after
  receiving a `RelayPathAvailable` event and attempting to use the
  relay.

The two terminal success outcomes of a session are now symmetric:
`DirectPathEstablished` for a successful candidate probe,
`RelayedPathEstablished` for a successful relay attempt. A session
emits exactly one of them, or `SessionFailed`.

The relay may be used for coordination only (hole-punch assistance)
or for forwarding; the protocol does not distinguish at this layer.
`NatRelayed` therefore means "the NAT phase concluded without a
direct path," not "traffic flows through the relay" — a distinction
the M9.5b-a design note already draws.

**Deliberately not in this commit.** The node's peer task does not
yet drive a `NatDriver`: `quip-node`'s `run_establishment` still
concludes the NAT phase from the transport being up, so it produces
`NatDirect` for every peer. Wiring the driver into the peer task —
and with it, the code path that produces `NatRelayed` from a real
peer — is the next commit.

Tests: `on_relay_result_success_emits_relayed_path_established`,
`on_relay_result_failure_removes_relay_from_session`,
`on_relay_result_of_unknown_relay_is_noop` (nat.rs);
`dispatch_relayed_established_is_observation_only`,
`on_relay_result_forwards_to_state_machine` (nat_driver.rs).

### M9.5b-c (part 3) — `NatDriver` wired into the peer task — LANDED

The §16 NAT phase no longer concludes from a hardcoded reading of the
transport. Each peer task now builds a `NatDriver<DhtHandle>` when it
enters `FlowPhase::NatTraversal`, drives it to a terminal event, and
translates that event into the flow's NAT completion.

- **`quip-node/src/lib.rs`.** A new `run_nat_phase` builds the driver,
  seeds the peer's current transport address as a host candidate,
  reports a successful probe for it, and drains the driver until it
  produces `DirectPathEstablished`, `RelayedPathEstablished`, or
  `SessionFailed`. `run_establishment`'s `FlowPhase::NatTraversal`
  arm calls it and translates the outcome: `Direct` →
  `on_nat_complete(true)` + `PeerLifecycle::NatDirect`; `Relayed` →
  `on_nat_complete(true)` + `PeerLifecycle::NatRelayed`; `Failed` →
  `on_nat_complete(false)` (the flow loop then emits
  `EstablishmentFailed`).

  **Evidence.** The transport is up, so the peer's current address is
  reachable from this node. That is the same evidence M9.4b used, but
  it now flows through the driver's candidate → probe →
  `DirectPathEstablished` pipeline rather than being read as a
  hardcoded boolean. When candidate exchange lands, only the evidence
  source changes; the pipeline is unchanged.

**Deliberately not in this commit.**

- Candidate exchange over the DHT. `DhtHandle::lookup_candidates` is
  still a no-op, so no `candidate_announce` exchange happens. The
  candidate seeded is the address the transport already uses.
- Real probing of candidate addresses. The probe is a direct report,
  not a fresh dial.
- Signing and sending `relay_discovery` on T0. The state machine
  emits `RelayDiscoveryRequested` when direct candidates are
  exhausted, but the peer task does not yet sign — the node's signer
  is not threaded down to the peer task. On loopback the direct probe
  succeeds first, so this branch is not reached by the two-node
  tests.
- `NatRelayed` from a real relayed path. The lifecycle state is
  reachable through the driver's `RelayedPathEstablished`, but
  producing it requires the above.

Tests: no new tests. The existing integration tests —
`ready_fires_after_connect`,
`peer_becomes_routing_eligible_after_establishment`,
`dht_mirrors_routing_eligibility` — now exercise the driver path
end-to-end: the node cannot reach `PeerLifecycle::NatDirect` without
the driver emitting `DirectPathEstablished`.

### M9.5b-c (part 4) — peer candidate exchange — LANDED

§12.3 exchanges candidates between exactly two peers of a session,
not across a DHT mesh. The `DhtClient` trait's mesh-shaped
`publish_candidates` and `lookup_candidates` now carry that peer
scope through the router.

- **`quip-node/src/dht.rs`.** `Outbound` becomes a two-field struct:
  `target: Option<NodeId>` (peer-scoped verbs) or `None` (mesh verbs,
  broadcast). `DhtInner` gains a `sessions: Mutex<BTreeMap<[u8; 16],
  NodeId>>` mapping a session to the peer it is with.
  `publish_candidates` routes to the peer registered for the
  announce's session, or drops when no session is registered — a
  candidate announce to the wrong peer is a protocol violation, and
  there is no safe fallback. `lookup_candidates(target, session_id)`
  emits an empty-list `candidate_announce` addressed to `target`;
  the peer's steady loop answers with its own announce for the same
  session. New public methods `note_session` and `forget_session`
  manage the mapping.
- **`quip-node/src/lib.rs`.** `dht_router_task` takes the new
  `Outbound` shape and routes peer-scoped messages to the named
  peer's sender, mesh messages to every peer. `run_nat_phase`
  registers the session with `dht.note_session` before starting the
  driver and clears it with `dht.forget_session` on every terminal
  path.

**Deliberately not in this commit.** The empty-list pull announces
with a zero timestamp and signature. `dht_result_from` verifies the
claimed `NodeId` on the peer's side; an empty announce with an empty
signature fails that check, so a real wire-level pull does not
currently reach the state machine. On loopback the seeded candidate
still succeeds first — the pipeline is exercised, the wiring for a
*remote* candidate pull is in place, and threading the signer
through is the follow-up.

Tests: `publish_candidates_routes_to_the_session_peer`,
`publish_candidates_without_a_session_is_dropped`,
`lookup_candidates_emits_peer_scoped_pull`,
`forget_session_removes_routing`,
`publish_connectivity_is_broadcast` (dht.rs).

### M9.5b-c (part 5) — signed NAT verbs and real candidate probing — LANDED

The NAT phase's evidence is now genuine. Outbound §12 verbs are
signed with the node's key, and the driver's probe requests are
answered by dialing the candidate rather than by asserting success.

- **`quip-node/src/lib.rs`.** `Node` gains a private `signer` field
  and a `signer_for_peers()` accessor. `peer_run` and
  `run_establishment` take a `&SharedSigner`; both call sites
  (`Node::connect`, `accept_loop`) clone the node's signer into the
  peer task.
- `run_nat_phase` seeds the peer's current transport address into
  the state machine as if the peer had announced it, sends a signed
  `candidate_announce` carrying this node's host candidate to the
  peer, and handles three driver events the previous cut ignored:
  `ProbeRequested` dials the candidate with a fresh client
  `Endpoint` under the App. A.5 5 s timeout — short-circuited when
  the address is the transport address, since the live connection
  is the proof — and `RelayDiscoveryRequested` signs and sends a
  `relay_discovery` on T0.
- A new `probe_candidate` helper opens a fresh client endpoint per
  probe. The probe carries no identity — the `KeyClaim` is
  generated fresh per probe — because §12.3 path validation does
  not authenticate the prober.

**What changed for the receiver.** The peer's `dht_result_from`
already verified `candidate_announce` signatures; the announces
were reaching it with zero-filled signatures and being rejected.
The two-node tests passed because `run_nat_phase` reported the
probe result directly, bypassing the wire. They now pass because
the signed announces survive `dht_result_from` and reach the state
machine.

**Test narrowed.** `dht_forged_connectivity_is_dropped` previously
asserted B's DHT queue stayed empty during a quiet connection. That
held only because no other DHT traffic existed. With the NAT
exchange sending a legitimate `candidate_announce`, the assertion
is narrowed to the property it exists to check: no `Connectivity`
result attributed to B when A delivered it. The legitimate
`Candidates` result is drained from the queue without tripping the
assertion.

**Deliberately not in this commit.** The pull emitted by
`DhtHandle::lookup_candidates` is still zero-signed: the trait
method has no signer parameter, and threading one through the trait
is a larger change than the value justifies — the peer's response
carries its own valid signature and is what advances the session.
Cluster merge/split and XOR routing were M9.5b-c's outstanding work; the
routing landed in part 7 and the split in `0464964`.

Tests: `nat_phase_exchanges_signed_candidates` (lib.rs). The
existing integration tests are unchanged in intent but now depend
on the signing path.

### M9.5b-c (part 6) — relay path end-to-end — LANDED

`PeerLifecycle::NatRelayed` is now reachable from a real peer. A node
whose direct candidates fail sends a signed `relay_discovery` on T0,
a `relay_capable` peer answers with a signed `relay_response` naming
itself, and the requester's lifecycle concludes `NatRelayed`. Two
config knobs make the branch reachable without touching the
production default; both are honest production settings, not
test-only scaffolding.

`quip-net/src/nat.rs`. `NatConfig` and `SessionState` gain a
`force_relay: bool`. A forced session skips the direct-candidate
ladder in `NatTraversal::poll` and goes straight to
`RequestRelays`; it still publishes its own candidates, only the
inbound direct path is refused. `NatTraversal::force_relay_for`
raises the flag per session; there is no un-force.

`quip-net/src/nat_driver.rs`. `NatDriver::on_dht_result` is
the routing arm factored out of `drain_dht`. It is the seam
`run_nat_phase` uses to feed a verified `DhtResult` into the
state machine without `on_peer_message`, which does not verify.
`NatDriver::force_relay_for` is a passthrough.

`quip-net/src/transport.rs`. `ConnectionDriver` gains
`local_addr()`, captured at construction from the enclosing
`Endpoint`. `quinn::Connection` does not expose the endpoint's
bound port, and the relay responder needs the address a peer
should send relayed traffic to.

`quip-node/src/lib.rs`. `NodeConfig` gains `force_relay` and
`relay_capable`, both default `false`. `run_nat_phase` answers an
inbound `relay_discovery` via a new `try_serve_relay_discovery`
helper before the `dht_result_from` intercept, because
`dht_result_from` returns `None` for that verb. Without that, a
relay-capable node that has not yet entered its steady loop drops
the discovery and the requester times out into `NatDirect`.
`probe_candidate` takes `now` and derives a fresh Ed25519 seed per
call; part 5 used the all-zero seed, a fixed identity any node
could impersonate.

The relay branch, end to end. A forced session sends its
`relay_discovery` on the first poll. The peer verifies the
signature, confirms the requester is the connection's peer and the
target is itself, and answers with a signed `RelayResponse` naming
itself as the sole relay. The requester feeds the response through
`dht_result_from` into `on_relay_response`, gets
`RelayPathAvailable`, attempts the relay, and concludes
`RelayedPathEstablished`. The `PeerLifecycle::NatRelayed` state that
the design note's §2a table has admitted since M9.5b-a is now
reachable from a real peer.

Deliberately not in this commit. `run_nat_phase`'s inbound path
handles the §12 verbs plus `relay_discovery`. Auto-served pin verbs
are still handled only in `run_peer_loop` and are dropped if they
arrive during establishment. §13 Coral verbs were the other half of
that gap; M9.6a's follow-up (`edef239`) answers them in `run_nat_phase`
as well, and ingests `AnnounceWitness` there. Cluster merge/split and
XOR-distance routing were M9.5b-c's outstanding work; the routing landed
in part 7, the split in `0464964`, and merge is still unexecuted
(Outstanding Work 16a).

Tests: `relay_path_produces_nat_relayed` (lib.rs);
`on_dht_result_routes_candidates` (nat_driver.rs);
`force_relay_from_config_skips_direct_candidates`,
`force_relay_for_overrides_config`,
`force_relay_for_unknown_session_is_noop` (nat.rs).

### M9.5b-c (part 7) — cluster membership and XOR routing — LANDED

The node now runs the Coral cluster machine against its
routing-eligible peers and routes mesh verbs by XOR distance.

`quip-net/src/cluster.rs`. `percentile` is a public nearest-rank
helper factored out of `percentile_at_or_below`; the node layer needs
the raw percentile, not the boolean threshold check.

`quip-node/src/dht.rs`. `PeerRecord` gains `rtt_ms: Option<u64>` —
`None` is "no valid sample" and never counts as zero (§5 of the
design note). `DhtHandle::note_rtt` records a slot-scoped sample and
derives the `RttClass`. `DhtHandle::closest_to(key, k)` returns the k
closest routing-eligible peers by XOR distance. `Outbound` gains a
`key` field: mesh verbs carry their Coral routing key, peer-scoped
verbs carry `None`.

`quip-node/src/cluster.rs` (new). `ClusterHandle` owns a
`ClusterState` and `ClusterConfig`. `recompute` derives members
(routing-eligible peers within the level's RTT threshold), applies
the §13.2 acceptance test, updates the §13.6 size estimate, and
returns a `ClusterView { id, level, size, members, acceptable,
split_due }`.

`quip-node/src/lib.rs`. `Node` gains a `ClusterHandle` at the `Local`
tier (id derived from its `NodeId`). `run_peer_loop` samples
`driver.rtt()` into `note_rtt`. `dht_router_task` forwards mesh verbs
to the `GATEWAY_ROUTER_COUNT` closest eligible peers.
`Node::cluster()` and `Node::cluster_view()` expose the handle and the
snapshot.

Deliberately not in this commit. Merge/split execution — choosing a
split target and migrating the cluster id — needs neighbour
`ClusterInfo`, which no peer yet reports; it lands with the
multi-cluster state M9.6 introduces. `acceptable` and `split_due` are
computed independently: acceptance is instantaneous, while a split
fires only after a sustained over-threshold period (§13.5), so the
two can disagree. That is the intended reading, but it is not yet
documented in code.

Tests: `note_rtt_records_sample_and_class`,
`note_rtt_stale_slot_is_noop`,
`closest_to_orders_by_xor_distance_and_filters_ineligible` (dht.rs);
`fresh_cluster_has_no_members_and_fails_acceptance`,
`members_are_eligible_peers_within_threshold`,
`missing_rtt_samples_are_not_members` (cluster.rs);
`cluster_starts_local_and_routes_to_eligible_peer` (lib.rs).

### M9.6a — witness accumulation and issuance — LANDED

Implements the design frozen in `docs/M9.6a-design.md`. A
node-wide `WitnessStore` keyed by `(subject, witness)` is fed by
the three seams of §2a: store ingress during establishment,
requester-side KT wiring so `ConnectionFlow::compute_kt_status`
sees the statements, and a new first branch in the steady loop for
post-establishment accumulation. The first-seen fact moves into a
shared `ClaimLog` (§2.5 of the note), consumed by both
`TrustPolicy` and the store, so §5.3.3's 6-hour rule has one home.

The Coral responder now returns valid, first-seen-matured
statements from the store (§3 of the note); the 4+ threshold stays
client-side. The issuance policy is the labelled placeholder of §4,
and the gap it fills — the draft describes re-issuance but not
first issuance — is recorded as a Spec item. The note's own
correction is also closed: `ConnectionFlow`'s witness map was never
populated in production, so `Ready(Verified)` was unreachable; seam
2 fills it.

One `quip-net` change: `compute_kt_status` excludes the local
NodeId, encoding verifier independence. §5.3.3's "independent" is
implied but not stated, so that too is recorded as a Spec item.

Deliberately not here: trust bootstrap (deferred to M9.6c); cluster
split execution (deferred to M9.6b); a cap on the store (N-Hard);
`ClaimLog` persistence (belongs with M9.7's store persistence).

Tests: `six_nodes_reach_verified_after_first_seen_window`,
`six_nodes_stay_pending_before_first_seen_window`, plus the unit
tests in `quip-node::witness` and `quip-node::claim_log`.

### Pre-6b — inbound dispatch hoist — LANDED

`message::dispatch` parsed a frame but did not enforce the negotiated
capability set. `ConnectionDriver::send` did enforce it, so §4's gate
was real on the way out and advisory on the way in. The node's four
inbound paths — handshake, NAT, discovery, steady state — also each
carried their own copy of the verb dispatch, and every copy had at
least once dropped a verb another copy handled: `relay_discovery`
during the NAT phase (M9.5b-c part 6), `AnnounceWitness` and Coral
verbs during the NAT phase (`edef239`).

One boundary and one classifier replace the four copies.

- `quip_net::message::dispatch_inbound(negotiated, bytes, tier)`
  parses and then calls `Message::check_capability`. `dispatch` is
  unchanged, so existing callers and tests are untouched; every
  inbound path calls the new function, and a verb whose capability was
  not negotiated is rejected with `E_CAPABILITY_VIOLATION` before a
  handler can act on it.
- `parse_inbound` reads `driver.agreed()` and calls it. It is the only
  place `tasks.rs` parses a frame.
- `classify_inbound` is the single dispatch order — witness, relay,
  NAT, Coral, pins, unhandled — and `InboundOptions` is the only thing
  a phase varies: handshake serves none of them, NAT and discovery
  serve relay and Coral, the steady loop serves relay, Coral and pins,
  and the datagram path serves none (only witness ingest applies). A
  flow is present only during discovery.
- `apply_inbound` performs the action. `InboundOutcome::Nat` means the
  caller *may* feed a `NatDriver`; `run_nat_phase` does, the other
  phases enqueue for the DHT router.

Three drops closed, not two. Besides the `relay_discovery`-during-
discovery and `AnnounceWitness`-during-handshake fixes this refactor
was for, a §12 result arriving during witness discovery is now enqueued
for the DHT router instead of being dropped. Each is a behaviour
change, not a preservation.

Observable change: an un-negotiated verb in the steady loop surfaces as
`NodeEvent::Error { error: CapabilityViolation }` rather than
`NodeEvent::Message`. The three establishment loops have no event sink,
so there the frame is dropped.

A conformant peer never meets the receive-side gate:
`Handshake::negotiate` returns the intersection and `send` enforces the
same set. The gate is for a peer that ignores its own negotiation,
which is why its test injects a frame rather than calling `send`.

Tests: `dispatch_inbound` reject/accept/parse-error (`message.rs`);
`injected_frame_is_rejected_by_dispatch_inbound` (`transport.rs`, using
a `cfg(test)`-only frame injection on `ConnectionDriver`);
`classify_inbound` over the verb × phase matrix and the `InboundOptions`
values (`tasks.rs`).

**What the tests do not prove.** The two phase-timed fixes —
`relay_discovery` served during discovery, `AnnounceWitness` ingested
during handshake — are tested at the routing layer: `classify_inbound`
returns the right outcome for the right phase, and the call sites
execute it. They are not tested by reproducing the timing that made the
drops: that requires a test-only gate that parks a peer mid-phase, which
is a larger surface than the frame injection and is not added. A future
instance of this class that escapes both the unit tests and CI would
escape for the same reason these did.

### M9.6b — cluster-info exchange and split execution — LANDED

§13.4's tuple existed as a `ClusterInfo` value and as a split branch,
but it was never on the wire: a node could not learn a neighbour's
cluster id, so the id filter §13.5 implies had nothing to read, and a
split had no observable effect. Part 1 puts the tuple on the wire and
applies the filter at read time; part 2 executes the split. The order is
forced: without the filter, a split that changes only the local id
changes nothing observable, so the split commit would have landed on a
base where its own test had nothing to assert.

- `quip-net`: `ClusterInfoAnnounce` — `[cluster_id, size, ctime,
  signature]` over `["quip-v1", "cluster_info", …]`. The tuple carries
  no node id: `verify(sender, v)` takes the authenticated peer id, the
  shape `RelayResponse` already uses. New T0 verb; capability
  `DHT_DISCOVERY`, which is in the baseline set, so no new bit.
- `quip-node::cluster`: `NeighbourClusters`, keyed by the authenticated
  sender, last write wins, bounded at `MAX_NEIGHBOUR_CLUSTERS`.
  `observe` rejects `size == 0` and a `ctime` more than
  `MAX_CTIME_SKEW_MS` ahead; the signature check is the caller's.
- `is_cluster_member(neighbours, peer, local_id)` — unknown is a
  member, a different advertised id is not. `recompute` filters with
  it. `is_routing_eligible` is unchanged: the conjunct belongs at the
  call sites that mean "member", not in the predicate that means
  "reachable".
- `cluster_task` publishes on `(id, size)` change, once per
  `CLUSTER_HEARTBEAT_S`, as a broadcast. `Node` holds its `JoinHandle`
  and `Drop` aborts it — the first background task in the crate not
  tied to a peer connection, so the abort had to be added rather than
  inherited.
- Inbound: `serve_cluster_info` is on for NAT, discovery and steady,
  off for handshake and datagrams; `classify_inbound` also requires an
  authenticated peer, because the tuple has no id to file it under.
  `apply_inbound` verifies, records, and replies only when our id
  differs, which converges in at most four messages.

**Part 2 — split execution.** `ClusterHandle::plan_split` evaluates
§13.5 when `split_due` and changes nothing; `split_if_due` applies the
plan.

- **Ids.** `cid^N = hash(cid)` is SHA-256 over the 16-byte id truncated
  to 16 bytes; `cid^F` is `cid^N` with bit 0 of the first byte flipped;
  `hash(cid^N)` is the full 256-bit center lookup key. The reading is
  provisional (note §8, question 2) because the draft does not define
  `hash`; a different definition changes those three functions and
  nothing else. `CreateNew` derives
  `SHA-256(node_id || now_ms || attempts)[..16]`.
- **Center.** The closest *connected* routing-eligible peer, because
  there is no address book — the note's §6 limitation, deferred to
  M9.8. `rtt_to_center` is that peer's sample; no peer means
  `u64::MAX`, so `JoinNear` cannot be taken on a mesh with nothing in
  it.
- **Acceptability.** A branch is acceptable when a peer advertises
  exactly that id, is within the RTT threshold, and reports at least
  `MIN_CLUSTER_SIZE`.
- **Attempts.** `record_split_attempt` runs before the move; past
  `MAX_SPLIT_ATTEMPTS` the plan is `CreateNew` regardless of the branch
  verdicts. §13.5's rule, and the reason a node cannot ping-pong between
  two clusters that keep rejecting it.
- **The move.** `migrate` replaces the id, resets `ctime` and `size`,
  clears the coordinator, the RTT timer and the attempt counter — a new
  cluster is not born already due to split.
- **The announcement.** The heartbeat performs the split, recomputes,
  and publishes through the existing tuple-change path. A split *is* a
  tuple change, so it needs no separate send.

**The attempt cap is inert, and the matrix's third row is where that was
found.** The note's sequence — record the attempt, then `migrate`, which
clears the counter — makes every split a success, so §13.5's
`MAX_SPLIT_ATTEMPTS` cannot fire. The code follows the note; the
divergence is between the note and the draft's "fails to find an
acceptable cluster". Recorded as Protocol design item 15a, with three
candidate readings for what ends an attempt and a recommendation; the
conformance matrix lists it as row 3 — a `FAIL` whose specification
status is `incomplete`.

The split is local and uncoordinated, as §13.5 describes: every node
evaluates the same inputs and may choose differently, and the partition
is the union of their choices. That is why the part-1 filter is
load-bearing rather than an optimisation — and why the two parts are one
milestone.

**Record is not member.** The record is written after the signature
verifies and *without* consulting the id; the filter runs at read time.
A neighbour announcing a foreign id stays in the store — filtering at
write time would require re-verifying the store after every local-id
change, which is the bug class the filter exists to prevent, and it
would make a local split unobservable.

Deliberately not here: merge (§13.4); a real DHT lookup for the center
(deferred to M9.8, the peer address book); sloppy replication (§13.5).

Tests: `ClusterInfoAnnounce` roundtrip, verb and arity rejection,
signature verified against the sender and rejected for another
(`cluster.rs`, `quip-net`); the verb in the all-variants roundtrip
(`message.rs`); unknown/foreign/boundary filter behaviour and
signed-tuple verification (`cluster.rs`, `quip-node`); the phase table
and `cluster_info` per phase (`tasks.rs`).

Split: the derivation pinned to SHA-256 rather than merely "different",
`cid^F` differing from `cid^N` in exactly bit 0, the center key being
`hash(cid^N)` and not `cid^N`, `fresh` depending on node, time and
attempts, and `migrate` resetting what must not carry over
(`cluster.rs`, `quip-net`). The timer, the three branches with their
resulting ids, the partition, and `split_if_due` actually migrating —
six tests, one shared three-peer setup, so the branch inputs are the
only thing that varies (`split_tests` in `cluster.rs`, `quip-node`).

**The dependency check was run, not assumed.** The partition test was
run with the read-time filter commented out: it fails at its *first*
assertion, because without the filter peer 3 is a member — the exchange
commit's contribution, made falsifiable. The relevant revert is the
filter rather than `apply_inbound`: the test drives `recompute` directly
and never opens a connection, so reverting the inbound arm would not
change its verdict. The edit was manual and restored before committing;
nothing in CI re-runs it, so a future change that removes the filter
would be caught by the test, not by the check.

**What the tests do not prove.** No test runs two nodes and waits for a
heartbeat. The interval is `CLUSTER_HEARTBEAT_S`, so a live test would
either sleep that long or need an injectable interval; neither is
added. The split tests move a `Timestamp` past the timer rather than
sleeping, and they read the mesh through a `DhtHandle` and a store of
recorded tuples — the same state a live node would hold, but assembled
directly. The exchange is proven piecewise — the wire form
round-trips, the classifier routes it in three phases and not two, the
store accepts and rejects the right tuples, the filter excludes a
foreign id, a split partitions the set — but no single test sends a
`cluster_info` from one node to another and observes the split that
follows. That end-to-end path is the first thing a live-mesh harness
should cover when one exists.

**The hoist's first new verb produced one instance of the quiet-drop
class, caught by unit test before merge.** The first draft of
`classify_inbound` routed `cluster_info` with no authenticated peer;
`apply_inbound` would then have failed its `Some(peer)` pattern and
returned `Handled`, dropping the frame silently. The test
`cluster_info_is_recorded_after_the_handshake` was written to assert the
negative case — "no authenticated sender, nothing to record" — and it
failed. This is the third instance of the class in two milestones
(`relay_discovery` during the NAT phase at part 6; `AnnounceWitness` and
the Coral verbs mid-establishment at 6a), and the first caught before
merge by a test rather than by CI. It is also evidence about the hoist:
the new verb found the new bug in one classifier, with one test naming
what the bug would have done — not in one of four copies, where the
negative case had no home.

**M9.6b design note revision.** The bf520fe review pair found that
docs/m9.6b-merge-design.md's §2 could not be transcribed as it stood:
§2b said the larger cluster's members adopt the smaller cluster's id
while §2c and §2d said the larger id survives; the size re-check was
"at the time of the proposal" in §2b and "at acceptance time" in §2c;
first-arrived-wins needed a receiver-side `PendingMerge` the note did
not define; the member-migration trigger was unspecified; the
completion denominator was "smaller cluster's members" in one place
and "remaining members" in another; failure mode 3 was named a failure
but stated as completion; §2a's RTT rule depended on a
`ClusterInfo.rtt` field that neither the code nor the draft carries;
and §2a's 1/4 rule was not what `ClusterState::should_merge` actually
evaluates. The revision makes three decisions and lands them:
eligibility is `should_merge`'s δ rule (the draft's 1/4 floor is
satisfied at δ=2 and oscillated at δ=0, which is the intent); the
RTT input is local samples against the peer cluster's members, with
no new wire field; and completion is a reachable-at-acceptance
majority, with partial migration a completion rule rather than a
failure. `merge_if_due` is named as `should_merge`'s caller, which
closes the note's own §1 gap and the fourth instance of the
uncalled-code class. No code, no draft change. Row 7 stays
FAIL / incomplete / review required until the merge code lands;
the note fix changes what "incomplete" means — a documentation gap,
not an undefined behaviour.

A second revision to the note's §2a was needed after the first
half of the merge implementation landed (028c102, corrected in
`98f7db2`). Two of §2a's four rules could not be enforced
by `ClusterState::merge_proposal_eligible` as the note stated:
rule 2 needs two RTT sample sets only the node layer holds, and
rule 4 needs a level field `ClusterInfo` does not carry. The
revision names where each rule lives — rules 1, 3 and the
no-merge-in-flight condition in the state machine; rule 2 in the
caller; rule 4 transitively through §13.2's threshold — and
reserves `MergeRejectReason::Level` for a future where the level
is carried on the wire. The class is the same one the bf520fe
review caught for `ClusterInfo.rtt`: the note stated a rule the
code could not enforce, and the code wins.

**BFT item 1 note revision.** The AI1/AI2 review pair on
docs/bft-item-1-design.md and the read-only field-name report
that followed found eight items the note did not have or got
wrong: the canonical key order in the digest map was written in
the literal order rather than the sorted order QUIP-CBOR
produces; the genesis claim was stale because §5.3.4 now defines
`d_(-1)`; `ApplyFailed` could not keep its meaning under an
infallible `apply`; `state_hash` was described as "gained" when
it is already in the CDDL and the code; the empty-output rule was
unstated; `apply`'s deterministic context was unstated;
divergence detection was asserted but untested; and the note had
no traceability between its items and the draft's clauses. The
revision addresses all eight and adds a ninth statement the
report's correction required: on Finding B, the note adopts the
chain-over-sequence reading and states it conditional on the
state-format SHOULD — a handler that takes the SHOULD gets the
chain check as well as the byte check, a handler that does not
gets only the byte check, and row 14's PASS rests on the byte
check for every handler and on the chain check for handlers that
take the recommendation. The note also states the three-place
naming that the read-only report confirmed in the CDDL and the
code (`prior_state_digest` as preimage key, `state_digest` as
checkpoint field, `checkpoint_digest` as transfer field). The
draft's §5.3.4 / §5.3.4.1 reconciliation is
`dd98192`: §5.3.4 gains the sentence that distinguishes the
`prior_state_digest` map key (`d_(n-1)`) from the
`state_digest` the checkpoint carries (`d_n`) and
the `checkpoint_digest` the transfer restates; §5.3.4.1's
state-format bullet gains the conditional consequence — a
handler that takes the SHOULD can have its chain digest
recomputed from the serialized state, a handler that does not
still satisfies the byte check but its chain check is only as
strong as the state format it chose. The SHOULD is not promoted
to MUST. Row 14's PASS is unchanged: the byte check is
universal and the chain check is conditional, which is what the
row's verdict already says.

The amendment records the δ rule by its own mechanics rather than
by the note's earlier "1/4 floor" phrasing, because the draft's
§13.4 does not carry a 1/4 floor — it carries the δ function and
the two `MUST join` bullets. The phrasing was a note-side
simplification of what the δ function does at `δ = 2`, and the
amendment states the mechanics directly.

**M9.6b merge — wire verbs and state-machine lifecycle.** The first
half of the merge implementation lands: the three coordinator-level
wire verbs (`cluster_merge_propose`, `cluster_merge_accept`,
`cluster_merge_reject`), the proposer-side `pending_merge` and the
acceptor-side `incoming_merge` slots on `ClusterState`, the
`pending_merge_settled` / `note_merge_result` lifecycle, and the
three unit tests the M9.6b merge note's §4 names. The production
caller (`ClusterHandle::merge_if_due`) and the integration test
(`merge_produces_larger_cluster_id`) are the next commit. Row 7
stays FAIL; its Test field gains the three test names and its
Source field gains the three new `ClusterState` methods, with the
note that `should_merge` still has no caller. `MERGE_PROPOSAL_TIMEOUT_S`
is `3 * CLUSTER_HEARTBEAT_S`, per the note's §2d. `MergeDecision`
is unchanged; the note's `Merge { into }` wording is reconciled
in the doc comment and corrected in a separate docs commit.
The acceptor's incoming_merge slot is single-occupancy: a second
proposal while the slot is held returns false and does not displace
the first, so the caller can respond `ClusterMergeReject { reason:
Busy }` as §2c requires. The initial commit wrote the slot as
latest-wins; this commit corrects that.

The production caller and the integration test land in this
commit. `ClusterHandle::merge_if_due` is `should_merge`'s caller,
closing the fourth instance of the name-the-caller class.
`ClusterHandle::plan_merge` evaluates the four §2a rules (rule 1
via `should_merge`, rule 2 via two p90 comparisons, rule 3 via
the `pending_split` slot, rule 4 transitively through §13.2's
threshold). The Busy path the incoming_merge fix made reachable
is exercised by the integration test. Row 7 moves to PASS;
specification status stays incomplete until the draft's §13.4
amendment folds §2 into the draft, which is the next docs
commit.

The draft's §13.4 now records the coordination rules the note's
§2a–§2d defined: the δ size rule stated by its own mechanics
(`δ = 2` requires a strict 4× ratio, `δ = 0` allows
any ratio to win the lower-id tie-break; no separate 1/4 floor is
claimed), the two-p90 RTT comparison with the §13.2 20-sample floor
on both sides, no pending split, and level enforced transitively
through §13.2. Authority is coordinator-to-coordinator: the smaller
cluster's coordinator proposes, the larger's decides, the larger id
survives, and the proposing coordinator broadcasts the accept to
its own members after the accepting coordinator broadcasts to its
members. Safety is first-arrived-wins with a receiver-side
single-occupancy slot and a `busy` reason; stale size is
re-checked at acceptance. Completion is a reachable-at-acceptance
majority; partial migration is completion, not failure; a merge
not complete within `MERGE_PROPOSAL_TIMEOUT` (three
`CLUSTER_HEARTBEAT`) is abandoned and not retried within
the same episode. §14.1 gains the three coordinator verbs;
§3's Protocol Constants Summary gains
`MERGE_PROPOSAL_TIMEOUT`. §13.4 gains a non-normative worked
example. The draft is what closes matrix row 7 to `clear`
and `non-blocking`; the code was what made the row
`PASS`.

**BFT-A item 1 — `OperationOutcome`, the two hooks, and the driver's
chain digest.** The first half of the execution contract lands,
implementing the note at `a5c0dfb` and the draft amendment at
`dd98192`: §1's outcome type, §2's `validate` hook and its two call
sites, §3's infallible `apply`, and §4's `d_n` construction.
`OperationOutcome` is a protocol type in
`quip-core/src/messages/operation_outcome.rs` — a text discriminant
(`success` or `application-failure`), an optional payload bounded at
256 bytes, and a closed, text-keyed CBOR map whose decode rejects an
unknown key, an unknown discriminant, a missing discriminant, a
non-byte payload and an oversize payload with `Error::BadEncoding`.
The two success shapes stay distinguishable on the wire because the
`payload` key is absent rather than empty, which is what §5.3.4's
outcome paragraph requires. `BftHandler` gains `validate`, with no
default — an application that cannot say whether an operation is
valid cannot participate — and both hooks take the deterministic
`OperationContext` carrying the operation index, the view, the
committed sequence and the prior state digest `d_(n-1)`; `apply`
takes the same context and returns an `OperationOutcome` instead of
a `Result`, so an application-level failure is the discriminant and
a panic is the application's bug. The primary validates before
proposing (a rejected operation returns `Error::Bft` and never
builds a round), and a backup validates after verifying the
preprepare and drops it on failure without setting round state,
setting `current`, or advancing the sequence. `BftDriver` maintains
`d_n = SHA-256(QUIP-CBOR(map{outcome, operation,
prior_state_digest}))` from the all-zero genesis, folds it at each
commit in `advance_chain_digest`, and exposes it through
`chain_digest()`; the encoder's canonical sort is what orders the
three keys, and the new
`chain_digest_advances_over_the_committed_sequence` test pins that
by encoding the same map in two different literal orders and
expecting identical bytes, then checking every replica's `d_0`
against a value recomputed outside the driver.

The event shape is unchanged in this commit: `apply_current` reads
the outcome's discriminant and still pushes `BftEvent::Applied` or
`BftEvent::ApplyFailed`, so the four fixtures keep their observable
behaviour — `FailingHandler` now returns
`ApplicationFailure(None)` instead of an `Err`, which is the fixture
the §5 test will use. `start_checkpoint` still calls the handler's
`state_digest()`, because §4 lands the driver's `d_n` as a quantity
of its own and §5's relation is commit 2: the checkpoint carrying
`d_n`, the fixture rewrite that makes a handler's `state_digest()`
agree with it by taking §5.3.4.1's state-format SHOULD, the
`apply_failure_is_a_state_transition` test, and the deletion of
`ApplyFailed` in favour of an outcome-carrying `Applied`. The four
S8 state-transfer tests are unchanged and pass, which is exactly
why the checkpoint's source is unchanged. Matrix row 8 stays FAIL —
its verdict waits on commit 2 — and row 14 is unchanged and
unaffected, since the byte check it rests on is unaffected by a
driver-side digest the transfer path does not yet consume.

Commit 2 (`1e45f18`) lands §5. `bft_checkpoint.state_digest` carries
`self.chain_digest`; both S8 fixtures take §5.3.4.1's state-format SHOULD
by computing `d_n` from the context in `apply` and serializing
`counter ++ d_n`, so `state_digest_of(&state_bytes()) == state_digest()`
and `state_digest()` equals the driver's `d_n` for the same sequence; the
formula lives once, in `chain_digest_for`, called by the driver's
`advance_chain_digest` and by both fixtures, and the fixture-local
`CHAIN_DOMAIN`, `chain_from_state` and `stored_chain` are gone.
`BftEvent::ApplyFailed` is deleted and `BftEvent::Applied` carries
`outcome: OperationOutcome`, one push for both outcomes;
`apply_failure_is_a_state_transition` replaces
`apply_failure_is_an_event_not_an_error`, asserting the failure
discriminant, `d_n` advancing, and sequence 1. The whole-state coverage
reading that row 14's previous justification rested on is retired by the
draft amendment, not by a code change: `d_n` covers (outcome, operation,
prior `d_n`), so a handler's own bookkeeping bytes are outside it by
construction, the class the counter-only substitution test named no longer
exists, and that test is replaced by
`state_transfer_rejects_substituted_chain_digest`, which substitutes the
bytes that carry `d_n` and asserts the same rejection. Row 14 stays PASS
with the re-pointed justification, and the Matrix's Method section gains
its tenth field, `Closure test` — one test per class the verdict depends
on — for row 8 (`apply_failure_is_a_state_transition`) and row 14 (the
byte check and the chain check).

**BFT-A item 1 review pair — record fixes.** The AI1/AI2 pair of
`1e45f18` and the read-only investigation that followed found that
the commit's central change — the checkpoint's source — is exercised
by no test that separates the two potential sources (the fixtures'
`state_digest()` now equals d_n, so reverting `let digest =
self.chain_digest;` to `self.handler.state_digest()` passes every
test in the diff), plus five record-level findings: row 8's `Source`
still described the pre-`35382d9` code, the note's Finding B
paragraph said "for handlers that take the recommendation" while the
code's chain check is universal, `start_checkpoint`'s comment and
`BftCheckpoint::state_digest`'s doc comment were stale on which
quantity the field carries, `docs/apply-contract.md:27` still
presented the retired test name as current, and the commit-2
paragraph had replaced the commit-1 paragraph rather than being
appended to it. The record fixes land at `<SHA>`: row 8's Source
rewritten to the enforced contract; row 14's Verdict and History
restated to the code's universal reading; the note's Finding B
paragraph corrected per its own "the code wins; the note is
corrected" convention; the two doc comments corrected to name d_n;
the apply-contract page's stale test name corrected to the test that
exists; a sentence added to the `Closure test` field's Method
definition covering rows whose Verdict depends on a class of handler
behaviour. The commit-1 entry above is restored verbatim from `35382d9`:
`1e45f18` had replaced it with a summary paragraph rather than
appending to it, which is the hygiene defect the pair named. A
test that proves the source — a fixture whose `state_digest()`
differs from d_n, driving a round and asserting the checkpoint
carries `chain_digest()` — is the next commit, and the row 8
`Closure test` field's one-test-per-class convention is unchanged
because the source is a *second* class the row does not yet name.

Session note: this tree is not rustfmt-clean. A `cargo fmt --all` during
the BFT-A item 1 work reformatted about 95 files; it was reverted
immediately, the two commits were rebuilt onto the pristine files with
each edit asserted to apply exactly once, and neither commit carries a
formatting hunk outside its edited regions. Future instructions check the
`rustfmt --check` delta and do not reformat.


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

Decisions the draft has made where the implementation preceded it, plus
the items still open. The open items are the Category 3 findings recorded
in Outstanding Work; the Spec pass items below are resolved unless marked
otherwise.

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
- **S8 — `bft_state_transfer` ring signature scope.** §5.3.4.1
  says the `ring_signature` covers the state transfer's own signing
  payload. A responder cannot produce a fresh quorum ring signature
  without an extra round trip the spec does not describe. The
  implementation treats the ring signature as the collection of
  `bft_checkpoint` signatures that made the checkpoint stable, and
  verifies it against the `bft_checkpoint` payload for
  `(ring_id, checkpoint_sequence, checkpoint_digest)`. **Resolved** as
  the checkpoint-signatures interpretation; §5.3.4.1 steps 2–3,
  §5.3.4's signing-payload paragraph, and §5.3.4's Ring Signature
  Validation bullets rewritten in `71b52dc`.
- **S9 — initial witness issuance.** §5.3.3 specifies that a
  witness re-issues every 12 hours, but not what triggers its first
  issuance. The implementation uses a labelled placeholder: a node
  issues about a peer once the peer's claim is `Trusted` and no
  statement has been issued in the last 12 hours. **Resolved**; the
  *First Issuance* block added to §5.3.3 in `71b52dc`.
- **S10 — verifier independence.** §5.3.3's "4+ independent"
  implies that a node's own statement about a peer does not count
  toward that node's `Verified` verdict, but does not say so.
  `compute_kt_status` excludes the local NodeId. **Resolved**; the
  *Independence* block added to §5.3.3 in `71b52dc`.
- **S11 — split attempt episode.** §13.5 conditioned the
  `MAX_SPLIT_ATTEMPTS` limit on "fails to find an acceptable cluster"
  without saying when an attempt ends, and `migrate` cleared the counter
  unconditionally, so the failure state never existed. **Resolved** in
  `3a8ae49`: an attempt succeeds or fails at the new cluster's first
  post-migration §13.2 test, the counter resets only on success, and
  `ClusterState::migrate` no longer clears it.
  Row 3's PASS was found premature by the read-only diagnostic; the
  two-axis matrix could not see the defect because the code agreed with
  the draft. The diagnostic is the read-only investigation reported in the
  review thread for `3a8ae49`; it exists only in that thread — no file in
  the tree records it — and it confirmed that `CreateNew`'s first verdict
  is false by construction and identified three candidate fixes. Shape B
  (pending attempts and a settle interval) replaced the first-verdict
  definition — see S14.
- **S12 — expiry filter.** §5.3.3 required re-issue after `valid_until`
  without saying whether an expired statement still counts.
  **Resolved** in `3a8ae49`: it no longer counts, the obligation to
  re-issue being the witness's and the filter the recipient's.
  `WitnessStore::statements_for` already filtered on expiry; the new test
  `statements_for_excludes_statements_past_valid_until` proves it.
- **S13 — quorum as a rule.** §5.3.4 stated the quorum as "5 of 7" and
  "3 of 4" without the rule behind them. **Resolved** in `3a8ae49`: the
  quorum is `n - f`, with those two sizes as specific cases.
  `RingMembership::quorum` already computed `n - f`; no code changed.
- **S14 — pending split attempts and the settle interval.** S11's
  definition made the attempt's outcome the new cluster's *first*
  post-migration §13.2 verdict, and that verdict is false by
  construction: a `CreateNew` cluster has no advertisers at the move, and
  a `JoinNear`/`JoinFar` cluster still sees the samples that made
  `split_due` true at the same timestamp. With "`MUST NOT` reset on
  failure" the counter only climbed and `MAX_SPLIT_ATTEMPTS` became a
  latch. **Resolved** in `c6a371a`: §13.5 now makes an attempt *pending*
  until the first eligible recompute, one `CLUSTER_HEARTBEAT` after the
  migration, so a peer has had the chance to advertise the new
  `cluster_id`; a pending attempt does not count against the cap, and the
  eligible verdict either clears the counter (acceptable) or increments
  it (unacceptable). `ClusterState::pending_split` records the attempt,
  `ClusterHandle::recompute` decides it once `pending_split_settled`
  holds, `apply_split` counts nothing, and a `CreateNew` decision begins a
  fresh pending attempt rather than counting as an outcome. The
  alternative (Shape A) was to clear the counter on a CreateNew decision,
  which would have exempted CreateNew from the failure rule rather than
  making the failure state reachable; the settle interval (Shape B) was
  chosen because it makes the draft's existing distinction work rather
  than changing the rule.
- **S15 — the state-transfer digest pair.** §5.3.4.1 gives
  `bft_state_transfer` two digests: `checkpoint_digest`, the checkpoint's
  chain digest restated so the checkpoint's signature set can be verified
  without carrying the checkpoint message, and `state_hash`, the SHA-256
  of the `state` bytes as transmitted. The implementation carried only
  `checkpoint_digest` and documented it as the digest of `state`, so the
  receiver's byte check compared SHA-256 of the bytes against a field the
  responder filled from `stable.digest`, the chain digest. The two
  quantities agreed only because the test handler defined `state_digest`
  as `sha256(state_bytes)`; a handler whose chain digest is a digest over
  the committed operation sequence, which §5.3.4 specifies, would have
  had every state transfer rejected. **Resolved** in `76c9d0e`:
  `BftStateTransfer` gains `state_hash` in the draft's field order, the
  responder fills it from the bytes it is about to send, and
  `handle_state_transfer_response` verifies the bytes against
  `state_hash` while the ring signature continues to be verified against
  `checkpoint_digest`. Conformance matrix row 14 moves `FAIL` → `PASS`.
  The row was correct before the reviews ran: it recorded the missing
  field and the conflated check when the code still had them, and the
  two reviews of `c6a371a` confirmed the entry rather than discovering
  it. Until S16, `state_hash` was a transport-integrity check only —
  both sides of the byte comparison were supplied by the sender — so the
  row's `PASS` rested on corruption detection, not on authentication;
  S16 binds the bytes to `checkpoint_digest`.
- **S16 — authenticating the transferred state.** A read-only
  investigation of `76c9d0e` found that `bft_state_transfer` authenticates
  only `(ring_id, checkpoint_sequence, checkpoint_digest)`: `state` and
  `state_hash` reach the receiver covered by no signature, and the byte
  check compares two values the sender supplies. A responder holding a
  genuine checkpoint signature could therefore supply arbitrary state
  with a matching `state_hash` and have it installed and applied, with
  `BftEvent::StateTransferApplied` then reporting a `checkpoint_digest`
  the installed state does not commit to. **Resolved** in `ece3e58`:
  `BftHandler` gains `state_digest_of(&self, state: &[u8]) -> Digest`
  with no default, and `handle_state_transfer_response` recomputes the
  chain digest from the transmitted state and rejects the transfer with
  `state transfer chain digest mismatch` before `apply_state`. §5.3.4.1
  step 4 (added in 84c29c4, rewritten here) carries the `MUST` sentences:
  the receiver recomputes and rejects, the chain digest covers every byte
  of the handler's serialized state rather than only the bytes carrying
  the digest, a handler must serialize its chain digest so the
  recomputation returns the digest it reports, and a handler `MUST NOT`
  install a byte the recomputed digest does not cover. The last clause is
  the §5.3.4.1 coverage reading made normative, and it is what the S16
  mechanism needed: the receiver's guarantee is only as strong as the
  handler's choice of coverage, so leaving the reading ambiguous would
  leave the class open to the next handler. The property the
  recomputation relies on — `state_digest_of(&state_bytes()) ==
  state_digest()` — is asserted in the `ChainDigestHandler` fixture, so a
  half-done serialization fails loudly. Tests:
  `state_transfer_rejects_substituted_state_with_matching_state_hash`
  replaces the bytes, repairs `state_hash`, leaves the signed triple
  untouched, and asserts the rejection; it fails against the
  pre-recomputation receiver, which returned `Ok(())`. New here:
  `state_transfer_rejects_counter_only_substitution` differs from the
  genuine state only in the counter bytes `0..8` and is rejected by the
  recomputation, which the whole-state test could not distinguish.
  The contract is `docs/bft-state-transfer-auth.md`. Matrix row 14 stays
  `PASS`; its justification changes, because the bytes are now bound to a
  signed value rather than to a sender-supplied checksum, and it carries a
  verdict history.
  CI: run 39640265939 on 84c29c4, all five jobs success.
  Mutation check: removing the recomputation gives `got Ok(())`;
  restoring it gives the chain-digest mismatch.
  `BftStateTransfer::verify` and `signing_payload` remain uncalled, the
  third instance of the name-the-caller class.
  `state_digest_of` returns the all-zero sentinel for a malformed state; a
  test feeding a wrongly-sized state is deferred with this note.
  The chain digest now covers all 40 bytes of `ChainDigestHandler`'s
  serialized state under the §5.3.4.1 coverage reading; a counter-only
  substitution is rejected by the new
  `state_transfer_rejects_counter_only_substitution` test. The fixture
  domain-separates that digest from `sha256(state)` so the two quantities
  stay distinguishable, which is what
  `state_transfer_distinguishes_chain_digest_from_byte_digest` checks.
  Deliberately not in this commit: the sentinel-branch test, the Frost
  rejection branch, and the `76c9d0e` style findings, which are a `docs:`
  follow-up.

---

## Outstanding work

Organized by the axis it belongs to — correctness, network
completion, validation, protocol design, or release discipline —
rather than by milestone number. The status table above names the
same items under their phase labels (BFT-A, BFT-V, N-Hard, Spec,
M9.5b-c, M9.6b, M9.6c, M9.7, M10.4, M10.5, M11).

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

   **Specified in §5.3.4 (including the outcome wire form);
   implementation pending.** The draft's "Application Execution
   Contract" states (c) under the hook reading: `validate` before
   consensus, `apply` after commitment, the apply output in the state
   digest, a deterministic context, failures recorded as the
   application's outcome, an empty-output default, the digest
   construction, the checkpoint relation, and the outcome encoding —
   text map keys, a text discriminant, a 256-byte payload bound. The
   reference implementation has not caught up — there is no `validate`
   hook, `state_digest` does not include the apply output, and a failure
   is not covered by the checkpoint. The conformance matrix records this
   as row 8: `FAIL` on the code, `clear` in the draft, `non-blocking`
   for submission. The note that argued for (c) is
   `docs/apply-contract.md`, now marked adopted with its open questions
   resolved. The digest binding —
   how the apply output is encoded and bound into the state digest — is
   specified in §5.3.4 and in that note's "The digest binding" section,
   as is the `OperationOutcome` wire form (text keys, a text
   discriminant, a 256-byte payload bound). Row 8 is now `clear` /
   `non-blocking`; its verdict stays `FAIL` because the implementation
   is the next BFT unit. The design contract for that unit is
   `docs/bft-item-1-design.md`. It surfaced a conflict — §5.3.4.1 said
   `checkpoint_digest` was the SHA-256 of the transferred state bytes,
   while §5.3.4 said the same field was the execution-state digest — and
   the draft amendment resolves it by keeping both quantities under the
   names the CDDL already gives them: `bft_checkpoint`'s `state_digest`
   is the chain digest, and `bft_state_transfer` carries the chain digest
   as `checkpoint_digest` alongside a separate `state_hash` for the
   bytes, which a receiver verifies before the state is applied. The
   chain's genesis is the all-zero 32-byte value, stated in the draft and
   provisional. The matrix records the byte digest as row 14 and row 8 now
   depends on it. Row 14 recorded the missing `state_hash` and the
   conflated check while the code still had both defects; the
   implementation has since gained the field, the responder fills it, and
   the byte check compares against it, so the row is `PASS`. The reviews
   of `c6a371a` confirmed that entry rather than discovering it.
   The note's revision (`a5c0dfb`) is the input to the code. The
   draft's §5.3.4 / §5.3.4.1 reconciliation landed at `dd98192`:
   §5.3.4 now distinguishes the `prior_state_digest` map
   key from the `state_digest` the checkpoint carries and
   the `checkpoint_digest` the transfer restates;
   §5.3.4.1's state-format bullet now states the conditional
   consequence without promoting the SHOULD. The code instruction
   reads a draft whose two sections agree on what the checkpoint
   carries and why row 14's PASS is unaffected. BFT-A item 1's
   code followed at `35382d9` and `1e45f18`, and its next step is
   the source-proving test.

   The AI1/AI2 pair of `1e45f18` found that the commit's central change
   — the checkpoint's source — is not proven by any test, because both
   fixtures' `state_digest()` now equals d_n; the follow-up commit that
   adds a divergent fixture and one source-proving test is the last
   piece of BFT-A item 1's implementation. The pair also found the five
   record-level defects the commit-2 subentry records and disposes of;
   those land at `<SHA>`, and the source-proving test follows.

2. **Prepared-operation carry-forward on view change.** The new
   primary does not re-propose operations prepared in an earlier
   view; `bft_new_view.prepared_messages` is emitted empty. A proper
   view change must carry a prepared certificate so the operation
   remains eligible for commitment. Its prerequisite is now clear: the
   quorum rule is stated as `n - f` in §5.3.4, so the certificate's
   threshold is derivable rather than an instance.

3. **Checkpoint carry-forward on view change.**
   `bft_new_view.checkpoint_messages` is emitted empty. The driver
   already retains `stable_checkpoint`, but `maybe_emit_new_view`
   does not encode it. Same shape as (2), and the same clear quorum rule
   applies to the checkpoint it carries.

4. **FROST ring signature verification** in
   `verify_checkpoint_ring_sig`. Requires a group public key on the
   ring; the driver does not hold one today. The individual-
   signature path is complete.

5. **S8 spec revision — RESOLVED in `71b52dc`.** The
   checkpoint-signatures interpretation is now the draft's text; see the
   Spec pass section. The FROST gap in item 4 is unaffected: the draft
   accepts both signature forms, the implementation verifies the
   individual form only.

5a. **Degraded-mode operation admission.** §5.3.4 forbids key rotation,
   revocation, witness membership changes, resource ownership transfers
   and Trusted-CID registrations on a 3-of-4 ring, and `BftDriver` has no
   gate: it accepts any operation kind once it has quorum, without
   distinguishing a degraded ring from a full one. Conformance-matrix
   row 18. Needs a kind check at proposal and a test that a degraded ring
   rejects the five kinds.

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

9. **Peer lifecycle race — RESOLVED by M9.5b-b.** The peer registry
   was keyed by `NodeId` alone; two connections from the same
   `NodeId` could race during cleanup, and the first's teardown
   could remove the second's live entry. M9.5b-b introduces
   `PeerSlot { node_id, generation }`, makes the DHT routing table
   slot-aware, and aborts the previous task on takeover. The
   remaining cleanup concern is the small window between task spawn
   and `JoinHandle` insertion documented in M9.5b-b's module docs;
   it is bounded and non-corrupting.

10. **Bounded DHT queues.** `DhtHandle` uses unbounded channels for
    both inbound and outbound. An authenticated peer can flood the
    queue faster than the application drains it, and memory becomes
    the backpressure mechanism — not what a protocol with §19.4
    DoS bounds wants. Replace with bounded channels and an explicit
    policy: coalesce by `NodeId` for announcements (latest-wins),
    drop newest or drop oldest for other kinds, per-peer limits.

11. **Adversarial DHT routing model.** A DHT is not hard because
    hash-to-bucket is hard; it's hard because an adversary controls
    which nodes you see, which answer, which are close, and which
    witnesses you select. The Coral layer needs explicit answers to
    Sybil resistance, eclipse resistance, routing-table poisoning,
    lookup termination, lookup amplification, inconsistent witness
    responses, stale witness statements, adversarial churn, and
    split-brain cluster membership.

### Protocol design (Spec)

12. **Membership boundaries.** The relationship between "QUIP
    peer," "Coral routing member," "witness candidate," "witness
    ring member," and "BFT ring member" is not specified. The
    protocol lets those sets coincide by accident; a dynamic Coral
    makes that worse. This needs a design document and a section in
    the draft. Especially: how does a changing DHT become a stable
    BFT membership, given that an attacker can influence the DHT?

12a. **Is the draft one document or several?** The draft's sections
    fall into three groups whose dependency on each other is weaker
    than the sections within each group: the federation protocol
    (§4 handshake, §5.1-§5.2 identity and DVV, §12 NAT, §14 verbs,
    §11 tiers, §16 establishment), the trust layer (§5.3 witness trust,
    §5.3.4 BFT, §6 revocation, §18 security model), and the content
    layer (§7 governance, §8 CIDs and merkle range, §9 threshold
    signatures, §13 Coral). Whether this is one Internet-Draft or
    several is a decision the draft must make before submission, and
    it is not one the conformance matrix can answer — the matrix rows
    the code-vs-draft comparison section by section, which is a
    statement about the code, not about the draft's packaging. The
    three groups' boundaries are the sections cited here; the
    decision affects how the draft is submitted and in what order, not
    what the code does.

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

15. **Name hints and trust anchor.** A name hint is a signed
    keyword set embedded in the Coral value blob for a resource
    announcement. The Coral lookup key is
    `SHA-256(NFC(sorted_keywords) || category)`. Hints are not
    lookup keys; the lookup returns a candidate set, and the client
    filters candidates through its own `TrustPolicy`. `register_tcid`
    is gated on `Trusted` or `Verified`; a rejected registration is
    answered with `E_NOT_AUTHORIZED`.

    Open questions: what a fresh client does with untrusted
    candidates (show or hide); whether `Unknown` peers can register
    storage-only TCIDs; whether `pin` / `unpin` follow the same
    trust gate as `register_tcid`; whether witness statements are
    filtered by `TrustPolicy` (and how to resolve the circularity
    that filtering produces the trust that would filter).

15a. **§13.5 split attempt throttle — the cap is unreachable.** The
    draft says: *"If a node fails to find an acceptable cluster after
    `MAX_SPLIT_ATTEMPTS` (RECOMMENDED: 3), it `MUST` create a new
    cluster with a random `cluster_id`."* The implementation never
    evaluates that condition. Every split ends in `migrate`, `migrate`
    clears `split_attempts`, and the counter is therefore 1 at every
    evaluation, so the limit cannot fire and a node can split every
    `heartbeat * 3` indefinitely. The divergence entered in
    `docs/M9.6b-design.md` §4, whose sequence — record the attempt, then
    `migrate`, which clears on success — simplifies the draft's
    *failure* condition into an unconditional reset. The code follows
    the note, so this is a draft-and-note gap, not a code bug.

    The undefined term is **what ends an attempt.** Three readings, each
    coherent:

    a. **The split's aftermath.** Clear the counter when the new
       cluster's `acceptable` is true on its first `recompute`. Failure
       preserves the counter, so a node that keeps splitting into
       unacceptable clusters is throttled. This is the draft read
       literally: an attempt fails when its result is not acceptable.
    b. **One attempt per `split_due` transition.** Clear when the timer
       clears. Simpler, and wrong: a split into an unacceptable cluster
       still resets the counter if the RTTs recover, which is precisely
       the case the throttle exists for.
    c. **One attempt per coordinator term.** Clear on rotation. Ties the
       throttle to an existing protocol clock, but a fast-rotating
       coordinator splits faster — the opposite of throttling under
       stress.

    **Recommendation: (a).** It is the only reading that throttles the
    case the sentence names, and it needs no new state: `acceptable` is
    already computed. §13.5 should define the episode, and
    `docs/M9.6b-design.md` §4 should be corrected with it. Recorded as
    conformance-matrix row 3: verdict `FAIL`, specification status
    `incomplete`.

### Application layer (M9)

16. **M9.5b-c — cluster merge/split and XOR routing — RESOLVED in
    `0464964`.** The sequence completed: parts 2–5 built the NAT and
    candidate path, part 6 closed the relay branch, part 7 derived
    cluster membership and XOR routing, and `0464964` executed the
    split, on top of the cluster-info exchange in `1b0dca5`. Two of the
    three things this entry used to list as remaining are gone with
    their subject: `LiveDht` no longer exists — `DhtHandle` implements
    `DhtClient` directly — and the DHT router routes mesh verbs by XOR
    distance. Coral lookups have been driven by `WitnessDiscovery`
    since M9.5a. Merge (§13.4) was never in this entry's scope and is
    still unexecuted; it is recorded as 16a rather than left as an
    inference from a missing caller.

16a. **§13.4 cluster merge is not executed.** `ClusterState::should_merge`
    can return `MergeDecision::Merge`, and no production code calls it:
    a node never leaves its cluster for a larger neighbour. M9.6b
    deliberately excluded merge (`docs/M9.6b-design.md` §6), so this is
    a scope boundary that has been reached, not a regression — but the
    absence should be findable rather than inferred. What a merge does
    to the member set, the announced tuple and the coordinator is
    undefined, and it needs a design pass of the split's shape: decide,
    move, announce, and let the id filter do the partition. It should
    reuse the exchange for the same reason the split does — the
    announcement is what makes the move observable.

17. **M9.6c — trust bootstrap.** Witness accumulation landed in M9.6a:
    a running node stores `WitnessStatement`s node-wide, serves them
    from the Coral responder, and feeds them to its own
    `ConnectionFlow`, so `Ready(Verified)` is reachable in a network
    with four independent, first-seen-matured witnesses. What remains
    is how a node gets *into* such a network. The bootstrapping problem
    is real: a two-node network can never reach `Verified`, because
    verification requires third parties, so a fresh node needs either a
    configured witness ring or a discovery path to one. That is M9.6c's
    scope.

18. **M9.7 — headless node binary and config.** A `quip-node`
    binary that runs without Flutter: config file (bind address,
    seed source, store path, bootstrap peers), logging, graceful
    shutdown. This is the deployment shape the VPS tier, bootstrap
    nodes, and witness rings depend on. Its prerequisites are met:
    M9.5b-c and M9.6a are landed, so the binary would have routing,
    cluster state and witness storage to configure.

19. **M9.6a follow-up — issuance redundancy.** Each peer task runs
    `maybe_issue` on every steady-loop iteration, so an N-node mesh
    sends each witness statement N−1 times; the `(subject, witness)`
    dedupe at the receiver makes the repetition harmless, but the
    outbound traffic is N−1× what it needs to be. A later milestone
    can hoist issuance above the peer tasks, into one node-wide
    timer. Recorded here so the redundancy is not rediscovered as a
    surprise.

20. **Inbound dispatch is duplicated across three phases — LANDED in
    Pre-6b.** The verb handlers in `run_nat_phase`, `run_discovery_phase`
    and `run_peer_loop` were three copies of the same dispatch, and each
    copy had silently dropped a verb the others handled: the relay path
    in M9.5b-c part 6, `AnnounceWitness` and Coral verbs during the NAT
    phase in M9.6a's follow-up. Pre-6b replaced them with one classifier
    (`classify_inbound`) and one applier (`apply_inbound`), with
    `InboundOptions` as the only per-phase variation. M9.6b's fourth
    inbound phase is a parameterised call, not a fourth copy.

### Interface layer (M10)

21. **M10.4 — platform signer shim.** A `SignerBackend` trait in
    `quip-node` and one implementation per platform: Kotlin/JNI for
    Android, Swift for iOS, C ABI for Linux/Windows. Hardware-backed
    Ed25519 is available on Android 13+ with TEE or StrongBox,
    absent in the iOS Secure Enclave (P-256 only), and software-only
    on Linux. The shim exposes the fallback as a first-class case
    and reports which backing a key uses. The trait belongs in
    `quip-node`, not `quip-node-ffi`, because a hardware-backed key
    cannot be coerced into `Ed25519Signer::from_seed`'s
    `[u8; 32]` shape — the private bytes never exist.

22. **M10.5 — end-to-end verification on Android.** The smoke tests
    from M10.1 through M10.3 re-run against an Android device,
    exercising the platform signer shim.

### Browser substrate (M11)

23. **Local gateway.** A `quip-daemon` or FFI-exposed server that
    answers `http://localhost:PORT/quip/<cid>` and
    `http://localhost:PORT/hint/<name>`, so any existing browser can
    resolve QUIP content without a bespoke browser. This is the tier
    that makes the "standards for content distribution" story real:
    URL shape, content-type negotiation, trust-policy enforcement,
    all reachable from a Firefox tab.

24. **Content layer.** Trusted CID wiring (inbound `register_tcid` →
    verify → policy → `GovernanceStore`), a CBOR value-blob schema
    for what responders publish as Coral values, and the name-hint
    mechanism that lets a client go from a hint string to a set of
    CIDs via Coral lookup.

25. **Content-type metadata.** CIDs do not carry MIME types. The
    options are pin-time metadata, byte sniffing, or address hints.
    Pin-time metadata is cleanest and mirrors how IPFS handles it.
    The alternative is serving everything as
    `application/octet-stream`, which makes the gateway useless for
    anything but downloads.

26. **The VPS tier.** A user-controlled always-on anchor. Not a new
    protocol layer: the same headless build (M9.7), deployed
    differently. Acts as rendezvous point, relay candidate,
    availability anchor, and custodian of witness statements. Also
    the mechanism by which a mobile client can be woken for sync —
    the VPS is a push provider, using APNs and FCM as
    notification-only channels.

27. **No rendering format.** The browser substrate renders standard
    web formats (HTML, CSS, JS, images, media) via the existing
    browser engine. QUIP does not define a markup language. Its
    contribution is the resolver, the address scheme, and the trust
    chrome around the content.

### FFI / API stabilization

28. **Node lifecycle.** Duplicate connections, reconnect behavior,
    shutdown ordering, FFI-safe ownership and lifetimes. M9.5b-b
    resolves the peer-generation race; the identity type boundary
    (Spec 14) is still open. The FFI surface should not be frozen
    until both are resolved.

29. **`NodeEventFfi::Message` decoding.** `Message` and `Datagram`
    carry `verb: String` + `raw: Vec<u8>`; a typed decoder
    (`decodeMessage(raw)`) is needed so Dart consumers do not
    reimplement CBOR parsing.

### Housekeeping

30. **Release tag.** `git tag v0.1.0-m9.5b-c && git push origin
    v0.1.0-m9.5b-c`, then `v0.1.0` once BFT-A lands. S8 was resolved in
    the draft in `71b52dc` and no longer gates the tag; the FROST
    implementation gap (BFT-A item 4) remains under BFT-A.

31. **GitHub metadata.** Repository description and topics. The
    README currently links to this file; the repo description is
    still blank.

32. **Move the `Send + Sync` bound onto `quip_core::time::Clock`.**
    The bound currently sits on `quip-node`'s `SharedClock` alias
    because widening the trait is a breaking change. Every
    reasonable clock satisfies the stronger bound; the alias should
    eventually become unnecessary.

33. **M9.6a note follow-up.** `docs/M9.6a-design.md` predates three
    things the implementation needed: `WitnessStore::accepts` (split
    out of `ingest` so the KT seam can feed the flow a statement the
    store already holds), `issue_statement` (the statement builder),
    and `WITNESS_VALIDITY_S` (the validity window). A `docs:` commit
    brings §2, §4, and §7 into line.

34. **Draft contribution log.** The reference implementation was
    developed against earlier drafts; the resolutions that became
    revision 03 are documented in the spec-pass section above. A
    short paragraph in the draft's doc history — one line per
    resolution, no reference to the reference implementation —
    would close the loop between what the draft now says and why.

35. **Outstanding Work cross-references are numeric.** Item numbers
    shift whenever an item is inserted, and a citation like "item 20"
    in `docs/M9.6a-design.md` is stale the moment a later commit
    inserts above it. Move the Outstanding Work list to named anchors
    (`<a id="ow-inbound-dispatch"></a>` or equivalent) and keep the
    numbers as display text only. Citations become anchors, which do
    not shift. Do this before the next milestone that cites an item
    by number.

36. **rustfmt drift across the tree.** The tree is not clean under the
    installed `rustfmt`: a `cargo fmt --all` during the BFT-A item 1
    work reformatted about 95 files and had to be reverted. CI has no
    fmt job; adding one is a separate decision, because the first run
    would reformat the whole tree rather than check it. Until then,
    instructions check the `rustfmt --check` delta and do not reformat.

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
| `quip-net/src/nat.rs` (`NatEvent::RelayedPathEstablished`) | M9.5b-c | relayed-path terminal outcome |
| `quip-net/src/nat.rs` (`NatTraversal::on_relay_result`) | M9.5b-c | sole producer of `RelayedPathEstablished` |
| `quip-net/src/nat.rs` (`SessionState::relay_outcome`) | M9.5b-c | concluded-relayed-session marker |
| `quip-net/src/nat_driver.rs` (`NatDriver::on_relay_result`) | M9.5b-c | driver passthrough |
| `quip-net/src/nat_driver.rs` (`NatDriver::on_dht_result`) | M9.5b-c | verified-DhtResult routing arm |
| `quip-net/src/nat.rs` (`NatTraversal::force_relay_for`) | M9.5b-c | per-session relay forcing |
| `quip-net/src/nat.rs` (`NatConfig::force_relay`) | M9.5b-c | per-node relay forcing default |
| `quip-net/src/transport.rs` (`ConnectionDriver::local_addr`) | M9.5b-c | endpoint bind address accessor |
| `quip-node/src/lib.rs` (`try_serve_relay_discovery`) | M9.5b-c | signed relay_response for inbound discovery |
| `quip-node/src/lib.rs` (`NodeConfig::force_relay`) | M9.5b-c | force sessions onto the relay branch |
| `quip-node/src/lib.rs` (`NodeConfig::relay_capable`) | M9.5b-c | opt-in relay responder |
| `quip-net/src/cluster.rs` (`percentile`) | M9.5b-c | nearest-rank percentile helper |
| `quip-net/src/cluster.rs` (`ClusterState::update_size`) | M2, M9.5b-c | §13.6 size-estimate input |
| `quip-net/src/cluster.rs` (`ClusterState::note_rtt_observation`) | M2, M9.5b-c | split-timer input |
| `quip-net/src/cluster.rs` (`near_cluster_id`, `far_cluster_id`, `center_lookup_key`, `fresh_cluster_id`) | M9.6b | §13.5 id derivation, `crypto`-gated |
| `quip-net/src/cluster.rs` (`ClusterState::migrate`) | M9.6b | the local move a split performs |
| `quip-net/src/crypto.rs` (`sha256_bytes`) | M9.6b | unwrapped digest for id derivation |
| `quip-node/src/dht.rs` (`PeerRecord::rtt_ms`) | M9.5b-c | raw RTT sample field |
| `quip-node/src/dht.rs` (`DhtHandle::note_rtt`) | M9.5b-c | slot-scoped RTT sample |
| `quip-node/src/dht.rs` (`DhtHandle::closest_to`) | M9.5b-c | XOR-distance routing selection |
| `quip-node/src/dht.rs` (`Outbound::key`) | M9.5b-c | mesh-verb routing key |
| `quip-node/src/cluster.rs` (`ClusterHandle`) | M9.5b-c | node-level cluster state |
| `quip-node/src/cluster.rs` (`ClusterView`) | M9.5b-c | derived membership snapshot |
| `quip-node/src/cluster.rs` (`NeighbourClusters`, `is_cluster_member`) | M9.6b | neighbour tuples, read-time id filter |
| `quip-node/src/cluster.rs` (`SplitPlan`, `plan_split`, `apply_split`, `split_if_due`) | M9.6b | split evaluation and execution |
| `quip-node/src/dht.rs` (`publish_cluster_info`) | M9.6b | broadcast of the local tuple |
| `quip-node/src/tasks.rs` (`cluster_task`) | M9.6b | heartbeat, announce, split trigger |
| `quip-node/src/lib.rs` (`Node::cluster`, `Node::cluster_view`) | M9.5b-c | cluster accessors |
| `quip-node/src/lib.rs` (`run_nat_phase`) | M9.5b-c | NAT phase driven through `NatDriver` |
| `quip-node/src/lib.rs` (`NatPhaseOutcome`) | M9.5b-c | NAT phase terminal outcome |
| `quip-node/src/lib.rs` (`socket_to_address`, `local_ip_address`) | M9.5b-c | socket/address conversion |
| `quip-node/src/lib.rs` (`probe_candidate`) | M9.5b-c (parts 5–6) | real candidate dial |
| `quip-node/src/lib.rs` (`Node::signer_for_peers`) | M9.5b-c | signer threading for peer tasks |
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
| `quip-net/src/transport.rs` (`RTT_SAMPLE_EPSILON`) | M9.5b-b | RTT-sample gating threshold |
| `quip-net/src/transport.rs` (`ConnectionDriver::rtt`) | M9.5b-b | gated RTT accessor |
| `quip-net/src/transport.rs` (M5.2–M5.4 test groups) | M5 | handshake/capability, T0/T1/T3, Key Claim |
| `quip-net/src/transport.rs` (M6.1 section) | M6.1 | §16 integration tests |
| `quip-net/src/transport.rs` (M7 section) | M7 | rate limiting |
| `quip-net/src/transport.rs` (M9.5b-b section) | M9.5b-b | RTT observation gating tests |
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
| `quip-node/src/lib.rs:1` | M9.1–M9.4a, M9.5b-b, M9.5b-c | `Node` type, store, clock, DHT routing, peer registry, lifecycle |
| `quip-node/src/lib.rs` (`NodeConfig`) | M9.1, M9.2, M9.4a, M9.5b-c | node configuration, clock, and capabilities |
| `quip-node/src/lib.rs` (`Node::bind`) | M9.1 | server bind + accept loop |
| `quip-node/src/lib.rs` (`Node::connect`) | M9.1, M9.4a, M9.5b-b | dial + inline handshake + slot registration |
| `quip-node/src/lib.rs` (`Node::store` and direct helpers) | M9.2 | store access and pin API |
| `quip-node/src/lib.rs` (`try_auto_serve_pins`) | M9.2 | pin/unpin/query_pins auto-serve |
| `quip-node/src/lib.rs` (`dht_router_task`) | M9.4a, M9.5b-c | peer-scoped and XOR mesh routing |
| `quip-node/src/lib.rs` (`run_peer_loop` DHT branch) | M9.4a | intercept §12 NAT verbs |
| `quip-node/src/dht.rs:1` | M9.4a, M9.5b-b, M9.5b-c | live `DhtClient`, slot-aware routing table, lifecycle mirror |
| `quip-node/src/dht.rs` (`LiveDht`) | M9.4a | DHT client implementation |
| `quip-node/src/dht.rs` (`DhtHandle`) | M9.4a, M9.5b-b, M9.5b-c | node-owned DHT handle |
| `quip-node/src/dht.rs` (`PeerRecord`) | M9.4a, M9.5b-b, M9.5b-c | routing-table entry shape with slot + lifecycle |
| `quip-node/src/dht.rs` (`dht_result_from`) | M9.4a | §12 verb verification and conversion |
| `quip-node/src/dht.rs` (`Outbound`) | M9.5b-c | peer-scoped vs mesh outbound |
| `quip-node/src/dht.rs` (`note_session`, `forget_session`) | M9.5b-c | session-to-peer routing |
| `quip-node/src/lib.rs` (`run_establishment`) | M9.4b, M9.5b-c | §16 flow driven per peer, lifecycle transitions, NAT via `NatDriver` |
| `quip-node/src/lib.rs` (`derive_session_id`) | M9.4b | symmetric session-id derivation |
| `quip-node/src/lib.rs` (`peer_run`) | M9.4b, M9.5b-b, M9.5b-c | establishment + steady-state entry point, slot-guarded, closing transition |
| `quip-node/src/dht.rs` (`DhtHandle` impl `DhtClient`) | M9.4b | shared handle as DhtClient |
| `quip-node/src/discovery.rs:1` | M9.5a | shared Coral discovery client |
| `quip-node/src/discovery.rs` (`DiscoveryHandle`) | M9.5a | shared handle |
| `quip-node/src/discovery.rs` (`respond_to_lookup`) | M9.5a | Coral server role |
| `quip-node/src/discovery.rs` (`respond_to_spillover`) | M9.5a | spillover server role |
| `quip-node/src/lib.rs` (`run_discovery_phase`) | M9.5a | flow witness phase driver |
| `quip-node/src/lib.rs` (`make_lookup_paths`) | M9.5a | path selection |
| `quip-node/src/lib.rs` (`handle_discovery_event`) | M9.5a | Coral verb routing |
| `quip-node/src/lib.rs` (`NodeConfig::signer`) | M9.5a | shared Ed25519 signer |
| `docs/M9.5b-design.md:1` | M9.5b-a | frozen contracts for NAT and cluster integration |
| `docs/conformance-matrix.md:1` | M9.6b | clause → source → test matrix; nine-field schema, eighteen rows, dependency edges, coverage inventory |
| `docs/apply-contract.md:1` | BFT-A 1 | the three execution contracts, compared, with a recommendation |
| `docs/bft-item-1-design.md:1` | BFT-A 1 | execution contract: outcome type, validate hook, chain digest, two-digest conflict |
| `quip-node/src/peer.rs:1` | M9.5b-b, M9.5b-c | peer slot and lifecycle vocabulary |
| `quip-node/src/peer.rs` (`PeerSlot`) | M9.5b-b | generation identity |
| `quip-node/src/peer.rs` (`PeerLifecycle`) | M9.5b-b | §2a transition table |
| `quip-node/src/peer.rs` (`PeerLifecycle::is_routing_eligible`) | M9.5b-c | routing-eligibility predicate |
| `quip-node/src/peer.rs` (`TransitionError`) | M9.5b-b | rejected-transition error type |
| `quip-node/src/lib.rs` (`Registry`) | M9.5b-b, M9.5b-c | peer handles + persistent generation counters + lifecycle |
| `quip-node/src/lib.rs` (`register_peer`) | M9.5b-b | slot allocation and prior-task abort |
| `quip-node/src/lib.rs` (`unregister_peer`) | M9.5b-b | slot-scoped cleanup |
| `quip-node/src/lib.rs` (`Registry::set_lifecycle`) | M9.5b-c | authoritative transition |
| `quip-node/src/lib.rs` (`Registry::routing_eligible_slots`) | M9.5b-c | derived slots |
| `quip-node/src/lib.rs` (`set_peer_lifecycle`) | M9.5b-c | single-writer transition path |
| `quip-node/src/lib.rs` (`Node::peer_slot`) | M9.5b-b | live generation query |
| `quip-node/src/lib.rs` (`Node::peer_lifecycle`) | M9.5b-c | live lifecycle query |
| `quip-node/src/lib.rs` (`Node::routing_eligible_peers`) | M9.5b-c | public derived eligibility set |
| `quip-node/src/witness.rs:1` | M9.6a | witness store and issuance |
| `quip-node/src/witness.rs` (`WitnessStore::ingest`) | M9.6a | dedupe-on-ingest with later-timestamp wins |
| `quip-node/src/witness.rs` (`WitnessStore::statements_for`) | M9.6a | responder query, 6-hour rule at query time |
| `quip-node/src/witness.rs` (`WitnessStore::maybe_issue`) | M9.6a | placeholder issuance policy |
| `quip-node/src/claim_log.rs:1` | M9.6a | first-seen fact, shared by trust and witness store |
| `quip-node/src/trust.rs` (`TrustPolicy::trusted_peers`) | M9.6a | subject enumeration for issuance |
| `quip-node/src/tasks.rs` (`run_discovery_phase` seam 1, 2) | M9.6a | store ingress + requester-side KT wiring |
| `quip-node/src/tasks.rs` (`run_peer_loop` seam 3) | M9.6a | steady-loop store ingress |
| `quip-net/src/establishment.rs` (`compute_kt_status`) | M9.6a | verifier independence (excludes local NodeId) |
| `quip-net/src/message.rs` (`dispatch_inbound`) | Pre-6b | parse + capability check |
| `quip-node/src/tasks.rs` (`parse_inbound`) | Pre-6b | sole inbound parse site |
| `quip-node/src/tasks.rs` (`classify_inbound`) | Pre-6b | one dispatch order, phase-parameterised |
| `quip-node/src/tasks.rs` (`apply_inbound`) | Pre-6b | the action set |
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
consumed in M9.5b-c), `message.rs` BFT arms (M4), `bft.rs` (M4),
`xtask/` (M6.2), `.github/workflows/ci.yml` (M6.3). Tagging on the
next touch is cheap.

**M9.5b-c note.** M9.5b-c is landed. Its scope included cluster
membership derivation and XOR-distance routing, both landed in part 7.
Cluster split *execution* — choosing a split target and migrating the
cluster id — needed neighbour `ClusterInfo` exchange, which no peer
reported at the time; it was deferred to M9.6b and landed there
(`1b0dca5` for the exchange, `0464964` for the split). The deferral was
recorded in the milestone row's scope cell, not in its status.