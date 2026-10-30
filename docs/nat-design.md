# NAT traversal — the problem and its mechanism

**Status:** design note. It states the problem §12 solves and the
mechanism that solves it. It does not change the draft; a follow-up
`docs:` commit folds the problem statement and the two-layer relay
principle into §12 and §19. It implements the frame's D4 (a durable
identity is what a routable address attaches to) and C2 (relay
encryption is two layers).

This note exists because the draft's §12 has six mechanisms and no
statement of the problem they solve. A reader of §12.1–§12.3 learns
what a `ConnectivityAnnounce` carries, what a `RelayResponse` echoes,
and what a candidate's priority is, and never learns why any of it is
necessary. A mechanism without its problem cannot be checked for
completeness, because nothing says what a complete set would have to
cover, and it cannot be checked for correctness, because nothing says
what it is correct *with respect to*.

---

## §1 — The problem

Two nodes behind unknown NATs must establish a direct path without a
centralised address-discovery service, and when direct fails, must fall
back to a relay path that neither node controls.

Three parts of that sentence are load-bearing:

- **Unknown NATs.** Neither node knows the other's external address, and
  neither knows its own without asking. The draft forbids STUN — §12.1,
  line 3213: "Implementations MUST NOT depend on STUN or any centralized
  address-discovery service", restated in A.5 at 6168 ("require STUN or
  any centralized address-discovery service") and named as the failure
  QUIP is answering at 6365 ("NAT traversal was centralized: STUN/TURN
  required") — so the external address must come from other peers.
- **No centralised discovery.** The Coral DHT is the discovery
  mechanism, and it is sharded by XOR distance: 167–169 ("Kademlia XOR
  distance for routing within clusters"), 185–188 (identity determines
  the DHT routing key), 986–1004 (the metric defined: `distance(a, b) =
  a XOR b` over 32 bytes), repeated for relays at 3418 and 3430. No
  single node holds every address.
- **A relay path neither node controls.** When direct fails, a relay
  forwards. The relay is an ordinary node that advertises capability —
  §12.1's `ConnectivityAnnounce` carries `relay_capable: bool` and
  `capacity: uint` at 3154–3155 — and it is a durable identity, because
  the Coral DHT assigns routable addresses to durable identities and an
  ephemeral identity has no routable address to return to (the frame's
  D4). The *supplier* role name is the frame's, not the draft's: a
  case-insensitive search for `supplier` over the draft returns nothing.
  The relay must not be able to read the payload it forwards (the
  frame's C2).

The draft's §12 has six mechanisms — address discovery, connectivity
announcements, candidate exchange, relay discovery, relay hop, HPKE
sealing — and states them without stating the problem they solve. This
note states the problem so the six mechanisms have a parent, and so a
reader can see which mechanism answers which part.

---

## §2 — The mechanism, by part

### §2a — Address discovery

A peer learns its own external address by asking, and publishes what it
learned. `NatDriver` (`quip-net/src/nat_driver.rs`) wraps the
`NatTraversal` state machine and routes its outbound requests: the DHT
side goes through the `DhtClient` trait (`publish_connectivity`,
`lookup_connectivity`, `publish_candidates`, `lookup_candidates`, and
the relay lookup), and the peer side goes to the connection. Inbound DHT
results and inbound peer messages feed back into the state machine. The
trait is synchronous and drained by `DhtClient::poll`, so a real
distribution runs the network in a background task; the driver does not
assume a DHT implementation.

The observations themselves are held in `AddressState`
(`quip-net/src/nat.rs`): one latest observation per observer
(`observations: BTreeMap<NodeId, Address>`), the derived `external`
address, the inferred `nat_type`, and a bounded `change_history` of
recent address changes. `observe_at(observer, observed, now)` records an
observation and recomputes the derived fields; `external()`, `nat_type()`,
`port_preservation()` and `recent_address_changes(now, window_ms)` read
what was derived. The external address is therefore an inference over
peers' reports, not a local fact — which is what §12.1's "DHT-observed
external address" (3150) means, and why the field is published rather
than merely stored.

What is published is `ConnectivityAnnounce` (`quip-net/src/nat_wire.rs`):
`node_id`, `external_addr`, `internal_addr`, `nat_type`,
`port_preservation`, `relay_capable`, `capacity`, `timestamp`, and a
signature by `node_id` — the draft's field list at 3146–3158, with the
signature convention the draft fixes at 3157. The re-announce cadence
lives in `NatConfig::reannounce_interval_ms()`, against the draft's
`CONNECTIVITY_TTL` of 600 s and its 480 s re-announce recommendation
(3216–3218).

Two of the draft's conditions have no procedure behind them in the code,
and this note does not invent one: the draft says a peer may use "the
most consistent result" of several observations (3211–3212), which the
code does not implement as a consistency rule — it keeps the latest
observation per observer and recomputes — and the NAT-type table at
3162–3207 has no classification procedure, while `AddressState` derives
`nat_type` from the observations it holds.

### §2b — Candidate exchange

A session belongs to exactly two peers, and candidates belong to a
session. `CandidateTable` (`quip-net/src/nat.rs`) is constructed per
`(peer, session_id)`: `add_local` and `add_remote` insert candidates
under a cap, `prune(now, ttl_s)` drops the unverified ones past the
timeout, `next_to_probe(now, ttl_s)` returns the one to try,
`record_probe(addr, success)` records the result, and `pending_probes()`
counts what is in flight. A `Candidate` is `{addr, kind, priority,
foundation, component}`, with `kind` taking the draft's four values
(0 host, 1 server-reflexive, 2 relayed, 3 peer-reflexive) and `priority`
application-defined, as the type's own documentation says.

On the wire, `CandidateAnnounce` is published and looked up by
`(target, session_id)` through the same `DhtClient`, which is what makes
the exchange two-party and session-scoped: a candidate announced for one
session is not a candidate for another. The draft's §12.3 (`nat-ice`,
section start 3440) fixes the session identifier (3454), the four type
values (3462–3463), the priority field (3464), the recommended ordering
(3482), the probe's non-retention rule (3532–3534), and
`CANDIDATE_TTL` (3565–3566, value at 3574).

### §2c — Relay discovery and selection

When no candidate works, the session asks the DHT for relays that can
reach the target. `RelayDiscovery` carries a fresh 16-byte `request_id`,
the `requester`, the `target`, `max_hops` (defaulting to
`RELAY_HOP_LIMIT`, 2, fixed at 441), a timestamp, and a signature;
`NatDriver::build_relay_discovery` builds it from the `request_id` the
state machine issued and signs it with the application's `Signer`,
because the DHT is not the requester. `RelayResponse` echoes both the
`request_id` and the `target` — the draft's rules at 3285, with the
discard rules at 3290 and 3293–3295 — so correlation needs no out-of-band
state: the request id demultiplexes, and the echoed target rejects a
response about somebody else's peer.

The selection side is `RelayManager` (`quip-net/src/nat.rs`).
`offer(entry, target)` indexes a `RelayEntry` by `relay_id` and records
the targets it claims to reach, evicting least-recently-offered entries
when the manager is at capacity; `find(target)` returns the relays that
claim that target; `best_for(target)` returns the best one; and
`best_chain(target, max_hops)` returns up to `max_hops` of them. The
ordering is fixed and total: XOR distance from the relay's `relay_id` to
the target, then available capacity (descending), then `cost`
(ascending), then observed reliability (`RelayRecord`'s success and
failure counters, read as `reliability_permille()`). Availability is a
filter before it is a ranking — a relay with no room left is not a
candidate at all.

That ordering is narrower than the draft's. The draft's §12.2 says a
relay is ranked by an application-defined cost metric, "lower is better"
(3269, 3309); the code ranks by XOR distance to the target first and uses
`cost` only as a tie-break. The two agree on the direction and disagree
about the primary key, and the divergence is recorded here rather than
smoothed over: an implementation that followed the draft's cost-first
reading would select a different relay than this one does.

One finding is not merely unanswered but unimplemented: `RelayResponse`
carries a signature with no identifiable signer — the audit's
UNIMPLEMENTABLE at 3261 — and the code's struct is the draft's, so it has
no signer field either (`request_id`, `target`, `requester`, `relays`,
`timestamp`, `signature`). Adding a signer is a wire change; it is
deferred (§4), not worked around.

### §2d — The relay hop and the two layers (C2)

A relay forwards an HPKE envelope. It can decrypt the envelope's hop
layer; it cannot decrypt the application's payload, which is encrypted
under a key the relay does not hold. The two layers are distinct and the
relay sees only the first.

The hop layer is the draft's, §12.2 at 3354–3390: `encrypted_key` is an
HPKE `mode_base` seal with `DHKEM(X25519, HKDF-SHA256)` /
`HKDF-SHA256` / `ChaCha20Poly1305`, `info = "QUIP-relay-hop-v1"`, empty
`aad`, and a recipient key that is the X25519 key derived from the
relay's Ed25519 `NodeId` through the RFC 8032 §4.1.2 birational map. The
plaintext is the symmetric traffic key for this hop followed by the
trailing portion of the chain, and `hops` is ordered from the sender
outward, so each relay learns exactly one thing it needs: the next hop
and the key for its own hop. The implementation is
`HpkeRelayHopSealer` (`quip-net/src/relay_hpke.rs`), with
`ed25519_to_x25519` for the key conversion; `mode_base` rather than a
sender-authenticated mode because the chain as a whole is signed by its
sender, so a per-hop sender authentication would be redundant.

The application layer is above it: the payload the relay forwards is
protected by QUIC+TLS 1.3, and the relay holds no key for it. The two
layers answer §19.1's statement at 5381 — "All traffic through relays
MUST be encrypted with the same QUIC+TLS 1.3 protection used for direct
connections. Relays cannot decrypt or inspect traffic" (5398)
unreconciled with a hop layer the relay demonstrably can decrypt (the
audit's AMBIGUOUS at 5381). The reconciliation is C2's: the relay
decrypts the envelope's hop layer, because that is how it learns where to
forward, and it cannot decrypt the payload, because the payload's key is
not in the envelope. "Cannot decrypt" (5398) is true of the payload and
false of the envelope, and the draft says it without the distinction.

### §2e — Why the DHT identity is durable (D4)

The Coral DHT assigns routable addresses to durable identities; an
ephemeral identity has no routable address to return to. `dht_id`
therefore equals `NodeId` in v1, and the Claim carries it explicitly so a
future rotation can diverge. A rotation rotates both; the DHT address
assignment lapses and peers re-resolve (the frame's D4).

For this note the consequence is concrete: a published
`ConnectivityAnnounce` is keyed by `node_id` (3149), a relay is addressed
by its `relay_id` (3309's ranking, and `RelayEntry.relay_id` in the
code), and a hop's recipient key is derived from that same Ed25519
identity. Every address in §2a–§2c hangs off a durable key, which is why
the identity is the thing that must not rotate casually, and why a
rotation re-resolves rather than republishes.

---

## §3 — What the note does not change

- The draft's §12 and §19 text. The note records the problem and the
  two-layer principle; the follow-up `docs:` commit folds them into the
  draft.
- The code. The note describes what the code does; it does not propose a
  code change.
- **Where the code and the draft diverge — or both fail — the note says
  so rather than describing the code as the draft.** Four cases are
  measured:
  `RelayResponse` has no signer field, so the draft's UNIMPLEMENTABLE at
  3261 is unimplemented in the code too (§2c); the NAT-type table has no
  classification procedure while `AddressState` derives a type anyway
  (§2a); "the most consistent result" (3211–3212) is not a rule the code
  applies — it keeps the latest observation per observer (§2a); and relay
  selection is XOR-distance-first with `cost` as a tie-break, where the
  draft ranks by cost (3269, §2c).
- **What the code does not do at all.** No code path classifies a NAT
  type from a defined procedure, tests a relay with the draft's test
  packet and acknowledgement (3322–3324), scores a relay's reputation by
  a formula (3325–3327), or rotates relays on a period (3426). Those are
  the draft's procedures, and the code has counters and timers where the
  draft has recommendations without definitions.

---

## §4 — What the note defers

- **The proximity threshold.** D7's merge trigger and A06's §13.4
  transcription both need a proximity threshold the draft does not
  define. The draft has the metric and the prose and no threshold: the
  XOR distance metric is defined at 986–1004 and repeated at 167–169,
  185–188, 3418 and 3430, and 3588 states the clustering principle
  ("organizes peers into hierarchical clusters based on network
  proximity"), but no section fixes a proximity threshold, and the phrase
  "proximity threshold" does not occur in the draft. The threshold is
  the transcription's item, not this note's.
- **Cross-level NAT.** The draft's §12 names no level restriction. A
  case-insensitive search for `level` over §12's line range (3095–3440)
  returns one line, and it is about a signature ("verify the sender's
  signature at the chain level, not …"); `ClusterLevel` does not appear.
  There is nothing to defer, and the absence is recorded because the
  merge note's rule 4 makes level a merge condition and a reader may
  expect NAT traversal to be level-aware. It is not, in the draft or in
  the code.
- **The draft audit's remaining NAT findings.** The audit records 35
  non-CLEAR findings across §12 and §19.1. This note answers one of them
  — 5381's unreconciled relay-encryption MUST, answered by §2d's
  two-layer statement — and the mechanism sections describe the
  behaviour the other 34 attach to without deciding them. Each is listed
  with its draft line and its disposition:

| Draft line | Verdict | Disposition |
|---|---|---|
| 3133–3137 | SILENT | deferred — `Address` field values have no receiver rule |
| 3151 | SILENT | deferred — `internal_addr` "(if known)" is mandatory with no unknown form |
| 3152 | AMBIGUOUS | deferred — no classification procedure; §2a records the derived type |
| 3155 | INCOMPLETE | deferred — no `capacity` value when `relay_capable` is false |
| 3211–3212 | AMBIGUOUS | deferred — "most consistent" undefined; §2a records the code's rule |
| 3216–3217 | SILENT | deferred — no rule for holders after TTL expiry |
| 3218 | AMBIGUOUS | deferred — 480 s fixed or default, against 3222–3225 |
| 3222 | INCOMPLETE | deferred — no churn metric; §2a records `change_history` |
| 3224 | AMBIGUOUS | deferred — "stable networks" undefined |
| 3225 | AMBIGUOUS | deferred — "high-churn" tied to the undefined metric at 3222 |
| 3261 | UNIMPLEMENTABLE | deferred — no signer in `RelayResponse`; §2c records the code matches |
| 3269 | AMBIGUOUS | deferred — cost units; §2c records the code's ranking |
| 3319–3321 | AMBIGUOUS | deferred — "critical operations" never enumerated |
| 3322–3324 | INCOMPLETE | deferred — test-packet format, acknowledgement, timeout undefined |
| 3325–3327 | INCOMPLETE | deferred — no scoring formula; §2c records the counter ratio |
| 3328–3329 | AMBIGUOUS | deferred — "fails" undefined |
| 3330–3332 | INCOMPLETE | deferred — no detection criterion or action |
| 3408 | AMBIGUOUS | deferred — "high-priority" undefined |
| 3424 | AMBIGUOUS | deferred — same "critical operations" as 3319 |
| 3425 | INCOMPLETE | deferred — same gap as 3330 |
| 3426 | INCOMPLETE | deferred — no rotation period |
| 3427 | INCOMPLETE | deferred — no rate, window, or action on exceed |
| 3454 | INCOMPLETE | deferred — uniqueness scope; §2b records `(peer, session_id)` |
| 3482 | INCOMPLETE | deferred — no priority formula; §2b records priority as application-defined |
| 3494–3495 | AMBIGUOUS | deferred — could contradict the ordering at 3492 |
| 3525–3528 | AMBIGUOUS | deferred — effect of a failed path validation undefined |
| 3558–3560 | AMBIGUOUS | deferred — "sensitive traffic" undefined |
| 3561–3563 | INCOMPLETE | deferred — "repeated", "same source", rate, window undefined |
| 3565–3566 | AMBIGUOUS | deferred — timer start undefined; constant against RECOMMENDED |
| 3567–3568 | INCOMPLETE | deferred — no error code or drop/notify behaviour |
| 5381 | AMBIGUOUS | **answered — §2d** states the two layers and reconciles the MUST |
| 5401 | INCOMPLETE | deferred — no cap value and no action on exceed |
| 5402 | INCOMPLETE | deferred — no reject or close action |
| 5406 | AMBIGUOUS | deferred — "multiple DHT paths" against signature plus connectivity check |
| 5408 | AMBIGUOUS | deferred — "unverified" undefined |

A finding in that table is not a defect this note leaves behind; it is a
defect the note *locates*. The problem statement is what makes the list
meaningful: every deferred row is a gap in one of the six mechanisms, and
none of them can be judged complete until §1's three parts say what
complete means.

---

## §5 — The draft's follow-up

The `docs:` commit that folds this note into the draft changes:

- §12's opening paragraph: add the problem statement (§1) as the
  section's first paragraph, so the six mechanisms have a parent.
- §12.2: add the two-layer relay statement (§2d) as a paragraph after
  the relay-hop HPKE description.
- §19.1: correct 5381's claim that relay traffic is protected
  end-to-end to the two-layer form (§2d). The draft's words at 5381 are "All traffic
  through relays MUST be encrypted with the same QUIC+TLS 1.3 protection
  used for direct connections", and 5398 adds "Relays cannot decrypt or
  inspect traffic"; the two-layer form qualifies both.
- §12.1: add the durable-identity sentence (§2e). §12.1 currently keys
  `ConnectivityAnnounce` by `node_id` (3149) and describes
  `external_addr` as the "DHT-observed external address" (3150) without
  saying why that address is a durable identity's — no sentence in §12.1
  mentions identity permanence, rotation, or re-resolution, and
  `grep -c 'rotat'` over the section returns nothing. The sentence
  belongs there, next to the field it explains.

The follow-up is A24 in the amendment plan, and it joins the plan when
this note lands.
