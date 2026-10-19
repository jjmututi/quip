# Conformance matrix

**Status: first delivery.** The method, the template, and the three rows
that M9.6b and the review's finding now make checkable. The full pass
follows; this exists so the shape can be reviewed before it is filled.

## What this is

One row per normative statement in `draft-mututi-quip-03.xml` that the
implementation claims to satisfy. The matrix answers two questions that
are usually conflated:

1. **Does the code do what the draft says?** — the verdict.
2. **Is the draft clear enough to be conformed to?** — the
   specification status.

A row can fail because the code is wrong, or because the sentence cannot
be met as written. Keeping those separate is the point. A matrix that
reports both as "fail" tells a reader nothing about whether to fix the
code or the text.

## Method

Each row has six fields:

| Field | Meaning |
|---|---|
| Clause | The draft section, and the normative sentence |
| Requirement | `MUST` / `SHOULD` / `MAY`, and what it obliges |
| Source | The code path, by symbol, with file |
| Test | The test that observes it, by name; `none` when untested |
| Verdict | `PASS` / `FAIL` / `PARTIAL` / `UNTESTED` |
| Specification status | `clear` / `incomplete` / `ambiguous` / `silent` |

Verdict vocabulary:

- **PASS** — the code enforces the statement and a test observes it.
- **FAIL** — the code does not enforce it, or enforces something else.
- **PARTIAL** — enforced on some paths, not all; the row names the paths.
- **UNTESTED** — the code may or may not enforce it; no test decides.

Specification status vocabulary:

- **clear** — the sentence is precise enough to check mechanically.
- **incomplete** — a term the sentence depends on is undefined.
- **ambiguous** — two readings, both arguable from the text.
- **silent** — the behaviour exists in the code and the draft does not
  mention it.

A `FAIL` with `clear` is a code defect. A `FAIL` with `incomplete` means
the draft cannot be conformed to until it says more; the code may be
following a design note that made a defensible choice the draft has not
ratified. Rows of the second kind become Protocol design items.


## Rows

### 1. §4 — receive-side capability enforcement — PASS

- **Clause.** §4 requires that a peer use only negotiated capabilities,
  and that a receiver reject a message whose verb requires a capability
  the peer did not negotiate, with `E_CAPABILITY_VIOLATION`.
- **Requirement.** `MUST` reject.
- **Source.** `quip_net::message::dispatch_inbound`, the only inbound
  parse site, called by `tasks::parse_inbound`. Every phase reaches it;
  none parses frames directly.
- **Test.** `dispatch_inbound_rejects_a_verb_the_peer_did_not_negotiate`;
  `dispatch_inbound_accepts_a_verb_the_peer_negotiated`;
  `dispatch_inbound_preserves_parse_errors` (`quip-net/src/message.rs`);
  `injected_frame_is_rejected_by_dispatch_inbound`
  (`quip-net/src/transport.rs`), which injects a frame below `send` so
  the receive path is exercised rather than the send-side check.
- **Verdict.** PASS. The gap the review found — §4 enforced on send and
  advisory on receive — is closed, and the transport test proves the
  wire → rejection path, not just the helper.
- **Specification status.** clear.

### 2. §5.3.3 — witness independence — PASS

- **Clause.** "A verifier's own statement about a subject `MUST NOT`
  count toward that verifier's threshold, even if the subject or another
  party echoes it back." (added in `71b52dc`)
- **Requirement.** `MUST NOT` count.
- **Source.** `quip_net::establishment::compute_kt_status`, which
  excludes the local `NodeId`.
- **Test.** `local_statement_does_not_count_toward_verified`
  (`quip-net/src/establishment.rs`).
- **Verdict.** PASS.
- **Specification status.** clear — S10 was resolved in `71b52dc`.

### 3. §13.5 — split attempt throttle — FAIL

- **Clause.** "If a node fails to find an acceptable cluster after
  `MAX_SPLIT_ATTEMPTS` (RECOMMENDED: 3), it `MUST` create a new cluster
  with a random `cluster_id`."
- **Requirement.** `MUST` create a new cluster once the attempt limit is
  reached.
- **Source.** `quip_net::cluster::ClusterState::record_split_attempt`
  and `ClusterState::migrate`, driven by
  `quip_node::cluster::ClusterHandle::plan_split` / `apply_split`.
- **Test.** none. The limit is unreachable as the code is sequenced, so
  a test would have to assert a state the implementation cannot enter.
- **Verdict.** **FAIL** — the `MUST` is not enforced. Every split ends
  in `migrate`, `migrate` clears `split_attempts`, and the counter is
  therefore `1` at every evaluation. The draft's condition is "fails to
  find an acceptable cluster"; the code never evaluates whether the new
  cluster is acceptable, so it cannot detect the failure the sentence is
  conditioned on.
- **Specification status.** **incomplete** — the draft does not say what
  ends an attempt, and "acceptable" is not defined at the point the
  counter would be read. The design note's §4 sequence (record, then
  `migrate`, which clears on success) is where the divergence entered:
  it simplified the draft's failure condition into an unconditional
  reset. Recorded as Protocol design item 15a, with three candidate
  readings and a recommendation.

## What follows

The remaining rows are the draft's other normative statements: handshake
and capability negotiation (§4, §16), the §10.1 signing conventions, the
§12 NAT verbs and their limits, §13.2's acceptance test, §13.7–§13.8
lookup and spillover, §5.3.4's BFT rounds and checkpoints, and §19.4's
stream limits. The pass is mechanical once the vocabulary above is
fixed, which is why only three rows are here: if the shape is wrong, it
is cheaper to change now.

Two conventions the full pass will keep:

- A row cites a **test name**, not a module, so a renamed or deleted
  test breaks the row visibly rather than silently.
- A `FAIL` whose specification status is not `clear` must name the
  Protocol design item it became. A failure with no landing place is a
  finding that gets rediscovered.
