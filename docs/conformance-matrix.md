# Conformance matrix

**Status: third delivery.** The seven-field row schema, its vocabulary,
and eight rows. The third delivery adds §5.3.4's execution contract as
the first `blocking` value, and the decisive query's answer changes with
it. The remaining rows follow; the schema is settled.

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

Each row has seven fields:

| Field | Meaning |
|---|---|
| Clause | The draft section, and the normative sentence |
| Requirement | `MUST` / `SHOULD` / `MAY`, and what it obliges |
| Source | The code path, by symbol, with file |
| Test | The test that observes it, by name; `none` when untested |
| Verdict | `PASS` / `FAIL` / `PARTIAL` / `UNTESTED` |
| Specification status | `clear` / `incomplete` / `ambiguous` / `silent` |
| Submission impact | `blocking` / `review required` / `non-blocking` |

The first four are evidence: they are what makes the judgements
checkable. The last three are judgements: does the code enforce the
sentence, is the sentence sufficient, and does the sentence stop the
draft being submitted.

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

Submission impact vocabulary:

- **`blocking`** — the draft cannot be submitted responsibly with the
  requirement in its current form. The draft edit is a prerequisite for
  submission; the implementation may or may not be conformant.
- **`review required`** — whether the requirement blocks submission is a
  decision that has not been made. The security or interoperability
  consequences are unassessed, or the requirement's sufficiency for an
  independent implementer is unjudged. It is on the schedule for a
  decision, not for a fix.
- **`non-blocking`** — the requirement is precise enough that an
  independent implementer could follow it. The row may still be `FAIL`
  on the code: that is the reference implementation's conformance gap,
  not the draft's.

The three values are not a priority order. A `review required` row can be
resolved by a decision that it is `non-blocking`; a `blocking` row can
stay blocking for as long as its edit takes to write.

**The decisive query.** The draft issues that prevent submission are the
rows where `Submission impact` is `blocking` or `review required` **and**
`Specification status` is not `clear`. A `blocking`/`clear` row is a
different list: its text is adequate and its edit is simply pending. The
query separates "the draft does not say enough" from "the draft says
enough and the edit has not landed."


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
- **Submission impact.** `non-blocking` — the code enforces the clause,
  the clause is clear, and the closure of the review's finding is
  evidence that it is workable as written.

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
- **Submission impact.** `non-blocking` — resolved text and conformant
  code.

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
- **Submission impact.** `review required` — an unbounded split rate is
  a resource-exhaustion and convergence-stability concern, so the
  throttle matters; whether it blocks submission depends on whether the
  draft's editor considers the throttle essential. That is a decision,
  not a fact.

### 4. §4 — capability dependency closure — PARTIAL

- **Clause.** "A peer `MUST NOT` advertise a capability whose
  dependencies are not also advertised… Implementations `MUST` reject a
  locally-configured capability set that violates this closure, and
  `MUST` reject a handshake in which the remote peer advertises such a
  set, closing the connection with `E_PROFILE_MISMATCH`. The local
  rejection `MUST` occur at configuration time, not at connection time,
  so that an inconsistent configuration never reaches the wire."
- **Requirement.** `MUST` reject, locally and remotely; the local
  rejection at configuration time.
- **Source.** `quip_net::handshake::Capabilities::validate_closure`,
  called from `Handshake::new_checked`, `Handshake::to_bytes`,
  `Handshake::from_bytes` and `Handshake::negotiate`.
- **Test.** `closure_accepts_baseline`,
  `closure_rejects_blake3_without_cid_addressing`,
  `closure_rejects_cidv1_without_cid_addressing`,
  `closure_rejects_merkle_range_without_blake3`,
  `closure_accepts_merkle_range_with_blake3_and_cid_addressing`,
  `closure_rejects_governance_without_dht`,
  `closure_rejects_nat_without_dht`,
  `closure_rejects_bft_checkpoint_without_dht`,
  `to_bytes_rejects_local_closure_violation`,
  `from_bytes_rejects_remote_closure_violation`,
  `negotiate_rejects_intersection_that_breaks_closure`.
- **Verdict.** PARTIAL — remote sets and the negotiated intersection are
  rejected, and `to_bytes` rejects a bad local set before any byte
  reaches the wire, so the clause's stated purpose holds. But
  `new_checked`, the entry point that would reject at construction, has
  no caller: a bad local configuration binds an endpoint and fails at
  its first handshake rather than at configuration time.
- **Specification status.** clear — the dependency list, the error code
  and the required timing are all stated.
- **Submission impact.** `non-blocking` — the text is adequate; the gap
  is in the reference implementation, and it is a `PARTIAL` rather than
  a `FAIL` because the observable guarantee holds.

### 5. §5.3.3 — re-issue after expiry — PARTIAL

- **Clause.** "After `valid_until` expires, the witness `MUST` be
  re-issued"; "Witnesses `SHOULD` re-issue statements every 12 hours."
- **Requirement.** `MUST` re-issue on expiry; `SHOULD` every 12 hours.
- **Source.** `quip_node::witness::WitnessStore::maybe_issue`, called by
  every peer task's steady loop.
- **Test.** `maybe_issue_enforces_the_12h_cadence`,
  `maybe_issue_skips_untrusted_subjects`; the `six_nodes_*` tests
  observe the effect on `KtStatus`.
- **Verdict.** PARTIAL — the 12-hour cadence re-issues while the witness
  is running, which satisfies the `MUST` whenever the witness is alive
  at expiry (12 h is earlier than 24 h, so the code enforces the
  `SHOULD` strictly enough to imply the `MUST`). Nothing detects an
  expired statement whose witness has gone, and the draft does not say
  who re-issues in that case.
- **Specification status.** ambiguous — "the witness `MUST` be
  re-issued" has no subject: the original witness, any holder, or the
  verifier. The two sentences also interact: the `SHOULD` at 12 h is
  what makes the `MUST` reachable, so an implementation that follows
  only the `MUST` may never re-issue proactively.
- **Submission impact.** `review required` — the interoperability
  question (may a verifier treat an expired statement as a liveness
  signal?) is a decision.

### 6. §5.3.4 — checkpoint quorum — PARTIAL

- **Clause.** Checkpoint verification requires quorum: "5-of-7 for a
  full ring, 3-of-4 degraded".
- **Requirement.** `MUST` verify a checkpoint signature set against the
  ring's quorum before treating the checkpoint as stable.
- **Source.** `quip_core::constants::{QUORUM, DEGRADED_QUORUM}` used by
  `quip_net::bft_driver`'s checkpoint verification; ring size comes from
  `WITNESS_COUNT = 7` and `MIN_WITNESSES = 4`.
- **Test.** `checkpoint_reaches_stability_at_quorum`.
- **Verdict.** PARTIAL — both stated sizes are enforced (5 for a full
  ring, 3 for a degraded four). The code uses two absolute constants, so
  a ring of five or six would require five signatures; whether that is
  the intended threshold is not derivable from the text.
- **Specification status.** ambiguous — the draft states two instances
  of a quorum and no rule. An independent implementer with a five-member
  ring cannot compute its threshold.
- **Submission impact.** `review required` — the difference between "5
  of 7" and "⌈2n/3⌉" is invisible at n = 7 and material at n = 5, which
  is a decision about whether other ring sizes are legal.

### 7. §13.4 — cluster merging — FAIL

- **Clause.** "When a node knows of two acceptable clusters at the same
  level, it will join the larger one"; with the preference function δ,
  "`MUST` join the larger cluster" when
  `|log(sizeA) - log(sizeB)| > δ`, and "`MUST` join the cluster with the
  lower `cluster_id`" otherwise.
- **Requirement.** `MUST` join the larger cluster past the δ threshold;
  `MUST` break ties on the lower `cluster_id`.
- **Source.** `quip_net::cluster::ClusterState::should_merge` returns
  `MergeDecision`, and **no production code calls it**
  (`grep -rn should_merge quip-node/src` is empty).
- **Test.** `merge_to_larger_when_delta_zero`,
  `merge_stays_when_own_size_larger`,
  `merge_tie_break_lower_cluster_id_wins`,
  `merge_delta_two_requires_size_ratio_greater_than_four` — all of the
  *decision*, none of a node acting on it.
- **Verdict.** **FAIL** — the requirement is not enforced. The decision
  function is implemented and unit-tested, which is why a test-count
  check would call this covered, but no code path ever joins a cluster
  for this reason. Recorded as Outstanding Work 16a.
- **Specification status.** **incomplete** — "join" is not defined: the
  draft does not say whether the joining node adopts the target's
  `cluster_id`, what happens to its own id, its coordinator, or the
  tuple it announces afterwards.
- **Submission impact.** `review required` — merge is how clusters
  converge to a stable size; leaving it unexecuted and undefined is
  either acceptable at this revision or not, and that is a decision.

### 8. §5.3.4 — execution contract for committed operations — FAIL

- **Clause.** §5.3.4 fixes ordering, the checkpoint and state-transfer
  formats, and the quorum that makes a checkpoint stable. It requires
  the state to be deterministically decodable and requires a recipient
  to reject an undecodable state. It does not say what happens when an
  operation commits and then *execution* fails — whether operations are
  validated before consensus, validated deterministically before
  consensus, or committed as state transitions.
- **Requirement.** none stated. The three resolutions are three
  different protocols: (a) `apply` is infallible by contract and
  applications validate before an operation enters consensus; (b)
  validation is deterministic and runs before consensus, so `apply`
  cannot fail on a committed operation; (c) the execution result is part
  of the consensus decision — the state transition is committed, not the
  request.
- **Source.** `quip_net::bft_driver::BftHandler::apply -> Result<()>`.
  `BftDriver::apply_current` pushes `BftEvent::ApplyFailed` on `Err` and
  then advances `sequence` regardless.
- **Test.** `apply_failure_is_an_event_not_an_error` — it asserts that
  the failure is an event and that every driver reaches sequence 1,
  which documents the divergence rather than preventing it.
- **Verdict.** **FAIL** — `apply` permits a post-commit failure the
  driver does not treat as fatal, so two replicas can disagree about
  state while both advance and both believe consensus progressed. The
  behaviour is (c)'s shape without (c)'s obligation: it takes the
  licence to commit a failure and omits the requirement that the failure
  be identical on every replica.
- **Specification status.** **incomplete** — "applied" is used and never
  defined with respect to failure, and the draft selects none of the
  three protocols. An independent implementer must choose one.
- **Submission impact.** **`blocking`** — a draft that does not state the
  execution contract cannot be submitted responsibly. The three
  resolutions are three protocols, and a reviewer of the draft has no
  way to know which one is being proposed. This is the first `blocking`
  row in the matrix.

## What follows

The remaining rows are the draft's other normative statements: handshake
and capability negotiation (§4, §16), the §10.1 signing conventions, the
§12 NAT verbs and their limits, §13.2's acceptance test, §13.7–§13.8
lookup and spillover, §5.3.4's BFT rounds and checkpoints, and §19.4's
stream limits.

The estimate is **two passes, not one.** Where the draft is `clear`, the
pass is mechanical: the comparison is a check, a row takes minutes, and
the work parallelises without coordination. Where it is not, the pass is
**design-time**: the judgement is whether an independent implementer
would reach the same behaviour from the text, which is a question the
code can inform and the draft's editor has to answer. Five of the eight
rows here are design-time (`ambiguous` or `incomplete`); the three
`incomplete` ones — §5.3.4's execution contract, §13.5's attempt episode
and §13.4's merge — decide the submission schedule, and only the first
is `blocking`. The mechanical rows decide only how long the matrix takes
to finish.

Two conventions the full pass will keep:

- A row cites a **test name**, not a module, so a renamed or deleted
  test breaks the row visibly rather than silently.
- A `FAIL` whose specification status is not `clear` must name the
  Protocol design item it became. A failure with no landing place is a
  finding that gets rediscovered.

A third convention, and it is normative: **name the caller.** Every row
whose `Source` is a function MUST name the code that calls it, or state
that nothing does. A unit-tested function with no caller is a code path
that exists and does nothing — invisible to a test count and to a review
that reads the function instead of its call sites. Two instances so far:
`Capabilities::new_checked` (row 4) and `ClusterState::should_merge`
(row 7), both with passing unit tests and no production caller. Row 3 is
the sequencing variant of the same failure: `record_split_attempt` is
called, and the limit it guards cannot be reached.

**The decisive query now returns five rows, one of them `blocking`.**
Row 8 is the first requirement whose draft edit is a prerequisite for
submission: until §5.3.4 says which execution contract it proposes, an
implementer cannot conform and a reviewer cannot tell what is being
proposed. The answer to the review's decisive question moves from "four
decisions, none blocking" to "five decisions, one blocking" — and the
blocking one is not a detail of Coral routing, it is the contract every
BFT application depends on.
