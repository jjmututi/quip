# Conformance matrix

**Status: fifth delivery.** The nine-field schema, its vocabulary, and
eighteen rows. The rows cover the decision points where the code and
the draft have a comparison to make. They do not cover the draft's
mechanical conformance (canonical CBOR, wire framing, ALPN, the
`quip-v1` prefix), which every wire test asserts and no row would add
to; they do not cover sections the code has not implemented (governance,
quarantine, Trusted CID registration), which are recorded in
`CHANGELOG.md`'s status table, not here; and they do not speak for the
draft's size or its division into one or several documents. "What
follows" names both the sections with a comparison yet to make and the
sections the code has not landed. **The decisive query returns zero
rows over the eighteen rows that exist; it does not speak for the
draft's unrowed statements.**

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

Each row has ten fields:

| Field | Meaning |
|---|---|
| Clause | The draft section, and the normative sentence |
| Requirement | `MUST` / `SHOULD` / `MAY`, and what it obliges |
| Source | The code path, by symbol, with file |
| Test | The test that observes it, by name; `none` when untested |
| Verdict | `PASS` / `FAIL` / `PARTIAL` / `UNTESTED` |
| Specification status | `clear` / `incomplete` / `ambiguous` / `silent` |
| Submission impact | `blocking` / `review required` / `non-blocking` |
| Depends on | The rows whose `Source` must exist for this row's `Source` to work; empty for a leaf |
| History | The row's verdict over time, one entry per commit that moved it; absent when the row has never moved |
| Closure test | The test, or one test per class the row's `Verdict` depends on, that exercises the requirement end-to-end; absent when the row has never been through the closure convention. Each named test is exactly one test, and it is the deciding evidence for its class. |

The first four are evidence: they are what makes the judgements
checkable. The next three are judgements: does the code enforce the
sentence, is the sentence sufficient, and does the sentence stop the
draft being submitted. The last three are structure, record and
closure: what this row stands on, how it got here, and the test that
closes it.

A `Closure test` field names the test, or one per class, whose passing
is the row's evidence; a row with a `Closure test` whose named test does
not exist or does not exercise the requirement is not `PASS`, regardless
of other tests' status.

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
- **Depends on.** none (leaf).

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
- **Depends on.** none (leaf).

### 3. §13.5 — split attempt throttle — PASS

- **Clause.** "A split attempt is pending from the moment the migration
  completes until the first §13.2 member-set computation that is eligible
  to decide it. An attempt is eligible to be decided once the new cluster
  has accumulated at least one `CLUSTER_HEARTBEAT` since the migration…
  A pending attempt `MUST NOT` count against `MAX_SPLIT_ATTEMPTS`. When
  the first eligible computation runs, the attempt is successful if the
  new cluster is acceptable per §13.2 and failed if it is not… A
  CreateNew decision ends the previous episode and begins a new pending
  attempt; the new attempt's outcome is decided by the first eligible
  computation, not by the first computation after the migration."
- **Requirement.** `MUST NOT` count a pending attempt; `MUST` reset on an
  eligible acceptable verdict; `MUST NOT` reset on an eligible
  unacceptable one; `MUST` create a new cluster after
  `MAX_SPLIT_ATTEMPTS` consecutive failures.
- **Source.** `ClusterState::migrate` starts `pending_split`;
  `ClusterState::note_split_outcome(acceptable, config)` decides only an
  attempt that is in flight; `ClusterHandle::recompute` decides once
  `pending_split_settled` is true (one `CLUSTER_HEARTBEAT` after the
  move); `plan_split` forces `CreateNew` when the consecutive count
  passes the cap. `apply_split` counts nothing.
- **Test.** `pending_attempt_does_not_count_against_the_cap`,
  `create_new_begins_a_fresh_pending_attempt`,
  `the_cap_is_reachable_after_the_settle_interval`,
  `a_pending_attempt_that_becomes_acceptable_clears_the_counter`,
  `a_failed_attempt_counts_only_after_the_settle_interval`,
  `note_split_outcome_clears_only_on_success`,
  `the_cap_forces_a_new_cluster_even_when_a_branch_is_acceptable`
  (`quip-node`, `split_tests`); `migrate_preserves_the_attempt_counter`,
  `consecutive_failures_reach_the_split_cap` (`quip-net`).
- **Verdict.** PASS. The pending-then-decided distinction is what the
  four new tests prove: a migration does not count, a `CreateNew`
  decision does not count, three settled failures reach the cap, and a
  settled acceptable verdict clears the counter.
- **Specification status.** clear — the episode is defined in terms of
  the §13.2 test and the `CLUSTER_HEARTBEAT` the draft already defines.
- **Submission impact.** `non-blocking`.
- **Depends on.** none for the counter; the split's observable effect
  depends on the cluster-info exchange (§3 of the M9.6b note), which has
  no row of its own.

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
- **Depends on.** row 1 — the negotiated set row 1's gate reads is the
  same set this closure validates.

### 5. §5.3.3 — re-issue after expiry — PASS

- **Clause.** "After `valid_until` expires, the witness `MUST` be
  re-issued"; "Witnesses `SHOULD` re-issue statements every 12 hours";
  and "A statement whose `valid_until` has passed no longer counts toward
  the verification threshold, regardless of whether the issuing witness
  has since re-issued. The obligation to re-issue is the witness's; the
  filter on expiry is the recipient's."
- **Requirement.** `MUST` re-issue on expiry (witness); `MUST NOT` count
  an expired statement (recipient); `SHOULD` re-issue every 12 hours.
- **Source.** `quip_node::witness::WitnessStore::statements_for` filters
  `stmt.valid_until > now`; `WitnessStore::maybe_issue` re-issues on the
  12-hour cadence, driven by every peer task's steady loop.
- **Test.** `statements_for_excludes_statements_past_valid_until` (the
  recipient's filter: valid statement counts, the same statement past
  `valid_until` does not); `maybe_issue_enforces_the_12h_cadence`,
  `maybe_issue_skips_untrusted_subjects`; the `six_nodes_*` tests
  observe the effect on `KtStatus`.
- **Verdict.** PASS. The two obligations now have two sides: the witness
  re-issues on the 12-hour cadence (which is earlier than expiry, so the
  `MUST` is reachable), and the recipient's threshold excludes an expired
  statement regardless of what the witness did.
- **Specification status.** clear — the expiry paragraph separates the
  obligation from the filter, which is what the clause lacked.
- **Submission impact.** `non-blocking`.
- **Depends on.** none (leaf).

### 6. §5.3.4 — checkpoint quorum — PASS

- **Clause.** "A quorum is `n - f` distinct ring members, where `n` is
  the ring size and `f` is the maximum number of Byzantine members
  tolerated… `n - f` is the general rule; specific ring sizes follow from
  it." A checkpoint is stable when signed by at least `n - f` members.
- **Requirement.** `MUST` verify a checkpoint signature set against the
  ring's quorum before treating the checkpoint as stable.
- **Source.** `RingMembership::quorum` (`quip-net/src/bft_driver.rs`)
  returns `n - f` with `f = (n - 1) / 3`; `maybe_emit_new_view` gates on
  it and checkpoint stability is computed from it.
- **Test.** `checkpoint_reaches_stability_at_quorum`,
  `view_change_promotes_new_primary`.
- **Verdict.** PASS — the code already computes the general rule; the
  draft now states it, so a five- or six-member ring has a derivable
  threshold.
- **Specification status.** clear.
- **Submission impact.** `non-blocking`.
- **Depends on.** none (leaf).

### 7. §13.4 — cluster merging — FAIL

- **Clause.** "When a node knows of two acceptable clusters at the same
  level, it will join the larger one"; with the preference function δ,
  "`MUST` join the larger cluster" when
  `|log(sizeA) - log(sizeB)| > δ`, and "`MUST` join the cluster with the
  lower `cluster_id`" otherwise.
- **Requirement.** `MUST` join the larger cluster past the δ threshold;
  `MUST` break ties on the lower `cluster_id`.
- **Source.** `ClusterState::should_merge` returns `MergeDecision`, and
  `ClusterHandle::merge_if_due` is its production caller
  (`grep -rn should_merge quip-node/src` now returns `plan_merge`).
  `ClusterHandle::plan_merge` evaluates §2a rules 1–3 (rule 1 via
  `should_merge`, rule 2 via two p90 comparisons, rule 3 via
  `pending_split`); rule 4 is transitive through §13.2. The lifecycle
  lives in `ClusterState::start_merge_proposal`,
  `note_merge_result`, `pending_merge_settled`,
  `merge_proposal_eligible` and the `pending_merge` / `incoming_merge`
  slots; the peer task drives `ClusterState::note_merge_result`
  through the `ClusterHandle::state` accessor — there is no
  handle-level wrapper for it. The three wire verbs
  (`cluster_merge_propose`, `cluster_merge_accept`,
  `cluster_merge_reject`) are DHT_DISCOVERY-gated, `Tier::Ctrl`, and
  classify as `InboundAction::Merge` in `classify_inbound`.
- **Test.** `merge_to_larger_when_delta_zero`,
  `merge_stays_when_own_size_larger`,
  `merge_tie_break_lower_cluster_id_wins`,
  `merge_delta_two_requires_size_ratio_greater_than_four` — all of the
  *decision*, none of a node acting on it. **none for completion**; those
  four exercise the decision, not the merge. The note's three unit tests
  now exist: `merge_requires_the_size_condition`,
  `merge_requires_enough_rtt_samples`, `merge_rejected_when_pending_split`,
  alongside `merge_wire_roundtrips`, `note_merge_result_clears_pending`,
  `note_merge_result_on_accept_returns_the_larger_id` and
  `incoming_merge_slot_rejects_a_second_proposal`. The integration test
  `merge_produces_larger_cluster_id` drives the full path on a
  two-cluster fixture (25 local + 20 larger peers, because §2a rule 2
  needs 20 samples on each side) and asserts the larger id survives,
  the pending slot clears, the split counter stays 0, and the `Busy`
  path refuses a second proposal.
- **Verdict.** **PASS** — the code path is complete: `merge_if_due` is
  `should_merge`'s production caller, evaluates the four §2a rules
  per the note's §3, and the integration test
  `merge_produces_larger_cluster_id` proves the completion and the
  `Busy` path. The draft's §13.4 now records the coordination rules
  (§2a–§2d) in `990a8e1`; the row is PASS / clear / non-blocking.
- **History.** bf520fe: design note landed, FAIL / incomplete /
  review required. `3fbee08`: note revised to resolve the bf520fe review
  pair's findings (direction of id adoption, size re-check timing,
  receiver-side `busy` state, migration trigger, completion
  denominator, RTT input, `should_merge` caller). Row stays FAIL /
  incomplete / review required; the note fix changes what "incomplete"
  means (documentation gap rather than undefined behaviour) and
  names the code path the merge milestone will add. `028c102`: wire verbs,
  `pending_merge` / `incoming_merge` slots and the lifecycle land in
  `quip-net`; the caller and integration test are commit 2. Row
  unchanged: the wire and state exist, the caller does not. `2bfe99d`: the
  caller (`ClusterHandle::merge_if_due` / `plan_merge`), the
  `classify_inbound` / `apply_inbound` merge arms, `ClusterView::
  pending_merge` and `merge_produces_larger_cluster_id` land; row
  moves FAIL → PASS, specification status stays `incomplete` until the
  §13.4 amendment. `990a8e1`: draft §13.4 amended with the coordination
  rules, §14.1 gains the three coordinator verbs, §3 gains
  `MERGE_PROPOSAL_TIMEOUT`; row moves FAIL / incomplete /
  review required → PASS / clear / non-blocking. Decisive query now
  returns zero rows.
- **Specification status.** clear — §13.4 now defines what a merge does
  to the cluster id (the larger survives), the member set (the
  smaller's members migrate to the larger id and are excluded by the id
  filter if they do not), the coordinator (the smaller's coordinator
  steps down on the next `elect_coordinator` interval; the larger's
  coordinator remains), and the tuple announced afterwards (the
  smaller's members announce the larger id).
- **Submission impact.** `non-blocking` — the draft defines "join", the
  amendment is landed, and an independent implementer can now read
  §13.4 and reach the same behaviour the reference implementation
  does. The remaining code-side gap is the hostile-coordinator case
  (the note's §4 and §5 record it as unproven); it is a code gap, not
  a draft gap.
- **Depends on.** row 13 (§13.6 — the size estimate merge compares; the
  size the δ rule compares is the estimate §13.6 defines) and row 12
  (§13.2 — the p90 the RTT rule compares is the acceptance test's p90,
  and the ≥ 20 sample floor is the same constant). A `FAIL` dependency
  would leave merge's decision input unverified even if merge had a
  caller. Rule 4 of §2a is enforced by §13.2's threshold rather than by
  a direct comparison, so row 7 depends on row 12 for the level
  distinction as well as for the acceptance test.

### 8. §5.3.4 — execution contract for committed operations — PASS

- **Clause.** §5.3.4 now specifies the application execution contract.
  Applications supply `validate` and `apply` hooks; `validate` runs
  before an operation enters consensus and `apply` after commitment. The
  committed state digest, and the `checkpoint_digest` a checkpoint
  carries, `MUST` include the `apply` output. The hooks `MUST NOT`
  consult a clock, a random source or any other non-deterministic input.
  A `validate` failure drops the `bft_preprepare` before consensus; an
  `apply` failure is recorded as the application's outcome, included in
  the digest, and treated as a state transition like any other.
- **Requirement.** `MUST` include the hook output in the digest; hooks
  `MUST NOT` be non-deterministic; `validate` failures `MUST` reject
  before consensus; `apply` failures `MUST` be recorded and agreed.
- **Source.** `quip_net::bft_driver::BftHandler::apply -> Result<()>`.
  `BftDriver::apply_current` pushes `BftEvent::ApplyFailed` on `Err` and
  then advances `sequence`; `BftHandler::state_digest` defaults to
  all-zeros and does not include the result. There is no `validate` hook.
- **Test.** `apply_failure_is_a_state_transition` drives a handler whose
  `apply` returns `OperationOutcome::ApplicationFailure(None)` through a
  full round and asserts that `BftEvent::Applied` carries that outcome,
  that the driver's `chain_digest` has advanced past the all-zero
  genesis, and that every driver reaches sequence 1 — the failure is a
  state transition, not an error path.
  `chain_digest_advances_over_the_committed_sequence` pins the
  construction: the same three-key map encoded in two literal orders
  yields identical bytes, and every replica's `d_0` equals a value
  recomputed outside the driver.
- **Verdict.** **PASS** — the code enforces §5.3.4's contract.
  `BftHandler::validate` runs at `propose` (a false return is
  `Error::Bft`, no round is built) and at `on_preprepare` after the
  signature is verified (a false return drops the preprepare without
  touching round state or the sequence). `BftHandler::apply` returns
  `OperationOutcome` and takes the deterministic `OperationContext`;
  `OperationOutcome` is the closed, text-keyed, 256-byte-bounded map of
  §5.3.4. The driver folds the outcome into
  `d_n = SHA-256(QUIP-CBOR(map{outcome, operation, prior_state_digest}))`,
  the checkpoint carries `d_n`, and `BftEvent::Applied` reports the
  outcome — including a failure, which the sequence and the digest treat
  like any other transition. `ApplyFailed` is gone because the draft
  draws no such distinction.
- **Specification status.** clear — §5.3.4 states the hook, the digest
  contract, the deterministic context, the failure contract, the
  empty-output default, the digest construction, the checkpoint relation
  and the outcome encoding: text map keys, a text discriminant, a
  256-byte payload bound, and a closed-map rule that §10 states once and
  §5.3.4 cites. Two independent implementers can now compute the same
  state digest from the same state.
- **Submission impact.** `non-blocking` — the draft is precise enough for
  an independent implementer. The construction and the wire form are
  specified in §5.3.4, and the implementation of `OperationOutcome`,
  `BftHandler::validate` and the state digest over the three-key map has
  landed (BFT-A item 1); no submission decision depends on this row.
- **Depends on.** rows 6 and 14 — a checkpoint is only stable at quorum
  (row 6), and the chain digest cannot be checked against a state
  transfer whose byte digest is wrong (row 14). The two digests are a
  pair: one commits to what was applied, the other to what the state is —
  the byte digest the transfer path checks is separate from the chain
  digest the checkpoint carries, and both checks are exercised by the S8
  tests the fixture rewrite touches.
- **History.** `35382d9`: commit 1 — `OperationOutcome`, `validate`, the
  infallible `apply` with the deterministic context, and the `d_n`
  construction land; `ApplyFailed` still fires and the checkpoint still
  carries the handler's digest, so the row stays `FAIL`. `<SHA>`: commit
  2 — the checkpoint carries `d_n`, the fixtures take §5.3.4.1's
  state-format SHOULD, `ApplyFailed` is deleted in favour of
  `Applied { outcome }`, and `apply_failure_is_a_state_transition`
  replaces `apply_failure_is_an_event_not_an_error`; row 8 `FAIL` →
  `PASS`. The `Closure test` field is added with this row; it names that
  test.
- **Closure test.** `apply_failure_is_a_state_transition`

### 9. §10.1 — signing convention — PASS

- **Clause.** A signature covers the message array with the signature
  field removed, encoded with QUIP-CBOR.
- **Requirement.** `MUST` sign the payload without the signature.
- **Source.** `signing_payload()` on each wire type in
  `quip-net/src/nat_wire.rs`, `quip-net/src/coral.rs`,
  `quip-net/src/cluster.rs` and `quip-net/src/bft.rs`. Called by each
  type's `verify`, and by the senders that fill the signature
  (`dht_result_from`, the relay responder, the cluster heartbeat); for
  the `bft.rs` types, by the driver handlers that verify votes, view
  changes, new views and checkpoints. **One exception, and it is the
  third instance of the uncalled-code class:** `bft_state_transfer`'s
  `BftStateTransfer::signing_payload` and `BftStateTransfer::verify` have
  no caller at all — production or test. The receive path verifies the
  checkpoint signature set through `verify_checkpoint_ring_sig` instead
  (row 17), so a signature over the transfer's own payload is never
  checked. The first two instances of the class were counted in the
  `c6a371a` and `76c9d0e` review rounds (`Capabilities::new_checked`,
  row 4; `ClusterState::should_merge`, row 7); this one is recorded here
  rather than fixed, because the treatment is either deletion or wiring
  and both are separate from §10.1.
- **Test.** `connectivity_announce_signing_payload_excludes_signature`,
  `relay_discovery_signing_payload_excludes_signature`,
  `signing_payload_excludes_signature` (`cluster_info`), plus the
  `*_verify_*` tests that fail when a covered field changes.
- **Verdict.** PASS.
- **Specification status.** clear.
- **Submission impact.** `non-blocking`.
- **Depends on.** none (leaf).

### 10. §5.3.3 — witness validity — PASS

- **Clause.** "A witness statement is valid for 24 hours from
  timestamp."
- **Requirement.** `MUST` not count an expired statement.
- **Source.** `ConnectionFlow::compute_kt_status` filters
  `stmt.valid_until > now`; `WitnessStore::ingest` rejects an expired
  statement on receipt. `compute_kt_status` is called by
  `ConnectionFlow::on_discovery_complete`; `ingest` by `apply_inbound`'s
  witness action.
- **Test.** `expired_witnesses_do_not_count`,
  `ingest_rejects_expired_statement`.
- **Verdict.** PASS.
- **Specification status.** clear.
- **Submission impact.** `non-blocking`.
- **Depends on.** none (leaf).

### 11. §5.3.3 — six-hour first-seen rule — PASS

- **Clause.** "Each witness's Key Claim must have been first seen 6+
  hours ago."
- **Requirement.** `MUST` exclude a witness whose claim is younger than
  six hours from the corroboration set.
- **Source.** `WitnessStore::statements_for`, called by
  `DiscoveryHandle::respond_to_lookup` (`quip-node/src/discovery.rs`).
- **Test.** `statements_for_excludes_witnesses_younger_than_the_6h_window`,
  `statements_for_includes_witnesses_past_the_6h_window`,
  `statements_for_excludes_witnesses_without_first_seen`,
  `statements_for_caps_at_the_statement_cap`; and end to end by
  `six_nodes_stay_pending_before_first_seen_window` versus
  `six_nodes_reach_verified_after_first_seen_window`.
- **Verdict.** PASS.
- **Specification status.** clear.
- **Submission impact.** `non-blocking`.
- **Depends on.** none (leaf).

### 12. §13.2 — cluster acceptance test — PASS

- **Clause.** Obtain a random subset of at least 20 nodes and accept the
  cluster when the 90th-percentile RTT is within the level's threshold.
- **Requirement.** `MUST` run the test against at least 20 samples and
  use the 90th percentile.
- **Source.** `ClusterState::is_acceptable` and
  `ACCEPTANCE_MIN_SAMPLES` (`quip-net/src/cluster.rs`), driven by
  `ClusterHandle::recompute` (`quip-node/src/cluster.rs`), which
  collects the RTT samples from the routing-eligible records.
- **Test.** `acceptance_rejects_too_few_samples`,
  `acceptance_accepts_all_within_threshold`,
  `acceptance_rejects_when_p90_above_threshold`,
  `acceptance_accepts_when_only_far_outliers`.
- **Verdict.** PASS. Note that the sample source is the routing table,
  not a random subset of the DHT; the test is on the local view, which
  is what §13.2's members can observe.
- **Specification status.** clear.
- **Submission impact.** `non-blocking`.
- **Depends on.** none (leaf).

### 13. §13.6 — cluster size estimate — PASS

- **Clause.** "Nodes `MUST` maintain an estimate of their cluster size
  for merging decisions", `size = 2^(average routing-table size)`.
- **Requirement.** `MUST` maintain the estimate.
- **Source.** `estimate_size_from_routing_table`
  (`quip-net/src/cluster.rs`), called from
  `ClusterHandle::recompute`, which feeds `ClusterState::update_size`.
- **Test.** `estimate_size_from_routing_table_saturates`; the cluster
  tests that assert `size` after `recompute`.
- **Verdict.** PASS for the estimate; the decision that consumes it
  (merge) is row 7 and does not run.
- **Specification status.** clear.
- **Submission impact.** `non-blocking`.
- **Depends on.** none (leaf); row 7 depends on this row.

### 14. §5.3.4.1 — byte digest for state transfer — PASS

- **Clause.** "The `state_hash` field `MUST` be the SHA-256 of the
  `state` bytes as transmitted." A transfer carries both digests: the
  checkpoint's chain digest as `checkpoint_digest` (what the ring
  signature covers) and `state_hash` (what the bytes must match).
- **Requirement.** `MUST` bind the transferred bytes; a receiver `MUST`
  verify `state_hash` before applying the state, and `MUST` recompute the
  chain digest from the bytes and reject the transfer if it does not
  equal `checkpoint_digest`.
- **Source.** `quip_net::bft::BftStateTransfer` carries both digests in
  the draft's field order — `checkpoint_digest`, then `state_hash`.
  `handle_state_transfer_response` compares `sha256(&msg.state)` with
  `state_hash`, then recomputes the chain digest with
  `BftHandler::state_digest_of(&msg.state)` and compares that with
  `checkpoint_digest`, before calling `BftHandler::apply_state`; the ring
  signature is verified against `checkpoint_digest` through
  `verify_checkpoint_ring_sig`, which rebuilds the `bft_checkpoint`
  payload with that value as the checkpoint's `state_digest`.
- **Test.** `state_transfer_rejects_digest_mismatch` corrupts the state
  bytes, leaves both digests intact, and asserts the byte check fires
  rather than the signature check. `state_transfer_roundtrip` asserts a
  real response carries the chain digest in `checkpoint_digest` and
  SHA-256 of its own bytes in `state_hash`, and that the install stores
  the chain digest.
  `state_transfer_distinguishes_chain_digest_from_byte_digest` runs the
  same path against the chain-digest fixture, whose state is
  `counter ++ d_n`, so `state_digest()` is the driver's `d_n` and
  `sha256(state_bytes())` is a different value for any state with a
  nonzero counter; it asserts they differ before transferring, and that
  the transfer is accepted.
  `state_transfer_rejects_substituted_state_with_matching_state_hash`
  replaces `state` with arbitrary bytes, recomputes `state_hash` so the
  byte check passes, leaves `checkpoint_digest` and `ring_signature`
  untouched, and asserts the transfer is rejected with
  `state transfer chain digest mismatch` and nothing is installed. It
  fails against the pre-recomputation receiver, which accepted the
  transfer. `state_transfer_rejects_substituted_chain_digest` differs
  from the genuine state only in the bytes `8..40` that carry `d_n`,
  repairs `state_hash`, and asserts the same rejection; it is the test
  that distinguishes chain-digest coverage from whole-state substitution,
  because the previous test differs in both ranges.
- **Verdict.** **PASS** — the bytes are bound to a signed value, and the
  binding is exactly as strong as the handler's state format. `state_hash`
  catches corruption, the ring signature binds the checkpoint triple
  including `checkpoint_digest`, and `state_digest_of` reads the chain
  digest out of the transmitted state and compares it with the signed
  `checkpoint_digest`. §5.3.4.1's coverage reading — the chain digest is
  a digest over **every** byte of the handler's serialized state, and a
  handler `MUST NOT` install a byte the digest does not cover — was
  retired by the draft amendment: §5.3.4.1 states the state-format rule
  as a SHOULD, and §5.3.4 makes the chain digest `d_n` over (outcome,
  operation, prior `d_n`). A handler that takes the SHOULD carries `d_n`
  in its state and the two checks agree; bytes the outcome does not carry
  — a handler's own bookkeeping — are outside `d_n` by construction and
  no check can cover them, which is why the class the old counter-only
  test named no longer exists. Row 14's `PASS` rests on the byte check
  for every handler and on the chain check for handlers that take the
  SHOULD; the amendment is what changed the justification, not the code.
- **History.** 84c29c4: `PASS` under the property reading. `ece3e58`:
  `PASS` under the coverage reading, §5.3.4.1 amended; counter bytes
  `0..8` covered by the digest, counter-only substitution rejected
  (`state_transfer_rejects_counter_only_substitution`). `<SHA>`: the
  fixtures take §5.3.4.1's state-format SHOULD and carry the driver's
  `d_n`; `state_digest_of` reads it back, the checkpoint's
  `state_digest` becomes `d_n`, and the whole-state coverage reading is
  retired by the amendment rather than by a code change. The
  counter-only test is replaced by
  `state_transfer_rejects_substituted_chain_digest`, which substitutes
  the bytes that carry `d_n`. Row stays `PASS`; the `Closure test` field
  is added with this row.
- **Specification status.** clear — the amendment gives the two digests
  distinct fields and distinct verification steps.
- **Submission impact.** `non-blocking` — the code gap this row recorded
  is closed, and no submission decision depended on it.
- **Depends on.** none (leaf); row 8 depends on this row, and row 17 for
  the checkpoint triple — `checkpoint_digest` is the value the ring
  signature covers, so the recomputation compares against a signed value.
  The contract is S16 in `CHANGELOG.md`.
- **Closure test.** `state_transfer_rejects_digest_mismatch` (byte check)
  and `state_transfer_rejects_substituted_chain_digest` (chain check) —
  one per class the row's `Verdict` depends on.

### 15. §5.3.4 — pre-prepare digest recomputation — PASS

- **Clause.** "Witnesses `MUST` recompute this digest from the received
  fields and reject the message with E_BFT_FAILURE if it does not
  match."
- **Requirement.** `MUST` recompute and reject on mismatch.
- **Source.** `BftPreprepare::verify_full` calls `verify_digest`
  (`quip-net/src/bft.rs`), which recomputes
  `SHA-256(ring_id || view || sequence || QUIP-CBOR(operation))`; called
  by `BftDriver::on_preprepare`.
- **Test.** `preprepare_verify_digest_accepts_matching`,
  `preprepare_verify_digest_rejects_tampered_operation`,
  `preprepare_verify_digest_rejects_wrong_digest_field`, plus the five
  sensitivity tests.
- **Verdict.** PASS.
- **Specification status.** clear.
- **Submission impact.** `non-blocking`.
- **Depends on.** none (leaf).

### 16. §5.3.4 — new-view quorum — PASS

- **Clause.** "A `bft_new_view` message `MUST` contain at least
  `VIEW_CHANGE_QUORUM` (5) valid view-change messages."
- **Requirement.** `MUST`.
- **Source.** `BftDriver::maybe_emit_new_view` returns without emitting
  unless `view_change.votes.len() >= membership.quorum()`, and only the
  primary for the target view emits.
- **Test.** `view_change_promotes_new_primary`.
- **Verdict.** PASS. The messages are carried as encoded
  `bft_view_change` messages and the encoded count is the vote count.
- **Specification status.** clear.
- **Submission impact.** `non-blocking`.
- **Depends on.** none (leaf).

### 17. §5.3.4 — state-transfer ring signature — PASS

- **Clause.** "Recipients of a `bft_state_transfer` `MUST` validate the
  `RingSignature` against the checkpoint signing payload for
  `(ring_id, checkpoint_sequence, checkpoint_digest)`, by either the
  individual or the FROST form, and `MUST` validate the quorum
  threshold before accepting any state transfer."
- **Requirement.** `MUST` validate the signature set and the quorum.
- **Source.** `verify_checkpoint_ring_sig`
  (`quip-net/src/bft_driver.rs`), called by
  `handle_state_transfer_response` before the byte check.
- **Test.** `state_transfer_rejects_bad_ring_signature`,
  `state_transfer_roundtrip`.
- **Verdict.** PASS for the individual form, which is one of the two
  forms the clause permits; the FROST branch is BFT-A item 4 and is not
  a conformance gap while the draft accepts either.
- **Specification status.** clear.
- **Submission impact.** `non-blocking`.
- **Depends on.** row 14 — the payload the signature covers is
  `checkpoint_digest`, whose meaning row 14 fixes.

### 18. §5.3.4 — critical operations in degraded mode — FAIL

- **Clause.** "Critical operations `MUST` be delayed until full consensus
  (5 of 7) is restored. The following operations `MUST NOT` proceed in
  DEGRADED mode: key rotation; key revocation; witness membership
  changes; resource ownership transfers; Trusted CID registrations that
  require witness validation."
- **Requirement.** `MUST NOT` proceed.
- **Source.** none. `grep -rn DEGRADED quip-net/src/bft_driver.rs` finds a
  doc comment and nothing else; the driver accepts any operation kind
  whenever it has quorum, and does not distinguish a 3-of-4 ring from a
  full one for operation admission.
- **Test.** none.
- **Verdict.** **FAIL** — the gate does not exist. A key rotation can
  commit with three of four signatures on a degraded ring.
- **Specification status.** clear — the list of operations and the
  quorum are both stated.
- **Submission impact.** `non-blocking` — a code gap against a clear
  clause, and it belongs with the degraded-ring work rather than the
  draft.
- **Depends on.** row 6 — the quorum that defines "degraded".

## What follows

**Coverage: 18 rows against 146 `MUST` and 104 `SHOULD` statements in
104 sections.** The rows cover the decision points where the reference
implementation gives a source to check against — the capability surface,
the witness threshold, the BFT quorum and execution contract, the cluster
acceptance and size rules, and the Coral merge/split decisions.
Everything else is inventoried, not guessed: the counts come from a
mechanical scan of `<bcp14>` tags per section, so the remaining work is a
list rather than an estimate.

Rows by section:

| Section | Rows |
|---|---|
| §4 Handshake and profile negotiation | 1, 4 |
| §5.3.3 Witness statements | 2, 5, 10, 11 |
| §5.3.4 BFT consensus, operations, execution | 6, 8, 15, 16, 17, 18 |
| §10.1 Signing convention | 9 |
| §13.2 Cluster acceptance | 12 |
| §13.4 Cluster merging | 7 |
| §13.5 Cluster splitting | 3 |
| §13.6 Cluster size estimation | 13 |
| §5.3.4.1 BFT checkpointing (byte digest) | 14 |

**Sections with a comparison yet to make.** The code is landed and
the row is worth writing; some are mechanical, some are design-heavy.
In the order the next passes should take them:

1. **§4's remaining `MUST`s** — version negotiation, ALPN, the
   capability-bit registry, extension handling. Mechanical (`clear`)
   except the registry, which is `silent` where the draft names bits the
   code does not use.
2. **§5.3.4's remaining `MUST`s** — the prepare/precommit/commit ordering
   rules, the contents a view-change vote must carry, the `new_view`'s
   prepared and checkpoint carry-forward (BFT-A items 2 and 3), and the
   checkpoint's state-format requirements. This is BFT-A's remaining work
   and the most design-heavy group.
3. **§8 CIDs and merkle range** — 16 `MUST`s, mostly `clear` and backed
   by `quip-storage` tests.
4. **§12 NAT** — 6 `MUST`s, backed by `nat.rs` / `nat_driver.rs` tests.
5. **§7 governance and §14 sync verbs** — 15 `MUST`s, partly
   unimplemented (quarantine, Trusted CID registration).
6. **The capability registry, security considerations and appendices** —
   mostly implementation guidance rather than interoperable behaviour;
   they need a decision about whether they belong in a conformance
   matrix at all.

§5.3.4's remaining `MUST`s and §7's governance `MUST`s are the two
design-heavy groups; the rest are mechanical. None of these rows
would be a draft ambiguity finding of the kind the eighteen-row
pass was for; they would be code-vs-draft comparisons on sections
the code has already implemented or will implement in the next
milestones.

**Sections the code does not implement.** These are recorded in
`CHANGELOG.md`'s status table as unlanded, not in the matrix as
rows, because a row whose `Source` is `none` and whose `Verdict`
is `FAIL` duplicates the status table's information without adding
a comparison. They become rows when the code lands:

- §7 governance (`register_tcid`, `quarantine`, `unquarantine`,
  `derivative_link`, `delegation`) — the storage plane exists;
  the wire dispatch and the authorization model do not. M11's
  content layer will land them.
- §14.2 `query_quarantined` and the governance-shaped SYNC verbs —
  same reason, same milestone.
- §13's `ClusterMerge*` verbs — already covered by row 7; the
  verbs are the code path row 7 names, not a separate row.

The estimate is **one pass, after the next two milestones.** Where the
draft is `clear`, the pass is mechanical: the comparison is a check, a
row takes minutes, and the work parallelises without coordination.
Where it is not, the row is design-time; the judgement is whether an
independent implementer would reach the same behaviour from the text,
which the code can inform and the draft's editor has to answer.
Doing the pass before BFT-A item 1 and M9.6c would row their sections
twice: once now, once after the code lands.

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
that reads the function instead of its call sites. Three instances so
far: `Capabilities::new_checked` (row 4); `ClusterState::should_merge`
(row 7), closed at `2bfe99d` when `ClusterHandle::merge_if_due` became
its caller; and `BftStateTransfer::verify` / `signing_payload`, which
have no caller at all — neither in production nor in a test — and are
recorded in row 9's `Source` rather than fixed. Row 3 is
the sequencing variant of the same failure: `record_split_attempt` is
called, and the limit it guards cannot be reached.

A fourth: **name the dependency.** Every row names the rows whose
`Source` it depends on. A row whose dependency is a `FAIL` is
transitively at risk unless the dependency is optional; the risk is
named in the row's `Verdict` field, not inferred by a reader.

**Two views, one file.** The flat table is the matrix: the content, one
row per clause. The topological sort of `Depends on` is the dependency
tree: a derived view, not a separate artifact. When a row's dependency
fails, the tree shows what is downstream of it; the flat table is where
the row itself is read. The tree is not maintained separately, because a
second copy of the edges would be wrong the first time a row is edited.

**A `PASS` on an `incomplete` specification is a draft finding.** The
verdict and the specification status can disagree in the direction that
matters: the code does the right thing while the draft names it wrongly,
so the row reads `PASS` on an `incomplete` clause. That is not a code gap
and it is not a passing row — it is the draft being wrong about something
the implementation accidentally got right. Such findings are discovered
by reading sections beside each other, not by per-clause checks, because
each clause is individually true. The design notes are the instrument;
the matrix records the finding.

Three of this project's cross-section findings were found that way —
S8's field-name contradiction, the unknown-keys rule that would have
closed an open map, and the chain-versus-byte digest collision — and all
three would have survived every test in the tree, because in each case
both behaviours were correct. That is why the design notes precede the
matrix passes rather than following them.

Rows 5 and 6 are the first instances where the finding was resolved by a
draft edit and a test rather than by a design note; they are the cheaper
half of the class.

A fourth trap kind was identified here: a draft whose own definition
makes a correct implementation produce a state the same definition calls
wrong. When the code agrees with the draft and the result is a latch, the
draft's definition is the defect, not the code.

**The decisive query returns zero rows: none `review required`, none
`blocking` — over the eighteen rows that exist.** It does not speak
for the draft's unrowed statements (see the status header and the
Method section's note). Rows 3, 5 and 6 left it in this revision, each by a
different route: §13.5's attempt episode and §5.3.3's expiry filter were
resolved by a draft decision plus a test, and §5.3.4's quorum by stating
`n - f` as the rule the code already implements. Row 7 (§13.4 merge) was
the last, and it left by the longest route: a design note (`bf520fe`),
two note revisions (`3fbee08`, `df3a48e`), the code (`028c102`,
`98f7db2`, `2bfe99d`), and finally the draft amendment that folded the
note's §2a–§2d into §13.4. For the first time in this matrix every row
whose submission impact a draft edit could settle is settled by the
draft.

The query speaks for the rows that exist. It does not speak for
the draft's statements that have no row: a normative statement the
code has not implemented is recorded in `CHANGELOG.md`'s status
table as unlanded, and a normative statement that every wire
message mechanically satisfies is not rowed at all. The query
returns zero rows over the eighteen rows that exist; that is a
statement about their specification status, not a statement about
the draft.

Rows 8 and 18 are `FAIL` on `clear` clauses — the `apply()` contract and
the degraded-mode gate. Row 14 was the third, the transfer's missing
`state_hash`, and it left the list when the field landed. Those rows are
code gaps behind adequate text, so they do not enter this query; they are
tracked as BFT-A item 1 and item 5a.
