# BFT item 1 — the execution contract

**Status: design contract for BFT-A item 1, revised at `a5c0dfb` after the
AI1/AI2 review pair and the read-only field-name report.** The note was
reviewed before the code landed; the pair's findings and the report's
conclusions are folded into §4, §5, and "What it depends on", and are
recorded in CHANGELOG.md's M9.6b design-note subentry. §5.3.4 is specified
(`6c5d12f`); the draft's §5.3.4.1 coverage rule and §5.3.4's sequence
chain are reconciled in the draft amendment that follows this commit.

**What this note implements, and what it decides.** Items that
implement draft clauses: §1's `OperationOutcome` implements
§5.3.4's outcome encoding (text keys, text discriminant,
256-byte payload bound); §2's `validate` call sites implement
§5.3.4's "runs before the operation enters consensus"; §3's
infallible `apply` implements §5.3.4's "an `apply` failure is
recorded as the application's declared outcome"; §4's `d_n`
construction implements §5.3.4's "digest construction", and §5's
state_digest relation implements §5.3.4.1's coverage rule
conditional on the state-format recommendation. Items that are
the note's own decisions, not draft clauses: the two `validate`
call sites (the draft does not name them); the event split in §5
(`Applied` on both outcomes, `ApplyFailed` deleted); the
chain-over-sequence reading in §4's "chain digest and byte
digest" paragraph, conditional on the state-format SHOULD; the
provisional genesis (the draft defines it, but calls it
provisional); and the `apply` signature change that receives the
deterministic context. The note records these as decisions so a
future reader can tell which parts of the contract are the
draft's and which are the note's.

## What it lands

1. **`OperationOutcome`** in `quip-core`. A protocol type, not an
   application one: a discriminant (`success` or `application-failure`,
   both text) and an optional payload of at most 256 bytes. Canonically
   CBOR-encoded as a map with the text keys `"discriminant"` and
   `"payload"`; decode rejects an unknown key and an oversize payload
   with `E_BAD_ENCODING`, per §10's closed-map rule.

2. **`BftHandler::validate`** in `quip-net`. Deterministic, and given the
   context §5.3.4 names: operation index, view, committed sequence and
   the previous state digest. Called before an operation enters
   consensus — by the primary before proposing, by a backup on receiving
   `bft_preprepare` before voting. A failure drops the preprepare and
   the sequence does not advance.

3. **`apply` returns `OperationOutcome` and receives the same
   deterministic context the draft gives `validate`: the operation
   index, the view, the committed sequence, and the previous state
   digest `d_(n-1)`. Infallible by signature: an application-level
   failure is the discriminant, not an `Err`. A panic inside `apply`
   is a programming error, not a protocol outcome.

4. **The chain digest in the driver.** `d_n = SHA-256(QUIP-CBOR(map{
   "operation": op_n, "outcome": outcome_n, "prior_state_digest":
   d_(n-1) }))`, keys ordered by QUIP-CBOR. The canonical order sorts
   on the full encoded key including the header byte, and the header
   bytes are `outcome` 0x67, `operation` 0x69, `prior_state_digest` 0x72,
   so the sorted order is **outcome, operation, prior_state_digest**
   — not the field order written in the map literal. `quip-core`'s
   encoder sorts this way (`quip-core/src/cbor/encode.rs`); a hand-written
   encoder that follows the literal order produces non-canonical bytes
   and a different digest.

5. **Events and checkpoint.** `Applied` fires on every committed
   operation and carries the `OperationOutcome` and the new `d_n`.
   `ApplyFailed` is deleted: the draft says an `apply` failure "is
   recorded as the application's declared outcome, included in the
   digest, and treated as a state transition like any other", so a
   separate failure event would draw a distinction the draft does not.
   The event's `text` field goes with it — there is no error text to
   carry, because an application-level failure is the outcome, not an
   error. The integration test that replaces
   `apply_failure_is_an_event_not_an_error` is named
   `apply_failure_is_a_state_transition`; it asserts that `Applied`
   fires with `OperationOutcome::ApplicationFailure` and that `d_n`
   advances.

   **The empty-output rule.** `d_n` advances on every committed
   operation, including an operation whose `OperationOutcome` payload
   is empty. The discriminant is in the map, so a success with no
   payload produces a digest that differs from the previous `d_n`;
   the map does not collapse. The draft's sentence "the digest treats
   the empty output as unchanged" refers to applications with no
   execution state — empty payload on every operation — which
   produces a chain of digests each dependent on the empty outcome.
   It does not mean `d_n == d_(n-1)`; that reading would let a
   failure be invisible in the chain, which the draft's "treated as a
   state transition like any other" rules out.

   `bft_checkpoint.state_digest` carries the chain digest, and
   `bft_state_transfer` carries `state_hash` alongside
   `checkpoint_digest`. The field is in the CDDL (§5.3.4.1) and in the
   code (`quip-net/src/bft.rs:722`); the note's contract relies on it,
   it does not add it.

6. **Tests** — the four groups under "What the test proves".

## What it depends on

- **§5.3.4's digest binding and wire form** (`6c5d12f`): the three-key
  map, text keys, text discriminant, 256-byte bound, closed maps.
- **`quip-core`'s CBOR** (`quip-core::cbor`) and the driver's existing
  round state machine.
- **The two-digest split, resolved in the draft.** §5.3.4 previously said
  `checkpoint_digest` *is* the state digest, while §5.3.4.1 said the field
  `MUST` be the SHA-256 of the state bytes as transmitted. Those are
  different quantities: one commits to what was applied, the other to what
  the state is. The amendment now distinguishes them —
  `bft_checkpoint`'s `state_digest` is the chain digest over the committed
  sequence; `bft_state_transfer`'s `checkpoint_digest` is that same chain
  digest, restated so the ring signature can be verified; and the transfer
  carries `state_hash`, the SHA-256 of the transferred bytes, which a
  receiver verifies before applying.

  They answer different questions and neither substitutes for the other.
  The chain digest detects diverged execution among honest replicas at
  checkpoint quorum: two replicas that applied the same committed sequence
  and diverged in a hook's output produce different chain digests. The
  byte digest detects a substituted or corrupted state transfer: bytes
  that do not hash to the announced digest are untrustworthy. Dropping
  either loses a property — without the chain digest a divergent replica
  is undetectable at quorum; without the byte digest a transfer cannot be
  verified against the message that carries it.

  **The genesis value.** §5.3.4 defines `d_(-1) = [0u8; 32]`. The
  all-zero 32-byte value is the draft's, and is provisional: if the
  draft later chooses a different genesis (the ring id, or a
  per-checkpoint sentinel), the implementation changes with the draft.
  That is the S9/S10 pattern: the code chooses, the draft ratifies or
  corrects, and the CHANGELOG records which state is current.

  **The chain digest and the byte digest.** §5.3.4 defines the chain
  digest over the committed operation sequence (the `d_n` construction
  above). §5.3.4.1 requires the chain digest to be "a digest over
  every byte of the handler's serialized state". The two agree when
  the state-format rule is taken: §5.3.4.1 recommends it as SHOULD, not MUST
  — the state should encode the DVV, the view, the sequence, and
  the post-checkpoint operations. When that recommendation is
  followed, the state carries the sequence, so
  `BftHandler::state_digest_of(&state)` recomputes `d_n` from the
  state by replaying the sequence, and `BftHandler::state_digest()`
  returns the same `d_n`. The receiver verifies two things:
  `SHA-256(state) == state_hash` (the byte check) and
  `state_digest_of(state) == checkpoint_digest` (the chain check).
  Both checks are about the same committed history; the first binds
  the bytes, the second binds the chain.

  A handler that does not take the state-format recommendation still
  satisfies the byte check — `state_hash` is `SHA-256(state)`
  regardless of what the state contains — but its
  `state_digest_of(state)` may not recompute `d_n`; the chain check
  is only as strong as the handler's state format. Row 14's PASS
  rests on the byte check for every handler and on the chain check
  for handlers that take the recommendation. If the draft later
  strengthens the state-format rule from SHOULD to MUST, the chain
  check becomes universal and row 14's PASS becomes stronger; until
  then, the note records the conditional.

  The three names that refer to the same `d_n` in three places are
  not one field: `prior_state_digest` is a preimage map key (draft
  1654); `state_digest` is the checkpoint's field carrying `d_n`
  (draft 1394); `checkpoint_digest` is the transfer's field
  restating the same `d_n` (draft 1404). The note adopts that
  naming; the draft's line 1665 needs the disambiguating sentence in
  the amendment that follows.

## What it defers

- **BFT-A items 2 and 3** — view change and the handling of a replica
  whose checkpoint digest disagrees. This item detects divergence; it
  does not act on it.
- **State-transfer integrity tests** for the two-digest split. The
  implementation must not silently choose one digest; the test for the
  other belongs with the checkpoint work.
- **Property and adversarial tests** (BFT-V): determinism under
  reordering, outcome fuzzing, digest collision assumptions.
- **Application state serialization** — still opaque to the protocol and
  the application's choice (§5.3.4.1).
- **The genesis digest's final value.** The draft states the all-zero
  32-byte value and this note records it as provisional; ratifying it is
  a draft decision, not an implementation one.

## What the test proves

- **Determinism.** Two drivers fed the same operations and outcomes
  compute the same digest at every sequence. This is the property the
  whole contract exists for.
- **The outcome is in the digest.** A success with a payload and a
  success without one produce different digests; so do the two failure
  shapes.
- **Validate rejects before consensus.** A handler whose `validate`
  fails causes the preprepare to be dropped on the primary and on a
  backup, with no sequence advance — two tests, because the call sites
  are different.
- **A failure outcome is committed.** The sequence advances, the digest
  covers the failure, and `Applied` reports it with
  `OperationOutcome::ApplicationFailure`. The test is
  `apply_failure_is_a_state_transition`, replacing
  `apply_failure_is_an_event_not_an_error`, whose name stopped being
  ironic when the contract was specified.
- **The wire form.** Roundtrip; unknown key rejected; 257-byte payload
  rejected; both discriminant values encoded and decoded.

**What it does not prove.** Two in-process drivers are not a network: no
Byzantine replica, no message loss, no view change, no state transfer.
Determinism is proven for the code path, not for the protocol under
hostile scheduling — that is BFT-V, and it is the reason this item is
"the execution contract" rather than "BFT is done".

Divergence detection is not tested here. The note's §2 claims the
chain "detects diverged execution among honest replicas at
checkpoint quorum", but none of the four test groups above
exercise a quorum of divergent replicas; that needs the BFT-V
simulator, and it is the reason this item is "the execution
contract" rather than "BFT is done".
