# BFT item 1 — the execution contract

**Status: design contract for BFT-A item 1.** Written before the code, as
the milestone contract: what it lands, what it depends on, what it defers,
and what the test proves. §5.3.4 is specified (`6c5d12f`), and the
two-digest conflict this note surfaced is resolved in the draft amendment
recorded under "What it depends on".

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

3. **`apply` returns `OperationOutcome`.** Infallible by signature: an
   application-level failure is the discriminant, not an `Err`. A panic
   inside `apply` is a programming error, not a protocol outcome.

4. **The chain digest in the driver.** `d_n = SHA-256(QUIP-CBOR(map{
   "operation": op_n, "outcome": outcome_n, "prior_state_digest":
   d_(n-1) }))`, keys ordered by QUIP-CBOR, which sorts them to
   `operation`, `outcome`, `prior_state_digest`. Genesis
   `d_(-1) = [0u8; 32]` — an assumption, because the draft does not
   define one.

5. **Events and checkpoint.** `Applied` carries the outcome and the new
   digest; `ApplyFailed` is emitted for the failure discriminant, so the
   existing event name keeps its meaning. `bft_checkpoint.state_digest`
   carries the chain digest, and `bft_state_transfer` gains `state_hash`
   alongside `checkpoint_digest` so the transfer carries both.

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

  **The genesis is `[0u8; 32]` and is provisional.** The draft now states
  the all-zero 32-byte value; if it later chooses a different one (the
  ring id, or a per-checkpoint sentinel), the implementation changes with
  the draft. That is the S9/S10 pattern: the code chooses, the draft
  ratifies or corrects, and the CHANGELOG records which state is current.

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
  covers the failure, and the event reports it. This replaces
  `apply_failure_is_an_event_not_an_error`, whose name stopped being
  ironic when the contract was specified.
- **The wire form.** Roundtrip; unknown key rejected; 257-byte payload
  rejected; both discriminant values encoded and decoded.

**What it does not prove.** Two in-process drivers are not a network: no
Byzantine replica, no message loss, no view change, no state transfer.
Determinism is proven for the code path, not for the protocol under
hostile scheduling — that is BFT-V, and it is the reason this item is
"the execution contract" rather than "BFT is done".
