# BFT state-transfer authentication

**Status:** design proposal, awaiting review. No code yet.

This note fixes the contract for authenticating a `bft_state_transfer`
(§5.3.4.1) before the state it carries is applied. It exists because a
read-only investigation of `76c9d0e` confirmed that the transfer's
bytes are checked only against `state_hash`, a field the sender
supplies, and that no signature in the receive path covers either
`state` or `state_hash`. A responder holding a genuine checkpoint
signature can therefore supply arbitrary state with a matching
`state_hash` and have it installed and applied.

The note is the record of the decision that closed that gap. It does
not change the draft's S8 decision — the checkpoint's signature set
remains the transfer's only signature — and it does not add a round
trip. It adds a check the receiver runs locally before installing the
state.

---

## §1 — The gap

`handle_state_transfer_response` verifies two things:

- The ring signature, through `verify_checkpoint_ring_sig`, against a
  rebuilt `bft_checkpoint` payload over
  `(ring_id, checkpoint_sequence, checkpoint_digest)`. `state` and
  `state_hash` never enter the payload.
- The byte checksum: `sha256(&msg.state) == msg.state_hash`. Both sides
  of that comparison are supplied by the sender.

Nothing ties the transmitted state to `checkpoint_digest`. A responder
that holds a genuine checkpoint signature can send arbitrary state and
a `state_hash` computed over it; the byte check passes by
construction, the signature check passes because the signature covers
only the checkpoint triple, and `apply_state` installs the substituted
state. The `BftEvent::StateTransferApplied` event then reports the
genuine `checkpoint_digest` beside state that digest does not commit
to.

`BftStateTransfer::verify` and `BftStateTransfer::signing_payload`
exist and build a payload over the transfer's own fields, but neither
has a caller. They are the third instance of the "name the caller"
class: `Capabilities::new_checked`, `ClusterState::should_merge`, and
now this. This note does not use them. It closes the gap with a local
check, not by wiring an uncalled function into the receive path.

---

## §2 — The decision

**The receiver MUST recompute the chain digest from the transmitted
state and MUST reject the transfer if that digest does not equal
`checkpoint_digest`.**

The recomputation happens after the byte check and before
`apply_state`. A mismatch rejects the transfer and the state is not
applied. This closes the substitution case: arbitrary state will not
produce the checkpoint's chain digest under the application's own
computation, so a responder that supplies a self-consistent
`(state, state_hash)` pair with a genuine checkpoint signature is
rejected at the recomputation.

**What "the chain digest from the state" means.** For any state a
handler produces, computing the chain digest from its serialized bytes
MUST equal the chain digest the handler would report through
`state_digest()`. That is the property the receiver's recomputation
relies on, and it is the property the trait change enforces:

    handler.state_digest_of(&handler.state_bytes()) == handler.state_digest()

for every handler state. A handler whose chain digest is a rolling
digest over applied operations must therefore serialize that rolling
digest into its state, so that recomputing the digest from the bytes
yields the same value.

This is a real requirement on applications and the draft states it as
`MUST` rather than `SHOULD` because a state transfer that cannot be
authenticated from its own state is a state transfer a responder can
substitute.

---

## §3 — The trait shape

`BftHandler` gains one method:

    fn state_digest_of(&self, state: &[u8]) -> Digest;

It is the inverse of the handler's serialization: given the state bytes
the handler would produce, it returns the chain digest the handler
would report. The default is not provided; every handler must implement
it, because a handler that cannot answer it cannot participate in a
state transfer.

**Why this shape and not the alternatives.** Three shapes were
considered:

- **`apply_state` returns the chain digest.** Smaller trait change, but
  the state is installed before the comparison, so a substituted state
  has already been applied by the time the check fails. Reversibility
  is not guaranteed by the trait, so this shape is not safe.
- **The checkpoint carries a state root verified against the state
  bytes.** Strongest, but a wire change to the checkpoint or the
  transfer. Out of scope for this decision.
- **`state_digest_of` on the handler.** Smallest trait change that is
  safe: the receiver checks the recomputation before installing, and
  no new wire field. This is the chosen shape.

**Receiver obligation.** The receiver MUST call `state_digest_of` on
`msg.state` and MUST compare the result against
`msg.checkpoint_digest` before `apply_state`. A mismatch rejects the
transfer with a distinct error so the caller can tell a chain-digest
mismatch from a byte-digest mismatch.

---

## §4 — What the change lands

- `quip-net/src/bft_driver.rs`: the `BftHandler` trait gains
  `state_digest_of(&self, state: &[u8]) -> Digest`;
  `handle_state_transfer_response` calls it on `msg.state` after the
  byte check and rejects on mismatch before `apply_state`.
- The test handlers gain `state_digest_of`. The counting handler
  returns `sha256(state)`. `ChainDigestHandler` serializes its rolling
  digest into `state_bytes()` and extracts it in `state_digest_of`, so
  the test fixture's state is self-describing and the recomputation
  works.
- The draft's §5.3.4.1 step 3 gains two sentences: the receiver MUST
  recompute the chain digest from the transmitted state and MUST
  reject the transfer on mismatch; and a handler whose chain digest
  is derived from applied operations MUST serialize that digest into
  its state.
- Matrix row 14's `Source` field names `state_digest_of` and the
  recomputation step, its `Test` field gains the substitution test,
  and the clause's "MUST bind the transferred bytes" becomes true
  rather than aspirational.
- A new test replaces the missing substitution test:
  `state_transfer_rejects_substituted_state_with_matching_state_hash`.
  It constructs a response with replaced `state` and `state_hash`,
  leaves `checkpoint_digest` and `ring_signature` untouched, and
  asserts the receiver rejects with the chain-digest mismatch.

**Deliberately not in this commit.** `BftStateTransfer::verify` and
`signing_payload` remain uncalled. They are the third instance of the
"name the caller" class, and the correct treatment is either deleting
them or wiring them, both of which are separate from this decision.
The Frost rejection branch stays untested for the same reason. The
`76c9d0e` style findings — the wire-compatibility correction, the test
doc-comment attribution, the S14 record of the two draft decisions,
the restore-and-run evidence pointer — are a `docs:` follow-up, not
this commit.