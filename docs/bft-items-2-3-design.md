# BFT-A items 2 and 3 — prepared-operation and checkpoint carry-forward on view change

**Status: design note.** Code lands in a later commit; this note is the
contract. It records what items 2 and 3 must do, the three sites where
the code does not yet do it, and one ambiguity in the draft that the
note names but does not resolve.

**What this note implements, and what it decides.** Two of the four
trap entries below are code traps (draft clause clear, code does not
satisfy). The third is a draft trap (the same section states two rules
that a four-member ring cannot both satisfy), and the fourth is a
draft-and-reference trap (a requirement the same section's own wire
form makes unreachable). The note records the trap kinds so a later
reader can tell what the code commit fixes from what a draft amendment
fixes.

## What it lands

**Prepared-operation carry-forward on view change.** The draft's
view-change paragraph requires: "The view change includes quorum
certificates for prepared messages and the latest stable checkpoint to
ensure safety across view changes." (draft 1515–1517). The prepared
messages' form is the same section's next requirement: "Each entry in
`prepared_messages` is a complete `bft_preprepare` message as it would
appear on the wire, including the primary's signature. It is not a
digest. The new primary re-proposes these messages, and witnesses
re-verify the primary's signature." (draft 1429). A replica that
prepared operations in view `v` includes their digests in the
`bft_view_change`'s `prepared_digests` field; the new primary collects
those digests with the view-change quorum and, in the `bft_new_view` it
emits, carries the full encoded `bft_preprepare` messages in
`prepared_messages`; a witness receiving the new-view verifies each
entry as a `BftPreprepare` (`BftPreprepare::verify` against the new
primary), re-proposes them, and does not accept an operation the new
primary has not re-proposed. The code sends the empty form at both
ends: `quip-net/src/bft_driver.rs:1003`
("let prepared_digests: Vec<Digest> = Vec::new();") and
`quip-net/src/bft_driver.rs:1153` ("prepared_messages: Vec::new(),").

**Checkpoint carry-forward on view change.** The same requirement names
the checkpoint beside the prepared messages — "quorum certificates for
prepared messages and the latest stable checkpoint" (draft 1515–1517) —
so the certificate the new-view carries is not only the prepared
operations. A replica includes its latest stable checkpoint digest in
`checkpoint_digest` on `bft_view_change`, which the code already
populates (`quip-net/src/bft_driver.rs:1010`,
"checkpoint_digest: self.checkpoint_digest,"); the new primary includes
the latest stable `bft_checkpoint` messages in the new-view's
`checkpoint_messages` field; a witness receiving the new-view verifies
each carried `bft_checkpoint` against the ring's signature set before
adopting it. The code sends the empty form at
`quip-net/src/bft_driver.rs:1154` ("checkpoint_messages: Vec::new(),").

**The state-transfer ring signature and the degraded ring.** The
draft's quorum list states the general rule and two instance values:

> A quorum is n - f distinct ring members, where n is the ring size and
> f is the maximum number of Byzantine members tolerated. For a full
> ring of seven f = 2 and the quorum is five (VIEW_CHANGE_QUORUM = 5);
> for a degraded ring of four f = 1 and the quorum is three
> (DEGRADED_QUORUM). n - f is the general rule; specific ring sizes
> follow from it. (draft 1444–1451)

> A bft_new_view message MUST contain at least n - f valid view-change
> messages. (draft 1452–1453)

Later in the same list the transfer's signature is stated flat, with no
degraded-ring alternative:

> A state transfer MUST include a RingSignature that is either:
>
> - 5 individual Ed25519 signatures from distinct witnesses, ordered by
>   canonical NodeId with corresponding signer list, or
> - A FROST aggregate signature from 5 of 7 witnesses.
>
> (draft 1457–1462)

> Recipients MUST validate the quorum threshold before accepting any
> state transfer. (draft 1465–1466)

The validation paragraph that follows constrains the payload the
signature covers, not the number of signers:

> Recipients of a bft_state_transfer MUST validate the RingSignature
> against the checkpoint signing payload for (ring_id,
> checkpoint_sequence, checkpoint_digest), by either: (draft 1469–1472)

The list is internally inconsistent for a four-member ring. The general
rule at line 1447 is `n - f`; the degraded ring's quorum at line 1449 is
three (`DEGRADED_QUORUM`); the state-transfer rule at lines 1457–1462
demands a flat five signatures with no degraded-ring alternative. A
four-member ring cannot produce five signatures, so the two rules cannot
both hold. This is a draft trap. The code's reading is the general rule:
`verify_checkpoint_ring_sig` (`quip-net/src/bft_driver.rs:1633`) rejects
a signature set shorter than `membership.quorum()`
(`quip-net/src/bft_driver.rs:1662`: "if irs.signatures.len() <
membership.quorum()"), which is 5 on a seven-member ring and 3 on a
four-member ring. The `quip-net/src/bft.rs:731–732` doc comment on
`BftStateTransfer::ring_signature` states the flat "5" and is the stale
site; this note records the divergence, the code commit corrects the doc
comment, and the draft amendment is deferred.

**Resolution of Trap 4 — the vote carries full preprepares.** Chosen over
the state-transfer-assisted alternative (Resolution B, which keeps
`prepared_digests` as digests and recovers the rest via state transfer,
at the cost of a permanent loss class: a prepared-but-not-committed
operation whose digest the new primary cannot reconstruct is lost across
the view change, weakening draft 1516–1517's "prepared across view
changes" guarantee). Under Resolution A, `bft_view_change`'s
`prepared_digests` field changes from `[* bytes .size 32]` to `[* bytes]`
carrying full encoded `bft_preprepare` messages, matching
`bft_new_view.prepared_messages`' already-existing wire form. The vote
becomes the certificate the draft at 1516 calls for, the new primary
reassembles `prepared_messages` by concatenating what the votes already
carry (each entry verified as a `BftPreprepare` against the new primary's
signature per draft 1429), no reconstruction is needed, no witness needs
state transfer to catch up on prepared operations, and the draft's three
statements compose. The wire weight is bounded by `CHECKPOINT_INTERVAL =
100` (`quip-core/src/constants.rs:99`): anything older than the last
stable checkpoint is covered by `checkpoint_messages` and
`checkpoint_digest`, so a witness's prepared set at view change is at
most 100 operations per witness, 700 in the worst case for a
seven-member ring, well within a view-change message budget. The wire
change is breaking: every construction of `BftViewChange` in the tree
(`quip-net/src/bft.rs:1263` `view_change_roundtrip`,
`quip-net/src/bft.rs:1277` `view_change_empty_prepared_roundtrips`,
`quip-net/src/bft_driver.rs:2662` `stale_view_change_vote_is_ignored`)
constructs `prepared_digests: Vec<...>` and changes to
`prepared_preprepares: Vec<Vec<u8>>` under Resolution A. The draft
amendment is a one-line CDDL change at `draft-mututi-quip-03.xml` line
1371 plus a prose confirmation at 1429, and lands as its own `docs:`
commit; the code change lands as the items 2–3 code commit. Neither this
note nor the code commit edits the draft.


## What it depends on

- **BFT-A item 1's chain digest.** `BftDriver::chain_digest()` and the
  invariant `BftCheckpoint::state_digest == chain_digest` (`1e45f18`,
  `476b42e`). A carried `bft_checkpoint` means something only because its
  `state_digest` is `d_n` and the ring signed that value.
- **Row 8's source-proving closure test.**
  `checkpoint_carries_the_chain_digest_not_the_handler_digest`
  (`476b42e`) is the evidence that the checkpoint's field is the driver's
  digest and not the handler's; item 3 carries that value into a new
  view.
- **Row 14's universal chain check.** `handle_state_transfer_response`
  compares `state_digest_of(&msg.state)` against `checkpoint_digest` for
  every accepted transfer. The two digests stay distinct here: a carried
  `bft_checkpoint` is adopted on the ring's signature set, and a state
  transfer is accepted on the chain check.
- **Draft 1429** — the prepared messages are complete `bft_preprepare`
  messages, not digests.
- **Draft 1452–1453** — a `bft_new_view` MUST contain at least `n - f`
  valid view-change messages; the code enforces it at
  `quip-net/src/bft_driver.rs:1120` ("if signers.len() <
  self.membership.quorum()").
- **Draft 1457–1466** — the state-transfer ring signature and the
  recipient's obligation to validate the quorum threshold.
- **Draft 1515–1517** — quorum certificates for prepared messages and
  the latest stable checkpoint.
- **The constants.** `DEGRADED_QUORUM = 3` at
  `quip-core/src/constants.rs:77`; `VIEW_CHANGE_QUORUM = 5` at
  `quip-core/src/constants.rs:96`. The driver uses `membership.quorum()`
  rather than either constant, so one rule serves both ring sizes.
- **The Resolution A wire form's downstream effect.**
  `BftViewChange.prepared_digests` (`quip-net/src/bft.rs:464`) becomes
  `prepared_preprepares: Vec<Vec<u8>>`; its `to_bytes`, `from_bytes`, and
  `signing_payload` (`quip-net/src/bft.rs:471–526`) each change from
  `digest_list` to `bytes_list` and from `as_bytes_n32` to a bytes-list
  decode; and the three tests named in the Resolution paragraph change
  with it. None of these change in this commit.

## What it defers

- **FROST ring signatures.** `verify_checkpoint_ring_sig` returns false
  for `RingSignature::Frost`, and the caller rejects the transfer.
  Landing FROST is BFT-V work, not items 2–3.
- **The four-replica Byzantine harness.** BFT-V.
- **The draft amendment that reconciles the flat five in lines 1457–1462
  with the general `n - f` rule at line 1447.** That is a draft commit,
  not a code commit, and it lands separately.
- **Application state serialization.** Unchanged; §5.3.4.1's SHOULD.
- **The Trap 4 draft amendment.** `draft-mututi-quip-03.xml` line 1371's
  `prepared_digests: [* bytes .size 32]` → `[* bytes]`, plus the
  confirming prose at 1429 that the field carries full encoded
  `bft_preprepare` messages, not digests. The wire-format change is a
  breaking change to draft-03's `bft_view_change`; the CHANGELOG will
  record it under the amendment's own entry, not this note's. The code
  change to match (`BftViewChange` field type and encoding, the three
  test fixtures, `start_view_change`'s digest capture,
  `maybe_emit_new_view`'s assembly, `on_new_view`'s per-entry
  verification) is the items 2–3 code commit, which follows this note
  and its resolution.

## The trap inventory (BFT-A items 2 and 3)

The item 1 note named no traps; this one names four.

**Trap 1 — code trap.** Draft line 1429 requires the `bft_new_view`'s
`prepared_messages` to contain complete `bft_preprepare` messages.
`quip-net/src/bft_driver.rs:1153` emits an empty `Vec`. A new view today
carries no prepared operations, so a witness that prepared an operation
in view `v` loses that preparation when the view changes. The
requirement is clear; the code does not satisfy it.

**Trap 2 — code trap.** Draft lines 1515–1517 require the view change to
include the latest stable checkpoint.
`quip-net/src/bft_driver.rs:1154` emits an empty `checkpoint_messages`
`Vec`. A new primary today does not carry its stable checkpoint into the
new view, so a lagging witness cannot learn the stable checkpoint from
the new view. Same shape as trap 1.

**Trap 3 — draft trap.** Draft lines 1457–1462 state the state-transfer
ring signature as a flat five with no degraded-ring alternative; draft
line 1449 states the degraded ring's quorum is three. A four-member ring
cannot produce five signatures. The code's `verify_checkpoint_ring_sig`
compares against `membership.quorum()` (`quip-net/src/bft_driver.rs:1662`)
and therefore accepts a three-signature transfer on a four-member ring;
the `quip-net/src/bft.rs:731–732` doc comment repeats the draft's flat
"5" and is the stale site. The trap is that a correct implementation of
the general `n - f` rule produces a state (a 3-of-4 transfer) that a
specific rule later in the same section calls wrong. This is a draft
trap, not a code trap: the code follows the general rule, and the draft
is what must be corrected.

**Trap 4 — draft trap and reference trap.** The `bft_view_change`
carries `prepared_digests: [* bytes .size 32]` (draft 1371): 32-byte
digests. The `bft_new_view` carries `prepared_messages: [* bytes]`
(draft 1382–1383): full encoded `bft_preprepare` messages, per draft
1429's "complete `bft_preprepare` message as it would appear on the
wire, including the primary's signature. It is not a digest." The new
primary is the party who builds the `bft_new_view` from the view-change
votes it has collected, and the votes carry digests. The new primary
cannot produce a preprepare from a digest: the operation is not in the
digest, and no field in `bft_view_change` carries it. Draft 1429
requires a state that the draft's own wire form makes unreachable for a
new primary that did not itself prepare the operation.

This is the fourth trap kind twice over. It is a draft trap because the
same section states a requirement (draft 1429) that a correct
implementation of the wire form the same section defines (draft 1371)
cannot meet. It is also a reference trap in the current code:
`BftViewChange.prepared_digests` (`quip-net/src/bft.rs:464`) is written
by no producer that fills it with values a new primary can reconstruct,
and read by no consumer that turns the digests into messages —
`start_view_change` sets `self.current = None` before it could copy
anything into the field (`quip-net/src/bft_driver.rs:997–1003`), and
`maybe_emit_new_view` (`quip-net/src/bft_driver.rs:1130`) writes
`prepared_messages: Vec::new()` unconditionally
(`quip-net/src/bft_driver.rs:1153`).

The draft's three statements do not compose: the vote carries digests,
the new view carries full messages, and the new primary reassembles them
from the votes. Item 1's note named no such trap. This note names it as
Trap 4, records the resolution below, and defers the draft amendment to
its own `docs:` commit.



## The test that proves it

One test per class, named by file and function.

**Class A — prepared-operation carry-forward.** Test:
`view_change_carries_prepared_operations` in
`quip-net/src/bft_driver.rs`'s tests module. The test drives one
operation to `Prepared` on a replica, then triggers a view change on that
replica; the replica's emitted `bft_view_change` must have
`prepared_digests.len() == 1`, and that digest must equal the digest of
the driver's in-flight operation (`BftDriver::current_operation`,
`quip-net/src/bft_driver.rs:568`). The new primary's `bft_new_view` must
have `prepared_messages.len() == 1`; a receiver must verify the entry as
a `BftPreprepare` against the new primary's signature, and after adoption
`current_operation()` must equal the carried operation. The class fails
today at the first assertion, because `prepared_digests` is empty.

**Class B — checkpoint carry-forward.** Test:
`new_view_carries_the_stable_checkpoint` in the same module. The test
brings every driver to a stable checkpoint at sequence `N` through the
existing `pump_checkpoints` path, forces a view change, and asserts: the
new primary's `bft_new_view.checkpoint_messages` has length at least one;
each entry decodes as a `BftCheckpoint` whose `state_digest` equals the
stable checkpoint's digest; and a receiver with a stale local checkpoint
(`checkpoint_sequence == 0`) accepts the new-view only when the carried
`checkpoint_digest` agrees with its recomputation through
`state_digest_of`, and rejects a new-view whose `checkpoint_digest`
disagrees. The class fails today at the `checkpoint_messages` length
assertion.

**Class C — state-transfer ring signature on a four-member ring.** Test:
`degraded_ring_state_transfer_accepts_three_of_four` in the same module.
Build a four-member ring, bring three replicas to a stable checkpoint
(`DEGRADED_QUORUM = 3`), make the fourth lagging, and assert the lagging
replica's `on_state_transfer` accepts the three-signature response. The
test proves the code's reading of the draft's general `n - f` rule; the
note names the flat five as the divergence the draft must reconcile, and
trap 3 records it.

## Matrix rows touched

Two rows are added by this commit, and no existing row's verdict moves.

- **Row 19** — draft 1429's `prepared_messages` requirement. `UNTESTED`;
  `clear`; `non-blocking`; depends on row 8 and the item 1 chain-digest
  work; closure test `view_change_carries_prepared_operations`.
- **Row 20** — draft 1515–1517's quorum certificates for prepared
  messages and the latest stable checkpoint. `UNTESTED`; `clear`;
  `non-blocking`; same dependencies; closure test
  `new_view_carries_the_stable_checkpoint`.
- Row 7 (`ClusterState::should_merge`, closed at `2bfe99d`) is
  unaffected. Rows 8 and 14 stay as they are: the carry-forward classes
  name them as dependencies, not as moving verdicts.

