# The `apply()` contract — proposal

**Status: proposal for BFT-A item 1.** Not a decision. The draft selects
none of the three resolutions below; this document argues for one, so
the draft can adopt or reject it with reasons rather than by default.

## The gap

`BftHandler::apply(&mut self, ring_id, sequence, operation) -> Result<()>`.

`BftDriver::apply_current` calls it, and on `Err`:

1. pushes `BftEvent::ApplyFailed { sequence, text }`,
2. sets the round state to `Idle`,
3. increments `sequence`.

So a failure is an event, and the ring moves on. Replica A applies the
operation and advances; replica B fails it and advances. Both believe
consensus progressed; their states differ.
`apply_failure_is_an_event_not_an_error` asserts exactly this — the test
is a description of the divergence, not a guard against it.

## Why the draft cannot stay silent

The trait's `Result` makes post-commit failure *representable*. Whether
that failure is a fault, an impossibility, or part of the state is what
decides the meaning of "committed", so it is not an implementation
detail. Three implementers reading §5.3.4 today would build three
different protocols, each defensible, all apparently conformant:

- one halts the node on a failed apply (a liveness fault),
- one retries or ignores the operation (a divergence),
- one records the failure and continues (state).

The draft's silence does not leave the choice open; it leaves the choice
to the implementer, which is the definition of an interoperability gap.


## The three resolutions

### (a) Infallible apply; applications validate before consensus

`apply` MUST NOT fail for an operation that reached consensus. Validation
happens before the operation is proposed, so a committed operation is
always executable.

- **Strength.** The simplest statement: by the time it is committed, the
  operation is known-good.
- **Weakness.** It does not say *who* validates or whether validation is
  deterministic. If the primary validates and the replicas trust it, a
  Byzantine primary admits operations the replicas cannot execute — the
  exact failure BFT exists to prevent. To be safe, (a) has to become (b).

### (b) Deterministic validation before consensus

Every replica runs a deterministic `validate(ring_id, sequence, operation)`
before voting; only operations that pass are voted for; `apply` is
infallible on committed operations.

- **Strength.** Invalid operations never enter the log, so the state
  transition is total by construction. Failures are programming errors
  and can halt safely.
- **Weakness.** The validation predicate is now part of the protocol and
  must be specified per application, or two implementations disagree
  about which operations are admissible — a divergence moved one step
  earlier. It also means a rejected operation is never ordered, so a
  client cannot learn *why* it was rejected from the log.

### (c) Commit the state transition

`apply` is deterministic and total. Its `Result` is part of the state
transition: the failure is recorded, covered by the state digest, and
identical on every replica. `ApplyFailed` is a committed outcome, not a
fault, and the driver's advance is correct.

- **Strength.** Matches the driver's existing shape, and it keeps
  application-level rejection ordered: an operation that is well-formed
  but fails its own preconditions becomes state rather than a stalled
  ring. That is what applications with governance and policy need.
- **Weakness.** Determinism becomes a hard obligation on every
  application — no clock, no I/O, no unordered iteration — and the state
  digest must cover the outcome, or a divergent result is invisible to
  checkpoints.

| | Who validates | When | Can `apply` fail? | What is committed | A failure means |
|---|---|---|---|---|---|
| (a) | the application | before proposal | no, by contract | the request | a programming error |
| (b) | every replica, deterministically | before the vote | no, by construction | the request | a fault; halt |
| (c) | every replica, deterministically | before or during execution | yes, deterministically | the transition and its outcome | state |


## Recommendation: (c), explicitly

The recommendation is (c) because the implementation already behaves as
(c) and does not satisfy (c). Today the driver commits the failure and
advances — that is (c)'s *shape* — while the trait imposes none of (c)'s
*obligations*: nothing requires `apply` to be deterministic, and nothing
requires the result to be covered by the digest. The current behaviour is
therefore the least safe reading of (c): it takes the licence to continue
past a failure and omits the condition that makes continuing safe.

Choosing (c) ratifies the shape and adds the missing MUSTs. Choosing (b)
would be defensible — it is the easier contract to reason about — but it
requires changing the failure path from "event and advance" to "halt",
and it loses ordered rejection, which QUIP's operations need: governance
authorization, pin policy and witness freshness are preconditions that
are easier to *record* than to *predict*, because predicting them
requires the proposal-time state to match the commit-time state.

If the draft prefers (b), it should say so explicitly and accept that a
rejected operation is dropped before consensus and never appears in the
log.

## What the draft must say

One paragraph in §5.3.4, adopting (c):

> Execution of a committed operation `MUST` be deterministic: the result
> `MUST NOT` depend on the local clock, on I/O, on iteration order, or on
> any input not present in the operation or the committed state. The
> result of execution is part of the state transition; a replica `MUST`
> include it in the state it commits and in the digest it checkpoints. A
> replica whose execution result differs from the ring's `MUST` be
> treated as faulty. An execution failure `MUST NOT` prevent the
> sequence from advancing.

## What changes in the code

- `BftHandler::apply` — document the determinism obligation, and that
  `Err` is a result rather than a veto.
- `BftEvent::ApplyFailed` — document it as a committed outcome.
- `BftHandler::state_digest` — document that it must cover execution
  outcomes, or a divergent result is invisible to checkpoints.
- `bft_driver.rs`'s failure path — no behaviour change; the comment that
  says it "does not halt the driver" becomes the contract rather than a
  caveat.

## Open questions

1. **Does the execution result enter `state_digest`?** Under (c) it must,
   or two replicas can diverge in the result and still agree on every
   checkpoint digest.
2. **Is a validation failure ordered?** Under (c) every proposed
   operation is ordered and its rejection is an outcome; under (b) it is
   dropped. The two produce different logs for the same input.
3. **May a replica vote against an operation it can validate?** Under (c)
   it may, but a committed operation must still execute deterministically
   — so a "no" vote must be a policy decision, not a prediction of
   failure.
4. **Does `ApplyFailed` feed fault suspicion?** Under (c), persistent
   disagreement about a *result* is evidence of a faulty replica, and the
   draft does not yet say what a ring does with that evidence.
