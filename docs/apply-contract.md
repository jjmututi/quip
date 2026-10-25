# The `apply()` contract — proposal

**Status: adopted; digest construction and outcome wire form specified
in this note, implementation pending.** §5.3.4's "Application Execution
Contract" states resolution (c) under the hook reading — the hook, the
digest contract, the deterministic context, the failure contract, the
empty-output default, the digest binding and the outcome encoding. What
remains is the implementation: the reference code has no `validate`
hook, does not include the `apply` output in the digest, and records a
failure without covering it in the checkpoint (BFT-A item 1). The rest
of this note is the reasoning that led to the choice, kept as the record
of what was considered.

Sections marked *record* below — §"The gap", §"The prior question",
§"The three resolutions", and §"Recommendation" — are the record of
what the implementation was and what was considered. They are in
present tense for the pre-contract shape (`apply(...) -> Result<()>`,
`BftEvent::ApplyFailed` on `Err`); the contract has since landed at
BFT-A item 1 and the §§"What changes in the code" and §"Open
questions" sections are the record of what the contract changed. The
§"The gap" section's `apply_failure_is_a_state_transition` paragraph
is the update that identifies which of the two shapes is current.

## The gap — *record*

`BftHandler::apply(&mut self, ring_id, sequence, operation) -> Result<()>`.

`BftDriver::apply_current` calls it, and on `Err`:

1. pushes `BftEvent::ApplyFailed { sequence, text }`,
2. sets the round state to `Idle`,
3. increments `sequence`.

So a failure is an event, and the ring moves on. Replica A applies the
operation and advances; replica B fails it and advances. Both believe
consensus progressed; their states differ.
`apply_failure_is_a_state_transition` (the test that replaced
`apply_failure_is_an_event_not_an_error` when §5.3.4's execution
contract landed at BFT-A item 1) drives exactly this shape: a
committed failure that the sequence advances past. It proves the
failure is now a committed outcome — `BftEvent::Applied` carries
`OperationOutcome::ApplicationFailure` and the chain digest folds
the outcome — not an error path. Before the contract landed, the
old test was a description of the divergence; after, the new one
is a guard against restoring the pre-contract shape.

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


## The prior question: hook or contract? — *record*

Before the three resolutions, the draft has to answer a prior
question: is `apply` a protocol-defined execution step — the
reference implementation's `BftHandler` is the definition of what
execution is — or a per-application hook, where the protocol
specifies *when* it is called and *what* it returns and the
application defines the semantics?

Under the first reading, the three resolutions are three contracts
the protocol imposes on execution. Under the second, they are three
hook shapes, and the draft's obligation is to pick one and specify
its signature, its call site, and what the protocol does with its
return value.

**The note recommends the hook reading.** A draft that says
"applications must implement `BftHandler`" is a draft that
specifies a Rust interface, not a protocol. The protocol specifies
the hook; the reference implementation's `BftHandler` is one hook of
that shape, not the definition of it.

Under the hook reading, the mechanical surface is small — the
developer writes `Operation`, `validate`, and `apply` — and the
protocol supplies everything else. That is the incentive: a
developer does not write BFT to use QUIP; the developer writes
operations and the protocol agrees on their sequence. The
mechanical hook is the boundary where the developer's job begins,
and it should be as small and as well-primitived as the draft can
make it.

## What the draft must supply beside the hook

Five paragraphs, not one. The hook alone is mechanical in the bad
sense — the developer writes everything and the protocol agrees on
the order of inputs. The primitives around the hook are the value
the protocol supplies.

1. **The hook.** Applications supply `validate` and `apply`. Both
   are called by the driver. `validate` runs before the operation
   enters consensus; `apply` runs after commitment. Neither is
   defined by the protocol.
2. **The digest contract.** `state_digest` includes the `apply`
   output. A `()`-returning `apply` means "no state transition" and
   is the default for applications with nothing to execute.
3. **The deterministic context.** `validate` and `apply` receive a
   context that includes the operation index, the view, the
   committed sequence, and the previous digest. They must not
   consult a wall clock, a random source, or any other
   non-deterministic input. This is the developer's obligation and
   the protocol's determinism guarantee depends on it.
4. **The failure contract.** A `validate` failure rejects the
   operation before consensus — the preprepare is dropped and the
   operation does not enter. An `apply` failure is recorded as the
   application's declared outcome, included in the digest, and
   treated as a state transition like any other. The protocol's
   guarantee is that every honest replica sees the same failure,
   not that failures cannot happen.
5. **The `()` default.** Applications with no execution state
   return `()`. The digest treats the empty output as unchanged.
   The *sequence* of operations is what is agreed; the outputs are
   the application's.

These five paragraphs are the difference between "the developer
must write BFT" and "the developer writes operations and the
protocol agrees on them." They are also the difference between the
draft's current silence on execution and a draft a developer could
read and use.

## The digest binding

The five paragraphs say the digest includes the `apply` output. They do
not say how the output is canonically encoded or how it is bound into
the digest, and without that, two independent implementations can both
comply and compute different digests for the same state. Three
paragraphs close the construction gap.

**Canonical outcome.** The `apply` hook returns a protocol-defined
`OperationOutcome`, not an application-defined `Result`. It has a
discriminant — success or application-failure — and an optional bounded
payload, and it is canonically CBOR-encoded under the draft's existing
rules. A success with no payload is distinguishable from a success with
an empty payload; a failure with a code is distinguishable from a
failure with a message. Error strings are not the payload; a string
would not encode identically across implementations and would make the
digest platform-dependent.

**Digest construction.** The state digest is computed as the protocol's
hash over a canonical CBOR map with three required keys: the operation
(the same canonical form the preprepare's digest uses), the prior state
digest — carried as `state_digest` in `bft_checkpoint` and restated as
`checkpoint_digest` in `bft_state_transfer` — and the `OperationOutcome`.
Keys are ordered by the draft's canonical map ordering. The resulting
digest is the new state commitment. This is the same shape as the
preprepare's existing
`SHA-256(ring_id || view || sequence || QUIP-CBOR(operation))`; the state
digest should match the draft's existing digest conventions rather than
introduce new ones.

**Checkpoint relation.** `checkpoint_digest` is the state digest. A
checkpoint carries it as `state_digest`; `bft_state_transfer` restates it
as `checkpoint_digest`. Neither re-derives a different digest from the
state. That is what makes "the state digest" in §5.3.4 mean a specific
quantity rather than a family of them.

Two consequences follow and should be named in the draft. First,
divergence is detected at checkpoint quorum, not repaired — the
protocol's answer to a failed quorum is a view change, and the
view-change protocol's handling of divergent replicas is BFT-A items 2
and 3. The draft should say the protocol detects and does not repair, so
a reader does not assume the checkpoint heals state it finds
inconsistent. Second, the outcome type is protocol-defined because the
digest is protocol-defined: an application that invents its own outcome
encoding is not conformant even if it "includes the output", because the
output's encoding is what the digest covers.

**The three encoding choices.** The construction above is not
implementable until the encoding is fixed, so the note fixes it.

- **Map keys are text.** Every other closed map in the draft uses text
  keys (`Candidate`, `RelayEntry`, `RelayHop`, `RelayChain`), and integer
  keys for the state digest's map alone would be a new convention for a
  single structure — a defect even where it saves bytes, because a
  reader's expectation is formed by the rest of the draft.
- **The discriminant is text** (`"success"` /
  `"application-failure"`). The draft's existing discriminants are mixed
  — `nat_type` and `Candidate.type` are integers, the message envelope's
  verb is text, error codes are integers — so no convention forces the
  choice. A text discriminant is self-describing where an integer `0`/`1`
  needs a lookup table, and the outcome is read by a human reviewer of a
  state digest at least as often as by a machine. The size difference is
  a few bytes in an input that is hashed anyway.
- **The payload bound is 256 bytes.** The draft has no outcome bound
  today. 256 bytes covers a failure reason or a small result; anything
  larger is a state change that should be modelled as state, not carried
  as an outcome payload. A future application that needs more is a
  version-level convention, not a local one.

Both maps are closed: a receiver rejects an unknown key. That rule is
stated once in §10 (QUIP-CBOR) and cited from §5.3.4, so the handshake's
open `extensions` map — and `Deps`, `app_metadata` and `app_data` — are
not accidentally closed by it.

## The three resolutions — *record*

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


## Recommendation: (c), explicitly — *record, and later adopted*

The recommendation is (c) because the implementation already behaves as
(c) and does not satisfy (c). Today the driver commits the failure and
advances — that is (c)'s *shape* — while the trait imposes none of (c)'s
*obligations*: nothing requires `apply` to be deterministic, and nothing
requires the result to be covered by the digest. The current behaviour is
therefore the least safe reading of (c): it takes the licence to continue
past a failure and omits the condition that makes continuing safe.

The recommendation is (c) under the hook reading, with the five
paragraphs above as the draft's obligation. Under the hook reading, (c)
is the only resolution that lets an application with no execution result
return `()` while an application with a result has its output enter the
digest.

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

The five paragraphs above, in §5.3.4, with this as their normative core:

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

1. **Does the execution result enter `state_digest`?** Under (c) it must.
   Otherwise two replicas can diverge in the result and agree on every
   checkpoint digest — a safety hole that would survive every test in the
   tree. If (c) is adopted without this sentence, the draft states an
   obligation the implementation cannot meet.
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
5. **The `OperationOutcome` wire form — RESOLVED in §5.3.4.** Text map
   keys, a text discriminant (`"success"` / `"application-failure"`), and
   a 256-byte payload bound; the reasons are in "The digest binding"
   above, and the "unknown keys" rule they rely on is stated once in §10
   and cited from §5.3.4.
