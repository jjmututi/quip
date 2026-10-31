# Respecification frame

**Status: record.** The decisions the draft-mututi-quip-03 respecification is
built on. The argument for each decision was made in the project's working
conversation and is not repeated here; this document records the decision, its
identifier, and the amendment that carries it. The amendments translate this
frame into the draft's voice.

**Tree at the frame's completion:** `c7c4f2c8f5f0e45e3857e6c40d6145fa0314fb8b` — "docs: record the M9.6c boundary batch commit-2 SHA"

## How to read this document

Each decision has an identifier — `D1` through `D8` for the frame decisions,
`C1` through `C3` for the closing decisions, `R<n>` for a register answer and
`N<n>` for a new-problem answer. An amendment's commit message cites the
identifier, not a prose name, so the citation is greppable. The amendment
index at the end maps identifiers to amendments.

The frame does not decide the draft's wording. It decides what the draft's
wording must say. The amendments decide the wording.

## The measurement instruments this frame rests on

The frame's decisions are derived from six working papers in `.cline/reviews/`,
none of which is committed — the three audits, their summary, the first pass,
and the plan:

- `.cline/reviews/draft-audit-2026-10-28.md` — 756 lines — the draft audit:
  ten line bands over `draft-mututi-quip-03.xml` (6699 lines), 535 rows in the
  form `draft line | statement | verdict | justification | section`.
- `.cline/reviews/audit-2026-10-28.md` — 206 lines — the workspace audit: the
  twenty conformance-matrix rows and their A/B1/B2/C findings.
- `.cline/reviews/audit-2026-10-28-summary.md` — 70 lines — that audit's
  summary: the findings counted by class.
- `.cline/reviews/audit-crossref-2026-10-28.md` — 569 lines — the mapping
  audit: the 485 joined lines against the workspace matrix, with the 412
  cells it could not reach.
- `.cline/reviews/protocol-intent-first-pass.md` — 815 lines — the first pass:
  the node index (N001–N018 and their sub-nodes) the register is keyed to, and
  the 139 draft-audit rows that named no node (line 799).
- `.cline/reviews/amendment-plan-2026-10-28.md` — 145 lines — the plan: the 21
  amendments, their sub-amendments, and the prerequisites P1–P3.

Two things about the instruments matter for reading a citation. First, the
draft audit's structure is ten line bands (`Band A — lines 70–1139` through
`Band J — lines 5912–6699`), one row per normative statement, a verdict of
CLEAR / AMBIGUOUS / INCOMPLETE / SILENT / UNIMPLEMENTABLE / CONTRADICTORY per
row, and a summary with per-class verdict counts, per-section coherence
verdicts, and a list of what the audit did not read. It does not group its
findings; a grouping is this frame's work, stated here and nowhere else.
Second, the counts the frame cites are the instruments' counts at the tree the
frame was written against; a later audit may measure a different number, and
the frame's count is the one the amendment plan was built on.

A frame decision that cites "the audit" cites a row or an anchor summary. A
decision that cites a group cites this frame's own grouping. The distinction
matters because a reader following a frame citation must be able to tell
whether the finding is the instrument's or the frame's.

### The frame's own grouping

The frame groups the audit's findings by what the answer *is*, not by the
audit's sections. The grouping was made in the project's working conversation
and is recorded here because it is the frame's, not the audit's:

- **The ten frame decisions (D1–D10)** answer the register's decision-requiring
  findings: identity, witness policy, BFT, merge, structure, governance,
  transport.
- **The three closing decisions (C1–C3)** answer the three findings the frame
  closed after the decisions were made: collusion bound, relay encryption,
  pending state.
- **The residue** is what the frame does not decide: the NAT findings (31 after
  C2's answer and A24's three), the 139 unnamed rows, the 412 unknown workspace
  cells. They are named in "What the respecification does not close" below.

A reader who wants the audit's own findings reads the audit; a reader who wants
the frame's grouping reads this section.

The grouping does not use the audit's band names and this frame does not adopt
them. The phrase "Group 3" appears nowhere in `docs/` or in `.cline/reviews/`:
a search for it over both returns nothing, so the grouping vocabulary below is
this frame's and is not attributable to the audit.

## The ten frame decisions

### D1 — NodeId is permanent and durable
The NodeId is held for a user's lifetime. Its compromise response is KT_VERIFIED
transfer and/or rotation. Draft line 716's "future versions MAY define rotation"
is a snare — it makes rotation a normative choice — and is deleted; the rotation
rule is stated in the body. A rotation rotates both `NodeId` and `dht_id`; the
Claim carries both explicitly; peers re-resolve after a rotation.
Carried by: A02a, A02c, A02f, A10.

### D2 — A Key Claim proves control of its key, nothing more
The Claim is self-signed and proves the signer holds the NodeId key. It does not
prove the user, the application, or the cluster behind the key. TOFU pins the
key on first contact; out-of-band verification establishes the identity behind
the key. The protocol states the risk and does not claim to eliminate it.
Carried by: A02d, A11.

### D3 — Ephemeral keys are derived from the application handle
The handle is `(app, NodeId)`. An ephemeral key is derived from the handle and
is context-scoped per the application's policy. Ephemeral keys sign application
payloads; the NodeId key signs protocol messages and DHT address claims.
Carried by: A02e, A12.

### D4 — `dht_id` equals `NodeId`
The Coral DHT assigns routable addresses to durable identities; an ephemeral
identity has no routable address to return to. `dht_id` therefore equals
`NodeId` in v1, and the Claim carries it explicitly so a future rotation can
diverge. A rotation rotates both; the DHT address assignment lapses and peers
re-resolve.
Carried by: A02f, A13.

### D5 — Policies are application-owned
The witness's issuance policy, the evidence rule the ring applies, and the
acceptance policy an application sets are all the application's. The protocol
supplies preconditions (the subject's claim is held; the witness has applied its
own policy), the re-issuance cadence, and the validity window. The
first-issuance trigger is the application's. A peer assumes the preconditions
held because the statement is the witness's signed assertion.
Carried by: A04.

### D6 — Degraded is when BFT cannot be invoked
A node is degraded with respect to BFT when any of four conditions fails for it:
(1) a ring is formed from always-on nodes representing applications; (2) the
ring has `n − f` reachable members; (3) reachable members can message each
other; (4) an application has a request that needs ordering. A degraded node
behaves like a mobile intermittent node. The network-size bound is seven
publishing applications (seven always-on representatives); below it, ordering is
DVV-based and BFT is structurally unavailable. A cluster whose always-on count
is below the threshold can merge with a nearby cluster whose combined count
reaches it; the merged cluster can form a ring.
Carried by: A05a, A05b, A05c, A05d, A05e, A05f.

The audit found the statements (1031, 5253, 5295, 5296, 5297). The
four-condition rule, the always-on rule, the seven-application bound, and the
merge-growth escape are this frame's decisions about those statements. They are
not in the audit and not in the draft.

### D7 — Merge is a cluster operation with a proximity trigger
Merge is an operation a cluster performs; it is not an application's. Its
trigger is the Coral DHT's proximity rule — when two clusters are within the
DHT's proximity threshold they are close enough to merge, subject to the four
merge conditions (eligibility, authority, safety, completion) that
`docs/m9.6b-merge-design.md` §2a–§2d defines. A merge-disabled cluster rejects
proposals with `merge_not_supported`.
Carried by: A06, P1.

The audit found the merge rule UNIMPLEMENTABLE (3765, 3766 with 3810–3853).
The proximity trigger and the merge-disabled rejection with
`merge_not_supported` are this frame's decisions. The four conditions
(eligibility, authority, safety, completion) are the merge design note's.

### D8 — The thesis is informative; the normative text begins at terminology
The draft's thesis paragraph is informative and moves above the RFC 2119
boilerplate. Appendix A becomes informational and its 13 MUSTs move into the
body's sections. A new non-normative "Implementation Status" appendix records
what the reference implementation does; the draft's normative text carries no
implementation claims.
Carried by: A18, A19, A20.

### D9 — Governance is normative; the application owns the policy
Quarantine is a normative protocol operation, not an advisory hint: a node that
supports governance honours a quorum-signed quarantine notice and does not return
quarantined content in discovery or range responses. The ring enforces; the
application supplies the policy the ring executes, and the application bears the
consequence of a wrong enforcement. The authority to request a quarantine is the
content's owner or the owner's delegate; a request that names neither is refused
at the ring's own check. A young node learns of a quarantine on first contact
with a governance-capable node; the protocol supplies the mechanism, and a young
node's knowledge is whatever it has learned. Re-publication is application-level
attribution: a new publisher re-publishing the same content is a new claim, and
the quarantine does not catch it.
Carried by: A14, A15, A16, A17.

### D10 — The transport's negotiated surface is defined once, referenced elsewhere
Capabilities, extension IDs, hash algorithms and the tier assignment of each verb
are defined once, in the negotiated-profile section of §4 and the tier section of
§11. The verb definitions reference them rather than restating them. A verb's
tier is named in the verb's own definition, where it is testable, not in the
tier section's table. A restated negotiation rule is a rule that can disagree
with the one in the negotiated-profile section; the draft states each once and
references it.
Carried by: A03.

## The register answers

One line per node the amendment plan touches. The register's 50 problems and
the 30 new problems are answered per node, not per problem, because the node is
the unit the amendments carry.

- **N001 Identity** — permanent durable NodeId; Key Claim proves key control;
  ephemeral keys from the handle; `dht_id` equals `NodeId`. Decisions D1–D4.
  Amendment A02 (with sub-amendments A02a–A02f), plus A10–A13.
- **N007 QUIC transport** — ratify the negotiated surface and rewrite what the
  capability/extension text leaves unsaid. Decision D10. Amendment A03.
- **N009 Witness trust** — TOFU on first contact; the universal plug exchanges
  identities; the witness ring is drawn from the cluster by XOR proximity.
  Decisions D2, D5. Amendments A04, A09.
- **N010 BFT consensus** — BFT runs when the four conditions hold; degraded
  means one fails; the size bound is seven always-on representatives; the
  merge-growth path is the escape. Decision D6. Amendment A05 (with
  sub-amendments A05a–A05f).
- **N011 Cluster topology changes** — merge is a cluster operation with a
  proximity trigger and four conditions; split keeps its existing rules.
  Decision D7. Amendment A06, with the prerequisite P1.
- **N014 Governance** — quarantine becomes normative, with an authority model,
  expiry, and young-node learning. Decision D9. Amendments A14–A17.
- **No node** — A01 (definitions), A07 (primitives), A08 (role model), A18–A20
  (structural, D8), A21 (terminology). A01, A07, A08 and A21 carry no decision;
  they are the scaffolding the decided amendments are written on.

## The closing decisions

### C1 — Collusion bound
A single node's view is bounded by its role. A set of colluding nodes can combine
their views; the combination is valuable only when the set is large, and a set
large enough to be valuable is a set large enough to be observed. The protocol
does not prevent collusion; it makes collusion costly and visible, and it states
both limits rather than claiming a guarantee.
Carried by: A22 (the §18 amendment, which joins the plan with the collusion
paragraph).

### C2 — Relay encryption is two layers
A relay forwards an HPKE envelope. It can decrypt the envelope's hop layer; it
cannot decrypt the application's payload, which is encrypted under a key the
relay does not hold. The two layers are distinct and the relay sees only the
first.
Carried by: P3 (the NAT design note) and the §12 amendment that follows it.

### C3 — `PENDING` and `KT_PENDING` are one state
A Key Claim the protocol has not yet verified is in the pending state, named
`KT_PENDING` in the trust layer's vocabulary. A node with no DHT connectivity
treats every claim it has not verified as pending, because it has no evidence to
leave the state.
Carried by: A23 (the pending-state sentence, §5.3.3 and §18).

## What the frame does not decide

- **The draft's wording.** The amendments decide it.
- **The NAT design note's content.** C2 states the two-layer principle; the note
  specifies the mechanism. P3.
- **The merge design note's revision.** D7 states the trigger; P1 is the note
  revision that records it.
- **The governance and transport amendments' wording.** D9 and D10 state what
  those amendments must say; the amendments state it.

## What the respecification does not close

The frame closes the contradictions the frame decided. Three classes of
finding are named and not decided:

- **31 NAT findings** are located in `docs/nat-design.md` §4 and deferred, one
  answered (5381, by C2) and three carried by A24 (3261, 3454, 3151 — see the
  amendment index). The remaining 31 each need a decision this frame does not
  make; the largest class is the rate/window/action class, which the frame's
  D11 will answer.
- **139 unnamed rows** the first pass could not assign to a node. They are
  statement-level findings with no concept to hang from. The second workspace
  audit assigns them; a decision follows if any is a concept the frame lacks.
- **412 unknown workspace cells** are unmeasured. The second workspace audit
  measures them; the frame's decisions cover their concepts but not their
  per-statement workspace status.

The frame is complete for the concepts it names. It is not complete for the
draft. The difference is the three classes above, and the mapping audit's
residue count is what says whether this list is the whole of it.

Both figures are stated in the instruments, not inferred here: the 139 at
`.cline/reviews/protocol-intent-first-pass.md` line 799 ("139 of 485 rows"),
and the 412 at `.cline/reviews/audit-crossref-2026-10-28.md` line 530 ("there
are 412 of them, = 85% of the 485 joined lines").

## The amendment index

| Amendment | Target | Decisions | Prerequisite |
|---|---|---|---|
| A01 | Definitions section | — (no decision; scaffolding) | — |
| A02 | §5.2 identity | D1, D2, D3, D4 | P2 |
| A03 | §11 / §15 transport | D10 | — |
| A04 | §5.3.3 witness trust | D5 | — |
| A05 | §5.3.4 BFT | D6 | P2 |
| A06 | §13 cluster | D7 | P1 |
| A07 | Primitives section | — (no decision; scaffolding) | — |
| A08 | Role model | — (no decision; scaffolding) | — |
| A09 | Supplier/consumer | D2, D5 | — |
| A10 | NodeId permanence | D1 | — |
| A11 | Key Claim proves | D2 | — |
| A12 | Ephemeral keys | D3 | — |
| A13 | dht_id equals NodeId | D4 | — |
| A14 | Quarantine normative | D9 | — |
| A15 | Authority model | D9 | — |
| A16 | Expiry and re-publication | D9 | — |
| A17 | Young node quarantine learning | D9 | — |
| A18 | Appendix A informational + 13 MUSTs relocate | D8 | — |
| A19 | Implementation-status appendix | D8 | — |
| A20 | Thesis + boilerplate frame | D8 | — |
| A21 | Terminology consolidation | — (no decision; scaffolding) | — |
| A22 | §18 collusion paragraph | C1 | — |
| A23 | §5.3.3 and §18 pending-state sentence | C3 | — |
| A24 | §12 / §19 NAT fold + three findings | C2 | P3 |

A22 and A23 are not in the plan's 21: A22 is the §18 collusion paragraph C1
awaits, and A23 is the pending-state sentence C3 awaits. Both join the plan when
written; the index lists them so C1's and C3's carriers have rows.

A24 is the NAT fold C2 awaits — the follow-up `docs:` commit that folds
`docs/nat-design.md` §1 and §2d into §12 and §19. It carries three of the
residue's NAT findings as sub-edits, each under a `revision` node of the
first pass's tree where a leftover is expected:

- **3261 — `RelayResponse` signer.** Node N006.1. D2 applies: the signer field
  is the responder's `NodeId`, because a Key Claim proves control of a key and
  a signature with no signer is a signature the receiver cannot resolve. The
  field is a wire addition; the code's struct is the draft's and has no signer,
  so A24 adds it.
- **3454 — `session_id` uniqueness scope.** Node N006. A ratification, not a
  decision: the code scopes a session `(peer, session_id)`, and the draft's
  "unique session identifier" gains the scope the code already enforces.
- **3151 — `internal_addr` "(if known)" but mandatory.** Node N006.2. A
  ratification: the CDDL makes the field mandatory, the comment says "(if
  known)", and the comment yields to the CDDL.

**Measured against the first pass.** Only the first of those three attributions
is the instrument's. N006.1's draft lines begin `3155, 3248, 3261, …` (line
637), so 3261 is filed there. N006's are `3482` alone (line 145) and N006.2's
are `3152, 6170` (line 654), so neither 3454 nor 3151 is filed under the node
the bullets above name: both appear in the first pass's list of draft-audit rows
that named no node (line 801, "139 of 485 rows"). The bullets record where the
findings belong by concept; the instrument files two of them nowhere. Closing
that gap is the first pass's second revision, and until it lands A24's 3454 and
3151 sub-edits rest on the code's answer (§2b, §2a of the NAT note) rather than
on a node citation.

## Prerequisites

- **P1 — the merge design note's §2a revision.** Blocks A06.
- **P2 — this document.** Blocks A05a–A05f and A02a–A02f. Closed by this commit.
- **P3 — the NAT design note.** Blocks the §12 amendment (C2's carrier).
