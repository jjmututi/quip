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

## The eight frame decisions

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

### D7 — Merge is a cluster operation with a proximity trigger
Merge is an operation a cluster performs; it is not an application's. Its
trigger is the Coral DHT's proximity rule — when two clusters are within the
DHT's proximity threshold they are close enough to merge, subject to the four
merge conditions (eligibility, authority, safety, completion) that
`docs/m9.6b-merge-design.md` §2a–§2d defines. A merge-disabled cluster rejects
proposals with `merge_not_supported`.
Carried by: A06, P1.

### D8 — The thesis is informative; the normative text begins at terminology
The draft's thesis paragraph is informative and moves above the RFC 2119
boilerplate. Appendix A becomes informational and its 13 MUSTs move into the
body's sections. A new non-normative "Implementation Status" appendix records
what the reference implementation does; the draft's normative text carries no
implementation claims.
Carried by: A18, A19, A20.

## The register answers

One line per node the amendment plan touches. The register's 50 problems and
the 30 new problems are answered per node, not per problem, because the node is
the unit the amendments carry.

- **N001 Identity** — permanent durable NodeId; Key Claim proves key control;
  ephemeral keys from the handle; `dht_id` equals `NodeId`. Decisions D1–D4.
  Amendment A02 (with sub-amendments A02a–A02f), plus A10–A13.
- **N007 QUIC transport** — ratify the negotiated surface and rewrite what the
  capability/extension text leaves unsaid. **No frame decision.** Amendment A03.
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
  expiry, and young-node learning. **No frame decision.** Amendments A14–A17.
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
Carried by: A05f (the DVV-ordering statement's companion).

## What the frame does not decide

- **The draft's wording.** The amendments decide it.
- **The NAT design note's content.** C2 states the two-layer principle; the note
  specifies the mechanism. P3.
- **The merge design note's revision.** D7 states the trigger; P1 is the note
  revision that records it.
- **The 139 unnamed rows.** The mapping audit assigns them.
- **The 412 unknown workspace cells.** The second workspace audit measures them.

## The amendment index

| Amendment | Target | Decisions | Prerequisite |
|---|---|---|---|
| A01 | Definitions section | — (no decision; scaffolding) | — |
| A02 | §5.2 identity | D1, D2, D3, D4 | P2 |
| A03 | §11 / §15 transport | — (no decision in the frame) | — |
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
| A14 | Quarantine normative | — (no decision in the frame) | — |
| A15 | Authority model | — (no decision in the frame) | — |
| A16 | Expiry and re-publication | — (no decision in the frame) | — |
| A17 | Young node quarantine learning | — (no decision in the frame) | — |
| A18 | Appendix A informational + 13 MUSTs relocate | D8 | — |
| A19 | Implementation-status appendix | D8 | — |
| A20 | Thesis + boilerplate frame | D8 | — |
| A21 | Terminology consolidation | — (no decision; scaffolding) | — |
| A22 | §18 collusion paragraph | C1 | — |

A22 is not in the plan's 21: it is the §18 amendment C1 awaits, and it joins the
plan when written. The index lists it so C1's carrier has a row.

## Prerequisites

- **P1 — the merge design note's §2a revision.** Blocks A06.
- **P2 — this document.** Blocks A05a–A05f and A02a–A02f. Closed by this commit.
- **P3 — the NAT design note.** Blocks the §12 amendment (C2's carrier).
