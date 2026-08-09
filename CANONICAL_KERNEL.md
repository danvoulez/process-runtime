# CANONICAL_KERNEL.md

**The evaporation test, applied — and its boundary, stated.**

> If this module disappeared tomorrow and was replaced by a perfectly
> competent world-standard implementation, which institutional decision
> would stop being defined?

If the answer is *none*, the module is commodity — replaceable scaffolding.

If the answer is *we would no longer know whether this fact may enter
history*, the module is canonical kernel.

The test is aggressive on implementation mechanisms. It is forbidden from
touching canonical meaning. Evaporating the mechanism is engineering;
evaporating the thesis is loss.

## 0. The vessels, in the right order

An earlier draft of this document claimed the intellectual property's
vessel is the conformance suite. That compressed the theory too far.

A vector can test:

```text
stale head → reject
```

but cannot, by itself, explain *why* the runtime governs the boundary of
a Responsibility instead of its interior. It can test that work product
never enters replay, but it does not contain the thesis that the Process
must be legible while the interior of work need not be.

The correct order is:

```text
The specification is the semantic vessel.
The conformance suite is its executable vessel.
The reference implementation is replaceable.
```

## 1. The three kernel layers

### 1.1 Ontological kernel — what things ARE

```text
Process            the institutional atom; not a chat, session, task,
                   workflow execution, or database row
Responsibility     a bounded institutional obligation — not a task,
                   a role, or a script for the worker
Work Environment   the semantic space between receiving an obligation
                   and returning something to the Institution — not a UI,
                   a sandbox, or canonical state
Submission         the boundary where work proposes to become fact
Commit             the only moment institutional consequence exists
```

These distinctions interlock: Responsibility defines the obligation and
its boundaries; the Work Environment holds bounded context, instruments,
and room for judgment; what leaves it crosses the submission boundary;
only authorized commit makes any of it institutional fact.

### 1.2 Constitutional kernel — what the Institution may demand

This layer answers a question most systems never ask: **how much of
human activity does the Institution have the architectural right to
require as legible?**

```text
continuity without appropriation of the doing
the Process must be legible; the worker need not be
boundary enforcement, not interior vigilance
strong invariants reduce the supervision required
Process exists so work can move between people
without turning people into workflow steps
```

Its operational chain:

```text
strong invariants
    ↓
boundary enforcement
    ↓
less need for interior surveillance
    ↓
more room for competent judgment
    ↓
without losing institutional continuity
```

This chain makes security and autonomy — normally in tension — two
consequences of the same architecture. It is the deepest decision in the
system.

### 1.3 Admission kernel — what may enter history

The rules any conforming runtime must enforce, each with vectors in the
conformance suite:

1. **Event core / envelope split** — signature outside the digest (§7.3).
2. **The 18-type fold contract** — what each event does to institutional
   state; e.g. `responsibility_completed` leaves the active set but does
   NOT terminate the Process (§7.6, §51).
3. **Terminal exclusivity** — no event after a terminal fold (RT-FOLD-004).
4. **`epoch_advanced` as canonical event** — authority change enters the
   ledger, and ONLY it changes the epoch (§10.1).
5. **Idempotency conflict rule** — same command_id + different payload is
   a conflict, never an execution (§16.1, RT-IDEM-001).
6. **Closed member sets as admission discipline** — the runtime rejects
   what the law did not name (RT-EVENT-004, RT-FOLD-003, RT-GRANT-001,
   RT-CMD-001).
7. **Stale head is inadmissible** — never silently reinterpreted (§8).
8. **Observation ≠ consequence** (§18).
9. **Work product is non-canonical** (§25.5).
10. **Grants carry institutional authority; ambient access carries none** (§4.4, §22).
11. **Effect keys suppress duplicate external consequences** (§17.2).
12. **Bootstrap expires its own authority** (§67–68).
13. **Evidence ceiling** — collect the minimum, not the maximum capturable (§36.1).
14. **Authority keys are anchored in canonical history** — genesis binds
    the initial key digest; rotation enters via canonical event; no
    bundle bootstraps its own authenticity (§7.7, RT-KEY-001/002).

## 2. Commodity (evaporates cleanly)

| Module | World-standard replacement | Institutional meaning lost on swap |
|---|---|---|
| `jcs-digest` implementation | `canonicalize` (npm), any RFC 8785 impl | none — the interface is the contract |
| Ed25519 via `node:crypto` | `@noble/ed25519`, libsodium, any FIPS impl | none |
| hash-link / sequence checks | any append-only log verifier | none (mechanism) |
| `base64url(JCS(x))` encoding | JWT-style envelope conventions | none |
| SQLite transactions | PostgreSQL, FoundationDB, DO SQLite | none (mechanism) |
| lease/fencing machinery | etcd leases, Kafka fencing | none (mechanism) |
| idempotency-key dedup | any content-addressed dedup | none (mechanism) |
| closed-member validation loops | JSON Schema `additionalProperties: false` | none (mechanism) |

**Replaceable does not mean replace now.** Zero-dependency is a feature
in a verification library: every dependency is a trust assumption in the
supply chain, and this product's promise is *verify without trusting*.
Where a mature standard satisfies the canonical contract, prefer it; do
not invent proprietary physics. The interface is the contract; which side
of it an implementation lives on is engineering, not ontology.

## 3. Dual-nature modules (commodity mechanism, canonical meaning)

| Mechanism (supermarket) | Canonical meaning (kernel) |
|---|---|
| compare-and-swap on a head digest | a stale `expected_head` makes a proposal **institutionally inadmissible** (§8) |
| fencing tokens / monotonic epochs | ownership change is itself a **canonical event**; replay verifies authority history (§10.1) |
| idempotency-key dedup | same id + different payload is a **conflict** (§16.1) |
| Ed25519 signing | signs the **raw 32-byte digest**, lives **outside** the digested core (RT-SIG-001) |
| durable timer/wait storage | wait resolution is an **authorized commit**; duplicate delivery MUST NOT duplicate consequence (§26.2, §27) |

## 4. The standing warning

The risk at this stage is not a missing idea. It is squeezing again and,
along with the commodity, accidentally squeezing the thesis.

So: evaporate mechanisms without mercy. Then stop at the three layers.

For every decision in them, the review question is not "is this clever?"
but:

> Does this fully express what we now understand — about Process,
> Responsibility, bounded agency, the Work Environment, work product,
> submission, evidence, observation, authority, handoff, consequence,
> continuity, and authorized commit?

If a future optimization would make any of those distinctions smaller to
make the implementation smaller, the optimization is the defect.
