# CONFORMANCE.md

How a third-party Process Runtime is judged — without touching the
reference implementation.

## Reading order

```text
1. docs/spec/PROCESS_RUNTIME_SPEC.md   (the law)
2. packages/driver-contract            (the adapter contract)
3. this document                       (the judgment)
```

## The profiles

`CONFORMING` is always qualified. The harness reports per-profile
outcomes; it never issues an unqualified claim.

| Profile | Groups | Status |
|---|---|---|
| `core` | HEAD, EPOCH, COMMIT, IDEMPOTENCY, WAITS, LEASES, TERMINATION | mandatory normative runtime behavior |
| `verify` | VERIFY (§12 replay verification) | declared capability |
| `export` | EXPORT (§56.3/§57 offline bundle verification) | declared capability |

Full conformance = `core + verify + export`.

A driver that does not declare a capability is SKIPped for that group
and the report states it explicitly:

```text
CONFORMING [core] (not evaluated: verify, export)
```

A FAIL in any evaluated group yields `NOT CONFORMING`, regardless of
what passed elsewhere. A runtime missing a normative MUST never receives
an unqualified result.

## What the harness does NOT depend on

```text
@prt/authority            (reference runtime)
better-sqlite3            (reference storage)
any reference internals
```

The harness imports only canonical protocol packages: the wire format
(`event/v1`), the canonical digest machinery, the command contract, the
canonical export verifier, and the driver contract.

## The adapter contract, in one breath

Implement `RuntimeDriver` (see `packages/driver-contract/src/index.ts`).
~10 methods, sync or async. Two factory functions: `fresh()` (empty
storage) and `reopen(d)` (same storage, new process instance — this is
how restart durability is judged). Export is self-contained: the runtime
owns its authority keys; the harness opens no side channel.

## Coverage map (honest)

Vectorized: HEAD (§8–9), EPOCH (§10, §30.3), COMMIT atomicity (§14–15),
crash-before-commit (§53.1), IDEMPOTENCY (§16, RT-IDEM-001), WAITS
(§26–27), LEASES (§30), TERMINATION (§51, RT-FOLD-004), VERIFY (§12),
EXPORT (§56.3, §57, §7.7).

Not yet vectorized (gaps, reported — not hidden):

```text
Kind-law admission (action legality under a pinned Kind)
Grant-mediated authorization on the commit path (§20–22)
Responsibility Work Environment semantics beyond the fold (§25)
full effect lifecycle depth (§17.1 proposed/approved/executing)
CAPABILITIES and EVIDENCE groups of §60 in depth
multi-Process causation scenarios (§24)
```

These gaps exist because Kind law has not landed as a dependency. They
are listed here so no reader mistakes the current profile for the full
specification.
