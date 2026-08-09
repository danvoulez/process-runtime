# process-runtime

**0.5.0-rc.3** — the executable boundary of PROCESS_RUNTIME_SPEC.

> Execution may propose. Only authorized commit makes institutional fact.

```text
canonical semantics + admission rules + invariants + conformance vectors
= permanent contract

reference implementation + storage + crypto implementation
+ scheduling + execution machinery
= replaceable infrastructure
```

The product of this repository is the canonical specification ([docs/spec](./docs/spec/PROCESS_RUNTIME_SPEC.md)) and its executable expression, the standalone conformance harness. The reference runtime included here is one implementation — replaceable by design. See [CANONICAL_KERNEL.md](./CANONICAL_KERNEL.md) for the evaporation test that draws the line.

Product surfaces (Workspaces, Gadgets, Consoles) and deployment bindings (Cloudflare Durable Objects, ADK schedulers, Gatekeepers, LAB executors) live elsewhere. Storage technology is not part of Process semantics (§46).

## Packages

| Package | Spec sections | Contents |
|---|---|---|
| `@prt/jcs-digest` | §7.1 | RFC 8785 (JCS) canonicalization, SHA-256, `sha256:<hex>` digests |
| `@prt/event-v1` | §7.3, §7.4, §7.5, §8, §12 | Event core/envelope (RT-EVENT-001…004), Ed25519 signatures over raw digest bytes (RT-SIG-001/002), structural chain verification |
| `@prt/grant-v1` | §20.1, §37.1 | Sealed grants: closed claims, Ed25519 by Process Authority, `base64url(JCS(grant))` token (RT-GRANT-001) |
| `@prt/command-digest` | §16.1, §48.1 | Canonical commands, `request_digest` payload sameness (RT-IDEM-001), replay/conflict decisions |
| `@prt/fold-core` | §7.6, §11, §26.1 | The 18 core folds, pure (RT-FOLD-001…005), typed Wait conditions (RT-WAIT-001) |
| `@prt/driver-contract` | §48 | The `RuntimeDriver` adapter contract — the only package a third-party runtime must read |
| `@prt/authority` | §6, §8–16, §26–30, §48–53 | Process Authority **commit kernel**: SQLite single-writer, atomic commit path, expected_head, epoch fencing, idempotent receipts, leases, waits/timers, terminal gate, replay verification (see scope note below) |
| `@prt/export-v1` | §56.3, §57, §58 | `process-export/v1` bundle writer + offline verifier (`prt verify`) with bundled key material (RT-EXPORT-001) |
| `@prt/conformance` | §60, §1.2 | **Standalone conformance harness** — the executable vessel. Runs §60 vectors against any third-party `RuntimeDriver`; imports zero reference-runtime internals |

Also in this repository: [CANONICAL_KERNEL.md](./CANONICAL_KERNEL.md) — the evaporation test applied, the three kernel layers, and the vessel ordering (spec → suite → reference).

## Run the conformance harness against YOUR runtime

Third-party runtimes implement a `RuntimeDriver` adapter (~200 lines) and run the identical vectors — no dependency on reference internals:

```js
// my-driver.mjs
export default {
  fresh: () => new MyRuntimeDriver(freshStorage()),
  reopen: (d) => new MyRuntimeDriver(d.backendId),   // same storage, new process
};
```

```bash
npm run build
node .tsc/packages/conformance/src/cli.js my-driver.mjs
# 12 vectors across HEAD, EPOCH, COMMIT, IDEMPOTENCY, WAITS, LEASES,
# TERMINATION (+ VERIFY/EXPORT when the driver declares capabilities)
# exit 0 = CONFORMING, 1 = NOT CONFORMING, each vector tagged with spec §
```

Optional driver capabilities (`verify`, `exportBundle`) gate the VERIFY and EXPORT groups — undeclared capabilities are SKIPped, not failed. The reference adapter (`@prt/authority`'s `referenceDriverFactory`) proves the harness against the reference runtime, and a deliberately broken driver in the test suite proves the harness catches violations.

## Requirements

Node.js ≥ 20 (tested on 20 and 22). Cryptography is `node:crypto` Ed25519, never hand-rolled. The only native dependency is `better-sqlite3` (used by `@prt/authority`), a commodity transactional store per §46 — storage is replaceable and not part of Process semantics.

## Build and test

```bash
npm ci        # installs from public npm sources; postinstall fetches the
              # prebuilt better-sqlite3 binary for your platform
npm test      # tsc build + full suite via the built-in Node test runner
```

Working from a constrained environment (no install scripts, no exec bits)? See [docs/install-constrained.md](./docs/install-constrained.md).

`npm test` compiles every package with `tsc` and runs the full suite with the built-in Node test runner; the suite must be fully green (`npm test` prints the live count). Coverage includes 200 property-based runs (fast-check) and the full §60 harness against both the reference adapter and a deliberately broken driver, proving:

- RT-FOLD-001/002 — same history folds to a byte-identical projection across runs **and across two independent implementations** (a deliberately separate naive folder cross-checks the reference one);
- RT-EVENT-002 — digest recomputation detects any tampering with a committed event;
- RT-SIG-001 — Ed25519 verifies over the raw 32-byte digest; signatures computed over the hex string correctly fail;
- RT-GRANT-001 — actors cannot widen or re-mint sealed grants;
- RT-IDEM-001 — same `command_id` + same `request_digest` replays the original receipt; different digest is a conflict, never an execution;
- RT-EXPORT-001 — signed histories verify fully offline from bundled historical key material, across key rotation.

And at the authority level (§60 groups HEAD, COMMIT, IDEMPOTENCY, WAITS, LEASES, TERMINATION, EXPORT):

- §8/§9 — two proposals cannot both win the same head; stale proposals are rejected, never reinterpreted;
- §10.1/§30.3 — epoch advancement is a canonical commit; leases and commands from older epochs are fenced;
- §14/§53.1 — a validation failure inside the commit path leaves no half-commit; a retry after a lost response returns the original receipt instead of a second consequence;
- §16.2 — idempotency records survive restart;
- §26.3/§27 — waits survive runner death; stale wait responses are rejected; duplicate at-least-once timer delivery is harmless;
- §51 — a closed Responsibility does not terminate the Process; the terminal gate blocks unresolved work;
- §56.3/§57 — `prt verify <bundle>` validates an exported Process end-to-end, offline.

## Using the verifier

```bash
npm run build
node .tsc/packages/export-v1/src/cli.js verify <process-export-dir>
# exit 0 = VALID, 1 = INVALID; each check prints ✓/✗ with detail
```

## Current scope: commit kernel, not yet full Process Authority

Honesty about what `@prt/authority` does NOT yet do, per §13's full validation list:

- **No Process Kind resolution.** `propose()` does not load the pinned Kind and does not check whether `command.action` is legal under it. Unknown (Kind-defined) event types are admitted opaquely per §7.4 — the kernel cannot yet distinguish "Kind-defined" from "garbage" without Kind law.
- **No Responsibility/Grant authority validation.** Responsibility existence is enforced by the fold; Grant-mediated authorization (§20–22) is not yet on the commit path.
- **Terminal gate is minimal** (no open waits, no active responsibilities). Kind-level evidence obligations arrive with Kind integration.

This is deliberate staging (§75: minimum permanent runtime first), not an oversight. The kernel becomes the full Authority when Process-kind law lands as a dependency. Until then, treat the package as exactly what it is: the canonical commit kernel.

## Design invariants enforced in code

- **Closed member sets everywhere.** Event cores, envelopes, signature objects, grant claims, commands, payloads, and Wait conditions all reject unknown members. Determinism across independent implementations comes from this.
- **Digest covers the core only.** Signatures are envelope members; there is no digest → signature → digest circularity.
- **Fold is pure.** No wall clock, no live state, no deployment configuration. History alone determines the projection.
- **Terminal exclusivity.** Any event arriving after a terminal fold is rejected (RT-FOLD-004).

## Conformance

Tests reference normative requirement identifiers (`RT-<AREA>-<NNN>`, spec §1.2). A MUST without a conformance test is a defect in the specification — report it.

## Roadmap

```text
v0.1.0  wire format + fold + conformance slice        ✓ shipped
v0.2.0  process-export/v1 bundle writer + offline
        verifier CLI (prt verify <bundle>)            ✓ shipped
v0.3.0  Process Authority reference implementation    ✓ shipped
v0.3.1  hardening from external review (9 defects)    ✓ shipped
v0.5.0  standalone third-party conformance harness    ✓ rc.3, you are here
        + spec as the semantic vessel (docs/spec, v0.5)
        + law closed behind implementation
        + clean-room distribution (integrity, acceptance, CI)
v0.5.x  Kind-law integration: the commit kernel becomes
        the full Process Authority (§13 complete)
v0.6.0  effect/capability path depth (§17.1 full
        lifecycle, reconciliation runtime, §37–40)
```

## License

Apache-2.0
