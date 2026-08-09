/**
 * Runtime Conformance Suite (§60) — first green slice.
 * Test names carry the RT identifiers they prove (§1.2).
 *
 * Groups covered here: CANONICAL HISTORY, PROJECTION, EPOCH,
 * WAIT CONDITIONS, EXPORT KEY MATERIAL mechanics.
 * Wire-format groups (EVENT CORE/ENVELOPE, SIGNATURES, FOLD CONTRACT,
 * GRANT TOKEN, IDEMPOTENCY DIGEST) are proven in each package's own
 * tests and cross-checked here at history level.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalize, type JsonValue } from "@prt/jcs-digest";
import {
  sealEvent,
  verifyChain,
  chainHead,
  generateAuthorityKeypair,
  signEventCore,
  verifyEventSignature,
  verifyEventEnvelope,
  type CanonicalEvent,
  type EventCore,
} from "@prt/event-v1";
import { foldHistory, validateWaitCondition } from "@prt/fold-core";

let seq = 0;
let prev: string | null = null;
let epoch = 1;

function reset(): void {
  seq = 0;
  prev = null;
  epoch = 1;
}

function emit(type: string, payload: Record<string, JsonValue>, signWith?: ReturnType<typeof generateAuthorityKeypair>): CanonicalEvent {
  const core: EventCore = {
    schema: "event/v1",
    process_id: "proc_conf",
    sequence: seq,
    previous: prev,
    epoch,
    type,
    payload,
    causation: null,
    authority: "conformance",
    committed_at: "2026-08-09T12:00:00Z",
  };
  const env = sealEvent(core, signWith ? signEventCore(core, signWith) : undefined);
  prev = env.digest;
  seq++;
  return env;
}

// ---------------------------------------------------------------- CANONICAL HISTORY

test("CANONICAL HISTORY: genesis valid — sequence 0, previous null", () => {
  reset();
  const g = emit("process_created", { kind_digest: "sha256:" + "a".repeat(64) });
  assert.equal(g.sequence, 0);
  assert.equal(g.previous, null);
  assert.equal(verifyChain([g]).length, 1);
});

test("CANONICAL HISTORY: second event links genesis", () => {
  reset();
  const g = emit("process_created", { kind_digest: "sha256:" + "a".repeat(64) });
  const e1 = emit("observation_recorded", {
    observation_id: "o1", subject: "s", result_digest: "sha256:" + "1".repeat(64), observed_at: "2026-08-09T12:01:00Z",
  });
  assert.equal(e1.previous, g.digest);
  assert.equal(chainHead(verifyChain([g, e1])), e1.digest);
});

test("CANONICAL HISTORY: event mutation detectable (RT-EVENT-002)", () => {
  reset();
  const g = emit("process_created", { kind_digest: "sha256:" + "a".repeat(64) });
  const mutated = { ...g, authority: "mallory" };
  assert.throws(() => verifyEventEnvelope(mutated), /RT-EVENT-002/);
});

test("CANONICAL HISTORY: overwrite detectable — replacement yields a different head (§8, §15)", () => {
  reset();
  const g = emit("process_created", { kind_digest: "sha256:" + "a".repeat(64) });
  const e1 = emit("observation_recorded", {
    observation_id: "o1", subject: "s", result_digest: "sha256:" + "1".repeat(64), observed_at: "2026-08-09T12:01:00Z",
  });
  // Attacker replaces e1 with a different event at the same sequence,
  // keeping a structurally valid previous link.
  const replacement = sealEvent({
    schema: "event/v1",
    process_id: "proc_conf",
    sequence: 1,
    previous: g.digest,
    epoch: 1,
    type: "process_failed",
    payload: { reason: "forged" },
    causation: null,
    authority: "mallory",
    committed_at: "2026-08-09T12:00:00Z",
  });
  // The forged chain is structurally valid but has a different head:
  assert.equal(verifyChain([g, replacement]).length, 2);
  assert.notEqual(chainHead([g, replacement]), chainHead([g, e1]));
  // Any receipt binding head_after = e1.digest no longer matches (§15).
  const receiptHeadAfter = e1.digest;
  assert.notEqual(chainHead([g, replacement]), receiptHeadAfter);
});

// ---------------------------------------------------------------- PROJECTION

test("PROJECTION: delete and rebuild yields identical projection (§11, RT-FOLD-002)", () => {
  reset();
  const events = [
    emit("process_created", { kind_digest: "sha256:" + "a".repeat(64) }),
    emit("responsibility_issued", { responsibility_id: "r1", role: "w", objective: "o", acceptance: {} }),
    emit("grant_issued", {
      grant_id: "g1", responsibility_id: "r1", actor: "agent:eve", action: "read",
      subject: "s", bounds: {}, expected_head: "sha256:" + "0".repeat(64), epoch: 1,
      expiry: "2026-08-10T00:00:00Z",
    }),
  ];
  const stored = foldHistory(events);
  // "Delete" the projection, rebuild from canonical events only.
  const rebuilt = foldHistory(events);
  assert.equal(canonicalize(stored as unknown as JsonValue), canonicalize(rebuilt as unknown as JsonValue));
});

// ---------------------------------------------------------------- EPOCH

test("EPOCH: monotonicity verifiable from events alone (§10.1, §12)", () => {
  reset();
  const events = [
    emit("process_created", { kind_digest: "sha256:" + "a".repeat(64) }),
    emit("epoch_advanced", { previous_epoch: 1, new_epoch: 2, reason: "restart" }),
  ];
  epoch = 2;
  events.push(emit("observation_recorded", {
    observation_id: "o1", subject: "s", result_digest: "sha256:" + "1".repeat(64), observed_at: "2026-08-09T12:01:00Z",
  }));
  assert.equal(verifyChain(events).length, 3);
  const p = foldHistory(events);
  assert.equal(p.epoch, 2);
});

// ---------------------------------------------------------------- WAIT CONDITIONS

test("WAIT CONDITIONS: condition field with wrong type rejected (RT-WAIT-001)", () => {
  assert.throws(() => validateWaitCondition({ kind: "timer", target_time: "soon" }), /RT-WAIT-001/);
  assert.throws(() => validateWaitCondition({ kind: "approval", approver: 42, resume_schema: "sha256:" + "5".repeat(64) }), /RT-WAIT-001/);
});

test("WAIT CONDITIONS: member outside kind's set rejected (RT-WAIT-001)", () => {
  assert.throws(
    () => validateWaitCondition({ kind: "timer", target_time: "2026-08-10T00:00:00Z", responder: "dan" }),
    /outside set/,
  );
});

test("WAIT CONDITIONS: nested process condition validated recursively (RT-WAIT-001)", () => {
  validateWaitCondition({
    kind: "process",
    target_process_id: "proc_other",
    condition: { kind: "timer", target_time: "2026-08-10T00:00:00Z" },
  });
  assert.throws(
    () => validateWaitCondition({ kind: "process", target_process_id: "proc_other", condition: { kind: "timer", target_time: "bad" } }),
    /RT-WAIT-001/,
  );
});

test("WAIT CONDITIONS: invalid condition rejected at fold boundary (RT-WAIT-001 + RT-FOLD-003)", () => {
  reset();
  const g = emit("process_created", { kind_digest: "sha256:" + "a".repeat(64) });
  const badWait = emit("wait_entered", { wait_id: "w1", condition: { kind: "timer", target_time: "not-a-time" } });
  assert.throws(() => foldHistory([g, badWait]), /RT-WAIT-001/);
});

// ---------------------------------------------------------------- EXPORT KEY MATERIAL (mechanics)

test("EXPORT KEY MATERIAL: rotated historical key still verifies old events (RT-EXPORT-001)", () => {
  reset();
  const keyV1 = generateAuthorityKeypair("authority@v1");
  const keyV2 = generateAuthorityKeypair("authority@v2");

  const g = emit("process_created", { kind_digest: "sha256:" + "a".repeat(64) }, keyV1);
  epoch = 2;
  const afterRotation = emit("epoch_advanced", { previous_epoch: 1, new_epoch: 2, reason: "key rotation" }, keyV2);

  // Simulated keys/ bundle: immutable inventory with validity windows.
  const keysBundle: Array<{ key_id: string; der: Uint8Array; valid_from_seq: number }> = [
    { key_id: "authority@v1", der: keyV1.publicKeyDer, valid_from_seq: 0 },
    { key_id: "authority@v2", der: keyV2.publicKeyDer, valid_from_seq: 1 },
  ];
  const resolveHistorical = (eventSeq: number) => (keyId: string) => {
    const candidates = keysBundle.filter((k) => k.key_id === keyId && k.valid_from_seq <= eventSeq);
    const latest = candidates[candidates.length - 1];
    return latest?.der;
  };

  // Old event verifies with the historical key, new event with the rotated key — fully offline.
  assert.ok(verifyEventSignature(g, resolveHistorical(g.sequence)));
  assert.ok(verifyEventSignature(afterRotation, resolveHistorical(afterRotation.sequence)));
});

test("EXPORT KEY MATERIAL: every key_id in signed history resolvable from bundle (RT-EXPORT-001)", () => {
  reset();
  const k1 = generateAuthorityKeypair("authority@1");
  const events = [
    emit("process_created", { kind_digest: "sha256:" + "a".repeat(64) }, k1),
    emit("process_completed", { terminal_node: "end" }, k1),
  ];
  const bundle = new Map([[k1.keyId, k1.publicKeyDer]]);
  for (const e of events) {
    assert.ok(e.signature !== undefined);
    assert.ok(bundle.has(e.signature.key_id), `key_id ${e.signature.key_id} missing from bundle`);
    assert.ok(verifyEventSignature(e, (id) => bundle.get(id)));
  }
});
