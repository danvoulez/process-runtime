import { test } from "node:test";
import assert from "node:assert/strict";
import { buildEventCore, type EventCore } from "@prt/event-v1";
import { foldEvent, foldHistory, emptyProjection, CORE_EVENT_TYPES } from "@prt/fold-core";

function core(type: string, sequence: number, epoch: number, payload: Record<string, unknown>): EventCore {
  return buildEventCore({
    schema: "event/v1",
    process_id: "proc_fold",
    sequence,
    previous: sequence === 0 ? null : "sha256:" + "0".repeat(64),
    epoch,
    type,
    payload,
    causation: null,
    authority: "test",
    committed_at: "2026-08-09T12:00:00Z",
  });
}

function genesis(): EventCore {
  return core("process_created", 0, 1, { kind_digest: "sha256:" + "k".repeat(64) });
}

test("§7.4: registry exposes exactly 18 core types (17 + authority_key_introduced)", () => {
  assert.equal(CORE_EVENT_TYPES.length, 18);
  assert.ok(CORE_EVENT_TYPES.includes("authority_key_introduced"));
});

test("RT-KEY-002: rotation enters canonical history; duplicate key_digest rejected", () => {
  let p = foldHistory([genesis()]);
  p = foldEvent(core("authority_key_introduced", 1, 1, {
    key_id: "authority@v2", key_digest: "sha256:" + "9".repeat(64), valid_from_seq: 1,
  }), p);
  assert.equal(p.authority_keys.length, 1);
  assert.equal(p.authority_keys[0]?.key_id, "authority@v2");
  assert.throws(
    () => foldEvent(core("authority_key_introduced", 2, 1, {
      key_id: "authority@v3", key_digest: "sha256:" + "9".repeat(64), valid_from_seq: 2,
    }), p),
    /duplicate introduced key_digest/,
  );
});

test("genesis initializes an empty active projection", () => {
  const p = foldEvent(genesis(), null);
  assert.equal(p.lifecycle, "active");
  assert.equal(p.epoch, 1);
  assert.deepEqual(p.responsibilities, {});
});

test("process_created after genesis is rejected", () => {
  const p = foldEvent(genesis(), null);
  assert.throws(() => foldEvent(genesis(), p), /genesis/);
});

test("responsibility lifecycle: issue → accept → submit → complete", () => {
  let p = foldHistory([genesis()]);
  p = foldEvent(core("responsibility_issued", 1, 1, {
    responsibility_id: "r1", role: "worker", objective: "review doc", acceptance: {},
  }), p);
  assert.equal(p.responsibilities.r1?.status, "issued");

  p = foldEvent(core("responsibility_accepted", 2, 1, { responsibility_id: "r1", actor: "human:dan" }), p);
  assert.equal(p.responsibilities.r1?.status, "accepted");
  assert.equal(p.responsibilities.r1?.actor, "human:dan");

  p = foldEvent(core("responsibility_submitted", 3, 1, { responsibility_id: "r1", actor: "human:dan" }), p);
  assert.equal(p.responsibilities.r1?.status, "submitted");

  p = foldEvent(core("responsibility_completed", 4, 1, { responsibility_id: "r1" }), p);
  assert.equal(p.responsibilities.r1, undefined);
});

test("grant issued then revoked removes active grant", () => {
  let p = foldHistory([genesis()]);
  p = foldEvent(core("grant_issued", 1, 1, {
    grant_id: "g1", responsibility_id: "r1", actor: "agent:x", action: "read",
    subject: "s", bounds: {}, expected_head: "sha256:" + "0".repeat(64), epoch: 1,
    expiry: "2026-08-10T00:00:00Z",
  }), p);
  assert.ok(p.grants.g1);
  p = foldEvent(core("grant_revoked", 2, 1, { grant_id: "g1" }), p);
  assert.equal(p.grants.g1, undefined);
});

test("wait entered suspends lifecycle; resolved restores active", () => {
  let p = foldHistory([genesis()]);
  p = foldEvent(core("wait_entered", 1, 1, { wait_id: "w1", condition: { kind: "timer", target_time: "2026-08-10T00:00:00Z" } }), p);
  assert.equal(p.lifecycle, "waiting");
  assert.ok(p.waits.w1);
  p = foldEvent(core("wait_resolved", 2, 1, { wait_id: "w1", resolution: { fired: true } }), p);
  assert.equal(p.lifecycle, "active");
  assert.equal(p.waits.w1, undefined);
});

test("epoch_advanced raises epoch and validates previous", () => {
  let p = foldHistory([genesis()]);
  p = foldEvent(core("epoch_advanced", 1, 1, { previous_epoch: 1, new_epoch: 2, reason: "restart" }), p);
  assert.equal(p.epoch, 2);
});

test("epoch_advanced with wrong previous_epoch rejected", () => {
  const p = foldHistory([genesis()]);
  assert.throws(
    () => foldEvent(core("epoch_advanced", 1, 1, { previous_epoch: 9, new_epoch: 10, reason: "x" }), p),
    /does not match current epoch/,
  );
});

test("epoch_advanced must increase", () => {
  const p = foldHistory([genesis()]);
  assert.throws(
    () => foldEvent(core("epoch_advanced", 1, 1, { previous_epoch: 1, new_epoch: 1, reason: "x" }), p),
    /must be greater/,
  );
});

test("effect committed then reconciled with pinned outcome (§17.1 + §40)", () => {
  let p = foldHistory([genesis()]);
  p = foldEvent(core("effect_committed", 1, 1, {
    effect_key: "e1", responsibility_id: "r1", operation: "linear.issue.create", provider: "linear",
  }), p);
  assert.equal(p.effects.e1?.state, "committed");
  p = foldEvent(core("effect_reconciled", 2, 1, { effect_key: "e1", prior_state: "unknown", outcome: "completed" }), p);
  assert.equal(p.effects.e1?.reconciliation, "completed");
  assert.equal(p.effects.e1?.state, "committed");
});

test("§17.2: duplicate effect_key rejected, never silently overwritten", () => {
  let p = foldHistory([genesis()]);
  p = foldEvent(core("effect_committed", 1, 1, {
    effect_key: "e1", responsibility_id: "r1", operation: "op_a", provider: "linear",
  }), p);
  assert.throws(
    () => foldEvent(core("effect_committed", 2, 1, {
      effect_key: "e1", responsibility_id: "r1", operation: "op_b", provider: "github",
    }), p),
    /duplicate effect_key/,
  );
  assert.equal(p.effects.e1?.operation, "op_a");
});

test("§10.1: ordinary event carrying a different epoch is corruption, not epoch change", () => {
  let p = foldHistory([genesis()]);
  assert.throws(
    () => foldEvent(core("observation_recorded", 1, 9, {
      observation_id: "o1", subject: "s", result_digest: "sha256:" + "2".repeat(64), observed_at: "2026-08-09T12:01:00Z",
    }), p),
    /epoch advances only via epoch_advanced/,
  );
  assert.equal(p.epoch, 1);
});

test("effect_reconciled outcome outside pinned set rejected", () => {
  const p = foldHistory([genesis()]);
  assert.throws(
    () => foldEvent(core("effect_reconciled", 1, 1, { effect_key: "e1", prior_state: "unknown", outcome: "maybe" }), p),
    /pinned set/,
  );
});

test("artifact and observation admitted into inventory", () => {
  let p = foldHistory([genesis()]);
  p = foldEvent(core("artifact_admitted", 1, 1, {
    artifact_id: "a1", digest: "sha256:" + "1".repeat(64), media: "application/pdf",
    size: 1024, storage_ref: "r2://bucket/a1", responsibility_id: "r1",
  }), p);
  assert.equal(p.artifacts.a1?.size, 1024);
  p = foldEvent(core("observation_recorded", 2, 1, {
    observation_id: "o1", subject: "provider-response", result_digest: "sha256:" + "2".repeat(64),
    observed_at: "2026-08-09T12:01:00Z",
  }), p);
  assert.equal(p.observations.o1?.responsibility_id, null);
});

test("process_completed folds to terminal", () => {
  const p = foldHistory([genesis(), core("process_completed", 1, 1, { terminal_node: "end", result: { ok: true } })]);
  assert.equal(p.lifecycle, "terminal");
  assert.equal(p.terminal?.outcome, "completed");
});

test("RT-FOLD-004: any event after terminal fold rejected", () => {
  const p = foldHistory([genesis(), core("process_completed", 1, 1, { terminal_node: "end" })]);
  assert.throws(
    () => foldEvent(core("observation_recorded", 2, 1, {
      observation_id: "o1", subject: "s", result_digest: "sha256:" + "2".repeat(64), observed_at: "2026-08-09T12:01:00Z",
    }), p),
    /RT-FOLD-004/,
  );
});

test("RT-FOLD-003: payload member outside closed set rejected", () => {
  const p = foldHistory([genesis()]);
  assert.throws(
    () => foldEvent(core("responsibility_issued", 1, 1, {
      responsibility_id: "r1", role: "w", objective: "o", acceptance: {}, smuggled: true,
    }), p),
    /RT-FOLD-003/,
  );
});

test("§7.4: Kind-defined type is opaque and changes nothing (§10.1: epoch included)", () => {
  const p = foldHistory([genesis()]);
  const after = foldEvent(core("kind_custom_receipt", 1, 1, { anything: "goes" }), p);
  assert.equal(after.epoch, 1);
  assert.deepEqual(after.responsibilities, p.responsibilities);
  assert.equal(after.lifecycle, p.lifecycle);
});

test("§7.4: Kind-supplied fold extension is invoked for Kind-defined types", () => {
  const p = foldHistory([genesis()]);
  const after = foldEvent(core("kind_custom_receipt", 1, 1, { anything: "goes" }), p, (_c, proj) => {
    proj.observations["from-kind"] = {
      responsibility_id: null, subject: "custom", result_digest: "sha256:" + "3".repeat(64),
      observed_at: "2026-08-09T12:02:00Z",
    };
    return proj;
  });
  assert.ok(after.observations["from-kind"]);
});

test("projection is derived: deleting and rebuilding yields identical state (§11)", () => {
  const events = [
    genesis(),
    core("responsibility_issued", 1, 1, { responsibility_id: "r1", role: "w", objective: "o", acceptance: {} }),
    core("wait_entered", 2, 1, { wait_id: "w1", condition: { kind: "timer", target_time: "2026-08-10T00:00:00Z" } }),
  ];
  const a = foldHistory(events);
  const b = foldHistory(events);
  assert.deepEqual(a, b);
});

test("emptyProjection is a valid baseline shape", () => {
  const p = emptyProjection(7);
  assert.equal(p.epoch, 7);
  assert.equal(p.terminal, null);
});
