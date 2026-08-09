import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildCanonicalCommand,
  requestDigest,
  decideIdempotency,
  type CanonicalCommand,
} from "@prt/command-digest";

function sampleCommand(): CanonicalCommand {
  return buildCanonicalCommand({
    command_id: "cmd_42",
    process_id: "proc_1",
    expected_head: "sha256:" + "d".repeat(64),
    epoch: 3,
    responsibility_id: "resp_1",
    actor: "agent:worker-7",
    action: "submit_result",
    payload: { result: "approved" },
    evidence: null,
    effect_key: null,
  });
}

test("RT-IDEM-001: identical commands produce identical request digests", () => {
  const a = requestDigest(sampleCommand());
  const b = requestDigest(sampleCommand());
  assert.equal(a, b);
  assert.match(a, /^sha256:[0-9a-f]{64}$/);
});

test("RT-IDEM-001: key insertion order does not change the digest", () => {
  const c = sampleCommand();
  const reordered = buildCanonicalCommand({
    payload: c.payload,
    action: c.action,
    actor: c.actor,
    responsibility_id: c.responsibility_id,
    epoch: c.epoch,
    expected_head: c.expected_head,
    process_id: c.process_id,
    command_id: c.command_id,
    evidence: c.evidence,
    effect_key: c.effect_key,
  });
  assert.equal(requestDigest(c), requestDigest(reordered));
});

test("RT-IDEM-001: one byte different → different digest", () => {
  const a = sampleCommand();
  const b = buildCanonicalCommand({ ...a, payload: { result: "rejectedd" } });
  assert.notEqual(requestDigest(a), requestDigest(b));
});

test("RT-IDEM-001: same id + same digest → replay original receipt", () => {
  const cmd = sampleCommand();
  const record = { command_id: cmd.command_id, request_digest: requestDigest(cmd), receipt: { head_after: "sha256:x" } };
  const decision = decideIdempotency(record, cmd);
  assert.equal(decision.kind, "replay");
  assert.deepEqual((decision as { receipt: unknown }).receipt, { head_after: "sha256:x" });
});

test("RT-IDEM-001: same id + different digest → conflict, never execute", () => {
  const cmd = sampleCommand();
  const record = { command_id: cmd.command_id, request_digest: requestDigest(cmd), receipt: {} };
  const altered = buildCanonicalCommand({ ...cmd, action: "submit_different_result" });
  assert.equal(decideIdempotency(record, altered).kind, "conflict");
});

test("RT-IDEM-001: unknown command_id → execute", () => {
  assert.equal(decideIdempotency(undefined, sampleCommand()).kind, "execute");
});

test("RT-IDEM-001: command missing a required member rejected", () => {
  const bad: Record<string, unknown> = { ...(sampleCommand() as object) };
  delete bad.expected_head;
  assert.throws(() => buildCanonicalCommand(bad), /RT-IDEM-001/);
});

test("RT-IDEM-001: command with member outside closed set rejected (closed-world admission)", () => {
  assert.throws(
    () => buildCanonicalCommand({ ...(sampleCommand() as object), extra: "SURPRISE" }),
    /outside closed set/,
  );
});
