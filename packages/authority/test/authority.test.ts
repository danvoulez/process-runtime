import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { generateAuthorityKeypair } from "@prt/event-v1";
import { ProcessAuthority, CommitRejection, type CommitReceipt } from "@prt/authority";

const keypair = generateAuthorityKeypair("authority/test");
const KIND = "sha256:" + "k".repeat(64);

let tmpDir: string;
function freshDb(): string {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "prt-auth-"));
  return path.join(tmpDir, "test.db");
}

function makeAuthority(dbPath: string, clock?: () => string): ProcessAuthority {
  return new ProcessAuthority(dbPath, { keypair, authorityId: "authority/test", clock });
}

function create(auth: ProcessAuthority, pid = "proc_1", cmdId = "cmd_genesis"): CommitReceipt {
  return auth.createProcess({ command_id: cmdId, process_id: pid, kind_digest: KIND });
}

function cmd(auth: ProcessAuthority, pid: string, id: string, action: string, payload: Record<string, unknown>) {
  return {
    command_id: id,
    process_id: pid,
    expected_head: auth.getHead(pid),
    epoch: auth.loadProjection(pid).epoch,
    responsibility_id: "resp/test",
    actor: "agent:test",
    action,
    payload,
    evidence: null,
    effect_key: null,
  };
}

test("§6: process creation commits genesis; receipt head_after is genesis digest", () => {
  const auth = makeAuthority(freshDb());
  const r = create(auth);
  assert.equal(r.result, "committed");
  assert.equal(r.head_after, r.event_digest);
  assert.equal(auth.listEvents("proc_1").length, 1);
  assert.equal(auth.getHead("proc_1"), r.event_digest);
  auth.close();
});

test("§6: duplicate process_id rejected", () => {
  const auth = makeAuthority(freshDb());
  create(auth);
  assert.throws(() => create(auth, "proc_1", "cmd_other"), (e: unknown) => e instanceof CommitRejection && (e as CommitRejection).code === "DUPLICATE_PROCESS");
  auth.close();
});

test("§16.1: retried creation returns original genesis receipt (duplicate), no second process", () => {
  const auth = makeAuthority(freshDb());
  const first = create(auth);
  const retry = create(auth);
  assert.equal(retry.result, "duplicate");
  assert.equal(retry.event_digest, first.event_digest);
  assert.equal(auth.listEvents("proc_1").length, 1);
  auth.close();
});

test("§13/§15: propose commits through the full path and returns receipt", () => {
  const auth = makeAuthority(freshDb());
  create(auth);
  const r = auth.propose(cmd(auth, "proc_1", "c1", "responsibility_issued", {
    responsibility_id: "r1", role: "worker", objective: "review", acceptance: {},
  }));
  assert.equal(r.head_after, r.event_digest);
  assert.notEqual(r.head_before, r.head_after);
  assert.equal(auth.loadProjection("proc_1").responsibilities.r1?.status, "issued");
  auth.close();
});

test("§8: stale expected_head rejected; proposal not reinterpreted", () => {
  const auth = makeAuthority(freshDb());
  create(auth);
  const staleHead = auth.getHead("proc_1");
  auth.propose(cmd(auth, "proc_1", "c1", "responsibility_issued", {
    responsibility_id: "r1", role: "w", objective: "o", acceptance: {},
  }));
  // Second proposer acting on the old head loses.
  const loser = {
    command_id: "c2", process_id: "proc_1", expected_head: staleHead, epoch: 1,
    responsibility_id: "resp/test", actor: "agent:test", action: "observation_recorded",
    payload: { observation_id: "o1", subject: "s", result_digest: KIND, observed_at: "2026-08-09T12:00:00Z" },
    evidence: null, effect_key: null,
  };
  assert.throws(() => auth.propose(loser), (e: unknown) => (e as CommitRejection).code === "STALE_HEAD");
  assert.equal(auth.listEvents("proc_1").length, 2);
  auth.close();
});

test("§9: two proposals cannot both win the same head", () => {
  const auth = makeAuthority(freshDb());
  create(auth);
  const head = auth.getHead("proc_1");
  const mk = (id: string, obs: string) => ({
    command_id: id, process_id: "proc_1", expected_head: head, epoch: 1,
    responsibility_id: "resp/test", actor: "agent:test", action: "observation_recorded",
    payload: { observation_id: obs, subject: "s", result_digest: KIND, observed_at: "2026-08-09T12:00:00Z" },
    evidence: null, effect_key: null,
  });
  auth.propose(mk("c1", "o1"));
  assert.throws(() => auth.propose(mk("c2", "o2")), (e: unknown) => (e as CommitRejection).code === "STALE_HEAD");
  auth.close();
});

test("§10.1: epoch advancement is a canonical commit; old-epoch commands rejected after", () => {
  const auth = makeAuthority(freshDb());
  create(auth);
  auth.advanceEpoch("c_epoch", "proc_1", "restart");
  assert.equal(auth.loadProjection("proc_1").epoch, 2);
  // Command carrying the old epoch is fenced.
  const staleEpochCmd = {
    command_id: "c_old", process_id: "proc_1", expected_head: auth.getHead("proc_1"), epoch: 1,
    responsibility_id: "resp/test", actor: "agent:test", action: "observation_recorded",
    payload: { observation_id: "o1", subject: "s", result_digest: KIND, observed_at: "2026-08-09T12:00:00Z" },
    evidence: null, effect_key: null,
  };
  assert.throws(() => auth.propose(staleEpochCmd), (e: unknown) => (e as CommitRejection).code === "STALE_EPOCH");
  auth.close();
});

test("§30: lease completes under current epoch; fenced after epoch advance (§30.3)", () => {
  const auth = makeAuthority(freshDb());
  create(auth);
  const lease = auth.claimInvocation("proc_1", "worker-1");
  auth.completeInvocation(lease);

  const stale = auth.claimInvocation("proc_1", "worker-2");
  auth.advanceEpoch("c_epoch", "proc_1", "failover");
  assert.throws(() => auth.completeInvocation(stale), (e: unknown) => (e as CommitRejection).code === "LEASE_FENCED");
  auth.close();
});

test("§30/§60: one valid Invocation owner — concurrent claim rejected, expired reclaimable", () => {
  let now = "2026-08-09T12:00:00.000Z";
  const auth = makeAuthority(freshDb(), () => now);
  create(auth);
  const first = auth.claimInvocation("proc_1", "worker-1", 1000);
  // Second owner while the first lease is live → rejected.
  assert.throws(() => auth.claimInvocation("proc_1", "worker-2"), (e: unknown) => (e as CommitRejection).code === "LEASE_FENCED");
  // After expiry, ownership is reclaimable (§54).
  now = "2026-08-09T12:00:02.000Z";
  const reclaimed = auth.claimInvocation("proc_1", "worker-2", 1000);
  assert.ok(reclaimed.lease_id !== first.lease_id);
  auth.close();
});

test("§30: cross-connection claim race — only one owner survives (UNIQUE + atomic upsert)", () => {
  const db = freshDb();
  const a = makeAuthority(db);
  create(a);
  a.close();

  // Two independent authority instances (separate SQLite connections).
  const connA = makeAuthority(db);
  const connB = makeAuthority(db);
  connA.claimInvocation("proc_1", "worker-A");
  // The second connection MUST NOT obtain a live lease for the same Process.
  assert.throws(() => connB.claimInvocation("proc_1", "worker-B"), (e: unknown) => (e as CommitRejection).code === "LEASE_FENCED");
  connA.close();
  connB.close();
});

test("§30: completeInvocation rejects a lease presented by the wrong worker", () => {
  const auth = makeAuthority(freshDb());
  create(auth);
  const lease = auth.claimInvocation("proc_1", "worker-1");
  assert.throws(
    () => auth.completeInvocation({ ...lease, worker_id: "worker-impostor" }),
    (e: unknown) => (e as CommitRejection).code === "LEASE_FENCED",
  );
  auth.close();
});

test("§30.2: expired lease cannot complete", () => {
  let now = "2026-08-09T12:00:00.000Z";
  const auth = makeAuthority(freshDb(), () => now);
  create(auth);
  const lease = auth.claimInvocation("proc_1", "worker-1", 1000);
  now = "2026-08-09T12:01:00.000Z";
  assert.throws(() => auth.completeInvocation(lease), (e: unknown) => (e as CommitRejection).code === "LEASE_EXPIRED");
  auth.close();
});

test("§16.1: duplicate command returns duplicate receipt without a second event", () => {
  const auth = makeAuthority(freshDb());
  create(auth);
  const c = cmd(auth, "proc_1", "c1", "responsibility_issued", {
    responsibility_id: "r1", role: "w", objective: "o", acceptance: {},
  });
  // Note: expected_head captured before first commit — retry must use the same command.
  const first = auth.propose(c);
  const retry = auth.propose(c);
  assert.equal(retry.result, "duplicate");
  assert.equal(retry.event_digest, first.event_digest);
  assert.equal(auth.listEvents("proc_1").length, 2);
  auth.close();
});

test("§16.1: same command_id with different payload is a conflict, never executed", () => {
  const auth = makeAuthority(freshDb());
  create(auth);
  auth.propose(cmd(auth, "proc_1", "c1", "responsibility_issued", {
    responsibility_id: "r1", role: "w", objective: "o", acceptance: {},
  }));
  const altered = cmd(auth, "proc_1", "c1", "responsibility_issued", {
    responsibility_id: "rDIFFERENT", role: "w", objective: "o", acceptance: {},
  });
  assert.throws(() => auth.propose(altered), (e: unknown) => (e as CommitRejection).code === "IDEMPOTENCY_CONFLICT");
  assert.equal(auth.listEvents("proc_1").length, 2);
  auth.close();
});

test("§16.2: idempotency records survive restart", () => {
  const db = freshDb();
  let auth = makeAuthority(db);
  create(auth);
  const c = cmd(auth, "proc_1", "c1", "responsibility_issued", {
    responsibility_id: "r1", role: "w", objective: "o", acceptance: {},
  });
  const first = auth.propose(c);
  auth.close();

  auth = makeAuthority(db); // restart
  const retry = auth.propose(c);
  assert.equal(retry.result, "duplicate");
  assert.equal(retry.event_digest, first.event_digest);
  assert.equal(auth.listEvents("proc_1").length, 2);
  auth.close();
});

test("§76: canonical events and pinned kind survive restart", () => {
  const db = freshDb();
  let auth = makeAuthority(db);
  create(auth);
  auth.propose(cmd(auth, "proc_1", "c1", "responsibility_issued", {
    responsibility_id: "r1", role: "w", objective: "o", acceptance: {},
  }));
  auth.close();

  auth = makeAuthority(db);
  const events = auth.listEvents("proc_1");
  assert.equal(events.length, 2);
  assert.equal(events[0]?.payload.kind_digest, KIND); // pinned kind remains pinned
  assert.equal(auth.verifyProcess("proc_1").status, "VALID");
  auth.close();
});

test("§26.3/§27: stale wait response rejected; duplicate timer delivery harmless", () => {
  const auth = makeAuthority(freshDb());
  create(auth);
  auth.propose(cmd(auth, "proc_1", "w1", "wait_entered", {
    wait_id: "wait1", condition: { kind: "timer", target_time: "2026-08-10T00:00:00Z" },
  }));
  // Timer fires (delivery 1) → resolves.
  const resolve = cmd(auth, "proc_1", "w2", "wait_resolved", { wait_id: "wait1", resolution: { fired: true } });
  auth.propose(resolve);
  assert.equal(auth.loadProjection("proc_1").lifecycle, "active");
  // At-least-once redelivery of the SAME command → duplicate receipt, no event.
  const redelivery = auth.propose(resolve);
  assert.equal(redelivery.result, "duplicate");
  assert.equal(auth.listEvents("proc_1").length, 3);
  // A DIFFERENT command resolving the same (now inactive) wait → rejected (§26.3).
  const stale = cmd(auth, "proc_1", "w3", "wait_resolved", { wait_id: "wait1", resolution: { fired: true } });
  assert.throws(() => auth.propose(stale), /unknown id/);
  auth.close();
});

test("§51: terminal blocked while responsibility active; allowed after closure", () => {
  const auth = makeAuthority(freshDb());
  create(auth);
  auth.propose(cmd(auth, "proc_1", "c1", "responsibility_issued", {
    responsibility_id: "r1", role: "w", objective: "o", acceptance: {},
  }));
  assert.throws(
    () => auth.propose(cmd(auth, "proc_1", "c2", "process_completed", { terminal_node: "end" })),
    (e: unknown) => (e as CommitRejection).code === "VALIDATION_FAILED",
  );
  auth.propose(cmd(auth, "proc_1", "c3", "responsibility_completed", { responsibility_id: "r1" }));
  const terminal = auth.propose(cmd(auth, "proc_1", "c4", "process_completed", { terminal_node: "end" }));
  assert.equal(terminal.result, "committed");
  assert.equal(auth.loadProjection("proc_1").lifecycle, "terminal");
  auth.close();
});

test("RT-FOLD-004: any proposal after terminal rejected", () => {
  const auth = makeAuthority(freshDb());
  create(auth);
  auth.propose(cmd(auth, "proc_1", "c1", "process_completed", { terminal_node: "end" }));
  assert.throws(
    () => auth.propose(cmd(auth, "proc_1", "c2", "observation_recorded", {
      observation_id: "o1", subject: "s", result_digest: KIND, observed_at: "2026-08-09T12:00:00Z",
    })),
    /RT-FOLD-004/,
  );
  auth.close();
});

test("§14/§53.1: validation failure inside the path leaves no half-commit", () => {
  const db = freshDb();
  const auth = new ProcessAuthority(db, {
    keypair,
    authorityId: "authority/test",
    evidenceValidator: () => { throw new Error("evidence missing"); },
  });
  create(auth);
  const headBefore = auth.getHead("proc_1");
  assert.throws(() =>
    auth.propose(cmd(auth, "proc_1", "c1", "observation_recorded", {
      observation_id: "o1", subject: "s", result_digest: KIND, observed_at: "2026-08-09T12:00:00Z",
    })), /evidence missing/);
  // No institutional commit occurred: head, sequence, events unchanged.
  assert.equal(auth.getHead("proc_1"), headBefore);
  assert.equal(auth.listEvents("proc_1").length, 1);
  auth.close();
});

test("§12: verifyProcess VALID; corrupted projection reported defective; history governs", () => {
  const auth = makeAuthority(freshDb());
  create(auth);
  auth.propose(cmd(auth, "proc_1", "c1", "responsibility_issued", {
    responsibility_id: "r1", role: "w", objective: "o", acceptance: {},
  }));
  assert.equal(auth.verifyProcess("proc_1").status, "VALID");

  // Simulate a defective stored projection (§12: canonical history governs).
  const store = (auth as unknown as { db: import("better-sqlite3").Database }).db;
  store.prepare("UPDATE processes SET projection = ? WHERE process_id = ?").run(JSON.stringify({ tampered: true }), "proc_1");
  const report = auth.verifyProcess("proc_1");
  assert.equal(report.status, "DEFECTIVE_PROJECTION");
  auth.close();
});

test("§12: tampered canonical event invalidates history", () => {
  const auth = makeAuthority(freshDb());
  create(auth);
  const store = (auth as unknown as { db: import("better-sqlite3").Database }).db;
  const event = JSON.parse((store.prepare("SELECT event FROM canonical_events WHERE process_id = ? AND sequence = 0").get("proc_1") as { event: string }).event) as Record<string, unknown>;
  event.authority = "mallory";
  store.prepare("UPDATE canonical_events SET event = ? WHERE process_id = ? AND sequence = 0").run(JSON.stringify(event), "proc_1");
  assert.equal(auth.verifyProcess("proc_1").status, "INVALID_HISTORY");
  auth.close();
});

test("§7.5: swapped signature detected by verifyProcess even though digest chain is intact", () => {
  const auth = makeAuthority(freshDb());
  create(auth);
  const store = (auth as unknown as { db: import("better-sqlite3").Database }).db;
  const row = store.prepare("SELECT event FROM canonical_events WHERE process_id = ? AND sequence = 0").get("proc_1") as { event: string };
  const event = JSON.parse(row.event) as Record<string, unknown>;
  // Attacker swaps only the signature bytes — the digest chain is untouched.
  (event.signature as { value: string }).value = Buffer.alloc(64, 7).toString("base64url");
  store.prepare("UPDATE canonical_events SET event = ? WHERE process_id = ? AND sequence = 0").run(JSON.stringify(event), "proc_1");
  const report = auth.verifyProcess("proc_1");
  assert.equal(report.status, "INVALID_HISTORY");
  assert.match(report.detail ?? "", /signature invalid/);
  auth.close();
});

test("§56.3: genesis anchors the authority key digest in canonical history", () => {
  const auth = makeAuthority(freshDb());
  create(auth);
  const genesis = auth.listEvents("proc_1")[0];
  const anchor = genesis?.payload.authority_key_digest;
  assert.match(anchor as string, /^sha256:[0-9a-f]{64}$/);
  auth.close();
});
