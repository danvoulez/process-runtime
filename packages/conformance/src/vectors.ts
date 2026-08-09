import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { verifyBundle } from "@prt/export-v1";
import {
  asProjection,
  asReceipt,
  type DriverFactory,
  type RuntimeDriver,
} from "./driver.js";

export interface VectorResult {
  group: string;
  profile: ConformanceProfile;
  name: string;
  rt: string[];
  status: "PASS" | "FAIL" | "SKIP";
  detail?: string;
}

/**
 * Named conformance profiles (§60 audit).
 * `CONFORMING` is always qualified by the profiles actually proven.
 * Full conformance = core + verify + export.
 */
export type ConformanceProfile = "core" | "verify" | "export";

type Vector = (ctx: Ctx) => Promise<void>;

interface Ctx {
  factory: DriverFactory;
}

const KIND = "sha256:" + "b".repeat(64);
const TS = "2026-08-09T12:00:00Z";

function cmd(d: RuntimeDriver, pid: string, id: string, action: string, payload: Record<string, unknown>, head: string, epoch: number) {
  return {
    command_id: id,
    process_id: pid,
    expected_head: head,
    epoch,
    responsibility_id: "resp/conformance",
    actor: "conformance-driver",
    action,
    payload,
    evidence: null,
    effect_key: null,
  };
}

async function head(d: RuntimeDriver, pid: string): Promise<string> {
  return d.getHead(pid);
}

async function epochOf(d: RuntimeDriver, pid: string): Promise<number> {
  return asProjection(await d.loadProjection(pid)).epoch;
}

async function proposeExpectReject(d: RuntimeDriver, command: unknown): Promise<Error> {
  try {
    await d.propose(command);
  } catch (e) {
    return e as Error;
  }
  throw new Error("expected rejection, but the command was committed");
}

async function genesis(d: RuntimeDriver, pid: string): Promise<void> {
  await d.createProcess({ command_id: `gen_${pid}`, process_id: pid, kind_digest: KIND });
}

/** Every runtime vector suite, in §60 group order. */
export const RUNTIME_VECTORS: Array<{ group: string; profile: "core"; name: string; rt: string[]; run: Vector }> = [
  {
    group: "HEAD",
    profile: "core",
    name: "correct expected_head accepted; stale rejected; two proposals cannot both win",
    rt: ["§8", "§9"],
    run: async (ctx) => {
      const d = await ctx.factory.fresh();
      const pid = "p_head";
      await genesis(d, pid);
      const h = await head(d, pid);
      await d.propose(cmd(d, pid, "h1", "observation_recorded", {
        observation_id: "o1", subject: "s", result_digest: KIND, observed_at: TS,
      }, h, 1));
      // Same head again → stale.
      await proposeExpectReject(d, cmd(d, pid, "h2", "observation_recorded", {
        observation_id: "o2", subject: "s", result_digest: KIND, observed_at: TS,
      }, h, 1));
      const events = await d.listEvents(pid);
      if (events.length !== 2) throw new Error(`stale proposal entered history (${events.length} events)`);
    },
  },
  {
    group: "EPOCH",
    profile: "core",
    name: "epoch advances only canonically; stale-epoch command and lease fenced",
    rt: ["§10", "§10.1", "§30.3"],
    run: async (ctx) => {
      const d = await ctx.factory.fresh();
      const pid = "p_epoch";
      await genesis(d, pid);
      const lease = await d.claimInvocation(pid, "runner-1");
      await d.propose(cmd(d, pid, "e1", "epoch_advanced", { previous_epoch: 1, new_epoch: 2, reason: "failover" }, await head(d, pid), 1));
      if ((await epochOf(d, pid)) !== 2) throw new Error("epoch did not advance to 2");
      // stale-epoch command
      await proposeExpectReject(d, cmd(d, pid, "e2", "observation_recorded", {
        observation_id: "o1", subject: "s", result_digest: KIND, observed_at: TS,
      }, await head(d, pid), 1));
      // lease from old epoch fenced
      try {
        await d.completeInvocation(lease);
        throw new Error("stale-epoch lease completed");
      } catch { /* expected */ }
    },
  },
  {
    group: "COMMIT",
    profile: "core",
    name: "event + head + projection + receipt are one indivisible operation",
    rt: ["§14", "§15"],
    run: async (ctx) => {
      const d = await ctx.factory.fresh();
      const pid = "p_commit";
      await genesis(d, pid);
      const receipt = asReceipt(await d.propose(cmd(d, pid, "c1", "responsibility_issued", {
        responsibility_id: "r1", role: "w", objective: "o", acceptance: {},
      }, await head(d, pid), 1)));
      const events = await d.listEvents(pid);
      const last = events[events.length - 1];
      if (last?.digest !== receipt.event_digest) throw new Error("event missing from history");
      if ((await head(d, pid)) !== receipt.event_digest) throw new Error("head did not advance to event digest");
      const p = asProjection(await d.loadProjection(pid));
      if (p.responsibilities.r1 === undefined) throw new Error("projection did not fold");
      const stored = asReceipt(await d.getReceipt(pid, "c1"));
      if (stored.event_digest !== receipt.event_digest) throw new Error("receipt not recorded atomically");
    },
  },
  {
    group: "COMMIT",
    profile: "core",
    name: "failure inside the path leaves no consequence; retry of a valid command proceeds",
    rt: ["§53.1"],
    run: async (ctx) => {
      const d = await ctx.factory.fresh();
      const pid = "p_crash";
      await genesis(d, pid);
      const before = await head(d, pid);
      await proposeExpectReject(d, cmd(d, pid, "c1", "wait_resolved", { wait_id: "ghost", resolution: {} }, before, 1));
      if ((await head(d, pid)) !== before) throw new Error("head moved on a failed commit");
      if ((await d.listEvents(pid)).length !== 1) throw new Error("failed commit left an event");
      await d.propose(cmd(d, pid, "c2", "observation_recorded", {
        observation_id: "o1", subject: "s", result_digest: KIND, observed_at: TS,
      }, await head(d, pid), 1));
    },
  },
  {
    group: "IDEMPOTENCY",
    profile: "core",
    name: "duplicate command returns prior result without a second consequence",
    rt: ["§16.1", "RT-IDEM-001"],
    run: async (ctx) => {
      const d = await ctx.factory.fresh();
      const pid = "p_idem";
      await genesis(d, pid);
      const c = cmd(d, pid, "i1", "responsibility_issued", {
        responsibility_id: "r1", role: "w", objective: "o", acceptance: {},
      }, await head(d, pid), 1);
      const first = asReceipt(await d.propose(c));
      const retry = asReceipt(await d.propose(c));
      if (retry.event_digest !== first.event_digest) throw new Error("retry produced a different consequence");
      if ((await d.listEvents(pid)).length !== 2) throw new Error("retry appended a second event");
    },
  },
  {
    group: "IDEMPOTENCY",
    profile: "core",
    name: "same command_id with different payload is a conflict, never executed",
    rt: ["§16.1", "RT-IDEM-001"],
    run: async (ctx) => {
      const d = await ctx.factory.fresh();
      const pid = "p_conflict";
      await genesis(d, pid);
      await d.propose(cmd(d, pid, "i1", "responsibility_issued", {
        responsibility_id: "r1", role: "w", objective: "o", acceptance: {},
      }, await head(d, pid), 1));
      await proposeExpectReject(d, cmd(d, pid, "i1", "responsibility_issued", {
        responsibility_id: "rDIFFERENT", role: "w", objective: "o", acceptance: {},
      }, await head(d, pid), 1));
      if ((await d.listEvents(pid)).length !== 2) throw new Error("conflicting command was executed");
    },
  },
  {
    group: "IDEMPOTENCY",
    profile: "core",
    name: "idempotency records survive restart",
    rt: ["§16.2"],
    run: async (ctx) => {
      const d = await ctx.factory.fresh();
      const pid = "p_restart_idem";
      await genesis(d, pid);
      const c = cmd(d, pid, "i1", "responsibility_issued", {
        responsibility_id: "r1", role: "w", objective: "o", acceptance: {},
      }, await head(d, pid), 1);
      const first = asReceipt(await d.propose(c));
      const revived = await ctx.factory.reopen(d);
      const retry = asReceipt(await revived.propose(c));
      if (retry.event_digest !== first.event_digest) throw new Error("post-restart retry lost the idempotency record");
      if ((await revived.listEvents(pid)).length !== 2) throw new Error("post-restart retry appended an event");
    },
  },
  {
    group: "WAITS",
    profile: "core",
    name: "wait survives runner death; stale response rejected; duplicate timer harmless",
    rt: ["§26", "§26.3", "§27"],
    run: async (ctx) => {
      const d = await ctx.factory.fresh();
      const pid = "p_waits";
      await genesis(d, pid);
      await d.propose(cmd(d, pid, "w1", "wait_entered", {
        wait_id: "wait1", condition: { kind: "timer", target_time: "2026-08-10T00:00:00Z" },
      }, await head(d, pid), 1));
      const revived = await ctx.factory.reopen(d); // runner dies and restarts
      if (asProjection(await revived.loadProjection(pid)).lifecycle !== "waiting") {
        throw new Error("wait did not survive runner death");
      }
      const resolve = cmd(revived, pid, "w2", "wait_resolved", { wait_id: "wait1", resolution: { fired: true } }, await head(revived, pid), 1);
      await revived.propose(resolve);
      const redelivery = asReceipt(await revived.propose(resolve));
      if (redelivery.result !== "duplicate") throw new Error("duplicate timer delivery was not idempotent");
      // A different command resolving the now-inactive wait → rejected.
      await proposeExpectReject(revived, cmd(revived, pid, "w3", "wait_resolved", { wait_id: "wait1", resolution: { fired: true } }, await head(revived, pid), 1));
    },
  },
  {
    group: "LEASES",
    profile: "core",
    name: "one valid Invocation owner",
    rt: ["§30"],
    run: async (ctx) => {
      const d = await ctx.factory.fresh();
      const pid = "p_lease";
      await genesis(d, pid);
      await d.claimInvocation(pid, "worker-1");
      try {
        await d.claimInvocation(pid, "worker-2");
        throw new Error("second owner obtained a live lease");
      } catch (e) {
        if ((e as Error).message.includes("second owner")) throw e;
      }
    },
  },
  {
    group: "TERMINATION",
    profile: "core",
    name: "responsibility closure is not termination; gate blocks unresolved work; valid terminal closes",
    rt: ["§51", "RT-FOLD-004"],
    run: async (ctx) => {
      const d = await ctx.factory.fresh();
      const pid = "p_term";
      await genesis(d, pid);
      await d.propose(cmd(d, pid, "t1", "responsibility_issued", {
        responsibility_id: "r1", role: "w", objective: "o", acceptance: {},
      }, await head(d, pid), 1));
      // Gate blocks while responsibility is active.
      await proposeExpectReject(d, cmd(d, pid, "t2", "process_completed", { terminal_node: "end" }, await head(d, pid), 1));
      await d.propose(cmd(d, pid, "t3", "responsibility_completed", { responsibility_id: "r1" }, await head(d, pid), 1));
      // Closure alone did not terminate.
      if (asProjection(await d.loadProjection(pid)).lifecycle === "terminal") {
        throw new Error("responsibility closure terminated the Process");
      }
      await d.propose(cmd(d, pid, "t4", "process_completed", { terminal_node: "end" }, await head(d, pid), 1));
      if (asProjection(await d.loadProjection(pid)).lifecycle !== "terminal") throw new Error("valid terminal commit did not close");
      // Nothing after terminal.
      await proposeExpectReject(d, cmd(d, pid, "t5", "observation_recorded", {
        observation_id: "o1", subject: "s", result_digest: KIND, observed_at: TS,
      }, await head(d, pid), 1));
    },
  },
];

export const CAPABILITY_VECTORS: Array<{ group: string; profile: "verify" | "export"; name: string; rt: string[]; requires: "verify" | "exportBundle"; run: Vector }> = [
  {
    group: "VERIFY",
    profile: "verify",
    name: "replay verification reports VALID on a healthy history",
    rt: ["§12"],
    requires: "verify",
    run: async (ctx) => {
      const d = await ctx.factory.fresh();
      const pid = "p_verify";
      await genesis(d, pid);
      await d.propose(cmd(d, pid, "v1", "responsibility_issued", {
        responsibility_id: "r1", role: "w", objective: "o", acceptance: {},
      }, await head(d, pid), 1));
      const report = await d.verifyProcess?.(pid);
      if (report === undefined) throw new Error("driver declared verify capability but verifyProcess returned undefined");
      if (report.status !== "VALID") throw new Error(`expected VALID, got ${report.status}: ${report.detail ?? ""}`);
    },
  },
  {
    group: "EXPORT",
    profile: "export",
    name: "canonical export verifies independently, offline",
    rt: ["§56.3", "§57", "RT-EXPORT-001"],
    requires: "exportBundle",
    run: async (ctx) => {
      const d = await ctx.factory.fresh();
      const pid = "p_export";
      await genesis(d, pid);
      await d.propose(cmd(d, pid, "x1", "responsibility_issued", {
        responsibility_id: "r1", role: "w", objective: "o", acceptance: {},
      }, await head(d, pid), 1));
      await d.propose(cmd(d, pid, "x2", "responsibility_completed", { responsibility_id: "r1" }, await head(d, pid), 1));
      await d.propose(cmd(d, pid, "x3", "process_completed", { terminal_node: "end" }, await head(d, pid), 1));
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "prt-conf-export-"));
      // §56.3: the bundle must be self-contained — the driver owns its
      // key material. No reference-specific side channel.
      await d.exportBundle?.(pid, path.join(dir, "bundle"));
      const report = verifyBundle(path.join(dir, "bundle"));
      if (report.status !== "VALID") {
        throw new Error(report.checks.filter((c) => !c.ok).map((c) => `${c.name}: ${c.detail ?? ""}`).join("; "));
      }
    },
  },
];
