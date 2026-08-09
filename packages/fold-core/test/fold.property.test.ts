import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { canonicalize, type JsonValue } from "@prt/jcs-digest";
import { buildEventCore, type EventCore } from "@prt/event-v1";
import { foldHistory } from "@prt/fold-core";
import type { Projection } from "@prt/fold-core";

/** Deterministic PRNG so generated histories are reproducible from the seed. */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const dummyPrev = "sha256:" + "0".repeat(64);

/** Build a random but semantically valid event history from a seed. */
function buildHistory(seed: number): EventCore[] {
  const rnd = mulberry32(seed);
  const pick = <T>(xs: T[]): T => xs[Math.floor(rnd() * xs.length)] as T;
  const chance = (p: number) => rnd() < p;

  const events: EventCore[] = [];
  let seq = 0;
  let epoch = 1;
  const push = (type: string, payload: Record<string, unknown>) => {
    events.push(buildEventCore({
      schema: "event/v1", process_id: "proc_prop", sequence: seq,
      previous: seq === 0 ? null : dummyPrev, epoch, type, payload,
      causation: null, authority: "property-test", committed_at: "2026-08-09T12:00:00Z",
    }));
    seq++;
  };

  push("process_created", { kind_digest: "sha256:" + "a".repeat(64) });

  const nResp = 1 + Math.floor(rnd() * 4);
  for (let i = 0; i < nResp; i++) {
    const id = `r${i}`;
    push("responsibility_issued", { responsibility_id: id, role: pick(["worker", "reviewer"]), objective: `obj${i}`, acceptance: {} });
    if (chance(0.8)) push("responsibility_accepted", { responsibility_id: id, actor: pick(["human:dan", "agent:eve"]) });
    if (chance(0.6)) push("responsibility_submitted", { responsibility_id: id, actor: "agent:eve" });
    if (chance(0.5)) push("responsibility_completed", { responsibility_id: id });
    else if (chance(0.2)) push("responsibility_revoked", { responsibility_id: id, reason: "expired" });
  }

  const nGrant = Math.floor(rnd() * 3);
  for (let i = 0; i < nGrant; i++) {
    const id = `g${i}`;
    push("grant_issued", {
      grant_id: id, responsibility_id: "r0", actor: "agent:eve", action: "linear.read",
      subject: "linear://ENG", bounds: {}, expected_head: dummyPrev, epoch,
      expiry: "2026-08-10T00:00:00Z",
    });
    if (chance(0.5)) push("grant_revoked", { grant_id: id });
  }

  const conditions: Record<string, unknown>[] = [
    { kind: "timer", target_time: "2026-08-10T00:00:00Z" },
    { kind: "approval", approver: "human:dan", resume_schema: "sha256:" + "5".repeat(64) },
    { kind: "webhook", webhook_identity: "wh_provider_1" },
  ];
  const nWait = Math.floor(rnd() * 3);
  for (let i = 0; i < nWait; i++) {
    const id = `w${i}`;
    push("wait_entered", { wait_id: id, condition: pick(conditions) });
    push("wait_resolved", { wait_id: id, resolution: { ok: chance(0.9) } });
  }

  const nEpoch = Math.floor(rnd() * 3);
  for (let i = 0; i < nEpoch; i++) {
    push("epoch_advanced", { previous_epoch: epoch, new_epoch: epoch + 1, reason: pick(["restart", "failover"]) });
    epoch++;
  }

  const nEffect = Math.floor(rnd() * 3);
  for (let i = 0; i < nEffect; i++) {
    const key = `e${i}`;
    push("effect_committed", { effect_key: key, responsibility_id: "r0", operation: "op", provider: pick(["linear", "github"]) });
    if (chance(0.6)) {
      push("effect_reconciled", { effect_key: key, prior_state: "unknown", outcome: pick(["completed", "not_completed", "still_unknown", "compensated"]) });
    }
  }

  const nArt = Math.floor(rnd() * 3);
  for (let i = 0; i < nArt; i++) {
    push("artifact_admitted", {
      artifact_id: `a${i}`, digest: "sha256:" + String(i).padStart(64, "0"), media: "text/plain",
      size: 100 + i, storage_ref: `r2://b/a${i}`, responsibility_id: "r0",
    });
  }

  const nObs = Math.floor(rnd() * 3);
  for (let i = 0; i < nObs; i++) {
    push("observation_recorded", {
      observation_id: `o${i}`, subject: "provider-response",
      result_digest: "sha256:" + String(i).padStart(64, "1"), observed_at: "2026-08-09T12:30:00Z",
    });
  }

  if (chance(0.5)) push("process_completed", { terminal_node: "end", result: { summary: "done" } });

  return events;
}

/**
 * Independent second implementation (RT-FOLD-002 cross-check).
 * Deliberately different code shape: single pass, mutable draft object,
 * no shared helpers with @prt/fold-core.
 */
function naiveFoldHistory(cores: EventCore[]): Projection {
  let p: Projection | null = null;
  for (const c of cores) {
    if (c.type === "process_created") {
      p = {
        lifecycle: "active", epoch: c.epoch, responsibilities: {}, grants: {},
        waits: {}, effects: {}, artifacts: {}, observations: {}, authority_keys: [], terminal: null,
      };
      const anchor = (c.payload as Record<string, unknown>).authority_key_digest;
      if (typeof anchor === "string" && anchor.startsWith("sha256:")) {
        p.authority_keys.push({ key_id: null, key_digest: anchor, valid_from_seq: 0 });
      }
      continue;
    }
    if (p === null) throw new Error("no genesis");
    const d: Projection = JSON.parse(JSON.stringify(p)) as Projection;
    // §10.1: only epoch_advanced changes the epoch (handled in its case).
    const pl = c.payload as Record<string, string>;
    switch (c.type) {
      case "responsibility_issued":
        d.responsibilities[pl.responsibility_id as string] = {
          status: "issued", role: pl.role as string, objective: pl.objective as string,
          actor: null, payload: c.payload,
        };
        break;
      case "responsibility_accepted": {
        const r = d.responsibilities[pl.responsibility_id as string];
        if (r) { r.status = "accepted"; r.actor = pl.actor as string; }
        break;
      }
      case "responsibility_submitted": {
        const r = d.responsibilities[pl.responsibility_id as string];
        if (r) r.status = "submitted";
        break;
      }
      case "responsibility_completed":
        delete d.responsibilities[pl.responsibility_id as string];
        break;
      case "responsibility_revoked":
        delete d.responsibilities[pl.responsibility_id as string];
        break;
      case "grant_issued":
        d.grants[pl.grant_id as string] = {
          responsibility_id: pl.responsibility_id as string, actor: pl.actor as string,
          action: pl.action as string, subject: pl.subject as string,
          epoch: (c.payload as Record<string, number>).epoch as number, expiry: pl.expiry as string,
        };
        break;
      case "grant_revoked":
        delete d.grants[pl.grant_id as string];
        break;
      case "wait_entered":
        d.waits[pl.wait_id as string] = { condition: c.payload.condition as Record<string, JsonValue> };
        d.lifecycle = "waiting";
        break;
      case "wait_resolved":
        delete d.waits[pl.wait_id as string];
        if (Object.keys(d.waits).length === 0 && d.lifecycle === "waiting") d.lifecycle = "active";
        break;
      case "epoch_advanced":
        d.epoch = (c.payload as Record<string, number>).new_epoch as number;
        break;
      case "effect_committed":
        d.effects[pl.effect_key as string] = {
          state: "committed", responsibility_id: pl.responsibility_id as string,
          operation: pl.operation as string, provider: pl.provider as string,
        };
        break;
      case "effect_reconciled": {
        const e = d.effects[pl.effect_key as string];
        if (e) {
          const outcome = pl.outcome as "completed" | "not_completed" | "still_unknown" | "compensated";
          e.reconciliation = outcome;
          e.state = ({ completed: "committed", not_completed: "rejected", still_unknown: "unknown", compensated: "compensated" } as const)[outcome];
        }
        break;
      }
      case "artifact_admitted":
        d.artifacts[pl.artifact_id as string] = {
          digest: pl.digest as string, media: pl.media as string,
          size: (c.payload as Record<string, number>).size as number,
          storage_ref: pl.storage_ref as string, responsibility_id: pl.responsibility_id as string,
        };
        break;
      case "observation_recorded":
        d.observations[pl.observation_id as string] = {
          responsibility_id: (c.payload as Record<string, string | null>).responsibility_id ?? null,
          subject: pl.subject as string, result_digest: pl.result_digest as string,
          observed_at: pl.observed_at as string,
        };
        break;
      case "process_completed":
        d.lifecycle = "terminal";
        d.terminal = { outcome: "completed", result: c.payload.result as JsonValue | undefined };
        break;
      case "process_failed":
        d.lifecycle = "terminal";
        d.terminal = { outcome: "failed", reason: pl.reason as string };
        break;
      case "authority_key_introduced":
        d.authority_keys.push({
          key_id: pl.key_id as string,
          key_digest: pl.key_digest as string,
          valid_from_seq: (c.payload as Record<string, number>).valid_from_seq as number,
        });
        break;
      default:
        break;
    }
    p = d;
  }
  if (p === null) throw new Error("empty");
  return p;
}

test("RT-FOLD-001/002: same history folds to byte-identical projection (self)", () => {
  fc.assert(
    fc.property(fc.integer(), (seed) => {
      const history = buildHistory(seed);
      const a = foldHistory(history);
      const b = foldHistory(history);
      assert.equal(canonicalize(a as unknown as JsonValue), canonicalize(b as unknown as JsonValue));
    }),
    { numRuns: 100 },
  );
});

test("RT-FOLD-002: two independent implementations fold byte-identical projections", () => {
  fc.assert(
    fc.property(fc.integer(), (seed) => {
      const history = buildHistory(seed);
      const reference = foldHistory(history);
      const naive = naiveFoldHistory(history);
      assert.equal(
        canonicalize(reference as unknown as JsonValue),
        canonicalize(naive as unknown as JsonValue),
      );
    }),
    { numRuns: 100 },
  );
});
