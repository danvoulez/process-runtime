import type { JsonValue } from "@prt/jcs-digest";
import type { EventCore } from "@prt/event-v1";
import { validateWaitCondition } from "./conditions.js";
import { assertClosedPayload, requirePayloadString } from "./payloads.js";
import { emptyProjection, type Projection } from "./projection.js";

function fail(rt: string, msg: string): never {
  throw new Error(`${rt}: ${msg}`);
}

/**
 * §7.6 / RT-FOLD-001: fold is a pure function of
 * (pinned Kind, event core, prior projection).
 * No wall clock, no live state, no deployment configuration.
 *
 * RT-FOLD-001 note: the pinned Process Kind parameter exists in the
 * signature even though core folds are Kind-independent, because
 * Kind-defined types (§7.4) may carry Kind-supplied fold semantics.
 */
export function foldEvent(core: EventCore, prior: Projection | null, kindFold?: KindFoldExtension): Projection {
  const payload = core.payload as Record<string, unknown>;
  assertClosedPayload(core.type, payload);

  // RT-FOLD-004: terminal exclusivity.
  if (prior !== null && prior.lifecycle === "terminal" && prior.terminal !== null) {
    fail("RT-FOLD-004", `event ${core.type} at sequence ${core.sequence} arrives after terminal fold`);
  }

  if (core.type === "process_created") {
    if (prior !== null) fail("RT-FOLD-001", "process_created must be the genesis fold");
    const initial = emptyProjection(core.epoch);
    // RT-KEY-001: the genesis anchor seeds the authority key inventory.
    const anchor = (core.payload as Record<string, unknown>).authority_key_digest;
    if (typeof anchor === "string" && anchor.startsWith("sha256:")) {
      initial.authority_keys.push({ key_id: null, key_digest: anchor, valid_from_seq: 0 });
    }
    return initial;
  }

  if (prior === null) fail("RT-FOLD-001", `cannot fold ${core.type} before genesis`);

  // §10.1: the epoch advances ONLY through an authorized epoch_advanced
  // commit. Any other event carrying a different epoch is corruption,
  // not an epoch change.
  if (core.type !== "epoch_advanced" && core.epoch !== prior.epoch) {
    fail("RT-FOLD-001", `event epoch ${core.epoch} != process epoch ${prior.epoch}: epoch advances only via epoch_advanced (§10.1)`);
  }

  const p = structuredClone(prior);

  switch (core.type) {
    case "responsibility_issued": {
      const id = requirePayloadString(core.type, payload, "responsibility_id");
      if (p.responsibilities[id] !== undefined) fail("RT-FOLD-003", `duplicate responsibility_id: ${id}`);
      p.responsibilities[id] = {
        status: "issued",
        role: requirePayloadString(core.type, payload, "role"),
        objective: requirePayloadString(core.type, payload, "objective"),
        actor: null,
        payload: payload as Record<string, JsonValue>,
      };
      return p;
    }

    case "responsibility_accepted": {
      const id = requirePayloadString(core.type, payload, "responsibility_id");
      const r = mustHave(p.responsibilities, id, core.type);
      r.status = "accepted";
      r.actor = requirePayloadString(core.type, payload, "actor");
      return p;
    }

    case "responsibility_submitted": {
      const id = requirePayloadString(core.type, payload, "responsibility_id");
      mustHave(p.responsibilities, id, core.type).status = "submitted";
      return p;
    }

    case "responsibility_completed": {
      const id = requirePayloadString(core.type, payload, "responsibility_id");
      const r = mustHave(p.responsibilities, id, core.type);
      r.status = "completed";
      delete p.responsibilities[id];
      return p;
    }

    case "responsibility_revoked": {
      const id = requirePayloadString(core.type, payload, "responsibility_id");
      delete p.responsibilities[id];
      return p;
    }

    case "grant_issued": {
      const id = requirePayloadString(core.type, payload, "grant_id");
      if (p.grants[id] !== undefined) fail("RT-FOLD-003", `duplicate grant_id: ${id}`);
      p.grants[id] = {
        responsibility_id: requirePayloadString(core.type, payload, "responsibility_id"),
        actor: requirePayloadString(core.type, payload, "actor"),
        action: requirePayloadString(core.type, payload, "action"),
        subject: requirePayloadString(core.type, payload, "subject"),
        epoch: typeof payload.epoch === "number" ? payload.epoch : core.epoch,
        expiry: requirePayloadString(core.type, payload, "expiry"),
      };
      return p;
    }

    case "grant_revoked": {
      const id = requirePayloadString(core.type, payload, "grant_id");
      mustHave(p.grants, id, core.type);
      delete p.grants[id];
      return p;
    }

    case "wait_entered": {
      const id = requirePayloadString(core.type, payload, "wait_id");
      const condition = payload.condition;
      if (typeof condition !== "object" || condition === null || Array.isArray(condition)) {
        fail("RT-FOLD-003", "wait_entered.payload.condition must be an object");
      }
      validateWaitCondition(condition); // §26.1 / RT-WAIT-001
      if (p.waits[id] !== undefined) fail("RT-FOLD-003", `duplicate wait_id: ${id}`);
      p.waits[id] = { condition: condition as Record<string, JsonValue> };
      p.lifecycle = "waiting";
      return p;
    }

    case "wait_resolved": {
      const id = requirePayloadString(core.type, payload, "wait_id");
      // §26.3: a response to a Wait that is no longer active MUST be rejected.
      mustHave(p.waits, id, core.type);
      delete p.waits[id];
      if (Object.keys(p.waits).length === 0 && p.lifecycle === "waiting") {
        p.lifecycle = "active";
      }
      return p;
    }

    case "epoch_advanced": {
      const newEpoch = payload.new_epoch;
      if (typeof newEpoch !== "number" || !Number.isInteger(newEpoch) || newEpoch < 0) {
        fail("RT-FOLD-003", "epoch_advanced.payload.new_epoch must be a non-negative integer");
      }
      if (core.epoch !== prior.epoch) {
        fail("RT-FOLD-003", `epoch_advanced event epoch ${core.epoch} != process epoch ${prior.epoch}`);
      }
      const previousEpoch = payload.previous_epoch;
      if (previousEpoch !== prior.epoch) {
        fail("RT-FOLD-003", `epoch_advanced.previous_epoch ${String(previousEpoch)} does not match current epoch ${prior.epoch}`);
      }
      if (newEpoch <= prior.epoch) {
        fail("RT-FOLD-003", "epoch_advanced.new_epoch must be greater than previous_epoch");
      }
      p.epoch = newEpoch;
      // §10.1: leases bound to older epochs are invalid after advancement.
      return p;
    }

    case "effect_committed": {
      const key = requirePayloadString(core.type, payload, "effect_key");
      // §17.2: an already-committed effect_key MUST NOT repeat the effect.
      if (p.effects[key] !== undefined) fail("RT-FOLD-003", `duplicate effect_key: ${key} (§17.2)`);
      p.effects[key] = {
        state: "committed",
        responsibility_id: requirePayloadString(core.type, payload, "responsibility_id"),
        operation: requirePayloadString(core.type, payload, "operation"),
        provider: requirePayloadString(core.type, payload, "provider"),
      };
      return p;
    }

    case "effect_reconciled": {
      const key = requirePayloadString(core.type, payload, "effect_key");
      const outcome = requirePayloadString(core.type, payload, "outcome");
      if (!["completed", "not_completed", "still_unknown", "compensated"].includes(outcome)) {
        fail("RT-FOLD-003", `effect_reconciled.payload.outcome not in pinned set: ${outcome}`);
      }
      // §40: reconciliation inspects what already exists; it cannot
      // reconcile an effect this runtime never recorded.
      const effect = mustHave(p.effects, key, core.type);
      effect.reconciliation = outcome as ReconciliationOutcome;
      // Map the reconciliation determination onto the §17.1 pinned lifecycle.
      effect.state = (
        { completed: "committed", not_completed: "rejected", still_unknown: "unknown", compensated: "compensated" } as const
      )[outcome as ReconciliationOutcome];
      return p;
    }

    case "artifact_admitted": {
      const id = requirePayloadString(core.type, payload, "artifact_id");
      p.artifacts[id] = {
        digest: requirePayloadString(core.type, payload, "digest"),
        media: requirePayloadString(core.type, payload, "media"),
        size: typeof payload.size === "number" ? payload.size : fail("RT-FOLD-003", "artifact size must be a number"),
        storage_ref: requirePayloadString(core.type, payload, "storage_ref"),
        responsibility_id: requirePayloadString(core.type, payload, "responsibility_id"),
      };
      return p;
    }

    case "observation_recorded": {
      const id = requirePayloadString(core.type, payload, "observation_id");
      p.observations[id] = {
        responsibility_id: typeof payload.responsibility_id === "string" ? payload.responsibility_id : null,
        subject: requirePayloadString(core.type, payload, "subject"),
        result_digest: requirePayloadString(core.type, payload, "result_digest"),
        observed_at: requirePayloadString(core.type, payload, "observed_at"),
      };
      return p;
    }

    case "process_completed": {
      p.lifecycle = "terminal";
      p.terminal = { outcome: "completed", result: payload.result as JsonValue | undefined };
      return p;
    }

    case "process_failed": {
      p.lifecycle = "terminal";
      p.terminal = { outcome: "failed", reason: requirePayloadString(core.type, payload, "reason") };
      return p;
    }

    case "authority_key_introduced": {
      // RT-KEY-002: rotation enters canonical history.
      const keyDigest = requirePayloadString(core.type, payload, "key_digest");
      if (!keyDigest.startsWith("sha256:")) fail("RT-FOLD-003", "key_digest must be sha256:<hex>");
      if (p.authority_keys.some((k) => k.key_digest === keyDigest)) {
        fail("RT-FOLD-005", `duplicate introduced key_digest: ${keyDigest}`);
      }
      const validFromSeq = payload.valid_from_seq;
      if (typeof validFromSeq !== "number" || !Number.isInteger(validFromSeq) || validFromSeq < 0) {
        fail("RT-FOLD-003", "valid_from_seq must be a non-negative integer");
      }
      p.authority_keys.push({
        key_id: requirePayloadString(core.type, payload, "key_id"),
        key_digest: keyDigest,
        valid_from_seq: validFromSeq,
      });
      return p;
    }

    default: {
      // §7.4: Kind-defined types — opaque unless Kind supplies fold semantics.
      if (kindFold !== undefined) return kindFold(core, p);
      return p;
    }
  }
}

export type KindFoldExtension = (core: EventCore, projection: Projection) => Projection;

type ReconciliationOutcome = "completed" | "not_completed" | "still_unknown" | "compensated";

function mustHave<T>(record: Record<string, T>, id: string, type: string): T {
  const v = record[id];
  if (v === undefined) fail("RT-FOLD-001", `${type} references unknown id: ${id}`);
  return v;
}

/** §12: replay — fold an entire verified history from genesis. */
export function foldHistory(cores: EventCore[], kindFold?: KindFoldExtension): Projection {
  let projection: Projection | null = null;
  for (const core of cores) {
    projection = foldEvent(core, projection, kindFold);
  }
  if (projection === null) fail("RT-FOLD-001", "empty history has no projection");
  return projection;
}
