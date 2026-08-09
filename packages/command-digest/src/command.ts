import { digestJson, type JsonValue } from "@prt/jcs-digest";

function fail(rt: string, msg: string): never {
  throw new Error(`${rt}: ${msg}`);
}

/**
 * §48.1: the consequential command contract.
 * Required members; evidence and effect_key where applicable.
 */
export const COMMAND_MEMBERS = [
  "command_id",
  "process_id",
  "expected_head",
  "epoch",
  "responsibility_id",
  "actor",
  "action",
  "payload",
  "evidence",
  "effect_key",
] as const;

export interface CanonicalCommand {
  command_id: string;
  process_id: string;
  expected_head: string;
  epoch: number;
  responsibility_id: string;
  actor: string;
  action: string;
  payload: Record<string, JsonValue>;
  evidence: Record<string, JsonValue> | null;
  effect_key: string | null;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function buildCanonicalCommand(input: unknown): CanonicalCommand {
  if (!isPlainObject(input)) fail("RT-IDEM-001", "command must be an object");
  for (const m of COMMAND_MEMBERS) {
    if (!Object.prototype.hasOwnProperty.call(input, m)) {
      fail("RT-IDEM-001", `command missing member: ${m}`);
    }
  }
  // Closed member set: the runtime rejects what the law did not name.
  for (const k of Object.keys(input)) {
    if (!(COMMAND_MEMBERS as readonly string[]).includes(k)) {
      fail("RT-IDEM-001", `command member outside closed set: ${k}`);
    }
  }
  const c = input as Record<string, unknown>;
  for (const m of ["command_id", "process_id", "responsibility_id", "actor", "action"] as const) {
    if (typeof c[m] !== "string" || (c[m] as string).length === 0) {
      fail("RT-IDEM-001", `command.${m} must be a non-empty string`);
    }
  }
  if (typeof c.expected_head !== "string" || !c.expected_head.startsWith("sha256:")) {
    fail("RT-IDEM-001", "command.expected_head must be a sha256:<hex> digest");
  }
  if (typeof c.epoch !== "number" || !Number.isInteger(c.epoch) || c.epoch < 0) {
    fail("RT-IDEM-001", "command.epoch must be a non-negative integer");
  }
  if (!isPlainObject(c.payload)) fail("RT-IDEM-001", "command.payload must be an object");
  if (c.evidence !== null && !isPlainObject(c.evidence)) fail("RT-IDEM-001", "command.evidence must be an object or null");
  if (c.effect_key !== null && typeof c.effect_key !== "string") {
    fail("RT-IDEM-001", "command.effect_key must be a string or null");
  }
  return c as unknown as CanonicalCommand;
}

/**
 * RT-IDEM-001: payload sameness is a digest comparison.
 * request_digest = "sha256:" + lowercase hex(SHA-256(JCS(canonical command))).
 */
export function requestDigest(command: CanonicalCommand): string {
  return digestJson(command as unknown as JsonValue).digest;
}

/**
 * Idempotency record (§16.1): what the authority stores per command_id.
 */
export interface IdempotencyRecord {
  command_id: string;
  request_digest: string;
  receipt: unknown;
}

export type IdempotencyDecision =
  | { kind: "execute" }
  | { kind: "replay"; receipt: unknown }
  | { kind: "conflict" };

/** §16.1: same id + same digest → replay; same id + different digest → conflict. */
export function decideIdempotency(record: IdempotencyRecord | undefined, command: CanonicalCommand): IdempotencyDecision {
  if (record === undefined) return { kind: "execute" };
  const digest = requestDigest(command);
  if (record.request_digest === digest) return { kind: "replay", receipt: record.receipt };
  return { kind: "conflict" };
}
