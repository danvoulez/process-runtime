import { digestJson, type JsonValue } from "@prt/jcs-digest";
import {
  CORE_MEMBERS,
  memberSetExactly,
  isRfc3339Utc,
  type EventCore,
} from "./types.js";

function fail(rt: string, msg: string): never {
  throw new Error(`${rt}: ${msg}`);
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isNonNegativeInteger(v: unknown): v is number {
  return typeof v === "number" && Number.isInteger(v) && v >= 0;
}

/**
 * RT-EVENT-001 + RT-EVENT-004 (core side).
 * Validates that an unknown value is a conforming event core:
 * exactly the RT-EVENT-001 member set, correctly typed.
 */
export function buildEventCore(input: unknown): EventCore {
  if (!isPlainObject(input)) fail("RT-EVENT-001", "event core must be a JSON object");
  if (!memberSetExactly(input, CORE_MEMBERS)) {
    fail("RT-EVENT-004", `event core must contain exactly: ${CORE_MEMBERS.join(", ")}`);
  }
  if (input.schema !== "event/v1") fail("RT-EVENT-001", 'schema must be "event/v1"');
  if (typeof input.process_id !== "string" || input.process_id.length === 0) {
    fail("RT-EVENT-001", "process_id must be a non-empty string");
  }
  if (!isNonNegativeInteger(input.sequence)) fail("RT-EVENT-001", "sequence must be a non-negative integer");
  if (input.previous !== null && typeof input.previous !== "string") {
    fail("RT-EVENT-001", "previous must be a digest string or null");
  }
  if (input.previous !== null && !(input.previous as string).startsWith("sha256:")) {
    fail("RT-EVENT-001", "previous digest must use sha256:<hex> representation");
  }
  if (!isNonNegativeInteger(input.epoch)) fail("RT-EVENT-001", "epoch must be a non-negative integer");
  if (typeof input.type !== "string" || input.type.length === 0) fail("RT-EVENT-001", "type must be a non-empty string");
  if (!isPlainObject(input.payload)) fail("RT-EVENT-001", "payload must be an object");
  if (input.causation !== null && !isPlainObject(input.causation)) {
    fail("RT-EVENT-001", "causation must be an object or null");
  }
  if (typeof input.authority !== "string" || input.authority.length === 0) {
    fail("RT-EVENT-001", "authority must be a non-empty string");
  }
  if (typeof input.committed_at !== "string" || !isRfc3339Utc(input.committed_at)) {
    fail("RT-EVENT-001", "committed_at must be an RFC 3339 UTC timestamp");
  }
  return input as unknown as EventCore;
}

/**
 * RT-EVENT-002: digest derivation.
 * digest_bytes = SHA-256(JCS(event_core)); digest = "sha256:" + lowercase hex.
 */
export function computeEventDigest(core: EventCore): { bytes: Uint8Array; digest: string } {
  const { bytes, digest } = digestJson(core as unknown as Record<string, JsonValue> as JsonValue);
  return { bytes, digest };
}
