import type { JsonValue } from "@prt/jcs-digest";

/** RT-EVENT-001: the event core — no digest, no signature. */
export interface EventCore {
  schema: "event/v1";
  process_id: string;
  sequence: number;
  previous: string | null;
  epoch: number;
  type: string;
  payload: Record<string, JsonValue>;
  causation: Record<string, JsonValue> | null;
  authority: string;
  committed_at: string;
}

/** §7.5 / RT-SIG-002: closed signature object. */
export interface SignatureObject {
  algorithm: "ed25519";
  key_id: string;
  value: string; // base64url-encoded Ed25519 signature bytes
}

/** RT-EVENT-003: canonical envelope = core + digest + signature?. */
export interface CanonicalEvent extends EventCore {
  digest: string;
  signature?: SignatureObject;
}

export const CORE_MEMBERS = [
  "schema",
  "process_id",
  "sequence",
  "previous",
  "epoch",
  "type",
  "payload",
  "causation",
  "authority",
  "committed_at",
] as const;

export const ENVELOPE_EXTRA_MEMBERS = ["digest", "signature"] as const;

export const SIGNATURE_MEMBERS = ["algorithm", "key_id", "value"] as const;

export function memberSetExactly(obj: Record<string, unknown>, members: readonly string[]): boolean {
  const keys = Object.keys(obj);
  if (keys.length !== members.length) return false;
  return members.every((m) => Object.prototype.hasOwnProperty.call(obj, m));
}

const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

export function isRfc3339Utc(s: string): boolean {
  return RFC3339_UTC.test(s) && !Number.isNaN(Date.parse(s));
}
