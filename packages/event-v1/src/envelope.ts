import { buildEventCore, computeEventDigest } from "./core.js";
import {
  CORE_MEMBERS,
  SIGNATURE_MEMBERS,
  memberSetExactly,
  type CanonicalEvent,
  type SignatureObject,
} from "./types.js";

function fail(rt: string, msg: string): never {
  throw new Error(`${rt}: ${msg}`);
}

/**
 * RT-EVENT-003: seal a core into a canonical envelope.
 * The digest covers the core only; signature is an envelope member.
 */
export function sealEvent(coreInput: unknown, signature?: SignatureObject): CanonicalEvent {
  const core = buildEventCore(coreInput);
  const { digest } = computeEventDigest(core);
  const envelope: CanonicalEvent = { ...core, digest };
  if (signature !== undefined) {
    assertSignatureObjectShape(signature);
    envelope.signature = signature;
  }
  return envelope;
}

/** RT-SIG-002: closed signature object shape. */
export function assertSignatureObjectShape(sig: unknown): asserts sig is SignatureObject {
  if (typeof sig !== "object" || sig === null || Array.isArray(sig)) {
    fail("RT-SIG-002", "signature must be an object");
  }
  const s = sig as Record<string, unknown>;
  if (!memberSetExactly(s, SIGNATURE_MEMBERS)) {
    fail("RT-SIG-002", `signature object must contain exactly: ${SIGNATURE_MEMBERS.join(", ")}`);
  }
  if (s.algorithm !== "ed25519") fail("RT-SIG-002", 'signature.algorithm must be "ed25519"');
  if (typeof s.key_id !== "string" || s.key_id.length === 0) fail("RT-SIG-002", "signature.key_id must be a non-empty string");
  if (typeof s.value !== "string" || s.value.length === 0) fail("RT-SIG-002", "signature.value must be base64url string");
}

/**
 * RT-EVENT-004 (envelope side): an envelope may contain only
 * core members + "digest" + optional "signature".
 */
export function assertEnvelopeMembersClosed(env: Record<string, unknown>): void {
  const allowed = new Set<string>([...CORE_MEMBERS, "digest", "signature"]);
  for (const k of Object.keys(env)) {
    if (!allowed.has(k)) fail("RT-EVENT-004", `envelope member not allowed: ${k}`);
  }
  if (!Object.prototype.hasOwnProperty.call(env, "digest")) {
    fail("RT-EVENT-003", "envelope must contain digest");
  }
}

/**
 * Full structural verification of a canonical event envelope:
 * closed members, valid core, digest recomputation (RT-EVENT-002).
 */
export function verifyEventEnvelope(input: unknown): CanonicalEvent {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    fail("RT-EVENT-003", "canonical event must be a JSON object");
  }
  const env = input as Record<string, unknown>;
  assertEnvelopeMembersClosed(env);
  // Strip envelope-only members before core validation (RT-EVENT-004 core side).
  const coreInput = Object.fromEntries(CORE_MEMBERS.map((m) => [m, env[m]]));
  const core = buildEventCore(coreInput);
  const { digest } = computeEventDigest(core);
  if (env.digest !== digest) fail("RT-EVENT-002", "digest recomputation mismatch");
  if (env.signature !== undefined) assertSignatureObjectShape(env.signature);
  return env as unknown as CanonicalEvent;
}
