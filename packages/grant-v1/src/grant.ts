import { verify as edVerify, sign as edSign, type KeyObject } from "node:crypto";
import { canonicalize, digestJson, type JsonValue } from "@prt/jcs-digest";
import { publicKeyFromDer, type AuthorityKeypair } from "@prt/event-v1";

function fail(rt: string, msg: string): never {
  throw new Error(`${rt}: ${msg}`);
}

/** §20 / §20.1: the closed claims set. */
export const GRANT_CLAIMS_MEMBERS = [
  "grant_id",
  "process_id",
  "responsibility_id",
  "actor",
  "action",
  "subject",
  "bounds",
  "expected_head",
  "epoch",
  "expiry",
] as const;

export interface GrantClaims {
  grant_id: string;
  process_id: string;
  responsibility_id: string;
  actor: string;
  action: string;
  subject: string;
  bounds: Record<string, JsonValue>;
  expected_head: string;
  epoch: number;
  expiry: string; // RFC 3339 UTC
}

/** RT-GRANT-001: grant/v1 canonical object. */
export interface GrantObject {
  schema: "grant/v1";
  claims: GrantClaims;
  algorithm: "ed25519";
  key_id: string;
  signature: string; // base64url
}

export const GRANT_OBJECT_MEMBERS = ["schema", "claims", "algorithm", "key_id", "signature"] as const;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function memberSetExactly(obj: Record<string, unknown>, members: readonly string[]): boolean {
  const keys = Object.keys(obj);
  if (keys.length !== members.length) return false;
  return members.every((m) => Object.prototype.hasOwnProperty.call(obj, m));
}

export function assertValidClaims(input: unknown): asserts input is GrantClaims {
  if (!isPlainObject(input)) fail("RT-GRANT-001", "claims must be an object");
  if (!memberSetExactly(input, GRANT_CLAIMS_MEMBERS)) {
    fail("RT-GRANT-001", `claims must contain exactly: ${GRANT_CLAIMS_MEMBERS.join(", ")}`);
  }
  for (const m of ["grant_id", "process_id", "responsibility_id", "actor", "action", "subject"] as const) {
    if (typeof input[m] !== "string" || (input[m] as string).length === 0) {
      fail("RT-GRANT-001", `claims.${m} must be a non-empty string`);
    }
  }
  if (!isPlainObject(input.bounds)) fail("RT-GRANT-001", "claims.bounds must be an object");
  if (typeof input.expected_head !== "string" || !input.expected_head.startsWith("sha256:")) {
    fail("RT-GRANT-001", "claims.expected_head must be a sha256:<hex> digest");
  }
  if (typeof input.epoch !== "number" || !Number.isInteger(input.epoch) || input.epoch < 0) {
    fail("RT-GRANT-001", "claims.epoch must be a non-negative integer");
  }
  if (typeof input.expiry !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(input.expiry)) {
    fail("RT-GRANT-001", "claims.expiry must be an RFC 3339 UTC timestamp");
  }
}

export function assertValidGrantObject(input: unknown): asserts input is GrantObject {
  if (!isPlainObject(input)) fail("RT-GRANT-001", "grant must be an object");
  if (!memberSetExactly(input, GRANT_OBJECT_MEMBERS)) {
    fail("RT-GRANT-001", `grant object must contain exactly: ${GRANT_OBJECT_MEMBERS.join(", ")}`);
  }
  if (input.schema !== "grant/v1") fail("RT-GRANT-001", 'grant.schema must be "grant/v1"');
  if (input.algorithm !== "ed25519") fail("RT-GRANT-001", 'grant.algorithm must be "ed25519"');
  if (typeof input.key_id !== "string" || input.key_id.length === 0) {
    fail("RT-GRANT-001", "grant.key_id must be a non-empty string");
  }
  if (typeof input.signature !== "string" || input.signature.length === 0) {
    fail("RT-GRANT-001", "grant.signature must be a base64url string");
  }
  assertValidClaims(input.claims);
}

/**
 * RT-GRANT-001: signature = Ed25519 over SHA-256(JCS(claims)) raw bytes.
 */
export function grantDigestBytes(claims: GrantClaims): Uint8Array {
  return digestJson(claims as unknown as JsonValue).bytes;
}

/** Mint a sealed grant (Process Authority side). */
export function mintGrant(claimsInput: unknown, authority: AuthorityKeypair): GrantObject {
  assertValidClaims(claimsInput);
  const sig = edSign(null, Buffer.from(grantDigestBytes(claimsInput)), authority.privateKey);
  return {
    schema: "grant/v1",
    claims: claimsInput,
    algorithm: "ed25519",
    key_id: authority.keyId,
    signature: Buffer.from(sig).toString("base64url"),
  };
}

/** Outer token encoding: base64url(JCS(grant_object)). */
export function encodeGrantToken(grant: GrantObject): string {
  return Buffer.from(canonicalize(grant as unknown as JsonValue), "utf8").toString("base64url");
}

export function decodeGrantToken(token: string): GrantObject {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(token, "base64url").toString("utf8"));
  } catch {
    fail("RT-GRANT-001", "token is not base64url-encoded JSON");
  }
  assertValidGrantObject(parsed);
  // Round-trip purity: the token must be the canonical encoding of the object.
  if (encodeGrantToken(parsed) !== token) {
    fail("RT-GRANT-001", "token encoding is not canonical base64url(JCS(grant))");
  }
  return parsed;
}

export type GrantKeyResolver = (keyId: string) => Uint8Array | undefined;

/**
 * Capability Gateway verification (§20.1, §37.1):
 * structure + authority signature. Claim evaluation against current
 * Process state (§21) happens above this layer.
 */
export function verifyGrantSignature(grant: GrantObject, resolveKey: GrantKeyResolver): boolean {
  const pubDer = resolveKey(grant.key_id);
  if (pubDer === undefined) return false;
  const publicKey = publicKeyFromDer(pubDer);
  return edVerify(null, Buffer.from(grantDigestBytes(grant.claims)), publicKey, Buffer.from(grant.signature, "base64url"));
}
