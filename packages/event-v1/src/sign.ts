import {
  createPublicKey,
  generateKeyPairSync,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from "node:crypto";
import { computeEventDigest } from "./core.js";
import { CORE_MEMBERS, type CanonicalEvent, type EventCore, type SignatureObject } from "./types.js";

/** The digest always covers the core only — never envelope members. */
function coreOf(env: CanonicalEvent): EventCore {
  return Object.fromEntries(CORE_MEMBERS.map((m) => [m, env[m]])) as unknown as EventCore;
}

export interface AuthorityKeypair {
  keyId: string;
  privateKey: KeyObject;
  /** SPKI DER bytes — the portable public representation for keys/ bundles. */
  publicKeyDer: Uint8Array;
}

export function generateAuthorityKeypair(keyId: string): AuthorityKeypair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    keyId,
    privateKey,
    publicKeyDer: publicKey.export({ format: "der", type: "spki" }),
  };
}

export function publicKeyFromDer(der: Uint8Array): KeyObject {
  return createPublicKey({ key: Buffer.from(der), format: "der", type: "spki" });
}

/**
 * RT-SIG-001: Ed25519 signs the raw 32-byte SHA-256 digest bytes.
 * Never the hex string, never the envelope serialization.
 */
export function signDigestBytes(digestBytes: Uint8Array, privateKey: KeyObject): Uint8Array {
  return edSign(null, Buffer.from(digestBytes), privateKey);
}

export function makeSignatureObject(
  keyId: string,
  digestBytes: Uint8Array,
  privateKey: KeyObject,
): SignatureObject {
  const sig = signDigestBytes(digestBytes, privateKey);
  return { algorithm: "ed25519", key_id: keyId, value: Buffer.from(sig).toString("base64url") };
}

/** Sign a core: returns the signature object to seal into the envelope. */
export function signEventCore(core: EventCore, keypair: AuthorityKeypair): SignatureObject {
  const { bytes } = computeEventDigest(core);
  return makeSignatureObject(keypair.keyId, bytes, keypair.privateKey);
}

export type KeyResolver = (keyId: string) => Uint8Array | undefined;

/**
 * Verify an envelope's signature against the raw digest bytes (RT-SIG-001).
 * Historical key material resolution is the caller's job (§7.5, RT-EXPORT-001).
 */
export function verifyEventSignature(env: CanonicalEvent, resolveKey: KeyResolver): boolean {
  if (env.signature === undefined) return false;
  const pubDer = resolveKey(env.signature.key_id);
  if (pubDer === undefined) return false;
  const { bytes } = computeEventDigest(coreOf(env));
  const publicKey = publicKeyFromDer(pubDer);
  const sigBytes = Buffer.from(env.signature.value, "base64url");
  return edVerify(null, Buffer.from(bytes), publicKey, sigBytes);
}
