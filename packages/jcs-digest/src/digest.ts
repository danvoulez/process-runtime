import { createHash } from "node:crypto";
import { canonicalize, type JsonValue } from "./jcs.js";

/** Raw 32-byte SHA-256 output. This is what Ed25519 signs (RT-SIG-001). */
export function sha256Bytes(canonicalUtf8: string): Uint8Array {
  return createHash("sha256").update(canonicalUtf8, "utf8").digest();
}

/** Canonical digest representation: "sha256:" + lowercase hex. */
export function sha256Digest(canonicalUtf8: string): string {
  return "sha256:" + Buffer.from(sha256Bytes(canonicalUtf8)).toString("hex");
}

/** Canonicalize a JSON value, then digest it. The spec's standard pair. */
export function digestJson(value: JsonValue): { canonical: string; bytes: Uint8Array; digest: string } {
  const canonical = canonicalize(value);
  const bytes = sha256Bytes(canonical);
  return { canonical, bytes, digest: "sha256:" + Buffer.from(bytes).toString("hex") };
}

/** Recompute a digest string for verification paths. */
export function digestMatches(value: JsonValue, expectedDigest: string): boolean {
  return digestJson(value).digest === expectedDigest;
}
