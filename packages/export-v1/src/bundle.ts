import type { JsonValue } from "@prt/jcs-digest";
import type { CanonicalEvent } from "@prt/event-v1";

export const EXPORT_FORMAT = "process-export/v1";

/** §56.3 / RT-EXPORT-001: immutable key material for offline verification. */
export interface KeyBundleEntry {
  key_id: string;
  /** base64url-encoded SPKI DER public key. */
  public_key: string;
  valid_from_seq: number;
}

/** Manifest without its own digest (digest input). */
export interface ExportManifest {
  format: typeof EXPORT_FORMAT;
  process_id: string;
  kind_digest: string;
  head: string;
  epoch: number;
  event_count: number;
  event_digests: string[];
  receipt_refs: string[];
  artifact_inventory: JsonValue[];
  evidence_inventory: JsonValue[];
  /** Binds the FULL key material: key_id + digest of the DER bytes. */
  key_inventory: Array<{ key_id: string; key_digest: string; valid_from_seq: number }>;
  schema_versions: string[];
  kind_reference: string | null;
}

export interface BundleVerificationCheck {
  name: string;
  ok: boolean;
  detail?: string;
}

export interface BundleVerificationReport {
  status: "VALID" | "INVALID";
  checks: BundleVerificationCheck[];
}

/** §57: receipt structural members the verifier can check offline. */
export const RECEIPT_MEMBERS = [
  "receipt_id",
  "process_id",
  "command_id",
  "head_before",
  "head_after",
  "event_digest",
  "epoch",
  "result",
  "committed_at",
] as const;

export type { CanonicalEvent };
