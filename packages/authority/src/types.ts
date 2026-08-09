import type { JsonValue } from "@prt/jcs-digest";
import type { CanonicalEvent, EventCore } from "@prt/event-v1";
import type { CanonicalCommand } from "@prt/command-digest";
import type { Projection } from "@prt/fold-core";

/** §15 Commit Receipt. States narrowly what it proves: this commit occurred. */
export interface CommitReceipt {
  receipt_id: string;
  process_id: string;
  command_id: string;
  head_before: string;
  head_after: string;
  event_digest: string;
  epoch: number;
  result: "committed" | "duplicate";
  committed_at: string;
}

/** §30 Invocation Lease. Permission to attempt advancement — not commit authority. */
export interface Lease {
  lease_id: string;
  process_id: string;
  worker_id: string;
  epoch: number;
  head_at_issue: string;
  issued_at: string;
  expires_at: string;
}

export interface ProcessMeta {
  process_id: string;
  kind_digest: string;
  created_at: string;
  epoch: number;
  current_head: string;
  sequence: number;
}

export type RejectionCode =
  | "STALE_HEAD"
  | "STALE_EPOCH"
  | "IDEMPOTENCY_CONFLICT"
  | "DUPLICATE_PROCESS"
  | "UNKNOWN_PROCESS"
  | "LEASE_EXPIRED"
  | "LEASE_FENCED"
  | "LEASE_UNKNOWN"
  | "VALIDATION_FAILED";

/** §8/§10/§16: rejections are explicit, never silent reinterpretation. */
export class CommitRejection extends Error {
  readonly code: RejectionCode;
  constructor(code: RejectionCode, message: string) {
    super(`${code}: ${message}`);
    this.code = code;
  }
}

export interface CreateProcessCommand {
  command_id: string;
  process_id: string;
  kind_digest: string;
  epoch?: number;
  subject?: Record<string, JsonValue>;
}

export type { CanonicalCommand, CanonicalEvent, EventCore, Projection };
