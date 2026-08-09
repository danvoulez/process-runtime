import type { JsonValue } from "@prt/jcs-digest";

/**
 * §11 folded projection. Derived state — never authoritative.
 * Must be discardable and rebuildable from canonical events alone.
 */

export interface ResponsibilityState {
  status: "issued" | "accepted" | "submitted" | "completed" | "revoked";
  role: string;
  objective: string;
  actor: string | null;
  payload: Record<string, JsonValue>;
}

export interface GrantState {
  responsibility_id: string;
  actor: string;
  action: string;
  subject: string;
  epoch: number;
  expiry: string;
}

export interface WaitState {
  condition: Record<string, JsonValue>;
}

/** §17.1: the pinned effect lifecycle. */
export type EffectLifecycleState =
  | "proposed"
  | "approved"
  | "executing"
  | "committed"
  | "rejected"
  | "unknown"
  | "compensated";

export interface EffectState {
  state: EffectLifecycleState;
  /** §40: what reconciliation determined about the external world. */
  reconciliation?: "completed" | "not_completed" | "still_unknown" | "compensated";
  responsibility_id: string;
  operation: string;
  provider: string;
}

export interface ArtifactRef {
  digest: string;
  media: string;
  size: number;
  storage_ref: string;
  responsibility_id: string;
}

export interface ObservationRef {
  responsibility_id: string | null;
  subject: string;
  result_digest: string;
  observed_at: string;
}

/** §7.7: an anchored authority key, introduced by genesis or rotation. */
export interface AuthorityKeyAnchor {
  /** null for the genesis anchor (RT-KEY-001), which binds no key_id. */
  key_id: string | null;
  key_digest: string;
  valid_from_seq: number;
}

export interface Projection {
  lifecycle: "active" | "waiting" | "terminal";
  epoch: number;
  responsibilities: Record<string, ResponsibilityState>;
  grants: Record<string, GrantState>;
  waits: Record<string, WaitState>;
  effects: Record<string, EffectState>;
  artifacts: Record<string, ArtifactRef>;
  observations: Record<string, ObservationRef>;
  authority_keys: AuthorityKeyAnchor[];
  terminal: { outcome: "completed" | "failed"; result?: JsonValue; reason?: string } | null;
}

export function emptyProjection(epoch: number): Projection {
  return {
    lifecycle: "active",
    epoch,
    responsibilities: {},
    grants: {},
    waits: {},
    effects: {},
    artifacts: {},
    observations: {},
    authority_keys: [],
    terminal: null,
  };
}
