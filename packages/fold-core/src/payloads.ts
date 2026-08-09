/**
 * §7.6 / RT-FOLD-003: closed payload member sets per core event type.
 * A payload containing members outside the set is rejected at commit time.
 */

export const PAYLOAD_MEMBERS: Readonly<Record<string, readonly string[]>> = {
  // authority_key_digest anchors the signing authority's public key in
  // genesis, so exported histories can be authenticated offline (§56.3).
  process_created: ["kind_digest", "subject", "authority_key_digest"],
  responsibility_issued: [
    "responsibility_id",
    "role",
    "objective",
    "subject",
    "inputs",
    "required_outputs",
    "permitted_proposals",
    "forbidden_actions",
    "capabilities",
    "deadline",
    "acceptance",
  ],
  responsibility_accepted: ["responsibility_id", "actor"],
  responsibility_submitted: ["responsibility_id", "actor", "result", "artifact_refs", "evidence_refs"],
  responsibility_completed: ["responsibility_id"],
  responsibility_revoked: ["responsibility_id", "reason"],
  grant_issued: [
    "grant_id",
    "responsibility_id",
    "actor",
    "action",
    "subject",
    "bounds",
    "expected_head",
    "epoch",
    "expiry",
  ],
  grant_revoked: ["grant_id"],
  wait_entered: ["wait_id", "condition"],
  wait_resolved: ["wait_id", "resolution"],
  epoch_advanced: ["previous_epoch", "new_epoch", "reason", "invalidated_leases"],
  effect_committed: ["effect_key", "responsibility_id", "operation", "provider", "receipt_ref"],
  effect_reconciled: ["effect_key", "prior_state", "outcome"],
  artifact_admitted: ["artifact_id", "digest", "media", "size", "storage_ref", "responsibility_id"],
  observation_recorded: ["observation_id", "responsibility_id", "subject", "result_digest", "observed_at"],
  process_completed: ["terminal_node", "result", "evidence_refs"],
  process_failed: ["reason", "evidence_refs"],
  authority_key_introduced: ["key_id", "key_digest", "valid_from_seq"],
};

export const CORE_EVENT_TYPES = Object.keys(PAYLOAD_MEMBERS);

export function assertClosedPayload(type: string, payload: Record<string, unknown>): void {
  const members = PAYLOAD_MEMBERS[type];
  if (members === undefined) {
    // §7.4: Kind-defined types are opaque to the runtime fold.
    return;
  }
  for (const k of Object.keys(payload)) {
    if (!members.includes(k)) {
      throw new Error(`RT-FOLD-003: payload member outside closed set for ${type}: ${k}`);
    }
  }
}

export function requirePayloadString(type: string, payload: Record<string, unknown>, member: string): string {
  const v = payload[member];
  if (typeof v !== "string" || v.length === 0) {
    throw new Error(`RT-FOLD-003: ${type}.payload.${member} must be a non-empty string`);
  }
  return v;
}
