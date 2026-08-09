import { isRfc3339Utc } from "@prt/event-v1";

/**
 * §26.1 / RT-WAIT-001: typed, closed Wait condition union.
 * A condition containing members outside the set defined for its kind
 * is rejected at commit time.
 */

const CONDITION_MEMBERS: Readonly<Record<string, readonly string[]>> = {
  human_response: ["kind", "responder", "resume_schema"],
  approval: ["kind", "approver", "resume_schema"],
  timer: ["kind", "target_time"],
  webhook: ["kind", "webhook_identity"],
  evidence: ["kind", "required_evidence"],
  process: ["kind", "target_process_id", "condition"],
  kind_defined: ["kind", "type", "parameters"],
};

export const CONDITION_KINDS = Object.keys(CONDITION_MEMBERS);

function fail(msg: string): never {
  throw new Error(`RT-WAIT-001: ${msg}`);
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function requireString(cond: Record<string, unknown>, member: string): void {
  const v = cond[member];
  if (typeof v !== "string" || v.length === 0) fail(`${member} must be a non-empty string`);
}

/** resume_schema: immutable digest string or content-addressed reference. */
function checkSchemaRef(v: unknown, member: string): void {
  if (typeof v === "string" && v.startsWith("sha256:")) return;
  if (isPlainObject(v) && typeof v.digest === "string" && v.digest.startsWith("sha256:")) return;
  fail(`${member} must be a sha256:<hex> digest or a content-addressed reference`);
}

export function validateWaitCondition(input: unknown): void {
  if (!isPlainObject(input)) fail("condition must be an object");
  const kind = input.kind;
  if (typeof kind !== "string" || !(kind in CONDITION_MEMBERS)) {
    fail(`unknown condition kind: ${String(kind)}`);
  }
  const members = CONDITION_MEMBERS[kind] as readonly string[];
  for (const k of Object.keys(input)) {
    if (!members.includes(k)) fail(`member outside set for kind ${kind}: ${k}`);
  }
  for (const m of members) {
    if (!Object.prototype.hasOwnProperty.call(input, m)) fail(`kind ${kind} missing member: ${m}`);
  }

  switch (kind) {
    case "human_response":
      requireString(input, "responder");
      checkSchemaRef(input.resume_schema, "resume_schema");
      break;
    case "approval":
      requireString(input, "approver");
      checkSchemaRef(input.resume_schema, "resume_schema");
      break;
    case "timer":
      if (typeof input.target_time !== "string" || !isRfc3339Utc(input.target_time)) {
        fail("target_time must be an RFC 3339 UTC timestamp");
      }
      break;
    case "webhook":
      requireString(input, "webhook_identity");
      break;
    case "evidence": {
      const req = input.required_evidence;
      if (!Array.isArray(req)) fail("required_evidence must be an array");
      for (const item of req) {
        if (!isPlainObject(item)) fail("required_evidence items must be objects");
        if (typeof item.type !== "string" || item.type.length === 0) fail("evidence descriptor needs type");
        if (item.digest === undefined && item.schema === undefined) {
          fail("evidence descriptor needs digest or schema");
        }
      }
      break;
    }
    case "process":
      requireString(input, "target_process_id");
      validateWaitCondition(input.condition); // nested same closed union
      break;
    case "kind_defined":
      requireString(input, "type");
      if (!isPlainObject(input.parameters)) fail("parameters must be an object");
      break;
  }
}
