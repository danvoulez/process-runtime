import type { CanonicalEvent } from "@prt/event-v1";

/**
 * @prt/driver-contract — the RuntimeDriver contract, standalone.
 *
 * This package is the ONLY thing a third-party runtime must read to be
 * judged by the conformance harness. It carries no implementation,
 * no storage, and no reference-runtime dependency of any kind.
 *
 * Reading order for a foreign implementation:
 *   1. canonical specification (docs/spec/PROCESS_RUNTIME_SPEC.md)
 *   2. this contract
 *   3. conformance documentation (docs/CONFORMANCE.md)
 */

export interface CreateProcessInput {
  command_id: string;
  process_id: string;
  kind_digest: string;
  epoch?: number;
  subject?: Record<string, unknown>;
}

export interface RuntimeDriver {
  readonly name: string;

  /** Optional capabilities; groups requiring them are SKIPped, not failed. */
  readonly capabilities: {
    verify: boolean;
    exportBundle: boolean;
  };

  /** §6 — commit genesis. Returns the commit receipt. Throws on rejection. */
  createProcess(cmd: CreateProcessInput): unknown | Promise<unknown>;

  /** §13 — the commit path. Returns the commit receipt. Throws on rejection. */
  propose(command: unknown): unknown | Promise<unknown>;

  /** §8 — the current canonical head. */
  getHead(processId: string): string | Promise<string>;

  /**
   * §11 — the folded projection. The harness asserts the CANONICAL
   * projection contract structurally (lifecycle, epoch, responsibilities,
   * grants, waits, effects, terminal), per §7.6.
   */
  loadProjection(processId: string): unknown | Promise<unknown>;

  /** §49 — canonical events in sequence order. */
  listEvents(processId: string): CanonicalEvent[] | Promise<CanonicalEvent[]>;

  /** §15 — the receipt recorded for a command_id, or undefined. */
  getReceipt(processId: string, commandId: string): unknown | Promise<unknown>;

  /** §30 — claim the single Invocation Lease. Throws when fenced. */
  claimInvocation(processId: string, workerId: string, ttlMs?: number): unknown | Promise<unknown>;

  /** §30.2/§30.3 — complete under a valid lease. Throws when invalid. */
  completeInvocation(lease: unknown): unknown | Promise<unknown>;

  /** §12 — replay + structural verification. Requires capabilities.verify. */
  verifyProcess?(processId: string): { status: string; detail?: string } | Promise<{ status: string; detail?: string }>;

  /**
   * §56.3 — write a canonical, SELF-CONTAINED export bundle.
   * The runtime owns its authority key material; the bundle must carry
   * everything offline verification needs (RT-EXPORT-001, §7.7).
   * Requires capabilities.exportBundle.
   */
  exportBundle?(processId: string, dir: string): unknown | Promise<unknown>;

  close?(): unknown | Promise<unknown>;
}

export interface DriverFactory {
  /** A driver over FRESH, empty storage. */
  fresh(): RuntimeDriver | Promise<RuntimeDriver>;
  /** A driver over the SAME storage the given driver used (restart). */
  reopen(driver: RuntimeDriver): RuntimeDriver | Promise<RuntimeDriver>;
}

// ------------------------------------------------------------- helpers

/** Narrow a structural projection view for vector assertions (§7.6). */
export interface ProjectionView {
  lifecycle: string;
  epoch: number;
  responsibilities: Record<string, { status?: string; actor?: string | null }>;
  grants: Record<string, unknown>;
  waits: Record<string, unknown>;
  effects: Record<string, { state?: string }>;
  terminal: unknown;
}

export function asProjection(p: unknown): ProjectionView {
  if (typeof p !== "object" || p === null) throw new Error("driver returned a non-object projection");
  const v = p as ProjectionView;
  if (typeof v.lifecycle !== "string") throw new Error("projection missing lifecycle (§11)");
  if (typeof v.epoch !== "number") throw new Error("projection missing epoch (§11)");
  return v;
}

export function asReceipt(r: unknown): { event_digest: string; result?: string; head_after?: string } {
  if (typeof r !== "object" || r === null) throw new Error("driver returned a non-object receipt");
  const v = r as { event_digest?: string; result?: string; head_after?: string };
  if (typeof v.event_digest !== "string") throw new Error("receipt missing event_digest (§15)");
  return v as { event_digest: string; result?: string; head_after?: string };
}
