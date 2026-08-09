import { createHash, randomUUID } from "node:crypto";
import { canonicalize, digestJson, type JsonValue } from "@prt/jcs-digest";
import {
  CORE_MEMBERS,
  sealEvent,
  signEventCore,
  verifyChain,
  verifyEventSignature,
  type AuthorityKeypair,
  type CanonicalEvent,
  type EventCore,
} from "@prt/event-v1";
import { buildCanonicalCommand, requestDigest, type CanonicalCommand } from "@prt/command-digest";
import { foldEvent, foldHistory, type KindFoldExtension, type Projection } from "@prt/fold-core";
import { openStore, type Store } from "./store.js";
import {
  CommitRejection,
  type CommitReceipt,
  type CreateProcessCommand,
  type Lease,
  type ProcessMeta,
} from "./types.js";

export interface AuthorityOptions {
  /** Signs every commit (§7.5). The reference authority signs by default. */
  keypair: AuthorityKeypair;
  /** Value of the event `authority` field (RT-EVENT-001). */
  authorityId: string;
  /** §35 evidence-obligation hook, evaluated before terminal/consequential commits. */
  evidenceValidator?: (core: EventCore, projection: Projection) => void;
  /** §7.4 Kind-supplied fold extension for Kind-defined event types. */
  kindFold?: KindFoldExtension;
  /** Injectable clock for deterministic tests. */
  clock?: () => string;
}

interface ProcessRow {
  process_id: string;
  kind_digest: string;
  created_at: string;
  epoch: number;
  current_head: string;
  sequence: number;
  projection: string;
}

export interface VerificationReport {
  status: "VALID" | "INVALID_HISTORY" | "DEFECTIVE_PROJECTION";
  detail?: string;
  head: string;
  epoch: number;
}

/**
 * §9/§13/§48: the Process Authority — the only component permitted to
 * convert a proposal into an institutional fact.
 *
 * Single-writer semantics (§9) come from one synchronous SQLite
 * connection per Process database: two successful commits cannot claim
 * the same previous head because the second observes a stale head
 * inside the same serial transaction stream.
 */
export class ProcessAuthority {
  private readonly db: Store;
  private readonly keypair: AuthorityKeypair;
  private readonly authorityId: string;
  private readonly evidenceValidator?: (core: EventCore, projection: Projection) => void;
  private readonly kindFold?: KindFoldExtension;
  private readonly clock: () => string;
  /** sha256:<hex> of the authority's SPKI DER public key. */
  private readonly authorityKeyDigest: string;

  constructor(dbPath: string, options: AuthorityOptions) {
    this.db = openStore(dbPath);
    this.keypair = options.keypair;
    this.authorityId = options.authorityId;
    this.evidenceValidator = options.evidenceValidator;
    this.kindFold = options.kindFold;
    this.clock = options.clock ?? (() => new Date().toISOString());
    this.authorityKeyDigest =
      "sha256:" + createHash("sha256").update(Buffer.from(options.keypair.publicKeyDer)).digest("hex");
  }

  close(): void {
    this.db.close();
  }

  // ---------------------------------------------------------------- reads

  private row(processId: string): ProcessRow {
    const r = this.db.prepare("SELECT * FROM processes WHERE process_id = ?").get(processId) as ProcessRow | undefined;
    if (r === undefined) throw new CommitRejection("UNKNOWN_PROCESS", `no such process: ${processId}`);
    return r;
  }

  private meta(processId: string): ProcessMeta {
    const { projection: _p, ...m } = this.row(processId);
    return m;
  }

  loadProjection(processId: string): Projection {
    return JSON.parse(this.row(processId).projection) as Projection;
  }

  getHead(processId: string): string {
    return this.meta(processId).current_head;
  }

  listEvents(processId: string): CanonicalEvent[] {
    this.row(processId);
    const rows = this.db
      .prepare("SELECT event FROM canonical_events WHERE process_id = ? ORDER BY sequence ASC")
      .all(processId) as Array<{ event: string }>;
    return rows.map((r) => JSON.parse(r.event) as CanonicalEvent);
  }

  getReceipt(processId: string, commandId: string): CommitReceipt | undefined {
    const r = this.db
      .prepare("SELECT receipt FROM receipts WHERE process_id = ? AND command_id = ?")
      .get(processId, commandId) as { receipt: string } | undefined;
    return r === undefined ? undefined : (JSON.parse(r.receipt) as CommitReceipt);
  }

  listReceipts(processId: string): CommitReceipt[] {
    this.row(processId);
    const rows = this.db
      .prepare("SELECT receipt FROM receipts WHERE process_id = ? ORDER BY rowid ASC")
      .all(processId) as Array<{ receipt: string }>;
    return rows.map((r) => JSON.parse(r.receipt) as CommitReceipt);
  }

  // ---------------------------------------------------------------- §6 creation

  createProcess(command: CreateProcessCommand): CommitReceipt {
    if (!command.kind_digest.startsWith("sha256:")) {
      throw new CommitRejection("VALIDATION_FAILED", "kind_digest must be sha256:<hex>");
    }
    const reqDigest = digestJson(command as unknown as JsonValue).digest;

    // §16.1: retried creation returns the original genesis receipt.
    const prior = this.db
      .prepare("SELECT request_digest, receipt FROM receipts WHERE process_id = ? AND command_id = ?")
      .get(command.process_id, command.command_id) as { request_digest: string; receipt: string } | undefined;
    if (prior !== undefined) {
      if (prior.request_digest === reqDigest) {
        return { ...(JSON.parse(prior.receipt) as CommitReceipt), result: "duplicate" };
      }
      throw new CommitRejection("IDEMPOTENCY_CONFLICT", `command_id ${command.command_id} reused with different payload`);
    }
    const existing = this.db.prepare("SELECT process_id FROM processes WHERE process_id = ?").get(command.process_id);
    if (existing !== undefined) throw new CommitRejection("DUPLICATE_PROCESS", `process_id in use: ${command.process_id}`);

    const epoch = command.epoch ?? 1;
    const payload: Record<string, JsonValue> = { kind_digest: command.kind_digest };
    if (command.subject !== undefined) payload.subject = command.subject;
    // Trust anchor (§56.3): the signing authority's key digest enters the
    // genesis event, so exported histories can be authenticated offline
    // against something the bundle cannot substitute.
    payload.authority_key_digest = this.authorityKeyDigest;

    const core: EventCore = {
      schema: "event/v1",
      process_id: command.process_id,
      sequence: 0,
      previous: null,
      epoch,
      type: "process_created",
      payload,
      causation: { command_id: command.command_id },
      authority: this.authorityId,
      committed_at: this.clock(),
    };

    const projection = foldEvent(core, null, this.kindFold);
    const envelope = sealEvent(core, signEventCore(core, this.keypair));
    const receipt = this.makeReceipt(command.process_id, command.command_id, "null", envelope);

    // §14: genesis is one indivisible institutional operation.
    this.db.transaction(() => {
      this.db
        .prepare(
          "INSERT INTO processes (process_id, kind_digest, created_at, epoch, current_head, sequence, projection) VALUES (?,?,?,?,?,?,?)",
        )
        .run(command.process_id, command.kind_digest, core.committed_at, projection.epoch, envelope.digest, 0, JSON.stringify(projection));
      this.insertEvent(command.process_id, envelope);
      this.insertReceipt(command.process_id, command.command_id, reqDigest, receipt);
    })();

    return receipt;
  }

  // ---------------------------------------------------------------- §13 commit path

  propose(commandInput: unknown): CommitReceipt {
    const command = buildCanonicalCommand(commandInput);
    const reqDigest = requestDigest(command);

    // better-sqlite3 transactions are synchronous and serial (§9).
    return this.db.transaction((): CommitReceipt => {
      const meta = this.meta(command.process_id);
      const storedProjection = JSON.parse(this.row(command.process_id).projection) as Projection;

      // §16.1 / RT-IDEM-001: replay or conflict before any other work.
      const prior = this.db
        .prepare("SELECT request_digest, receipt FROM receipts WHERE process_id = ? AND command_id = ?")
        .get(command.process_id, command.command_id) as { request_digest: string; receipt: string } | undefined;
      if (prior !== undefined) {
        if (prior.request_digest === reqDigest) {
          const receipt = JSON.parse(prior.receipt) as CommitReceipt;
          return { ...receipt, result: "duplicate" };
        }
        throw new CommitRejection("IDEMPOTENCY_CONFLICT", `command_id ${command.command_id} reused with different payload`);
      }

      // §8: the optimistic concurrency boundary. Never reinterpret stale proposals.
      if (command.expected_head !== meta.current_head) {
        throw new CommitRejection(
          "STALE_HEAD",
          `expected_head ${command.expected_head} != current_head ${meta.current_head}`,
        );
      }

      // §10: fencing epoch.
      if (command.epoch !== meta.epoch) {
        throw new CommitRejection("STALE_EPOCH", `command epoch ${command.epoch} != process epoch ${meta.epoch}`);
      }

      const core: EventCore = {
        schema: "event/v1",
        process_id: command.process_id,
        sequence: meta.sequence + 1,
        previous: meta.current_head,
        epoch: meta.epoch,
        type: command.action,
        payload: command.payload,
        causation: { command_id: command.command_id },
        authority: this.authorityId,
        committed_at: this.clock(),
      };

      // §51: terminal proposals face the pinned gate before anything else.
      if (command.action === "process_completed" || command.action === "process_failed") {
        this.terminalGate(storedProjection);
      }

      // §35: evidence obligations hook.
      this.evidenceValidator?.(core, storedProjection);

      // §7.6 dry-run fold: closed payloads, wait conditions, terminal
      // exclusivity, epoch advancement rules — all validated here.
      const nextProjection = foldEvent(core, storedProjection, this.kindFold);

      const envelope = sealEvent(core, signEventCore(core, this.keypair));
      const receipt = this.makeReceipt(command.process_id, command.command_id, meta.current_head, envelope);

      // §14: one indivisible institutional operation.
      this.insertEvent(command.process_id, envelope);
      this.db
        .prepare("UPDATE processes SET current_head = ?, sequence = ?, epoch = ?, projection = ? WHERE process_id = ?")
        .run(envelope.digest, core.sequence, nextProjection.epoch, JSON.stringify(nextProjection), command.process_id);
      this.insertReceipt(command.process_id, command.command_id, reqDigest, receipt);

      return receipt;
    })();
  }

  /** §51 default gate: nothing unresolved may remain. Kind law may tighten further. */
  private terminalGate(projection: Projection): void {
    const active = Object.keys(projection.responsibilities);
    if (active.length > 0) {
      throw new CommitRejection("VALIDATION_FAILED", `unresolved responsibilities block terminal commit: ${active.join(", ")}`);
    }
    const waits = Object.keys(projection.waits);
    if (waits.length > 0) {
      throw new CommitRejection("VALIDATION_FAILED", `open waits block terminal commit: ${waits.join(", ")}`);
    }
  }

  // ---------------------------------------------------------------- §10.1 epoch

  /** Convenience: epoch advancement is an ordinary authorized commit (§10.1). */
  advanceEpoch(commandId: string, processId: string, reason: string): CommitReceipt {
    const meta = this.meta(processId);
    return this.propose({
      command_id: commandId,
      process_id: processId,
      expected_head: meta.current_head,
      epoch: meta.epoch,
      responsibility_id: "authority/epoch",
      actor: this.authorityId,
      action: "epoch_advanced",
      payload: { previous_epoch: meta.epoch, new_epoch: meta.epoch + 1, reason },
      evidence: null,
      effect_key: null,
    });
  }

  // ---------------------------------------------------------------- §30 leases

  claimInvocation(processId: string, workerId: string, ttlMs = 60_000): Lease {
    const meta = this.meta(processId);
    const nowIso = this.clock();
    const now = Date.parse(nowIso);

    const lease: Lease = {
      lease_id: `lease_${randomUUID()}`,
      process_id: processId,
      worker_id: workerId,
      epoch: meta.epoch,
      head_at_issue: meta.current_head,
      issued_at: nowIso,
      expires_at: new Date(now + ttlMs).toISOString(),
    };

    // §30/§60: single-owner acquisition as ONE atomic statement.
    // The UNIQUE(process_id) constraint plus the conditional UPSERT makes
    // concurrent claims across connections race-safe: SQLite serializes
    // writers, and the second claim updates nothing when a live lease
    // exists. Expired leases are reclaimed atomically (§54).
    const result = this.db
      .prepare(
        `INSERT INTO leases (lease_id, process_id, worker_id, epoch, head_at_issue, issued_at, expires_at)
         VALUES (@lease_id, @process_id, @worker_id, @epoch, @head_at_issue, @issued_at, @expires_at)
         ON CONFLICT(process_id) DO UPDATE SET
           lease_id = excluded.lease_id,
           worker_id = excluded.worker_id,
           epoch = excluded.epoch,
           head_at_issue = excluded.head_at_issue,
           issued_at = excluded.issued_at,
           expires_at = excluded.expires_at
         WHERE leases.expires_at <= @now`,
      )
      .run({ ...lease, now: nowIso });

    if (result.changes === 0) {
      const holder = this.db
        .prepare("SELECT lease_id, worker_id FROM leases WHERE process_id = ?")
        .get(processId) as { lease_id: string; worker_id: string };
      throw new CommitRejection(
        "LEASE_FENCED",
        `process ${processId} already owned by ${holder.worker_id} (${holder.lease_id})`,
      );
    }
    return lease;
  }

  /** §30.2/§30.3: expired or epoch-fenced leases cannot complete. */
  completeInvocation(lease: Lease): void {
    const stored = this.db.prepare("SELECT * FROM leases WHERE lease_id = ?").get(lease.lease_id) as Lease | undefined;
    if (stored === undefined) throw new CommitRejection("LEASE_UNKNOWN", lease.lease_id);
    if (stored.worker_id !== lease.worker_id) {
      throw new CommitRejection("LEASE_FENCED", `lease ${lease.lease_id} belongs to ${stored.worker_id}, not ${lease.worker_id}`);
    }
    if (Date.parse(this.clock()) > Date.parse(stored.expires_at)) {
      throw new CommitRejection("LEASE_EXPIRED", lease.lease_id);
    }
    const meta = this.meta(stored.process_id);
    if (stored.epoch !== meta.epoch) {
      throw new CommitRejection("LEASE_FENCED", `lease epoch ${stored.epoch} fenced by process epoch ${meta.epoch}`);
    }
    this.db.prepare("DELETE FROM leases WHERE lease_id = ?").run(lease.lease_id);
  }

  // ---------------------------------------------------------------- §12 verification

  verifyProcess(processId: string): VerificationReport {
    const meta = this.meta(processId);
    const envelopes = this.listEvents(processId);
    try {
      verifyChain(envelopes);
    } catch (e) {
      return { status: "INVALID_HISTORY", detail: (e as Error).message, head: meta.current_head, epoch: meta.epoch };
    }
    // §7.5: hash integrity is not authenticity. Signatures made with this
    // authority's key MUST verify; a swapped or corrupted signature is
    // corruption even though the digest chain is untouched.
    for (const env of envelopes) {
      if (env.signature !== undefined && env.signature.key_id === this.keypair.keyId) {
        const ok = verifyEventSignature(env, (id) => (id === this.keypair.keyId ? this.keypair.publicKeyDer : undefined));
        if (!ok) {
          return { status: "INVALID_HISTORY", detail: `signature invalid at sequence ${env.sequence}`, head: meta.current_head, epoch: meta.epoch };
        }
      }
    }
    const cores = envelopes.map(
      (env) => Object.fromEntries(CORE_MEMBERS.map((m) => [m, env[m]])) as unknown as EventCore,
    );
    const rebuilt = foldHistory(cores, this.kindFold);
    const stored = this.loadProjection(processId);
    // §12: if replay disagrees, the stored projection is defective; history governs.
    if (canonicalize(rebuilt as unknown as JsonValue) !== canonicalize(stored as unknown as JsonValue)) {
      return { status: "DEFECTIVE_PROJECTION", detail: "stored projection does not match replay", head: meta.current_head, epoch: meta.epoch };
    }
    const head = envelopes[envelopes.length - 1]?.digest;
    if (head !== meta.current_head) {
      return { status: "INVALID_HISTORY", detail: "stored head does not match final event", head: meta.current_head, epoch: meta.epoch };
    }
    return { status: "VALID", head: meta.current_head, epoch: meta.epoch };
  }

  // ---------------------------------------------------------------- internals

  private insertEvent(processId: string, envelope: CanonicalEvent): void {
    this.db
      .prepare("INSERT INTO canonical_events (process_id, sequence, digest, event) VALUES (?,?,?,?)")
      .run(processId, envelope.sequence, envelope.digest, JSON.stringify(envelope));
  }

  private insertReceipt(processId: string, commandId: string, reqDigest: string, receipt: CommitReceipt): void {
    this.db
      .prepare("INSERT INTO receipts (process_id, command_id, request_digest, receipt) VALUES (?,?,?,?)")
      .run(processId, commandId, reqDigest, JSON.stringify(receipt));
  }

  private makeReceipt(processId: string, commandId: string, headBefore: string, envelope: CanonicalEvent): CommitReceipt {
    return {
      receipt_id: `rcpt_${randomUUID()}`,
      process_id: processId,
      command_id: commandId,
      head_before: headBefore,
      head_after: envelope.digest,
      event_digest: envelope.digest,
      epoch: envelope.epoch,
      result: "committed",
      committed_at: envelope.committed_at,
    };
  }
}
