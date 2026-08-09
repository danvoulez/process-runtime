import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { generateAuthorityKeypair, type AuthorityKeypair, type CanonicalEvent } from "@prt/event-v1";
import type { KeyBundleEntry } from "@prt/export-v1";
import type { DriverFactory, RuntimeDriver } from "@prt/driver-contract";
import { ProcessAuthority } from "./authority.js";
import { writeBundle } from "./export-writer.js";

/**
 * Reference adapter: wraps ProcessAuthority as a conformance RuntimeDriver.
 *
 * This adapter lives in the reference runtime — NOT in the harness.
 * Third parties write an equivalent adapter for their own storage and
 * execution machinery and run the identical vectors.
 */
export class AuthorityDriver implements RuntimeDriver {
  readonly name = "@prt/authority (reference, SQLite)";
  readonly capabilities = { verify: true, exportBundle: true };

  private readonly auth: ProcessAuthority;
  readonly dbPath: string;
  private readonly keypair: AuthorityKeypair;

  constructor(dbPath: string, keypair: AuthorityKeypair) {
    this.dbPath = dbPath;
    this.keypair = keypair;
    this.auth = new ProcessAuthority(dbPath, { keypair, authorityId: "authority/conformance" });
  }

  exportKeys(): KeyBundleEntry[] {
    return [
      {
        key_id: this.keypair.keyId,
        public_key: Buffer.from(this.keypair.publicKeyDer).toString("base64url"),
        valid_from_seq: 0,
      },
    ];
  }

  createProcess(cmd: Parameters<ProcessAuthority["createProcess"]>[0]): unknown {
    return this.auth.createProcess(cmd);
  }

  propose(command: unknown): unknown {
    return this.auth.propose(command);
  }

  getHead(processId: string): string {
    return this.auth.getHead(processId);
  }

  loadProjection(processId: string): unknown {
    return this.auth.loadProjection(processId);
  }

  listEvents(processId: string): CanonicalEvent[] {
    return this.auth.listEvents(processId);
  }

  getReceipt(processId: string, commandId: string): unknown {
    return this.auth.getReceipt(processId, commandId);
  }

  claimInvocation(processId: string, workerId: string, ttlMs?: number): unknown {
    return this.auth.claimInvocation(processId, workerId, ttlMs);
  }

  completeInvocation(lease: Parameters<ProcessAuthority["completeInvocation"]>[0]): void {
    this.auth.completeInvocation(lease);
  }

  verifyProcess(processId: string): { status: string; detail?: string } {
    const r = this.auth.verifyProcess(processId);
    return r.detail !== undefined ? { status: r.status, detail: r.detail } : { status: r.status };
  }

  /** §56.3: self-contained bundle — the runtime supplies its own keys. */
  exportBundle(processId: string, dir: string): void {
    writeBundle(this.auth, processId, dir, { keys: this.exportKeys() });
  }

  close(): void {
    this.auth.close();
  }
}

const sharedKeypair = generateAuthorityKeypair("authority/conformance");

/** DriverFactory for the reference implementation (fresh temp storage per driver). */
export const referenceDriverFactory: DriverFactory = {
  fresh(): RuntimeDriver {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "prt-driver-"));
    return new AuthorityDriver(path.join(dir, "runtime.db"), sharedKeypair);
  },
  reopen(driver: RuntimeDriver): RuntimeDriver {
    const d = driver as AuthorityDriver;
    d.close();
    return new AuthorityDriver(d.dbPath, sharedKeypair);
  },
};
