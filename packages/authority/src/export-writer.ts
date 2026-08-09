import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { canonicalize, digestJson, type JsonValue } from "@prt/jcs-digest";
import { EXPORT_FORMAT, type ExportManifest, type KeyBundleEntry } from "@prt/export-v1";
import type { ProcessAuthority } from "./authority.js";

function fail(section: string, msg: string): never {
  throw new Error(`${section}: ${msg}`);
}

export interface ExportOptions {
  kindBytes?: Uint8Array;
  kindReference?: string;
  keys: KeyBundleEntry[];
}

/**
 * §56.3: write a canonical, self-contained export bundle.
 * Lives with the reference runtime (it needs the store); the canonical
 * VERIFIER lives in @prt/export-v1 and depends on nothing here.
 */
export function writeBundle(
  authority: ProcessAuthority,
  processId: string,
  destDir: string,
  options: ExportOptions,
): ExportManifest & { digest: string } {
  const events = authority.listEvents(processId);
  if (events.length === 0) fail("§56", "cannot export a process with no events");
  const receipts = authority.listReceipts(processId);
  const head = authority.getHead(processId);
  const projection = authority.loadProjection(processId);

  if (fs.existsSync(destDir)) fail("§56.3", `destination already exists: ${destDir}`);
  for (const sub of ["receipts", "artifacts", "evidence", "keys", "kind"]) {
    fs.mkdirSync(path.join(destDir, sub), { recursive: true });
  }

  const lines = events.map((e) => canonicalize(e as unknown as JsonValue));
  fs.writeFileSync(path.join(destDir, "events.jsonl"), lines.join("\n") + "\n", "utf8");

  for (const r of receipts) {
    fs.writeFileSync(path.join(destDir, "receipts", `${r.receipt_id}.json`), canonicalize(r as unknown as JsonValue), "utf8");
  }

  fs.writeFileSync(path.join(destDir, "keys", "keys.json"), canonicalize(options.keys as unknown as JsonValue), "utf8");

  let kindReference: string | null = options.kindReference ?? null;
  if (options.kindBytes !== undefined) {
    fs.writeFileSync(path.join(destDir, "kind", "kind.bin"), options.kindBytes);
    kindReference = "kind/kind.bin";
  }

  const genesis = events[0];
  const kindDigest = genesis?.payload.kind_digest;
  if (typeof kindDigest !== "string") fail("§56", "genesis payload missing kind_digest");

  const keyInventory = options.keys.map((k) => ({
    key_id: k.key_id,
    key_digest: "sha256:" + createHash("sha256").update(Buffer.from(k.public_key, "base64url")).digest("hex"),
    valid_from_seq: k.valid_from_seq,
  }));

  const manifest: ExportManifest = {
    format: EXPORT_FORMAT,
    process_id: processId,
    kind_digest: kindDigest,
    head,
    epoch: projection.epoch,
    event_count: events.length,
    event_digests: events.map((e) => e.digest),
    receipt_refs: receipts.map((r) => `receipts/${r.receipt_id}.json`),
    artifact_inventory: [],
    evidence_inventory: [],
    key_inventory: keyInventory,
    schema_versions: ["event/v1"],
    kind_reference: kindReference,
  };

  const { digest } = digestJson(manifest as unknown as JsonValue);
  const finalManifest = { ...manifest, digest };
  fs.writeFileSync(path.join(destDir, "manifest.json"), canonicalize(finalManifest as unknown as JsonValue), "utf8");

  return { ...manifest, digest };
}
