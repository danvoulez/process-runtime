import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { generateAuthorityKeypair, signEventCore } from "@prt/event-v1";
import { ProcessAuthority, writeBundle } from "@prt/authority";
import { canonicalize, digestJson, type JsonValue } from "@prt/jcs-digest";
import { verifyBundle, type KeyBundleEntry } from "@prt/export-v1";

const keypair = generateAuthorityKeypair("authority/export-test");
const KIND = "sha256:" + "k".repeat(64);

function tmp(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "prt-export-"));
}

function buildProcess(): { auth: ProcessAuthority; dbPath: string } {
  const dbPath = path.join(tmp(), "proc.db");
  const auth = new ProcessAuthority(dbPath, { keypair, authorityId: "authority/export-test" });
  auth.createProcess({ command_id: "gen", process_id: "proc_exp", kind_digest: KIND });
  const head1 = auth.getHead("proc_exp");
  auth.propose({
    command_id: "c1", process_id: "proc_exp", expected_head: head1, epoch: 1,
    responsibility_id: "resp/test", actor: "agent:test", action: "responsibility_issued",
    payload: { responsibility_id: "r1", role: "worker", objective: "ship", acceptance: {} },
    evidence: null, effect_key: null,
  });
  const head2 = auth.getHead("proc_exp");
  auth.propose({
    command_id: "c2", process_id: "proc_exp", expected_head: head2, epoch: 1,
    responsibility_id: "r1", actor: "agent:test", action: "responsibility_completed",
    payload: { responsibility_id: "r1" },
    evidence: null, effect_key: null,
  });
  const head3 = auth.getHead("proc_exp");
  auth.propose({
    command_id: "c3", process_id: "proc_exp", expected_head: head3, epoch: 1,
    responsibility_id: "resp/test", actor: "agent:test", action: "process_completed",
    payload: { terminal_node: "end", result: { shipped: true } },
    evidence: null, effect_key: null,
  });
  return { auth, dbPath };
}

function keys(): KeyBundleEntry[] {
  return [{ key_id: keypair.keyId, public_key: Buffer.from(keypair.publicKeyDer).toString("base64url"), valid_from_seq: 0 }];
}

test("§56.3/§57: exported bundle verifies fully offline", () => {
  const { auth } = buildProcess();
  const dir = path.join(tmp(), "export");
  const manifest = writeBundle(auth, "proc_exp", dir, { keys: keys() });
  auth.close();

  assert.match(manifest.digest, /^sha256:[0-9a-f]{64}$/);
  const report = verifyBundle(dir);
  const failures = report.checks.filter((c) => !c.ok);
  assert.deepEqual(failures, [], failures.map((f) => `${f.name}: ${f.detail ?? ""}`).join("; "));
  assert.equal(report.status, "VALID");
});

test("§57: tampered event in the bundle is detected", () => {
  const { auth } = buildProcess();
  const dir = path.join(tmp(), "export");
  writeBundle(auth, "proc_exp", dir, { keys: keys() });
  auth.close();

  const eventsPath = path.join(dir, "events.jsonl");
  const lines = fs.readFileSync(eventsPath, "utf8").trim().split("\n");
  const tampered = JSON.parse(lines[1] as string) as Record<string, unknown>;
  tampered.authority = "mallory";
  lines[1] = JSON.stringify(tampered);
  fs.writeFileSync(eventsPath, lines.join("\n") + "\n");

  const report = verifyBundle(dir);
  assert.equal(report.status, "INVALID");
});

test("RT-EXPORT-001: missing key material makes signatures unverifiable", () => {
  const { auth } = buildProcess();
  const dir = path.join(tmp(), "export");
  writeBundle(auth, "proc_exp", dir, { keys: [] }); // no keys bundled
  auth.close();

  const report = verifyBundle(dir);
  assert.equal(report.status, "INVALID");
  const keyCheck = report.checks.find((c) => c.name.includes("key_id"));
  assert.equal(keyCheck?.ok, false);
});

test("§56.3: tampered manifest detected by self-digest", () => {
  const { auth } = buildProcess();
  const dir = path.join(tmp(), "export");
  writeBundle(auth, "proc_exp", dir, { keys: keys() });
  auth.close();

  const manifestPath = path.join(dir, "manifest.json");
  const m = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
  m.head = "sha256:" + "0".repeat(64);
  fs.writeFileSync(manifestPath, canonicalize(m as unknown as JsonValue));

  const report = verifyBundle(dir);
  assert.equal(report.status, "INVALID");
  assert.equal(report.checks.find((c) => c.name === "manifest digest recomputation")?.ok, false);
});

test("§57: CLI prt verify exits 0 on VALID and 1 on INVALID", () => {
  const { auth } = buildProcess();
  const dir = path.join(tmp(), "export");
  writeBundle(auth, "proc_exp", dir, { keys: keys() });
  auth.close();

  const compiled = path.resolve(".tsc/packages/export-v1/src/cli.js");

  const okOut = execFileSync(process.execPath, [compiled, "verify", dir], { encoding: "utf8" });
  assert.match(okOut, /VALID/);

  fs.writeFileSync(path.join(dir, "events.jsonl"), "garbage\n");
  let code = 0;
  try {
    execFileSync(process.execPath, [compiled, "verify", dir], { encoding: "utf8", stdio: "pipe" });
  } catch (e) {
    code = (e as { status: number }).status;
  }
  assert.equal(code, 1);
});

test("§56.3: bundle embeds pinned Kind bytes when provided — and verifies them against kind_digest", () => {
  // Process whose kind_digest IS the digest of the embedded bytes.
  const kindBytes = new TextEncoder().encode("process-kind-law-v1");
  const kindDigest = "sha256:" + createHash("sha256").update(kindBytes).digest("hex");
  const dbPath = path.join(tmp(), "proc.db");
  const auth = new ProcessAuthority(dbPath, { keypair, authorityId: "authority/export-test" });
  auth.createProcess({ command_id: "gen", process_id: "proc_kind", kind_digest: kindDigest });

  const dir = path.join(tmp(), "export");
  writeBundle(auth, "proc_kind", dir, { keys: keys(), kindBytes });
  auth.close();

  assert.ok(fs.existsSync(path.join(dir, "kind", "kind.bin")));
  const report = verifyBundle(dir);
  assert.equal(report.status, "VALID", JSON.stringify(report.checks.filter((c) => !c.ok)));
});

test("§56: swapped Kind bytes detected — existence is not enough", () => {
  const kindBytes = new TextEncoder().encode("process-kind-law-v1");
  const kindDigest = "sha256:" + createHash("sha256").update(kindBytes).digest("hex");
  const dbPath = path.join(tmp(), "proc.db");
  const auth = new ProcessAuthority(dbPath, { keypair, authorityId: "authority/export-test" });
  auth.createProcess({ command_id: "gen", process_id: "proc_kind", kind_digest: kindDigest });

  const dir = path.join(tmp(), "export");
  writeBundle(auth, "proc_kind", dir, { keys: keys(), kindBytes });
  auth.close();

  fs.writeFileSync(path.join(dir, "kind", "kind.bin"), "different kind bytes");
  const report = verifyBundle(dir);
  assert.equal(report.status, "INVALID");
  assert.equal(report.checks.find((c) => c.name === "embedded Kind bytes match kind_digest")?.ok, false);
});

test("§56.3: unexpected extra file breaks the single canonical reading", () => {
  const { auth } = buildProcess();
  const dir = path.join(tmp(), "export");
  writeBundle(auth, "proc_exp", dir, { keys: keys() });
  auth.close();

  fs.writeFileSync(path.join(dir, "smuggled.txt"), "not part of the bundle");
  const report = verifyBundle(dir);
  assert.equal(report.status, "INVALID");
  assert.equal(report.checks.find((c) => c.name.includes("closed bundle inventory"))?.ok, false);
});

test("§56.3: manifest path reference escaping the bundle root is rejected", () => {
  const { auth } = buildProcess();
  const dir = path.join(tmp(), "export");
  writeBundle(auth, "proc_exp", dir, { keys: keys() });
  auth.close();

  const manifestPath = path.join(dir, "manifest.json");
  const m = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
  (m.receipt_refs as string[]).push("../../etc/passwd");
  // Re-seal the tampered manifest digest so only confinement can catch it.
  const core = { ...m } as Record<string, unknown>;
  delete core.digest;
  const sealed = { ...core, digest: digestJson(core as unknown as JsonValue).digest };
  fs.writeFileSync(manifestPath, canonicalize(sealed as unknown as JsonValue));

  const report = verifyBundle(dir);
  assert.equal(report.status, "INVALID");
  assert.equal(report.checks.find((c) => c.name.includes("confined"))?.ok, false);
});

test("trust anchor: key substitution + full re-signing attack is detected", () => {
  const { auth } = buildProcess();
  const dir = path.join(tmp(), "export");
  writeBundle(auth, "proc_exp", dir, { keys: keys() });
  auth.close();

  // Attacker: generates own keypair, re-signs EVERY event (digests unchanged,
  // since signatures are envelope members), swaps keys.json, and re-seals the
  // manifest including new key_inventory digests and the manifest self-digest.
  const attacker = generateAuthorityKeypair("authority/export-test");
  const eventsPath = path.join(dir, "events.jsonl");
  const lines = fs.readFileSync(eventsPath, "utf8").trim().split("\n");
  const reSigned = lines.map((l) => {
    const env = JSON.parse(l) as Record<string, unknown>;
    const core: Record<string, unknown> = {};
    for (const k of ["schema", "process_id", "sequence", "previous", "epoch", "type", "payload", "causation", "authority", "committed_at"]) {
      core[k] = env[k];
    }
    const sig = signEventCore(core as never, attacker);
    return JSON.stringify({ ...env, signature: sig });
  });
  fs.writeFileSync(eventsPath, reSigned.join("\n") + "\n");

  const attackerDerB64 = Buffer.from(attacker.publicKeyDer).toString("base64url");
  fs.writeFileSync(path.join(dir, "keys", "keys.json"), canonicalize([{ key_id: attacker.keyId, public_key: attackerDerB64, valid_from_seq: 0 }] as unknown as JsonValue));

  const manifestPath = path.join(dir, "manifest.json");
  const m = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
  m.key_inventory = [{
    key_id: attacker.keyId,
    key_digest: "sha256:" + createHash("sha256").update(Buffer.from(attacker.publicKeyDer)).digest("hex"),
    valid_from_seq: 0,
  }];
  const coreManifest = { ...m } as Record<string, unknown>;
  delete coreManifest.digest;
  const sealedManifest = { ...coreManifest, digest: digestJson(coreManifest as unknown as JsonValue).digest };
  fs.writeFileSync(manifestPath, canonicalize(sealedManifest as unknown as JsonValue));

  const report = verifyBundle(dir);
  assert.equal(report.status, "INVALID");
  assert.equal(report.checks.find((c) => c.name.includes("anchored in canonical history"))?.ok, false);
});
