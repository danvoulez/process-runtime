/**
 * Harness self-test: the standalone §60 harness runs against the
 * reference adapter. Third-party drivers run the identical vectors.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { runConformance } from "@prt/conformance";
import { referenceDriverFactory } from "@prt/authority";

test("§60 harness: reference runtime is conforming under its own vectors", async () => {
  const report = await runConformance(referenceDriverFactory);
  const failures = report.results.filter((r) => r.status === "FAIL");
  assert.deepEqual(
    failures.map((f) => `${f.group}: ${f.name} — ${f.detail ?? ""}`),
    [],
    "reference runtime must pass every vector",
  );
  assert.equal(report.fail, 0);
  assert.ok(report.pass >= 10);
  assert.equal(report.conforming, true);
});

test("§60 harness: a deliberately broken driver fails the vectors", async () => {
  // A "runtime" that accepts stale heads must be caught.
  const broken = {
    name: "broken-runtime",
    capabilities: { verify: false, exportBundle: false },
    state: { head: "sha256:" + "0".repeat(64), seq: 0 },
    createProcess() { return { event_digest: this.state.head }; },
    propose(cmd: { expected_head: string }) {
      // BUG: never checks expected_head — always commits.
      this.state.seq++;
      this.state.head = "sha256:" + String(this.state.seq).padStart(64, "0");
      return { event_digest: this.state.head };
    },
    getHead() { return this.state.head; },
    loadProjection() { return { lifecycle: "active", epoch: 1, responsibilities: {}, grants: {}, waits: {}, effects: {}, terminal: null }; },
    listEvents() { return Array.from({ length: this.state.seq + 1 }, () => ({}) as never); },
    getReceipt() { return { event_digest: this.state.head }; },
    claimInvocation() { return {}; },
    completeInvocation() { /* accepts everything */ },
  };
  const factory = { fresh: () => broken, reopen: () => broken };
  const report = await runConformance(factory);
  assert.equal(report.conforming, false);
  const headVector = report.results.find((r) => r.group === "HEAD");
  assert.equal(headVector?.status, "FAIL");
});

test("§60 harness CLI: runs a driver module and reports conformance", async () => {
  // Write a tiny driver module that re-exports the reference factory.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "prt-cli-"));
  const driverPath = path.join(dir, "driver.mjs");
  const authorityJs = path.resolve("node_modules/@prt/authority/driver.js");
  fs.writeFileSync(
    driverPath,
    `import { referenceDriverFactory } from ${JSON.stringify("file://" + authorityJs.replace("driver.js", "index.js"))};\nexport default referenceDriverFactory;\n`,
  );
  const cli = path.resolve(".tsc/packages/conformance/src/cli.js");
  const out = execFileSync(process.execPath, [cli, driverPath], { encoding: "utf8" });
  assert.match(out, /CONFORMING/);
  assert.match(out, /HEAD/);
  assert.match(out, /TERMINATION/);
});
