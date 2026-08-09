#!/usr/bin/env node
/**
 * prt — Process Runtime reference CLI.
 *
 *   prt verify <process-export-dir>
 *
 * Independently verifies a canonical Process export (§57, §58).
 * Exit code 0 = VALID, 1 = INVALID, 2 = usage error.
 */
import { verifyBundle } from "./verify.js";

const [, , command, dir] = process.argv;

if (command !== "verify" || dir === undefined) {
  console.error("usage: prt verify <process-export-dir>");
  process.exit(2);
}

const report = verifyBundle(dir);

for (const c of report.checks) {
  const mark = c.ok ? "✓" : "✗";
  console.log(`${mark} ${c.name}${c.detail !== undefined ? ` — ${c.detail}` : ""}`);
}
console.log(`\n${report.status}`);

process.exit(report.status === "VALID" ? 0 : 1);
