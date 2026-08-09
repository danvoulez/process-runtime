// Test runner: enumerate test files explicitly instead of relying on
// `node --test <dir>` glob semantics, which differ across Node versions
// (20 vs 22). Build first, then pass every .test.js path to the runner.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");

execFileSync(process.execPath, [path.join(root, "scripts", "build.mjs")], {
  cwd: root,
  stdio: "inherit",
});

const testsRoot = path.join(root, ".tsc", "packages");
const files = [];
const walk = (dir) => {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(p);
    else if (entry.isFile() && entry.name.endsWith(".test.js")) files.push(p);
  }
};
walk(testsRoot);
files.sort();

if (files.length === 0) {
  console.error("no test files found under .tsc/packages");
  process.exit(1);
}

try {
  execFileSync(process.execPath, ["--test", ...files], { cwd: root, stdio: "inherit" });
} catch (e) {
  process.exit(e.status ?? 1);
}
