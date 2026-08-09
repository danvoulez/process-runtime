// Build: compile all packages with tsc, then expose @prt/* to the test
// runtime by copying compiled sources into node_modules (no symlinks —
// the target filesystem does not support them).
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const tsc = path.join(root, "node_modules", "typescript", "bin", "tsc");

// Clean compile: stale artifacts of deleted tests/sources must never survive.
fs.rmSync(path.join(root, ".tsc"), { recursive: true, force: true });

execFileSync(process.execPath, [tsc, "-p", "tsconfig.json"], {
  cwd: root,
  stdio: "inherit",
});

const pkgs = fs.readdirSync(path.join(root, "packages"));
for (const p of pkgs) {
  const compiledSrc = path.join(root, ".tsc", "packages", p, "src");
  if (!fs.existsSync(compiledSrc)) continue;
  const dest = path.join(root, "node_modules", "@prt", p);
  fs.rmSync(dest, { recursive: true, force: true });
  fs.mkdirSync(dest, { recursive: true });
  for (const f of fs.readdirSync(compiledSrc)) {
    fs.copyFileSync(path.join(compiledSrc, f), path.join(dest, f));
  }
  fs.writeFileSync(
    path.join(dest, "package.json"),
    JSON.stringify({ name: `@prt/${p}`, type: "module", main: "index.js" }, null, 2) + "\n",
  );
}
console.log("build ok");
