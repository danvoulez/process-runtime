// Release acceptance test (rc contract §5). Run as a stranger would:
// copies the repository to a clean directory, installs from package
// sources, builds, tests, runs the harness against an external driver
// and a deliberately broken one, and performs the static boundary checks.
//
//   node scripts/acceptance.mjs            full run (includes npm ci)
//   node scripts/acceptance.mjs --static   static checks only (no install)
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const staticOnly = process.argv.includes("--static");
const results = [];
const check = (name, ok, detail) => {
  results.push({ name, ok, detail });
  console.log(`${ok ? "✓" : "✗"} ${name}${detail ? ` — ${detail}` : ""}`);
  return ok;
};

const run = (args, opts) => {
  try {
    const out = execFileSync(args[0], args.slice(1), { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], ...opts });
    return { code: 0, out };
  } catch (e) {
    return { code: e.status ?? 1, out: String(e.stdout ?? "") + String(e.stderr ?? "") };
  }
};

// ---- static boundary checks (always) -------------------------------------

const grepFor = (needle, dirs) => {
  const hits = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.isFile()) {
        const c = fs.readFileSync(p, "utf8");
        if (c.includes(needle)) hits.push(p);
      }
    }
  };
  for (const d of dirs) walk(d);
  return hits;
};

check(
  "no reference imports in harness/verifier source",
  grepFor("@prt/authority", [path.join(root, "packages/conformance/src"), path.join(root, "packages/export-v1/src")]).length === 0 &&
    grepFor("better-sqlite3", [path.join(root, "packages/conformance/src"), path.join(root, "packages/export-v1/src")]).length === 0,
);

const lock = JSON.parse(fs.readFileSync(path.join(root, "package-lock.json"), "utf8"));
const lockPkgs = Object.entries(lock.packages).filter(([k]) => k !== "");
check("lockfile has no internal registry URLs", !JSON.stringify(lock).includes("msh.team"));
check(
  "lockfile carries integrity for every package",
  lockPkgs.every(([, v]) => typeof v.integrity === "string"),
  `${lockPkgs.filter(([, v]) => typeof v.integrity === "string").length}/${lockPkgs.length}`,
);

const rootPkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
const confPkg = JSON.parse(fs.readFileSync(path.join(root, "packages/conformance/package.json"), "utf8"));
const suiteVersion = fs.readFileSync(path.join(root, "packages/conformance/src/version.ts"), "utf8");
const v = rootPkg.version;
check(
  "version stamps agree (root, lock, conformance, SUITE_VERSION)",
  lock.packages[""].version === v && confPkg.version === v && suiteVersion.includes(`"${v}"`),
  v,
);

check(
  "harness declares no transitive reference dependency",
  (() => {
    const deps = (p) => Object.keys(JSON.parse(fs.readFileSync(path.join(root, p, "package.json"), "utf8")).dependencies ?? {});
    const seen = new Set();
    const visit = (p) => { for (const d of deps(p)) { if (seen.has(d)) continue; seen.add(d); if (d.startsWith("@prt/")) visit(`packages/${d.slice(5)}`); } };
    visit("packages/conformance");
    return !seen.has("@prt/authority");
  })(),
);

if (!staticOnly) {
  // ---- clean-environment run ---------------------------------------------
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "prt-acceptance-"));
  const copy = (src, dst) => {
    for (const e of fs.readdirSync(src, { withFileTypes: true })) {
      if (["node_modules", ".tsc", ".git"].includes(e.name)) continue;
      const s = path.join(src, e.name), d = path.join(dst, e.name);
      if (e.isDirectory()) { fs.mkdirSync(d, { recursive: true }); copy(s, d); }
      else if (e.isFile()) fs.copyFileSync(s, d);
    }
  };
  copy(root, work);

  const ci = run(["npm", "ci"], { cwd: work });
  check("clean checkout: npm ci succeeds from package sources", ci.code === 0, ci.code !== 0 ? ci.out.slice(-400) : undefined);

  if (ci.code === 0) {
    check(
      "native dependency built by the documented install",
      fs.existsSync(path.join(work, "node_modules/better-sqlite3/build/Release/better_sqlite3.node")),
    );
    const t = run(["npm", "test"], { cwd: work });
    check("clean checkout: full repository test suite passes", t.code === 0, t.code !== 0 ? t.out.slice(-400) : undefined);

    const foreign = fs.mkdtempSync(path.join(os.tmpdir(), "prt-foreign-"));
    fs.writeFileSync(path.join(foreign, "driver.mjs"),
      `import { referenceDriverFactory } from "file://${work}/node_modules/@prt/authority/index.js";\nexport default referenceDriverFactory;\n`);
    const ref = run([process.execPath, path.join(work, ".tsc/packages/conformance/src/cli.js"), path.join(foreign, "driver.mjs")], { cwd: work });
    check("standalone harness: reference driver passes", ref.code === 0 && ref.out.includes("CONFORMING ["), ref.out.trim().split("\n").at(-1));

    fs.writeFileSync(path.join(foreign, "broken.mjs"), `
const h = "sha256:" + "0".repeat(64);
export default { fresh: () => ({
  name: "broken", capabilities: { verify: false, exportBundle: false },
  state: { head: h, seq: 0 },
  createProcess() { return { event_digest: this.state.head }; },
  propose() { this.state.seq++; this.state.head = "sha256:" + String(this.state.seq).padStart(64, "0"); return { event_digest: this.state.head }; },
  getHead() { return this.state.head; },
  loadProjection() { return { lifecycle: "active", epoch: 1, responsibilities: {}, grants: {}, waits: {}, effects: {}, terminal: null }; },
  listEvents() { return Array.from({ length: this.state.seq + 1 }, () => ({})); },
  getReceipt() { return { event_digest: this.state.head }; },
  claimInvocation() { return {}; }, completeInvocation() {},
}), reopen: (d) => d };
`);
    const broken = run([process.execPath, path.join(work, ".tsc/packages/conformance/src/cli.js"), path.join(foreign, "broken.mjs")], { cwd: work });
    check("standalone harness: deliberately broken driver fails", broken.code === 1 && broken.out.includes("NOT CONFORMING"));
  }
}

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} acceptance checks green${failed.length ? ` — FAILED: ${failed.map((f) => f.name).join("; ")}` : ""}`);
process.exit(failed.length ? 1 : 0);
