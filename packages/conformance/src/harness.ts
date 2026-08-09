import type { DriverFactory } from "./driver.js";
import { CAPABILITY_VECTORS, RUNTIME_VECTORS, type ConformanceProfile, type VectorResult } from "./vectors.js";

export interface ProfileOutcome {
  profile: ConformanceProfile;
  evaluated: boolean;
  pass: number;
  fail: number;
  skip: number;
}

export interface ConformanceReport {
  driverName: string;
  results: VectorResult[];
  profiles: ProfileOutcome[];
  pass: number;
  fail: number;
  skip: number;
  /** No FAIL in any evaluated group. Always read together with `profiles`. */
  conforming: boolean;
  /** Human-qualified claim, e.g. "CONFORMING [core+verify+export]". */
  qualified: string;
}

/**
 * §60 Runtime Conformance harness.
 *
 * Runs every vector against a third-party RuntimeDriver. The harness
 * knows nothing about the reference implementation: storage, language,
 * and deployment are the driver's business.
 */
export async function runConformance(factory: DriverFactory): Promise<ConformanceReport> {
  const results: VectorResult[] = [];
  let driverName = "unknown";

  for (const v of RUNTIME_VECTORS) {
    results.push(await runOne(v, { factory }));
    if (driverName === "unknown") {
      const probe = await factory.fresh();
      driverName = probe.name;
      await probe.close?.();
    }
  }

  for (const v of CAPABILITY_VECTORS) {
    const probe = await factory.fresh();
    const supported = probe.capabilities[v.requires];
    await probe.close?.();
    if (!supported) {
      results.push({ group: v.group, profile: v.profile, name: v.name, rt: v.rt, status: "SKIP", detail: `driver does not declare capability: ${v.requires}` });
      continue;
    }
    results.push(await runOne(v, { factory }));
  }

  const pass = results.filter((r) => r.status === "PASS").length;
  const fail = results.filter((r) => r.status === "FAIL").length;
  const skip = results.filter((r) => r.status === "SKIP").length;

  // §2 of the release contract: CONFORMING is always profile-qualified.
  // A runtime missing an evaluated normative group never receives an
  // unqualified result; skipped profiles are reported, not hidden.
  const profileNames: ConformanceProfile[] = ["core", "verify", "export"];
  const profiles: ProfileOutcome[] = profileNames.map((p) => {
    const rs = results.filter((r) => r.profile === p);
    return {
      profile: p,
      evaluated: rs.some((r) => r.status !== "SKIP"),
      pass: rs.filter((r) => r.status === "PASS").length,
      fail: rs.filter((r) => r.status === "FAIL").length,
      skip: rs.filter((r) => r.status === "SKIP").length,
    };
  });
  const conforming = fail === 0;
  const passed = profiles.filter((p) => p.evaluated && p.fail === 0).map((p) => p.profile);
  const notEvaluated = profiles.filter((p) => !p.evaluated).map((p) => p.profile);
  const qualified = conforming
    ? `CONFORMING [${passed.join("+")}]${notEvaluated.length > 0 ? ` (not evaluated: ${notEvaluated.join(", ")})` : ""}`
    : "NOT CONFORMING";

  return { driverName, results, profiles, pass, fail, skip, conforming, qualified };
}

async function runOne(
  v: { group: string; profile: ConformanceProfile; name: string; rt: string[]; run: (ctx: { factory: DriverFactory }) => Promise<void> },
  ctx: { factory: DriverFactory },
): Promise<VectorResult> {
  try {
    await v.run(ctx);
    return { group: v.group, profile: v.profile, name: v.name, rt: v.rt, status: "PASS" };
  } catch (e) {
    return { group: v.group, profile: v.profile, name: v.name, rt: v.rt, status: "FAIL", detail: (e as Error).message };
  }
}

export function formatReport(report: ConformanceReport): string {
  const lines: string[] = [`driver: ${report.driverName}`, ""];
  let group = "";
  for (const r of report.results) {
    if (r.group !== group) {
      group = r.group;
      lines.push(`${group}  (profile: ${r.profile})`);
    }
    const mark = r.status === "PASS" ? "✓" : r.status === "SKIP" ? "○" : "✗";
    const rt = r.rt.length > 0 ? ` [${r.rt.join(", ")}]` : "";
    lines.push(`  ${mark} ${r.name}${rt}${r.detail !== undefined ? ` — ${r.detail}` : ""}`);
  }
  lines.push("", `${report.pass} pass · ${report.fail} fail · ${report.skip} skip`, report.qualified);
  return lines.join("\n");
}
