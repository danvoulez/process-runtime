#!/usr/bin/env node
/**
 * prt-conformance — standalone §60 harness for third-party runtimes.
 *
 *   prt-conformance <driver-module>
 *
 * The driver module must export (default or named `factory`) a
 * DriverFactory:
 *
 *   export default {
 *     fresh: () => new MyRuntimeDriver(...),
 *     reopen: (d) => new MyRuntimeDriver(d.backendId),
 *   };
 *
 * Exit 0 = conforming, 1 = not conforming, 2 = usage/driver error.
 */
import path from "node:path";
import { pathToFileURL } from "node:url";
import { runConformance, formatReport } from "./harness.js";
import type { DriverFactory } from "./driver.js";

const [, , driverModule] = process.argv;

if (driverModule === undefined) {
  console.error("usage: prt-conformance <driver-module>");
  process.exit(2);
}

const mod = (await import(pathToFileURL(path.resolve(driverModule)).href)) as {
  default?: DriverFactory;
  factory?: DriverFactory;
};

const factory = mod.default ?? mod.factory;
if (factory === undefined || typeof factory.fresh !== "function" || typeof factory.reopen !== "function") {
  console.error("driver module must export a DriverFactory (default export or named `factory`)");
  process.exit(2);
}

const report = await runConformance(factory);
console.log(formatReport(report));
process.exit(report.conforming ? 0 : 1);
