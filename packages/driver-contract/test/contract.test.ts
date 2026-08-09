import { test } from "node:test";
import assert from "node:assert/strict";
import { asProjection, asReceipt } from "@prt/driver-contract";

test("contract helpers narrow structural views", () => {
  assert.equal(asProjection({ lifecycle: "active", epoch: 1 }).lifecycle, "active");
  assert.throws(() => asProjection({}), /lifecycle/);
  assert.equal(asReceipt({ event_digest: "sha256:x" }).event_digest, "sha256:x");
  assert.throws(() => asReceipt({}), /event_digest/);
});
