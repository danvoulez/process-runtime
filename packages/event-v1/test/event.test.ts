import { test } from "node:test";
import assert from "node:assert/strict";
import { sign as nodeSign } from "node:crypto";
import { canonicalize } from "@prt/jcs-digest";
import {
  buildEventCore,
  computeEventDigest,
  sealEvent,
  verifyEventEnvelope,
  verifyChain,
  chainHead,
  generateAuthorityKeypair,
  signEventCore,
  verifyEventSignature,
  makeSignatureObject,
  type EventCore,
} from "@prt/event-v1";

function genesisCore(): EventCore {
  return buildEventCore({
    schema: "event/v1",
    process_id: "proc_test_1",
    sequence: 0,
    previous: null,
    epoch: 1,
    type: "process_created",
    payload: { kind_digest: "sha256:" + "a".repeat(64) },
    causation: null,
    authority: "institution/bootstrap",
    committed_at: "2026-08-09T12:00:00Z",
  });
}

test("RT-EVENT-001: valid core accepted", () => {
  const core = genesisCore();
  assert.equal(core.schema, "event/v1");
});

test("RT-EVENT-004: core member outside closed set rejected", () => {
  const bad = { ...(genesisCore() as object), injected: true };
  assert.throws(() => buildEventCore(bad), /RT-EVENT-004/);
});

test("RT-EVENT-004: missing core member rejected", () => {
  const bad: Record<string, unknown> = { ...(genesisCore() as object) };
  delete bad.epoch;
  assert.throws(() => buildEventCore(bad), /RT-EVENT-004/);
});

test("RT-EVENT-001: bad types rejected", () => {
  assert.throws(() => buildEventCore({ ...(genesisCore() as object), sequence: 0.5 }), /RT-EVENT-001/);
  assert.throws(() => buildEventCore({ ...(genesisCore() as object), committed_at: "tomorrow" }), /RT-EVENT-001/);
  assert.throws(() => buildEventCore({ ...(genesisCore() as object), previous: "md5:abc" }), /RT-EVENT-001/);
});

test("RT-EVENT-002: digest matches SHA-256 over JCS(core)", async () => {
  const { createHash } = await import("node:crypto");
  const core = genesisCore();
  const { bytes, digest } = computeEventDigest(core);
  const expected = createHash("sha256").update(canonicalize(core as never), "utf8").digest();
  assert.deepEqual(Buffer.from(bytes), expected);
  assert.equal(digest, "sha256:" + expected.toString("hex"));
  assert.equal(bytes.length, 32);
});

test("RT-EVENT-003: seal produces envelope with digest, signature optional", () => {
  const env = sealEvent(genesisCore());
  assert.equal(typeof env.digest, "string");
  assert.equal(env.signature, undefined);
  assert.equal(verifyEventEnvelope(env).digest, env.digest);
});

test("RT-EVENT-002: signature is excluded from digest computation", () => {
  const kp = generateAuthorityKeypair("auth/1");
  const core = genesisCore();
  const unsigned = sealEvent(core);
  const signed = sealEvent(core, signEventCore(core, kp));
  assert.equal(unsigned.digest, signed.digest);
});

test("RT-EVENT-004: envelope member outside closed set rejected", () => {
  const env = { ...(sealEvent(genesisCore()) as object), tenant: "evil" };
  assert.throws(() => verifyEventEnvelope(env), /RT-EVENT-004/);
});

test("RT-EVENT-002: tampered payload detected by digest recomputation", () => {
  const env = sealEvent(genesisCore());
  const tampered = { ...env, payload: { kind_digest: "sha256:" + "b".repeat(64) } };
  assert.throws(() => verifyEventEnvelope(tampered), /RT-EVENT-002/);
});

test("§12: valid two-event chain verifies; head is last digest", () => {
  const g = sealEvent(genesisCore());
  const second = sealEvent({
    ...genesisCore(),
    sequence: 1,
    previous: g.digest,
    type: "responsibility_issued",
    payload: { responsibility_id: "r1", role: "worker", objective: "do", acceptance: {} },
  });
  const chain = verifyChain([g, second]);
  assert.equal(chain.length, 2);
  assert.equal(chainHead(chain), second.digest);
});

test("§12: sequence gap is corruption", () => {
  const g = sealEvent(genesisCore());
  const gap = sealEvent({ ...genesisCore(), sequence: 7, previous: g.digest });
  assert.throws(() => verifyChain([g, gap]), /sequence gap/);
});

test("§12: broken previous link is corruption", () => {
  const g = sealEvent(genesisCore());
  const orphan = sealEvent({ ...genesisCore(), sequence: 1, previous: "sha256:" + "0".repeat(64) });
  assert.throws(() => verifyChain([g, orphan]), /broken previous link/);
});

test("§10: epoch decrease detected during chain verification", () => {
  const g = sealEvent(genesisCore());
  const older = sealEvent({ ...genesisCore(), sequence: 1, previous: g.digest, epoch: 0 });
  assert.throws(() => verifyChain([g, older]), /epoch decreased/);
});

test("§12: mutation of a committed event breaks the chain", () => {
  const g = sealEvent(genesisCore());
  const second = sealEvent({ ...genesisCore(), sequence: 1, previous: g.digest });
  const mutatedGenesis = { ...g, epoch: 99 };
  assert.throws(() => verifyChain([mutatedGenesis, second]));
});

test("RT-SIG-001: Ed25519 verifies over the raw 32-byte digest", () => {
  const kp = generateAuthorityKeypair("auth/bootstrap");
  const core = genesisCore();
  const env = sealEvent(core, signEventCore(core, kp));
  const resolver = (id: string) => (id === "auth/bootstrap" ? kp.publicKeyDer : undefined);
  assert.ok(verifyEventSignature(env, resolver));
});

test("RT-SIG-001: signature over the hex string does NOT verify (bytes are pinned)", () => {
  const kp = generateAuthorityKeypair("auth/1");
  const core = genesisCore();
  const { digest } = computeEventDigest(core);
  // Wrong construction: sign the ASCII hex representation instead of raw bytes.
  const wrongSig = nodeSign(null, Buffer.from(digest, "utf8"), kp.privateKey);
  const env = sealEvent(core, makeSignatureObject("auth/1", computeEventDigest(core).bytes, kp.privateKey));
  env.signature = { algorithm: "ed25519", key_id: "auth/1", value: wrongSig.toString("base64url") };
  const resolver = () => kp.publicKeyDer;
  assert.equal(verifyEventSignature(env, resolver), false);
});

test("RT-SIG-002: signature object with extra member rejected", () => {
  const kp = generateAuthorityKeypair("auth/1");
  const core = genesisCore();
  const sig = { ...signEventCore(core, kp), comment: "x" };
  assert.throws(() => sealEvent(core, sig as never), /RT-SIG-002/);
});

test("RT-SIG: unknown key_id fails verification, not exception", () => {
  const kp = generateAuthorityKeypair("auth/1");
  const core = genesisCore();
  const env = sealEvent(core, signEventCore(core, kp));
  assert.equal(verifyEventSignature(env, () => undefined), false);
});
