import { test } from "node:test";
import assert from "node:assert/strict";
import { generateAuthorityKeypair } from "@prt/event-v1";
import {
  mintGrant,
  encodeGrantToken,
  decodeGrantToken,
  verifyGrantSignature,
  grantDigestBytes,
  type GrantClaims,
} from "@prt/grant-v1";

const authority = generateAuthorityKeypair("process-authority/1");

function sampleClaims(): GrantClaims {
  return {
    grant_id: "grant_1",
    process_id: "proc_1",
    responsibility_id: "resp_1",
    actor: "agent:worker-7",
    action: "linear.issue.create",
    subject: "linear://team/ENG",
    bounds: { max_calls: 1 },
    expected_head: "sha256:" + "c".repeat(64),
    epoch: 3,
    expiry: "2026-08-10T00:00:00Z",
  };
}

const resolveAuthority = (id: string) => (id === authority.keyId ? authority.publicKeyDer : undefined);

test("RT-GRANT-001: minted grant verifies with authority key", () => {
  const grant = mintGrant(sampleClaims(), authority);
  assert.ok(verifyGrantSignature(grant, resolveAuthority));
});

test("RT-GRANT-001: grant/v1 parses with closed member set", () => {
  const grant = mintGrant(sampleClaims(), authority);
  const token = encodeGrantToken(grant);
  const decoded = decodeGrantToken(token);
  assert.deepEqual(decoded, grant);
});

test("RT-GRANT-001: actor cannot widen a sealed grant (claims closed set)", () => {
  const grant = mintGrant(sampleClaims(), authority);
  const widened = {
    ...grant,
    claims: { ...grant.claims, action: "admin.delete.everything" },
  };
  // Re-encoding is possible, but signature no longer matches the claims.
  assert.equal(verifyGrantSignature(widened as never, resolveAuthority), false);
});

test("RT-GRANT-001: actor cannot re-mint (no authority key → signature invalid)", () => {
  const attacker = generateAuthorityKeypair("attacker");
  const forged = mintGrant(sampleClaims(), attacker);
  // Gateway resolves only the authority's key id; attacker's key_id unknown.
  assert.equal(verifyGrantSignature(forged, resolveAuthority), false);
});

test("RT-GRANT-001: claims outside closed set rejected", () => {
  assert.throws(() => mintGrant({ ...sampleClaims(), scope: "*" }, authority), /RT-GRANT-001/);
});

test("RT-GRANT-001: grant object with extra member rejected at decode", () => {
  const grant = mintGrant(sampleClaims(), authority);
  const tampered = { ...(grant as object), backdoor: true };
  const token = Buffer.from(JSON.stringify(tampered), "utf8").toString("base64url");
  assert.throws(() => decodeGrantToken(token), /RT-GRANT-001/);
});

test("RT-GRANT-001: outer encoding is exactly base64url(JCS(grant))", () => {
  const grant = mintGrant(sampleClaims(), authority);
  const token = encodeGrantToken(grant);
  // Non-canonical re-encoding (different key order) must be rejected.
  const raw = JSON.parse(Buffer.from(token, "base64url").toString("utf8"));
  const shuffled = Buffer.from(
    `{"signature":${JSON.stringify(raw.signature)},"key_id":${JSON.stringify(raw.key_id)},"algorithm":"ed25519","claims":${JSON.stringify(raw.claims)},"schema":"grant/v1"}`,
    "utf8",
  ).toString("base64url");
  assert.throws(() => decodeGrantToken(shuffled), /not canonical/);
});

test("RT-GRANT-001: grant digest covers claims, not the signature", () => {
  const claims = sampleClaims();
  const a = mintGrant(claims, authority);
  const b = mintGrant(claims, authority);
  assert.deepEqual(grantDigestBytes(a.claims), grantDigestBytes(b.claims));
  // Ed25519 is deterministic: identical claims → identical signature.
  assert.equal(a.signature, b.signature);
});

test("RT-GRANT-001: verification fails with wrong public key, not exception", () => {
  const other = generateAuthorityKeypair("other-authority");
  const grant = mintGrant(sampleClaims(), authority);
  assert.equal(verifyGrantSignature(grant, () => other.publicKeyDer), false);
});
