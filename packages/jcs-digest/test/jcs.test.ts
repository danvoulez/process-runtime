import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { canonicalize, digestJson, digestMatches, sha256Digest } from "@prt/jcs-digest";

test("JCS: object keys sorted by UTF-16 code units", () => {
  // RFC 8785 §3.2.3 ordering: code-unit order, not locale order.
  const out = canonicalize({ b: 1, a: 2, A: 3, "0": 4, peach: 5, "péché": 6 });
  assert.equal(out, '{"0":4,"A":3,"a":2,"b":1,"peach":5,"péché":6}');
});

test("JCS: no whitespace anywhere", () => {
  const out = canonicalize({ a: [1, 2, { b: "c" }], d: null });
  assert.equal(out, '{"a":[1,2,{"b":"c"}],"d":null}');
});

test("JCS: numbers use ECMA-262 Number::toString", () => {
  assert.equal(canonicalize(1e21), "1e+21");
  assert.equal(canonicalize(1e-7), "1e-7");
  assert.equal(canonicalize(0.1), "0.1");
  assert.equal(canonicalize(-0), "0");
  assert.equal(canonicalize(9007199254740991), "9007199254740991");
});

test("JCS: non-finite numbers rejected", () => {
  assert.throws(() => canonicalize(Number.NaN), /not in the JSON data model/);
  assert.throws(() => canonicalize(Number.POSITIVE_INFINITY), /not in the JSON data model/);
});

test("JCS: string escaping is minimal JSON escaping", () => {
  assert.equal(canonicalize('a"b\\c'), '"a\\"b\\\\c"');
  assert.equal(canonicalize("\u0001"), '"\\u0001"');
  assert.equal(canonicalize("é"), '"é"');
});

test("JCS: nested arrays and objects", () => {
  assert.equal(canonicalize([3, [2, { z: 1, y: [true, null] }]]), '[3,[2,{"y":[true,null],"z":1}]]');
});

test("digest: sha256Digest is sha256:<lowercase hex> over UTF-8", () => {
  const expected = "sha256:" + createHash("sha256").update('{"a":1}', "utf8").digest("hex");
  assert.equal(sha256Digest('{"a":1}'), expected);
});

test("digestJson: canonical form is stable across key insertion order", () => {
  const a = digestJson({ x: 1, y: { p: 2, q: 3 } });
  const b = digestJson({ y: { q: 3, p: 2 }, x: 1 });
  assert.equal(a.canonical, b.canonical);
  assert.equal(a.digest, b.digest);
  assert.equal(a.bytes.length, 32);
});

test("digestMatches: positive and negative", () => {
  const { digest } = digestJson({ hello: "world" });
  assert.ok(digestMatches({ hello: "world" }, digest));
  assert.ok(!digestMatches({ hello: "mars" }, digest));
});
