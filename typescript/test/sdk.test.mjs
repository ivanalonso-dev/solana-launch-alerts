import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  sign, verifySignature, verifyRequest, parseAlert, isKnownType, levelRank, InvalidAlertError, KNOWN_TYPES,
} from "../dist/index.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const vectors = JSON.parse(readFileSync(join(root, "examples", "test-vectors.json"), "utf8"));
const { secret, timestamp: ts } = vectors;
const now = Number(ts) + 10;
const exampleFiles = readdirSync(join(root, "examples")).filter((f) => /^[a-z]+_[a-z_]+\.json$/.test(f));
const example = () => JSON.parse(readFileSync(join(root, "examples", exampleFiles[0]), "utf8"));

for (const c of vectors.cases) {
  test(`vector sign: ${c.name}`, () => assert.equal(sign(secret, ts, c.body), c.signature));
  test(`vector verify (string): ${c.name}`, () => assert.ok(verifySignature(secret, ts, c.body, c.signature, { now })));
  test(`vector verify (bytes): ${c.name}`, () =>
    assert.ok(verifySignature(secret, ts, Buffer.from(c.body, "utf8"), c.signature, { now })));
}

test("rejects tampered body, wrong secret, bad inputs", () => {
  const c = vectors.cases[0];
  assert.ok(!verifySignature(secret, ts, c.body + " ", c.signature, { now }));
  assert.ok(!verifySignature("other", ts, c.body, c.signature, { now }));
  assert.ok(!verifySignature(secret, undefined, c.body, c.signature, { now }));
  assert.ok(!verifySignature(secret, ts, c.body, "", { now }));
  assert.ok(!verifySignature(secret, "abc", c.body, c.signature, { now }));
  assert.ok(!verifySignature(secret, ts, c.body, "short", { now }));
});

test("rejects stale and future timestamps", () => {
  const c = vectors.cases[0];
  for (const delta of [301, -301, 10000]) {
    assert.ok(!verifySignature(secret, ts, c.body, c.signature, { now: Number(ts) + delta }));
  }
});

test("verifyRequest: plain headers in any case, Fetch Headers, other provider", () => {
  const c = vectors.cases[2];
  assert.ok(verifyRequest({ "x-trenchwatch-timestamp": ts, "X-TRENCHWATCH-SIGNATURE": c.signature }, c.body, secret, { now }));
  const h = new Headers({ "X-Trenchwatch-Timestamp": ts, "X-Trenchwatch-Signature": c.signature });
  assert.ok(verifyRequest(h, c.body, secret, { now }));
  const acme = { "X-Acme-Timestamp": ts, "X-Acme-Signature": c.signature };
  assert.ok(verifyRequest(acme, c.body, secret, { provider: "Acme", now }));
  assert.ok(!verifyRequest(acme, c.body, secret, { now }));
});

for (const f of exampleFiles) {
  test(`example parses: ${f}`, () => {
    const a = parseAlert(readFileSync(join(root, "examples", f)));
    assert.equal(a.type, f.replace(".json", ""));
    assert.ok(isKnownType(a.type));
    assert.equal(a.sandbox, true);
  });
}

test("unknown type and fields are accepted", () => {
  const d = { ...example(), type: "future_code", new_field: 1 };
  const a = parseAlert(d);
  assert.ok(!isKnownType(a.type));
  assert.equal(a.new_field, 1);
});

test("invalid alerts throw", () => {
  const cases = [
    (d) => delete d.id, (d) => (d.level = "HIGH"), (d) => (d.sandbox = "yes"),
    (d) => (d.operator = {}), (d) => (d.evidence = ["x"]), (d) => (d.token = 5),
  ];
  for (const mutate of cases) {
    const d = example();
    mutate(d);
    assert.throws(() => parseAlert(d), InvalidAlertError);
  }
  assert.throws(() => parseAlert("{not json"), InvalidAlertError);
});

test("level ranks and known types match the spec", () => {
  assert.deepEqual(["RELATED", "COORDINATED", "SUSPECTED", "CONFIRMED"].map(levelRank), [0, 1, 2, 3]);
  const spec = readFileSync(join(root, "SPEC.md"), "utf8");
  for (const t of KNOWN_TYPES) assert.ok(spec.includes("`" + t + "`"), t);
});
