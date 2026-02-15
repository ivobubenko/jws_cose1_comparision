import assert from "node:assert/strict";
import test from "node:test";
import {
  COSE_ALG_HMAC_256_256,
  COSE_HEADER_ALG,
  createCose1,
  createCoseProtectedHeader,
  decodeCoseSign1,
  verifyCose1,
} from "../functions/cose1.js";

const SECRET = "test-secret";

test("createCoseProtectedHeader sets algorithm and optional compression", () => {
  const baseHeader = createCoseProtectedHeader();
  const compressedHeader = createCoseProtectedHeader({ compress: true });

  assert.equal(baseHeader.get(COSE_HEADER_ALG), COSE_ALG_HMAC_256_256);
  assert.equal(baseHeader.has("zip"), false);
  assert.equal(compressedHeader.get("zip"), "DEF");
});

test("createCose1 + verifyCose1 works with basic payload", () => {
  const payload = { sub: "123", role: "user" };
  const created = createCose1(payload, SECRET);
  const verified = verifyCose1(created.token, SECRET);

  assert.equal(verified.valid, true);
  assert.deepEqual(verified.payload, payload);
});

test("createCose1 + verifyCose1 works with compressed payload", () => {
  const payload = { sub: "123", data: "A".repeat(256) };
  const created = createCose1(payload, SECRET, { compress: true });
  const verified = verifyCose1(created.token, SECRET);

  assert.equal(verified.valid, true);
  assert.deepEqual(verified.payload, payload);
  assert.equal(verified.protectedHeader.get("zip"), "DEF");
});

test("createCose1 + verifyCose1 works with CBOR Map payload", () => {
  const payload = new Map([
    [1, "issuer"],
    [2, "subject"],
    [1000, "hello"],
  ]);
  const created = createCose1(payload, SECRET, { compress: true });
  const verified = verifyCose1(created.token, SECRET);

  assert.equal(verified.valid, true);
  assert.equal(verified.payload instanceof Map, true);
  assert.equal(verified.payload.get(1), "issuer");
  assert.equal(verified.payload.get(2), "subject");
  assert.equal(verified.payload.get(1000), "hello");
});

test("verifyCose1 returns invalid for wrong secret", () => {
  const token = createCose1({ hello: "world" }, SECRET).token;
  const verified = verifyCose1(token, "wrong-secret");

  assert.equal(verified.valid, false);
  assert.equal(verified.payload, null);
});

test("createCose1 + verifyCose1 works with base64 token encoding", () => {
  const payload = { data: "abc123" };
  const created = createCose1(payload, SECRET, { tokenEncoding: "base64" });
  const verified = verifyCose1(created.token, SECRET, { tokenEncoding: "base64" });

  assert.equal(verified.valid, true);
  assert.deepEqual(verified.payload, payload);
});

test("createCose1 + verifyCose1 works with base45 token encoding", () => {
  const payload = { data: "abc123" };
  const created = createCose1(payload, SECRET, { tokenEncoding: "base45" });
  const verified = verifyCose1(created.token, SECRET, { tokenEncoding: "base45" });

  assert.equal(verified.valid, true);
  assert.deepEqual(verified.payload, payload);
});

test("decodeCoseSign1 throws on invalid structure", () => {
  const invalidEmptyArrayCbor = Buffer.from([0x80]);
  assert.throws(
    () => decodeCoseSign1(invalidEmptyArrayCbor),
    /Invalid COSE_Sign1 structure/,
  );
});
