import assert from "node:assert/strict";
import test from "node:test";
import {
  createJws,
  createJwsHeader,
  parseJwsToken,
  verifyJws,
} from "../functions/jws.js";

const SECRET = "test-secret";

test("createJwsHeader sets mandatory header values", () => {
  assert.deepEqual(createJwsHeader(), { alg: "HS256", typ: "JWT" });
  assert.deepEqual(createJwsHeader({ compress: true }), {
    alg: "HS256",
    typ: "JWT",
    zip: "DEF",
  });
});

test("createJws + verifyJws works with basic payload", () => {
  const payload = { sub: "123", role: "user" };
  const created = createJws(payload, SECRET);
  const verified = verifyJws(created.token, SECRET);

  assert.equal(verified.valid, true);
  assert.deepEqual(verified.payload, payload);
});

test("createJws + verifyJws works with compressed payload", () => {
  const payload = {
    sub: "123",
    data: "A".repeat(256),
  };
  const created = createJws(payload, SECRET, { compress: true });
  const verified = verifyJws(created.token, SECRET);

  assert.equal(verified.valid, true);
  assert.deepEqual(verified.payload, payload);
  assert.equal(verified.header.zip, "DEF");
});

test("verifyJws returns invalid for wrong secret", () => {
  const token = createJws({ hello: "world" }, SECRET).token;
  const verified = verifyJws(token, "wrong-secret");

  assert.equal(verified.valid, false);
  assert.equal(verified.payload, null);
});

test("createJws + verifyJws works with base64 token encoding", () => {
  const payload = { data: "abc123" };
  const created = createJws(payload, SECRET, { tokenEncoding: "base64" });
  const verified = verifyJws(created.token, SECRET, { tokenEncoding: "base64" });

  assert.equal(verified.valid, true);
  assert.deepEqual(verified.payload, payload);
});

test("createJws + verifyJws works with base45 token encoding", () => {
  const payload = { data: "abc123" };
  const created = createJws(payload, SECRET, { tokenEncoding: "base45" });
  const verified = verifyJws(created.token, SECRET, { tokenEncoding: "base45" });

  assert.equal(verified.valid, true);
  assert.deepEqual(verified.payload, payload);
});

test("parseJwsToken throws on invalid format", () => {
  assert.throws(() => parseJwsToken("not-a-jws"), /Invalid JWS format/);
});
