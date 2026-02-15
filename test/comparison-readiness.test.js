import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import base45 from "base45";
import * as api from "../index.js";

const SECRET = "comparison-secret";

function metricsForTokenString(token) {
  const bytes = Buffer.from(token, "utf8");
  const sha256Hex = crypto.createHash("sha256").update(bytes).digest("hex");

  return {
    rawBytes: bytes.length,
    base64Length: bytes.toString("base64").length,
    base45Length: base45.encode(Uint8Array.from(bytes)).length,
    sha256Hex,
  };
}

test("index exports main APIs and namespaces", () => {
  assert.equal(typeof api.createJws, "function");
  assert.equal(typeof api.createCose1, "function");
  assert.equal(typeof api.jws.createJws, "function");
  assert.equal(typeof api.cose1.createCose1, "function");
  assert.equal(typeof api.helper.toBuffer, "function");
});

test("JWS and COSE1 can be compared under same environment settings", () => {
  const payload = Buffer.alloc(256, "a");
  const jwsCreated = api.createJws(payload, SECRET, { compress: false });
  const coseCreated = api.createCose1(payload, SECRET, { compress: false });

  const jwsVerified = api.verifyJws(jwsCreated.token, SECRET);
  const coseVerified = api.verifyCose1(coseCreated.token, SECRET);

  assert.equal(jwsVerified.valid, true);
  assert.equal(coseVerified.valid, true);
  assert.equal(jwsVerified.payload, payload.toString("utf8"));
  assert.equal(coseVerified.payload, payload.toString("utf8"));

  const jwsMetrics = metricsForTokenString(jwsCreated.token);
  const coseMetrics = metricsForTokenString(coseCreated.token);

  assert.equal(jwsMetrics.sha256Hex.length, 64);
  assert.equal(coseMetrics.sha256Hex.length, 64);
  assert.ok(jwsMetrics.rawBytes > 0);
  assert.ok(coseMetrics.rawBytes > 0);
  assert.ok(jwsMetrics.base64Length > 0);
  assert.ok(coseMetrics.base64Length > 0);
  assert.ok(jwsMetrics.base45Length > 0);
  assert.ok(coseMetrics.base45Length > 0);
});

test("token sizes increase with payload size for both algorithms", () => {
  const payloadSizes = [32, 256, 1024];
  const jwsLengths = [];
  const coseLengths = [];

  for (const size of payloadSizes) {
    const payload = Buffer.alloc(size, "a");
    const jwsCreated = api.createJws(payload, SECRET, { compress: false });
    const coseCreated = api.createCose1(payload, SECRET, { compress: false });

    jwsLengths.push(jwsCreated.token.length);
    coseLengths.push(coseCreated.token.length);
  }

  assert.ok(jwsLengths[1] > jwsLengths[0]);
  assert.ok(jwsLengths[2] > jwsLengths[1]);
  assert.ok(coseLengths[1] > coseLengths[0]);
  assert.ok(coseLengths[2] > coseLengths[1]);
});
