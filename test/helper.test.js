import assert from "node:assert/strict";
import test from "node:test";
import {
  decodePayloadBuffer,
  preparePayloadBuffer,
  toBuffer,
} from "../functions/helper.js";

test("toBuffer keeps Buffer input unchanged", () => {
  const input = Buffer.from("abc", "utf8");
  const output = toBuffer(input);

  assert.strictEqual(output, input);
});

test("toBuffer converts string and object inputs", () => {
  const stringOutput = toBuffer("hello");
  const objectOutput = toBuffer({ a: 1 });

  assert.equal(stringOutput.toString("utf8"), "hello");
  assert.equal(objectOutput.toString("utf8"), JSON.stringify({ a: 1 }));
});

test("preparePayloadBuffer and decodePayloadBuffer roundtrip compressed JSON payload", () => {
  const payload = { name: "Alice", admin: true };
  const prepared = preparePayloadBuffer(payload, true);
  const decoded = decodePayloadBuffer(prepared, true);

  assert.deepEqual(decoded, payload);
});

test("decodePayloadBuffer returns plain string when payload is not JSON", () => {
  const payload = Buffer.from("plain-text", "utf8");
  const decoded = decodePayloadBuffer(payload, false);

  assert.equal(decoded, "plain-text");
});
