import crypto from "node:crypto";
import { writeFileSync } from "node:fs";
import { createCose1 } from "../functions/cose1.js";
import { createJws } from "../functions/jws.js";
import { makeEquivalentClaims } from "./claims-generator.js";
import {
  collectPairLog,
  logsToMarkdown,
  printPairLog,
} from "./measurement-logger.js";

function randomInput(byteLength) {
  return crypto.randomBytes(byteLength).toString("base64url");
}

function buildInputs() {
  return [
    { label: "empty", content: "" },
    { label: "random-1", content: randomInput(100) },
    { label: "random-2", content: randomInput(1000) },
    { label: "random-3", content: randomInput(3000) },
  ];
}

function buildLogs(secret, compress) {
  const encodings = ["base64", "base45"];
  const inputs = buildInputs();
  const pairLogs = [];

  for (const encoding of encodings) {
    for (const input of inputs) {
      const { jwsClaims, cose1Claims } = makeEquivalentClaims(input.content);

      const jwsResult = createJws(jwsClaims, secret, {
        compress,
        tokenEncoding: encoding,
      });
      const cose1Result = createCose1(cose1Claims, secret, {
        compress,
        tokenEncoding: encoding,
      });
      const pairLog = collectPairLog(`${input.label}`, jwsResult, cose1Result, {
        tokenEncoding: encoding,
      });
      pairLogs.push(pairLog);
    }
  }

  return pairLogs;
}

const outputFile = "MEASUREMENTS.md";
const secret = "measurement-secret";
const compress = true;

const pairLogs = buildLogs(secret, compress);

const markdown = logsToMarkdown(pairLogs);
writeFileSync(outputFile, markdown, "utf8");
console.log(`Wrote ${outputFile}`);
