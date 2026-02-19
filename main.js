import { makeEquivalentClaims } from "./common/claims.js";
import { createCoseSign1, verifyCoseSign1 } from "./cose_sign1/cose_sign1.js";
import { readPemKey } from "./common/read_key.js";
import { logCaseMetrics, printMetricsHeader } from "./common/logger.js";
import { createJWS } from "./jws/jws.js";
import {
  generateInputString,
  makeSizedString,
} from "./common/generate_payload.js";
import base45 from "base45";
import { writeFileSync } from "node:fs";
import { measureMaxInputCapacityForCurrentTypes } from "./qr/measure_capacity.js";

const privateKey = readPemKey("private_key.txt");
const publicKey = readPemKey("public_key.txt");

export const utf8ByteLength = (s) => new TextEncoder().encode(s).length;

const testCases = [
  { label: "0B", input: 0 },
  { label: "1B", input: 1 },
  { label: "8B", input: 8 },
  { label: "16B", input: 16 },
  { label: "32B", input: 32 },
  { label: "64B", input: 64 },
  { label: "128B", input: 128 },
  { label: "256B", input: 256 },
  { label: "512B", input: 512 },
  { label: "1KB", input: 1024 },
  { label: "2KB", input: 2048 },
  { label: "4KB", input: 4096 },
  { label: "8KB", input: 8192 },
];
generateInputString(10000);
printMetricsHeader();

for (const test of testCases) {
  const input = makeSizedString(test.input);
  const { jwsClaims, cose1Claims } = makeEquivalentClaims(input);
  const {
    coseSign1,
    uncompressedCoseSign1: ucCs1,
    signature: sgCs1,
  } = createCoseSign1(cose1Claims, privateKey);
  console.log(verifyCoseSign1(coseSign1, publicKey));
  const { jws, signature: sgJws } = createJWS(jwsClaims, privateKey);
  const coseSign1Base45 = base45.encode(coseSign1);
  const coseSign1Base64 = coseSign1.toString("base64url");

  logCaseMetrics({
    caseId: "cose1",
    encoding: "raw",
    input,
    payload: cose1Claims,
    container: coseSign1,
    uncompressedContainer: ucCs1,
    signature: sgCs1,
  });
  logCaseMetrics({
    caseId: "cose1",
    encoding: "base45",
    input,
    payload: cose1Claims,
    container: coseSign1Base45,
    uncompressedContainer: base45.encode(ucCs1),
    signature: sgCs1,
  });
  logCaseMetrics({
    caseId: "cose1",
    encoding: "base64url",
    input,
    payload: cose1Claims,
    container: coseSign1Base64,
    uncompressedContainer: Buffer.from(ucCs1).toString("base64url"),
    signature: sgCs1,
  });

  logCaseMetrics({
    caseId: "jws",
    encoding: "base64url",
    input,
    payload: jwsClaims,
    container: jws,
    uncompressedContainer: jws,
    signature: sgJws,
  });
}

const targetQrVersion = 40;
const eccLevels = ["L", "M", "Q", "H"];

const capacityColumns = [
  "ecc_level",
  "type",
  "target_qr_version",
  "max_input_chars",
  "max_input_bytes",
  "qr_version_at_max",
];

const escapeCsv = (value) => {
  const text = String(value ?? "");
  if (/[",\n\r]/.test(text)) return `"${text.replace(/"/g, '""')}"`;
  return text;
};

const capacityRows = [];
for (const eccLevel of eccLevels) {
  const capacityByType = measureMaxInputCapacityForCurrentTypes({
    targetVersion: targetQrVersion,
    qrOptions: { ecc: eccLevel },
  });
  for (const [type, result] of Object.entries(capacityByType)) {
    capacityRows.push({
      ecc_level: eccLevel,
      type,
      target_qr_version: targetQrVersion,
      max_input_chars: result.maxInputChars,
      max_input_bytes: result.maxInputBytes,
      qr_version_at_max: result.qrVersionAtMax,
    });
  }
}

const capacityCsv = [
  capacityColumns.join(","),
  ...capacityRows.map((row) =>
    capacityColumns.map((column) => escapeCsv(row[column])).join(","),
  ),
].join("\n");

writeFileSync("capacity.csv", `${capacityCsv}\n`, "utf8");
