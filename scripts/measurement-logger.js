import base45 from "base45";
import { createRequire } from "node:module";
import { decodeCoseToken } from "../functions/cose1.js";
import { decodeJwsToken } from "../functions/jws.js";

const require = createRequire(import.meta.url);
const { encode } = require("cbor");

function utf8Size(value) {
  return Buffer.byteLength(String(value), "utf8");
}

function base64SizeFromBytes(bytes) {
  return Buffer.from(bytes).toString("base64").length;
}

function base45SizeFromBytes(bytes) {
  return base45.encode(Uint8Array.from(bytes)).length;
}

function jwsSignedBytes(jwsResult, tokenEncoding = "base64url") {
  const compactToken = decodeJwsToken(jwsResult.token, tokenEncoding);
  return Buffer.from(compactToken, "utf8");
}

function coseSignedBytes(cose1Result, tokenEncoding = "base64url") {
  if (Buffer.isBuffer(cose1Result.tokenBytes)) {
    return cose1Result.tokenBytes;
  }

  return decodeCoseToken(cose1Result.token, tokenEncoding);
}

function collectPairLog(
  label,
  jwsResult,
  cose1Result,
  { tokenEncoding = "base64url" } = {},
) {
  const jwsBytes = jwsSignedBytes(jwsResult, tokenEncoding);
  const coseBytes = coseSignedBytes(cose1Result, tokenEncoding);
  const jwsHeaderSize = utf8Size(JSON.stringify(jwsResult.header ?? {}));
  const coseHeaderSize =
    cose1Result.protectedHeader instanceof Map
      ? encode(cose1Result.protectedHeader).length
      : 0;

  return {
    label,
    tokenEncoding,
    jws: {
      headerSizeBytes: jwsHeaderSize,
      payloadSizeBytes: Buffer.isBuffer(jwsResult.payload)
        ? jwsResult.payload.length
        : utf8Size(""),
      tokenTransportSizeBytes: utf8Size(jwsResult.token),
      tokenRawSizeBytes: jwsBytes.length,
      tokenBase64SizeBytes: base64SizeFromBytes(jwsBytes),
      tokenBase45SizeBytes: base45SizeFromBytes(jwsBytes),
    },
    cose1: {
      headerSizeBytes: coseHeaderSize,
      payloadSizeBytes: Buffer.isBuffer(cose1Result.payload)
        ? cose1Result.payload.length
        : utf8Size(""),
      tokenTransportSizeBytes: utf8Size(cose1Result.token),
      tokenRawSizeBytes: coseBytes.length,
      tokenBase64SizeBytes: base64SizeFromBytes(coseBytes),
      tokenBase45SizeBytes: base45SizeFromBytes(coseBytes),
    },
  };
}

function printPairLog(pairLog) {
  const rows = [
    {
      label: pairLog.label,
      algorithm: "jws",
      encoding: pairLog.tokenEncoding,
      headerSizeBytes: pairLog.jws.headerSizeBytes,
      payloadSizeBytes: pairLog.jws.payloadSizeBytes,
      tokenTransportSizeBytes: pairLog.jws.tokenTransportSizeBytes,
      tokenRawSizeBytes: pairLog.jws.tokenRawSizeBytes,
      tokenBase64SizeBytes: pairLog.jws.tokenBase64SizeBytes,
      tokenBase45SizeBytes: pairLog.jws.tokenBase45SizeBytes,
    },
    {
      label: pairLog.label,
      algorithm: "cose1",
      encoding: pairLog.tokenEncoding,
      headerSizeBytes: pairLog.cose1.headerSizeBytes,
      payloadSizeBytes: pairLog.cose1.payloadSizeBytes,
      tokenTransportSizeBytes: pairLog.cose1.tokenTransportSizeBytes,
      tokenRawSizeBytes: pairLog.cose1.tokenRawSizeBytes,
      tokenBase64SizeBytes: pairLog.cose1.tokenBase64SizeBytes,
      tokenBase45SizeBytes: pairLog.cose1.tokenBase45SizeBytes,
    },
  ];

  console.table(rows);
}

function logsToMarkdown(pairLogs) {
  const header = [
    "| Label | Encoding | Algorithm | Header_Bytes | Payload_Bytes | Transport_Bytes | Raw_Bytes | Base64_Bytes | Base45_Bytes |",
    "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
  ];

  const rows = pairLogs.flatMap((pairLog) => [
    `| ${pairLog.label} | ${pairLog.tokenEncoding} | jws | ${pairLog.jws.headerSizeBytes} | ${pairLog.jws.payloadSizeBytes} | ${pairLog.jws.tokenTransportSizeBytes} | ${pairLog.jws.tokenRawSizeBytes} | ${pairLog.jws.tokenBase64SizeBytes} | ${pairLog.jws.tokenBase45SizeBytes} |`,
    `| ${pairLog.label} | ${pairLog.tokenEncoding} | cose1 | ${pairLog.cose1.headerSizeBytes} | ${pairLog.cose1.payloadSizeBytes} | ${pairLog.cose1.tokenTransportSizeBytes} | ${pairLog.cose1.tokenRawSizeBytes} | ${pairLog.cose1.tokenBase64SizeBytes} | ${pairLog.cose1.tokenBase45SizeBytes} |`,
  ]);

  return [...header, ...rows, ""].join("\n");
}

export { collectPairLog, printPairLog, logsToMarkdown };
