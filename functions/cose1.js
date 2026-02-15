import crypto from "node:crypto";
import base64url from "base64url";
import base45 from "base45";
import zlib from "node:zlib";
import { createRequire } from "node:module";
import {
  decodePayloadBuffer,
  preparePayloadBuffer,
  toBuffer,
} from "./helper.js";

const require = createRequire(import.meta.url);
const { decode, encode } = require("cbor");
const COSE_HEADER_ALG = 1;
const COSE_ALG_HMAC_256_256 = 5;

function createCoseProtectedHeader(options = {}) {
  const header = new Map();
  header.set(COSE_HEADER_ALG, COSE_ALG_HMAC_256_256);

  if (options.compress) {
    header.set("zip", "DEF");
  }

  return header;
}

function prepareCosePayload(payload, options = {}) {
  return preparePayloadBuffer(payload, Boolean(options.compress), encode);
}

function createCoseSigStructure(
  protectedHeaderBytes,
  payloadBytes,
  externalAad = Buffer.alloc(0),
) {
  const structure = [
    "Signature1",
    protectedHeaderBytes,
    externalAad,
    payloadBytes,
  ];
  return encode(structure);
}

function createCoseSignature(sigStructureBytes, secret) {
  const hmac = crypto.createHmac("sha256", toBuffer(secret));
  hmac.update(sigStructureBytes);
  return hmac.digest();
}

function decodeCoseSign1(coseBytesOrToken) {
  const bytes = Buffer.isBuffer(coseBytesOrToken)
    ? coseBytesOrToken
    : base64url.toBuffer(coseBytesOrToken);
  const decoded = decode(bytes);

  if (!Array.isArray(decoded) || decoded.length !== 4) {
    throw new Error("Invalid COSE_Sign1 structure");
  }

  return {
    bytes,
    protectedHeaderBytes: decoded[0],
    unprotectedHeader: decoded[1],
    payloadBytes: decoded[2],
    signatureBytes: decoded[3],
  };
}

function encodeCoseToken(tokenBytes, tokenEncoding = "base64url") {
  if (tokenEncoding === "base64url") {
    return base64url(tokenBytes);
  }

  if (tokenEncoding === "base64") {
    return Buffer.from(tokenBytes).toString("base64");
  }

  if (tokenEncoding === "base45") {
    return base45.encode(Uint8Array.from(tokenBytes));
  }

  throw new Error("Unsupported COSE token encoding");
}

function decodeCoseToken(token, tokenEncoding = "base64url") {
  if (tokenEncoding === "base64url") {
    return base64url.toBuffer(token);
  }

  if (tokenEncoding === "base64") {
    return Buffer.from(String(token), "base64");
  }

  if (tokenEncoding === "base45") {
    return Buffer.from(base45.decode(String(token)));
  }

  throw new Error("Unsupported COSE token encoding");
}

function decodeCoseSign1WithEncoding(
  coseBytesOrToken,
  tokenEncoding = "base64url",
) {
  if (Buffer.isBuffer(coseBytesOrToken)) {
    return decodeCoseSign1(coseBytesOrToken);
  }

  const tokenBytes = decodeCoseToken(coseBytesOrToken, tokenEncoding);
  return decodeCoseSign1(tokenBytes);
}

function decodeCosePayload(payloadBytes, protectedHeader = new Map()) {
  const isCompressed =
    protectedHeader instanceof Map && protectedHeader.get("zip") === "DEF";
  const normalizedPayload = isCompressed
    ? zlib.inflateRawSync(payloadBytes)
    : payloadBytes;

  try {
    const decodedPayload = decode(normalizedPayload);

    if (Buffer.isBuffer(decodedPayload)) {
      return decodePayloadBuffer(decodedPayload, false);
    }

    return decodedPayload;
  } catch {
    return decodePayloadBuffer(normalizedPayload, false);
  }
}

function verifyCoseSignature(sigStructureBytes, signatureBytes, secret) {
  const expected = createCoseSignature(sigStructureBytes, secret);

  if (expected.length !== signatureBytes.length) {
    return false;
  }

  return crypto.timingSafeEqual(expected, signatureBytes);
}

function createCose1(payload, secret, options = {}) {
  const protectedHeader = createCoseProtectedHeader(options);
  const protectedHeaderBytes = encode(protectedHeader);
  const unprotectedHeader = new Map();
  const payloadBytes = prepareCosePayload(payload, options);
  const sigStructureBytes = createCoseSigStructure(
    protectedHeaderBytes,
    payloadBytes,
  );
  const signatureBytes = createCoseSignature(sigStructureBytes, secret);
  const coseSign1Object = [
    protectedHeaderBytes,
    unprotectedHeader,
    payloadBytes,
    signatureBytes,
  ];
  const tokenBytes = encode(coseSign1Object);
  const token = encodeCoseToken(
    tokenBytes,
    options.tokenEncoding ?? "base64url",
  );

  return {
    token,
    tokenBytes,
    protectedHeader,
    payload: payloadBytes,
    signature: signatureBytes,
  };
}

function verifyCose1(tokenOrBytes, secret, options = {}) {
  const parsed = decodeCoseSign1WithEncoding(
    tokenOrBytes,
    options.tokenEncoding ?? "base64url",
  );
  const protectedHeader = decode(parsed.protectedHeaderBytes);
  const sigStructureBytes = createCoseSigStructure(
    parsed.protectedHeaderBytes,
    parsed.payloadBytes,
  );
  const valid = verifyCoseSignature(
    sigStructureBytes,
    parsed.signatureBytes,
    secret,
  );

  if (!valid) {
    return {
      valid: false,
      protectedHeader,
      payload: null,
    };
  }

  const payload = decodeCosePayload(parsed.payloadBytes, protectedHeader);

  return {
    valid: true,
    protectedHeader,
    unprotectedHeader: parsed.unprotectedHeader,
    payload,
  };
}

export {
  COSE_HEADER_ALG,
  COSE_ALG_HMAC_256_256,
  createCoseProtectedHeader,
  prepareCosePayload,
  createCoseSigStructure,
  createCoseSignature,
  encodeCoseToken,
  decodeCoseToken,
  decodeCoseSign1,
  decodeCoseSign1WithEncoding,
  decodeCosePayload,
  verifyCoseSignature,
  createCose1,
  verifyCose1,
};
