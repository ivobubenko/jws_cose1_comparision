import base64url from "base64url";
import base45 from "base45";
import jws from "jws";
import { decodePayloadBuffer, preparePayloadBuffer, toBuffer } from "./helper.js";

function createJwsHeader(options = {}) {
  const header = {
    alg: "HS256",
    typ: "JWT",
  };

  if (options.compress) {
    header.zip = "DEF";
  }

  return header;
}

function prepareJwsPayload(payload, options = {}) {
  return preparePayloadBuffer(payload, Boolean(options.compress));
}

function encodeJwsPayload(payloadBytes) {
  return base64url(payloadBytes);
}

function signJwsToken(header, payloadForSigning, secret) {
  return jws.sign({
    header,
    payload: payloadForSigning,
    secret: toBuffer(secret),
  });
}

function parseJwsToken(token) {
  const parts = String(token).split(".");

  if (parts.length !== 3) {
    throw new Error("Invalid JWS format");
  }

  return {
    encodedHeader: parts[0],
    encodedPayload: parts[1],
    encodedSignature: parts[2],
  };
}

function decodeJwsHeader(tokenOrEncodedHeader) {
  const encodedHeader = String(tokenOrEncodedHeader).includes(".")
    ? parseJwsToken(tokenOrEncodedHeader).encodedHeader
    : tokenOrEncodedHeader;

  const headerText = base64url.toBuffer(encodedHeader).toString("utf8");
  return JSON.parse(headerText);
}

function decodeJwsPayload(encodedPayload, header = {}) {
  const payloadBytes = base64url.toBuffer(encodedPayload);

  if (header.zip === "DEF") {
    const compressedPayload = base64url.toBuffer(payloadBytes.toString("utf8"));
    return decodePayloadBuffer(compressedPayload, true);
  }

  return decodePayloadBuffer(payloadBytes, false);
}

function verifyJwsSignature(token, secret) {
  return jws.verify(token, "HS256", toBuffer(secret));
}

function encodeJwsToken(compactToken, tokenEncoding = "base64url") {
  if (tokenEncoding === "base64url") {
    return compactToken;
  }

  if (tokenEncoding === "base64") {
    return Buffer.from(compactToken, "utf8").toString("base64");
  }

  if (tokenEncoding === "base45") {
    return base45.encode(Uint8Array.from(Buffer.from(compactToken, "utf8")));
  }

  throw new Error("Unsupported JWS token encoding");
}

function decodeJwsToken(token, tokenEncoding = "base64url") {
  if (tokenEncoding === "base64url") {
    return String(token);
  }

  if (tokenEncoding === "base64") {
    return Buffer.from(String(token), "base64").toString("utf8");
  }

  if (tokenEncoding === "base45") {
    const decodedBytes = Buffer.from(base45.decode(String(token)));
    return decodedBytes.toString("utf8");
  }

  throw new Error("Unsupported JWS token encoding");
}

function createJws(payload, secret, options = {}) {
  const header = createJwsHeader(options);
  const payloadBytes = prepareJwsPayload(payload, options);
  const payloadForSigning = options.compress
    ? base64url(payloadBytes)
    : payloadBytes.toString("utf8");
  const compactToken = signJwsToken(header, payloadForSigning, secret);
  const parsed = parseJwsToken(compactToken);
  const token = encodeJwsToken(compactToken, options.tokenEncoding ?? "base64url");

  return {
    token,
    header,
    payload: payloadBytes,
    encodedPayload: parsed.encodedPayload,
    signature: parsed.encodedSignature,
  };
}

function verifyJws(token, secret, options = {}) {
  const compactToken = decodeJwsToken(token, options.tokenEncoding ?? "base64url");
  const parsed = parseJwsToken(compactToken);
  const header = decodeJwsHeader(compactToken);
  const valid = verifyJwsSignature(compactToken, secret);

  if (!valid) {
    return {
      valid: false,
      header,
      payload: null,
    };
  }

  const payload = decodeJwsPayload(parsed.encodedPayload, header);

  return {
    valid: true,
    header,
    payload,
  };
}

export {
  createJwsHeader,
  prepareJwsPayload,
  encodeJwsPayload,
  encodeJwsToken,
  decodeJwsToken,
  signJwsToken,
  parseJwsToken,
  decodeJwsHeader,
  decodeJwsPayload,
  verifyJwsSignature,
  createJws,
  verifyJws,
};
