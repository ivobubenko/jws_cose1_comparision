import base45 from "base45";
import { makeSizedString } from "../common/generate_payload.js";
import { makeEquivalentClaims } from "../common/claims.js";
import { readPemKey } from "../common/read_key.js";
import { createCoseSign1 } from "../cose_sign1/cose_sign1.js";
import { createJWS } from "../jws/jws.js";
import { measureMinQrVersion } from "./measure_qr.js";

const DEFAULT_TARGET_VERSION = 40;
const DEFAULT_MAX_INPUT_CHARS = 1 << 16;
const DEFAULT_START_CHARS = 64;

function assertPositiveInt(value, name) {
  if (!Number.isInteger(value) || value < 0) {
    throw new TypeError(`${name} must be a non-negative integer`);
  }
}

function evaluateSize({
  sizeChars,
  makeInput,
  makeTokenText,
  targetVersion,
  qrOptions,
}) {
  const input = makeInput(sizeChars);
  const tokenText = makeTokenText(input);
  const qrVersion = measureMinQrVersion(tokenText, qrOptions);
  const fits = qrVersion !== null && qrVersion <= targetVersion;

  return { sizeChars, input, tokenText, qrVersion, fits };
}

export function measureMaxInputCapacityForType({
  targetVersion = DEFAULT_TARGET_VERSION,
  makeTokenText,
  makeInput = makeSizedString,
  qrOptions = {},
  maxInputChars = DEFAULT_MAX_INPUT_CHARS,
  startChars = DEFAULT_START_CHARS,
} = {}) {
  if (typeof makeTokenText !== "function") {
    throw new TypeError("makeTokenText must be a function");
  }
  if (typeof makeInput !== "function") {
    throw new TypeError("makeInput must be a function");
  }
  assertPositiveInt(targetVersion, "targetVersion");
  assertPositiveInt(maxInputChars, "maxInputChars");
  assertPositiveInt(startChars, "startChars");

  const initial = evaluateSize({
    sizeChars: 0,
    makeInput,
    makeTokenText,
    targetVersion,
    qrOptions,
  });

  if (!initial.fits) {
    return {
      maxInputChars: null,
      maxInputBytes: null,
      qrVersionAtMax: null,
      firstFail: initial,
    };
  }

  let low = initial;
  let highSize = Math.max(1, startChars);
  let high = null;

  while (highSize <= maxInputChars) {
    const probe = evaluateSize({
      sizeChars: highSize,
      makeInput,
      makeTokenText,
      targetVersion,
      qrOptions,
    });

    if (!probe.fits) {
      high = probe;
      break;
    }

    low = probe;
    highSize *= 2;
  }

  if (high === null) {
    return {
      maxInputChars: low.sizeChars,
      maxInputBytes: Buffer.byteLength(low.input, "utf8"),
      qrVersionAtMax: low.qrVersion,
      tokenCharsAtMax: low.tokenText.length,
      reachedSearchLimit: low.sizeChars === maxInputChars,
      nextFailSizeChars: null,
    };
  }

  let left = low.sizeChars;
  let right = high.sizeChars;
  let best = low;
  let firstFail = high;

  while (left + 1 < right) {
    const mid = Math.floor((left + right) / 2);
    const probe = evaluateSize({
      sizeChars: mid,
      makeInput,
      makeTokenText,
      targetVersion,
      qrOptions,
    });

    if (probe.fits) {
      best = probe;
      left = mid;
    } else {
      firstFail = probe;
      right = mid;
    }
  }

  return {
    maxInputChars: best.sizeChars,
    maxInputBytes: Buffer.byteLength(best.input, "utf8"),
    qrVersionAtMax: best.qrVersion,
    tokenCharsAtMax: best.tokenText.length,
    reachedSearchLimit: false,
    nextFailSizeChars: firstFail.sizeChars,
  };
}

export function makeCurrentTypeTokenBuilders({ privateKey }) {
  if (!privateKey) throw new TypeError("privateKey is required");

  return {
    cose1_base45: (input) => {
      const { cose1Claims } = makeEquivalentClaims(input);
      const { coseSign1 } = createCoseSign1(cose1Claims, privateKey);
      return base45.encode(coseSign1);
    },
    cose1_base64url: (input) => {
      const { cose1Claims } = makeEquivalentClaims(input);
      const { coseSign1 } = createCoseSign1(cose1Claims, privateKey);
      return Buffer.from(coseSign1).toString("base64url");
    },
    jws_base64url: (input) => {
      const { jwsClaims } = makeEquivalentClaims(input);
      const { jws } = createJWS(jwsClaims, privateKey);
      return jws;
    },
  };
}

export function measureMaxInputCapacityForCurrentTypes({
  targetVersion = DEFAULT_TARGET_VERSION,
  qrOptions = {},
  privateKeyPath = "private_key.txt",
  makeInput = makeSizedString,
  maxInputChars = DEFAULT_MAX_INPUT_CHARS,
  startChars = DEFAULT_START_CHARS,
} = {}) {
  const privateKey = readPemKey(privateKeyPath);
  const builders = makeCurrentTypeTokenBuilders({ privateKey });
  const out = {};

  for (const [type, makeTokenText] of Object.entries(builders)) {
    out[type] = measureMaxInputCapacityForType({
      targetVersion,
      makeTokenText,
      makeInput,
      qrOptions,
      maxInputChars,
      startChars,
    });
  }

  return out;
}
