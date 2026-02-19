import { decode, encode } from "cbor2";
import { deflateSync, inflateSync } from "node:zlib";
import { createSign, createVerify } from "node:crypto";

export const createCoseSign1 = (claims, privateKey) => {
  const payloadBytes = encode(claims);
  const protectedBytes = encode(new Map([[1, -7]]));
  const sigStructure = [
    "Signature1",
    protectedBytes,
    new Uint8Array(0),
    payloadBytes,
  ];

  const toSign = encode(sigStructure);
  const sign = createSign("SHA256");
  sign.update(toSign);
  sign.end();

  const sigP1363 = sign.sign({
    key: privateKey,
    dsaEncoding: "ieee-p1363",
  });

  const coseSign1 = [
    new Uint8Array(protectedBytes),
    new Map(),
    new Uint8Array(payloadBytes),
    new Uint8Array(sigP1363),
  ];
  return {
    coseSign1: deflateSync(encode(coseSign1)),
    uncompressedCoseSign1: encode(coseSign1),
    signature: sigP1363,
  };
};

export const verifyCoseSign1 = (cose1, publicKey) => {
  const inflated = inflateSync(cose1);
  const [protectedBytes, , payloadBytes, signature] = decode(inflated);
  const verify = createVerify("SHA256");

  verify.update(
    encode([
      "Signature1",
      new Uint8Array(protectedBytes),
      new Uint8Array(0),
      new Uint8Array(payloadBytes),
    ]),
  );
  verify.end();
  return verify.verify(
    { key: publicKey, dsaEncoding: "ieee-p1363" },
    signature,
  );
};
