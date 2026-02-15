import zlib from "node:zlib";

function toBuffer(value) {
  if (Buffer.isBuffer(value)) {
    return value;
  }

  if (value instanceof Uint8Array) {
    return Buffer.from(value);
  }

  if (typeof value === "string") {
    return Buffer.from(value, "utf8");
  }

  return Buffer.from(JSON.stringify(value), "utf8");
}

function preparePayloadBuffer(payload, compress = false, serializer = toBuffer) {
  const rawPayload = serializer(payload);

  if (compress) {
    return zlib.deflateRawSync(rawPayload);
  }

  return rawPayload;
}


function decodePayloadBuffer(payloadBytes, compressed = false) {
  const normalizedPayload = compressed
    ? zlib.inflateRawSync(payloadBytes)
    : payloadBytes;
  const payloadText = normalizedPayload.toString("utf8");

  try {
    return JSON.parse(payloadText);
  } catch {
    return payloadText;
  }
}

export { toBuffer, preparePayloadBuffer, decodePayloadBuffer };
