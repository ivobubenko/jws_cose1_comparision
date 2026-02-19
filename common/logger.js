import { encode } from "cbor2";
import { appendFileSync, existsSync, writeFileSync } from "node:fs";
import { measureMinQrVersion } from "../qr/measure_qr.js";

const METRIC_COLUMNS = [
  "case_id",
  "encoding",
  "input_bytes",
  "input_length",
  "payload_bytes",
  "final_size_wo_compression",
  "final_size",
  "signature_bytes",
  "min_qr_version",
];

const ALLOWED_ENCODINGS = new Set(["base45", "base64url", "raw"]);
const DEFAULT_CSV_PATH = "metrics.csv";
const UTF8_ENCODER = new TextEncoder();

function safeJsonStringify(value) {
  const seen = new WeakSet();
  return JSON.stringify(value, (key, currentValue) => {
    if (typeof currentValue === "bigint") return currentValue.toString();
    if (currentValue && typeof currentValue === "object") {
      if (seen.has(currentValue)) return "[Circular]";
      seen.add(currentValue);
    }
    return currentValue;
  });
}

function toUtf8Uint8Array(value) {
  return UTF8_ENCODER.encode(String(value));
}

function toUint8Array(value) {
  if (value === null || value === undefined) return new Uint8Array(0);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  return toUtf8Uint8Array(value);
}

function byteSizeOf(value) {
  if (value === null || value === undefined) return 0;
  if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) {
    return toUint8Array(value).byteLength;
  }
  if (typeof value === "string") return toUtf8Uint8Array(value).byteLength;
  if (
    value instanceof Map ||
    value instanceof Set ||
    typeof value === "object"
  ) {
    return toUtf8Uint8Array(safeJsonStringify(value)).byteLength;
  }
  return toUtf8Uint8Array(value).byteLength;
}

function payloadByteSize(payload) {
  if (payload === null || payload === undefined) return 0;
  if (payload instanceof Map) return toUint8Array(encode(payload)).byteLength;
  if (typeof payload === "object" && !ArrayBuffer.isView(payload)) {
    return toUtf8Uint8Array(safeJsonStringify(payload)).byteLength;
  }
  return byteSizeOf(payload);
}

function signatureByteSize(signature) {
  if (signature === null || signature === undefined) return 0;
  if (ArrayBuffer.isView(signature) || signature instanceof ArrayBuffer) {
    return toUint8Array(signature).byteLength;
  }
  if (typeof signature === "string") {
    try {
      return toUint8Array(Buffer.from(signature, "base64url")).byteLength;
    } catch {
      return toUtf8Uint8Array(signature).byteLength;
    }
  }
  return byteSizeOf(signature);
}

function toQrText(container, encoding) {
  if (typeof container === "string") return container;
  if (ArrayBuffer.isView(container) || container instanceof ArrayBuffer) {
    const bytes = toUint8Array(container);
    if (encoding === "raw") {
      return Buffer.from(bytes).toString("base64url");
    }
    return Buffer.from(bytes).toString("latin1");
  }
  return String(container ?? "");
}

function minQrVersion(container, encoding) {
  try {
    const text = toQrText(container, encoding);
    return measureMinQrVersion(text);
  } catch {
    return null;
  }
}

function formatMetricRow(row) {
  return METRIC_COLUMNS.map((column) =>
    String(row[column]).replace(/\t/g, " "),
  ).join("\t");
}

function escapeCsvValue(value) {
  const text = String(value ?? "");
  if (/[",\n\r]/.test(text)) {
    return `"${text.replace(/"/g, '""')}"`;
  }
  return text;
}

function formatCsvRow(row) {
  return METRIC_COLUMNS.map((column) => escapeCsvValue(row[column])).join(",");
}

export function printMetricsHeader({ csvPath = DEFAULT_CSV_PATH } = {}) {
  console.log(METRIC_COLUMNS.join("\t"));
  writeFileSync(csvPath, `${METRIC_COLUMNS.join(",")}\n`, "utf8");
}

export function buildCaseMetrics({
  caseId,
  encoding,
  input,
  uncompressedContainer,
  payload,
  container,
  signature,
}) {
  if (!ALLOWED_ENCODINGS.has(encoding)) {
    throw new Error(
      `Unsupported encoding '${encoding}'. Use base45 or base64url.`,
    );
  }

  const payloadBytes = payloadByteSize(payload);
  const bytesTotal = byteSizeOf(container);
  const uncompressedBytes = byteSizeOf(uncompressedContainer);
  const signatureBytes = signatureByteSize(signature);
  const inputBytes = byteSizeOf(input);
  const inputLength =
    input === null || input === undefined ? 0 : String(input).length;
  const qrVersion = minQrVersion(container, encoding);

  return {
    case_id: caseId,
    encoding,
    input_bytes: inputBytes,
    input_length: inputLength,
    payload_bytes: payloadBytes,
    final_size: bytesTotal,
    final_size_wo_compression: uncompressedBytes,
    signature_bytes: signatureBytes,
    min_qr_version: qrVersion,
  };
}

export function logCaseMetrics(params, { csvPath = DEFAULT_CSV_PATH } = {}) {
  const metrics = buildCaseMetrics(params);
  console.log(formatMetricRow(metrics));
  if (!existsSync(csvPath)) {
    writeFileSync(csvPath, `${METRIC_COLUMNS.join(",")}\n`, "utf8");
  }
  appendFileSync(csvPath, `${formatCsvRow(metrics)}\n`, "utf8");
  return metrics;
}
