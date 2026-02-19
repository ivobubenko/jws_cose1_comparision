import crypto from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
const randFloat = () => crypto.randomBytes(4).readUInt32BE(0) / 2 ** 32;

export const generateInputString = (
  sizeChars,
  { chunkChars = 24, reuse = 0.25 } = {},
) => {
  if (!Number.isInteger(sizeChars) || sizeChars < 0)
    throw new TypeError("sizeChars must be a non-negative integer");
  if (!Number.isInteger(chunkChars) || chunkChars <= 0)
    throw new TypeError("chunkChars must be a positive integer");
  if (typeof reuse !== "number" || reuse < 0 || reuse > 1)
    throw new TypeError("reuse must be in [0, 1]");
  if (sizeChars === 0) return "";

  const dict = [];
  let out = "";

  while (out.length < sizeChars) {
    let chunk;
    if (dict.length > 0 && randFloat() < reuse) {
      chunk = dict[crypto.randomInt(0, dict.length)];
    } else {
      const bytesNeeded = Math.ceil((chunkChars * 3) / 4);
      chunk = crypto
        .randomBytes(bytesNeeded)
        .toString("base64url")
        .slice(0, chunkChars);
      dict.push(chunk);
    }
    out += chunk;
  }

  writeFileSync("testdata.txt", out);
};
let cachedData = null;
let cachedPath = null;
export const makeSizedString = (
  sizeChars,
  { filePath = "testdata.txt", start = 0 } = {},
) => {
  if (cachedData === null || cachedPath !== filePath) {
    cachedData = readFileSync(filePath, "utf8");
    cachedPath = filePath;
  }

  const end = start + sizeChars;
  if (end > cachedData.length) {
    throw new RangeError(
      `testdata.txt too small: need ${end} chars, have ${cachedData.length}. Regenerate a bigger file.`,
    );
  }

  const s = cachedData.slice(start, end);
  if (!/^[A-Za-z0-9_-]*$/.test(s)) {
    throw new Error(
      "Loaded slice contains characters outside base64url alphabet.",
    );
  }
  return s;
};
