import { readFileSync } from "node:fs";

export function readPemKey(filePath) {
  const pem = readFileSync(filePath, { encoding: "utf8" });
  return pem.replace(/\r\n/g, "\n").trim() + "\n";
}
