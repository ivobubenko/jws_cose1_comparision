const ISS = "asphalesqr.com";
const SUB = "user:123";
const AUD = "asphalesqr-web";
const IAT = 1739616000;
const EXP = 1739619600;
const JTI_UUID = "550e8400-e29b-41d4-a716-446655440000";

function hexToBytes(hex) {
  const clean = hex.toLowerCase();
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function uuidToBytes(uuid) {
  return hexToBytes(uuid.replaceAll("-", ""));
}

export function makeEquivalentClaims(input) {
  const jwsClaims = {
    iss: ISS,
    sub: SUB,
    aud: AUD,
    iat: IAT,
    exp: EXP,
    jti: JTI_UUID,
    data: input,
  };

  const cose1Claims = new Map([
    [1, ISS],
    [2, SUB],
    [3, AUD],
    [6, IAT],
    [4, EXP],
    [7, uuidToBytes(JTI_UUID)],
    [1000, input],
  ]);

  return { jwsClaims, cose1Claims };
}
