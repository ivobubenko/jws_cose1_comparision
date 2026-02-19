import jws from "jws";

export const createJWS = (claims, privateKey) => {
  const token = jws.sign({
    header: { typ: "JWT", alg: "ES256" },
    payload: claims,
    privateKey,
  });

  const [, , signaturePart] = token.split(".");

  return {
    jws: token,
    signature: signaturePart,
  };
};
