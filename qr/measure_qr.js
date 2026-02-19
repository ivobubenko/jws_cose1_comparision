import { QRCodeWriter, BarcodeFormat, EncodeHintType } from "@zxing/library";

export const measureMinQrVersion = (
  text,
  { ecc = "L", margin = 4, charset = "UTF-8" } = {},
) => {
  const baseHints = new Map();
  baseHints.set(EncodeHintType.ERROR_CORRECTION, ecc);
  baseHints.set(EncodeHintType.MARGIN, margin);
  baseHints.set(EncodeHintType.CHARACTER_SET, charset);

  const writer = new QRCodeWriter();

  for (let v = 1; v <= 40; v++) {
    const hints = new Map(baseHints);
    hints.set(EncodeHintType.QR_VERSION, v);
    try {
      writer.encode(text, BarcodeFormat.QR_CODE, 1, 1, hints);
      return v;
    } catch (e) {}
  }
  return null;
};
