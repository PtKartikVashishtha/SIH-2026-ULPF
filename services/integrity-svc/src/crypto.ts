import { sign, verify, createHash, KeyObject, createPrivateKey, createPublicKey } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";

export function loadPrivateKey(pathOrPem: string): KeyObject {
  const pem = existsSync(pathOrPem) ? readFileSync(pathOrPem, "utf-8") : pathOrPem;
  return createPrivateKey(pem);
}

export function loadPublicKey(pathOrPem: string): KeyObject {
  const pem = existsSync(pathOrPem) ? readFileSync(pathOrPem, "utf-8") : pathOrPem;
  return createPublicKey(pem);
}

export function signData(data: Buffer | string, privateKey: KeyObject): string {
  const buf = typeof data === "string" ? Buffer.from(data, "utf-8") : data;
  const sigBuf = sign(null, buf, privateKey);
  return sigBuf.toString("hex");
}

export function verifySignature(data: Buffer | string, signatureHex: string, publicKey: KeyObject): boolean {
  try {
    const buf = typeof data === "string" ? Buffer.from(data, "utf-8") : data;
    const sigBuf = Buffer.from(signatureHex, "hex");
    return verify(null, buf, publicKey, sigBuf);
  } catch {
    return false;
  }
}

export function sha256(data: Buffer | string): string {
  const buf = typeof data === "string" ? Buffer.from(data, "utf-8") : data;
  return createHash("sha256").update(buf).digest("hex");
}
