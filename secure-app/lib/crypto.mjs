import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual,
} from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);

export const KDF = Object.freeze({
  name: "scrypt",
  N: 131_072,
  r: 8,
  p: 1,
  keyLength: 64,
  maxmem: 384 * 1024 * 1024,
});

const VERIFY_CONTEXT = Buffer.from("cybertarcza/verifier/v1", "utf8");
const VAULT_AAD = Buffer.from("cybertarcza/vault/v1", "utf8");

export async function deriveKeys(password, saltBase64, params = KDF) {
  if (typeof password !== "string" || password.length < 16 || password.length > 512) {
    throw new Error("invalid_master_password");
  }

  const salt = saltBase64 ? Buffer.from(saltBase64, "base64") : randomBytes(32);
  if (salt.length !== 32) throw new Error("invalid_kdf_salt");

  const material = await scrypt(password.normalize("NFKC"), salt, params.keyLength, {
    N: params.N,
    r: params.r,
    p: params.p,
    maxmem: params.maxmem ?? KDF.maxmem,
  });

  const buffer = Buffer.from(material);
  const encryptionKey = Buffer.from(buffer.subarray(0, 32));
  const verificationKey = Buffer.from(buffer.subarray(32, 64));
  buffer.fill(0);

  return { encryptionKey, verificationKey, salt };
}

export function makeVerifier(verificationKey) {
  return createHmac("sha256", verificationKey).update(VERIFY_CONTEXT).digest();
}

export function verifyKey(verificationKey, verifierBase64) {
  const expected = Buffer.from(verifierBase64, "base64");
  const actual = makeVerifier(verificationKey);
  const valid = expected.length === actual.length && timingSafeEqual(expected, actual);
  actual.fill(0);
  return valid;
}

export function encryptVault(value, encryptionKey) {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey, nonce, {
    authTagLength: 16,
  });
  cipher.setAAD(VAULT_AAD);
  const plaintext = Buffer.from(JSON.stringify(value), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  plaintext.fill(0);

  return {
    algorithm: "AES-256-GCM",
    nonce: nonce.toString("base64"),
    tag: tag.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
}

export function decryptVault(envelope, encryptionKey) {
  if (envelope?.algorithm !== "AES-256-GCM") throw new Error("unsupported_encryption");

  const nonce = Buffer.from(envelope.nonce, "base64");
  const tag = Buffer.from(envelope.tag, "base64");
  const ciphertext = Buffer.from(envelope.ciphertext, "base64");
  if (nonce.length !== 12 || tag.length !== 16 || ciphertext.length > 4 * 1024 * 1024) {
    throw new Error("invalid_encrypted_vault");
  }

  const decipher = createDecipheriv("aes-256-gcm", encryptionKey, nonce, {
    authTagLength: 16,
  });
  decipher.setAAD(VAULT_AAD);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

  try {
    return JSON.parse(plaintext.toString("utf8"));
  } finally {
    plaintext.fill(0);
  }
}

export function clearKey(buffer) {
  if (Buffer.isBuffer(buffer)) buffer.fill(0);
}
