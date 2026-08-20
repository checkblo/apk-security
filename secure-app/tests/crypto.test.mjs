import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { deriveKeys, encryptVault, decryptVault, clearKey } from "../lib/crypto.mjs";
import { VaultStore } from "../lib/vault.mjs";

test("AES-GCM detects tampering", async () => {
  const { encryptionKey, verificationKey } = await deriveKeys("poprawne bardzo dlugie haslo testowe 2026");
  try {
    const envelope = encryptVault({ secret: "wartosc" }, encryptionKey);
    assert.deepEqual(decryptVault(envelope, encryptionKey), { secret: "wartosc" });
    const bytes = Buffer.from(envelope.ciphertext, "base64");
    bytes[0] ^= 1;
    envelope.ciphertext = bytes.toString("base64");
    assert.throws(() => decryptVault(envelope, encryptionKey));
  } finally {
    clearKey(encryptionKey);
    clearKey(verificationKey);
  }
});

test("vault rejects a wrong password and persists encrypted mutations", async () => {
  const directory = await mkdtemp(join(tmpdir(), "cybertarcza-test-"));
  const store = new VaultStore(join(directory, "vault.json"));
  try {
    const password = "szesc losowych slow daje bezpieczne haslo glowne";
    const setupKey = await store.setup(password);
    clearKey(setupKey);
    await assert.rejects(() => store.unlock("zupelnie bledne haslo, ktore ma ponad 16 znakow"), /invalid_credentials/);
    const key = await store.unlock(password);
    try {
      await store.mutate(key, "test", (vault) => vault.completedControls.push("account-passkeys"));
      const value = await store.read(key);
      assert.ok(value.completedControls.includes("account-passkeys"));
      const backup = await store.exportEncrypted();
      assert.equal(backup.includes(Buffer.from("account-passkeys")), false);
      assert.equal(backup.includes(Buffer.from("Windows 11 IoT")), false);
    } finally {
      clearKey(key);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
