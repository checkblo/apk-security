import { mkdir, open, readFile, rename, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { randomBytes, randomUUID } from "node:crypto";
import {
  KDF,
  clearKey,
  decryptVault,
  deriveKeys,
  encryptVault,
  makeVerifier,
  verifyKey,
} from "./crypto.mjs";

const CONTROLS = Object.freeze([
  { id: "win-updates", area: "windows", weight: 10, label: "Automatyczne aktualizacje Windows 11 IoT", detail: "System oraz Microsoft Defender są aktualne." },
  { id: "win-bitlocker", area: "windows", weight: 9, label: "Szyfrowanie BitLocker", detail: "Dysk systemowy jest zaszyfrowany, a klucz odzyskiwania zapisany poza komputerem." },
  { id: "win-defender", area: "windows", weight: 9, label: "Defender, SmartScreen i zapora", detail: "Ochrona w czasie rzeczywistym, reputacja aplikacji i wszystkie profile zapory są włączone." },
  { id: "win-ransomware", area: "windows", weight: 7, label: "Ochrona przed ransomware", detail: "Kontrolowany dostęp do folderów i kopia offline są skonfigurowane." },
  { id: "android-updates", area: "android", weight: 8, label: "Aktualizacje Xiaomi 14 Pro 5G", detail: "HyperOS/Android oraz poprawki systemowe Google Play są aktualne." },
  { id: "android-advanced", area: "android", weight: 8, label: "Zaawansowana ochrona Android", detail: "Play Protect, ochrona przed kradzieżą i blokada instalacji z nieznanych źródeł są włączone." },
  { id: "android-lock", area: "android", weight: 6, label: "Silna blokada telefonu", detail: "PIN ma co najmniej 6 cyfr, powiadomienia są ukryte, a Find Hub aktywny." },
  { id: "router-admin", area: "router", weight: 8, label: "Unikalne hasło administratora routera Vectra", detail: "Hasło panelu routera jest inne niż hasło Wi-Fi." },
  { id: "router-radio", area: "router", weight: 8, label: "WPA3/WPA2-AES i wyłączone WPS", detail: "Nie jest używane WEP, WPA ani TKIP." },
  { id: "router-services", area: "router", weight: 7, label: "Wyłączone UPnP i zdalne zarządzanie", detail: "Panel administracyjny nie jest dostępny z internetu." },
  { id: "router-guest", area: "router", weight: 5, label: "Oddzielna sieć dla IoT i gości", detail: "Urządzenia smart-home nie mają dostępu do komputera i telefonu." },
  { id: "account-manager", area: "accounts", weight: 9, label: "Menedżer unikalnych haseł", detail: "Każde konto używa innego, losowego hasła." },
  { id: "account-passkeys", area: "accounts", weight: 9, label: "Passkeys lub dwa klucze sprzętowe", detail: "Poczta, konto Google i menedżer haseł mają odporne na phishing uwierzytelnianie." },
  { id: "account-recovery", area: "accounts", weight: 5, label: "Bezpieczne odzyskiwanie kont", detail: "Kody awaryjne są przechowywane offline, a zapasowy klucz jest w osobnym miejscu." },
]);

function defaultVault() {
  return {
    schema: 1,
    completedControls: [],
    assets: [
      { id: randomUUID(), type: "computer", name: "Windows 11 IoT", notes: "Komputer główny", createdAt: new Date().toISOString() },
      { id: randomUUID(), type: "phone", name: "Xiaomi 14 Pro 5G", notes: "Telefon Android", createdAt: new Date().toISOString() },
      { id: randomUUID(), type: "router", name: "Router Vectra", notes: "Model do uzupełnienia", createdAt: new Date().toISOString() },
    ],
    identities: [],
    scans: [],
    audit: [{ at: new Date().toISOString(), event: "vault_created" }],
  };
}

function cleanText(value, max) {
  if (typeof value !== "string") return "";
  return value.normalize("NFKC").replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, max);
}

function normalizeVault(value) {
  const controlIds = new Set(CONTROLS.map((item) => item.id));
  const completedControls = Array.isArray(value?.completedControls)
    ? [...new Set(value.completedControls.filter((id) => controlIds.has(id)))]
    : [];

  const assets = Array.isArray(value?.assets)
    ? value.assets.slice(0, 100).map((item) => ({
        id: typeof item.id === "string" ? item.id : randomUUID(),
        type: ["computer", "phone", "router", "iot", "other"].includes(item.type) ? item.type : "other",
        name: cleanText(item.name, 80),
        notes: cleanText(item.notes, 240),
        createdAt: typeof item.createdAt === "string" ? item.createdAt : new Date().toISOString(),
      })).filter((item) => item.name)
    : [];

  const identities = Array.isArray(value?.identities)
    ? value.identities.slice(0, 50).map((item) => ({
        id: typeof item.id === "string" ? item.id : randomUUID(),
        email: cleanText(item.email, 254).toLowerCase(),
        label: cleanText(item.label, 60),
        createdAt: typeof item.createdAt === "string" ? item.createdAt : new Date().toISOString(),
      })).filter((item) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(item.email))
    : [];

  const scans = Array.isArray(value?.scans) ? value.scans.slice(-100) : [];
  const audit = Array.isArray(value?.audit) ? value.audit.slice(-200) : [];
  return { schema: 1, completedControls, assets, identities, scans, audit };
}

export class VaultStore {
  constructor(filePath) {
    this.filePath = filePath;
    this.writeQueue = Promise.resolve();
  }

  async initializeDirectory() {
    await mkdir(dirname(this.filePath), { recursive: true, mode: 0o700 });
  }

  async exists() {
    try {
      const info = await stat(this.filePath);
      return info.isFile();
    } catch (error) {
      if (error?.code === "ENOENT") return false;
      throw error;
    }
  }

  async setup(password) {
    if (await this.exists()) throw new Error("already_initialized");
    await this.initializeDirectory();
    const salt = randomBytes(32);
    const { encryptionKey, verificationKey } = await deriveKeys(password, salt.toString("base64"));
    try {
      const document = {
        format: "cybertarcza-v1",
        createdAt: new Date().toISOString(),
        kdf: { name: KDF.name, N: KDF.N, r: KDF.r, p: KDF.p, salt: salt.toString("base64") },
        verifier: makeVerifier(verificationKey).toString("base64"),
        vault: encryptVault(defaultVault(), encryptionKey),
      };
      await this.writeDocument(document);
      return Buffer.from(encryptionKey);
    } finally {
      clearKey(encryptionKey);
      clearKey(verificationKey);
    }
  }

  async unlock(password) {
    const document = await this.readDocument();
    if (document?.format !== "cybertarcza-v1" || document?.kdf?.name !== "scrypt") {
      throw new Error("invalid_vault_format");
    }

    const params = {
      ...KDF,
      N: document.kdf.N,
      r: document.kdf.r,
      p: document.kdf.p,
    };
    if (params.N !== KDF.N || params.r !== KDF.r || params.p !== KDF.p) {
      throw new Error("unsupported_kdf_parameters");
    }

    const { encryptionKey, verificationKey } = await deriveKeys(password, document.kdf.salt, params);
    try {
      if (!verifyKey(verificationKey, document.verifier)) throw new Error("invalid_credentials");
      normalizeVault(decryptVault(document.vault, encryptionKey));
      return Buffer.from(encryptionKey);
    } finally {
      clearKey(encryptionKey);
      clearKey(verificationKey);
    }
  }

  async read(encryptionKey) {
    const document = await this.readDocument();
    return normalizeVault(decryptVault(document.vault, encryptionKey));
  }

  async mutate(encryptionKey, event, callback) {
    const operation = this.writeQueue.then(async () => {
      const document = await this.readDocument();
      const vault = normalizeVault(decryptVault(document.vault, encryptionKey));
      const result = await callback(vault);
      vault.audit.push({ at: new Date().toISOString(), event: cleanText(event, 80) });
      vault.audit = vault.audit.slice(-200);
      document.updatedAt = new Date().toISOString();
      document.vault = encryptVault(normalizeVault(vault), encryptionKey);
      await this.writeDocument(document);
      return result;
    });
    this.writeQueue = operation.catch(() => {});
    return operation;
  }

  async exportEncrypted() {
    return readFile(this.filePath);
  }

  async readDocument() {
    const raw = await readFile(this.filePath, "utf8");
    if (raw.length > 6 * 1024 * 1024) throw new Error("vault_too_large");
    return JSON.parse(raw);
  }

  async writeDocument(document) {
    const temporary = join(dirname(this.filePath), `.vault-${randomBytes(12).toString("hex")}.tmp`);
    const handle = await open(temporary, "wx", 0o600);
    try {
      await handle.writeFile(`${JSON.stringify(document)}\n`, { encoding: "utf8" });
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temporary, this.filePath);
  }
}

export { CONTROLS, cleanText };
