import { readFile, readdir } from "node:fs/promises";
import { extname, join, relative } from "node:path";

const root = process.cwd();
const checks = [];

function pass(name) {
  checks.push({ name, ok: true });
}

function assert(condition, name) {
  if (!condition) throw new Error(name);
  pass(name);
}

async function text(path) {
  return readFile(join(root, path), "utf8");
}

async function files(path, output = []) {
  for (const entry of await readdir(path, { withFileTypes: true })) {
    if ([".git", "node_modules", ".next", ".sites-runtime", "release"].includes(entry.name)) continue;
    const absolute = join(path, entry.name);
    if (entry.isDirectory()) await files(absolute, output);
    else output.push(absolute);
  }
  return output;
}

const required = [
  "Dockerfile", "docker-compose.yml", "Caddyfile", "secure-app/server.mjs",
  "secure-app/lib/crypto.mjs", "secure-app/lib/vault.mjs", "secure-app/lib/eu-compliance.mjs",
  "secure-app/public/index.html", "secure-app/public/app.js", "secure-app/public/styles.css",
  "secure-app/tests/crypto.test.mjs", "secure-app/tests/server.test.mjs",
  "secure-app/tests/eu-compliance.test.mjs", "android/app/src/main/AndroidManifest.xml",
];

for (const path of required) {
  await readFile(join(root, path));
}
pass("komplet wymaganych plików");

const compose = await text("docker-compose.yml");
assert(compose.includes('"127.0.0.1:8443:8443"'), "Docker publikuje usługę tylko na localhost");
assert((compose.match(/cap_drop:\s*\n\s*- ALL/g) ?? []).length === 2, "oba kontenery usuwają capabilities");
assert((compose.match(/read_only: true/g) ?? []).length === 2, "oba kontenery mają system plików tylko do odczytu");
assert(!/docker\.sock/i.test(compose), "brak montowania Docker Socket");

const dockerfile = await text("Dockerfile");
assert(/^FROM node:24-alpine$/m.test(dockerfile), "obraz aplikacji używa Node 24 Alpine");
assert(/^USER 1000:1000$/m.test(dockerfile), "aplikacja działa jako użytkownik bez roota");
assert(dockerfile.includes("--frozen-intrinsics"), "Node uruchamia się z zamrożonymi intrinsics");

const server = await text("secure-app/server.mjs");
for (const header of ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "Permissions-Policy", "Cross-Origin-Resource-Policy"]) {
  assert(server.includes(header), `nagłówek bezpieczeństwa: ${header}`);
}
assert(server.includes("requireSession(request, response, true)"), "mutacje API wymagają sesji i CSRF");

const html = await text("secure-app/public/index.html");
const app = await text("secure-app/public/app.js");
const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]);
const duplicateIds = ids.filter((id, index) => ids.indexOf(id) !== index);
const selectors = [...app.matchAll(/\$\("#([A-Za-z0-9_-]+)"\)/g)].map((match) => match[1]);
const missingIds = [...new Set(selectors)].filter((id) => !ids.includes(id));
assert(duplicateIds.length === 0, "interfejs nie ma zduplikowanych identyfikatorów");
assert(missingIds.length === 0, "każdy selektor UI wskazuje istniejący element");
for (const endpoint of ["/api/compliance/rights", "/api/compliance/incidents", "/api/compliance/vulnerabilities", "/api/compliance/components", "/api/compliance/evidence"]) {
  assert(server.includes(endpoint) && app.includes(endpoint), `usługa end-to-end: ${endpoint}`);
}

const manifest = await text("android/app/src/main/AndroidManifest.xml");
assert(manifest.includes('android:allowBackup="false"'), "Android blokuje kopię danych aplikacji");
assert(manifest.includes('android:usesCleartextTraffic="false"'), "Android blokuje nieszyfrowany HTTP");
assert(!/<uses-permission/i.test(manifest), "Android nie żąda uprawnień systemowych");

const secretPatterns = [
  /-----BEGIN (?:RSA|OPENSSH|EC|DSA) PRIVATE KEY-----/,
  /\bghp_[A-Za-z0-9]{30,}\b/,
  /\bgithub_pat_[A-Za-z0-9_]{50,}\b/,
  /\bAKIA[0-9A-Z]{16}\b/,
];
const readable = new Set([".js", ".mjs", ".ts", ".tsx", ".java", ".kt", ".kts", ".json", ".yml", ".yaml", ".md", ".txt", ".ps1", ".sh", ".xml", ".css", ".html"]);
const leaked = [];
for (const path of await files(root)) {
  if (!readable.has(extname(path).toLowerCase()) && !["Dockerfile", "Caddyfile"].includes(path.split("/").at(-1))) continue;
  const content = await readFile(path, "utf8");
  if (secretPatterns.some((pattern) => pattern.test(content))) leaked.push(relative(root, path));
}
assert(leaked.length === 0, "brak prywatnych kluczy i typowych tokenów w źródłach");

console.log(`CyberTarcza: ${checks.length}/${checks.length} kontroli wydania zaliczonych.`);
for (const check of checks) console.log(`  OK  ${check.name}`);
