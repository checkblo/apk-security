import { createServer } from "node:http";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { clearKey } from "./lib/crypto.mjs";
import { CONTROLS, VaultStore, cleanText } from "./lib/vault.mjs";
import {
  EU_PROFILES,
  RECORD_STATUSES,
  VULNERABILITY_STATUSES,
  buildComplianceExport,
  buildComplianceSummary,
  buildCycloneDx,
  buildDeadlineList,
  createComponent,
  createEvidence,
  createIncident,
  createRightRequest,
  createVulnerability,
  defaultCompliance,
} from "./lib/eu-compliance.mjs";

const ROOT = dirname(fileURLToPath(import.meta.url));
const PUBLIC = join(ROOT, "public");
const PORT = Number.parseInt(process.env.PORT ?? "3000", 10);
const HOST = process.env.HOST ?? "0.0.0.0";
const APP_ORIGIN = process.env.APP_ORIGIN ?? "https://localhost:8443";
const COOKIE_SECURE = process.env.COOKIE_SECURE !== "0";
const DISABLE_EXTERNAL_CHECKS = process.env.DISABLE_EXTERNAL_CHECKS === "1";
const DATA_FILE = process.env.DATA_FILE ?? "/data/cybertarcza.vault";
const HIBP_KEY_FILE = process.env.HIBP_API_KEY_FILE ?? "/run/secrets/hibp_api_key";
const BODY_LIMIT = 64 * 1024;
const SESSION_IDLE_MS = 30 * 60 * 1000;
const SESSION_MAX_MS = 8 * 60 * 60 * 1000;

const store = new VaultStore(DATA_FILE);
const sessions = new Map();
const loginAttempts = new Map();
let setupInProgress = false;

const STATIC = new Map([
  ["/", ["index.html", "text/html; charset=utf-8"]],
  ["/index.html", ["index.html", "text/html; charset=utf-8"]],
  ["/app.js", ["app.js", "text/javascript; charset=utf-8"]],
  ["/styles.css", ["styles.css", "text/css; charset=utf-8"]],
  ["/manifest.webmanifest", ["manifest.webmanifest", "application/manifest+json; charset=utf-8"]],
  ["/sw.js", ["sw.js", "text/javascript; charset=utf-8"]],
  ["/icon.svg", ["icon.svg", "image/svg+xml; charset=utf-8"]],
  ["/windows-audit.ps1", ["windows-audit.ps1", "text/plain; charset=utf-8"]],
]);

function setSecurityHeaders(response, contentType = "application/json; charset=utf-8") {
  response.setHeader("Content-Type", contentType);
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; manifest-src 'self'");
  response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  response.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=(), interest-cohort=()");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("X-Permitted-Cross-Domain-Policies", "none");
  if (COOKIE_SECURE) response.setHeader("Strict-Transport-Security", "max-age=31536000");
}

function json(response, status, value, headers = {}) {
  setSecurityHeaders(response);
  for (const [name, content] of Object.entries(headers)) response.setHeader(name, content);
  response.statusCode = status;
  response.end(JSON.stringify(value));
}

function jsonDownload(response, filename, value) {
  json(response, 200, value, {
    "Content-Disposition": `attachment; filename=${filename}`,
    "X-Content-Type-Options": "nosniff",
  });
}

function parseCookies(request) {
  const values = {};
  for (const part of (request.headers.cookie ?? "").split(";")) {
    const separator = part.indexOf("=");
    if (separator < 1) continue;
    values[part.slice(0, separator).trim()] = decodeURIComponent(part.slice(separator + 1).trim());
  }
  return values;
}

function sessionCookie(id, maxAge = Math.floor(SESSION_MAX_MS / 1000)) {
  return `ct_session=${encodeURIComponent(id)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${COOKIE_SECURE ? "; Secure" : ""}`;
}

function destroySession(id) {
  const session = sessions.get(id);
  if (session) clearKey(session.key);
  sessions.delete(id);
}

function getSession(request) {
  const id = parseCookies(request).ct_session;
  if (!id) return null;
  const session = sessions.get(id);
  if (!session) return null;
  const now = Date.now();
  if (now - session.lastSeen > SESSION_IDLE_MS || now - session.createdAt > SESSION_MAX_MS) {
    destroySession(id);
    return null;
  }
  session.lastSeen = now;
  return { id, ...session };
}

function createSession(encryptionKey) {
  const id = randomBytes(32).toString("base64url");
  const session = {
    key: Buffer.from(encryptionKey),
    csrf: randomBytes(32).toString("base64url"),
    createdAt: Date.now(),
    lastSeen: Date.now(),
  };
  sessions.set(id, session);
  return { id, ...session };
}

function requireSession(request, response, csrf = false) {
  const session = getSession(request);
  if (!session) {
    json(response, 401, { error: "authentication_required" });
    return null;
  }
  if (csrf) {
    const origin = request.headers.origin;
    const token = request.headers["x-csrf-token"];
    if (origin !== APP_ORIGIN || typeof token !== "string" || token !== session.csrf) {
      json(response, 403, { error: "invalid_request_protection" });
      return null;
    }
  }
  return session;
}

async function readBody(request) {
  const contentType = request.headers["content-type"] ?? "";
  if (!contentType.toLowerCase().startsWith("application/json")) throw new Error("json_required");
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > BODY_LIMIT) throw new Error("body_too_large");
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : {};
}

function clientBucket(request) {
  return request.socket.remoteAddress ?? "local";
}

function loginAllowed(request) {
  const key = clientBucket(request);
  const now = Date.now();
  const state = loginAttempts.get(key) ?? { failures: [], blockedUntil: 0 };
  state.failures = state.failures.filter((at) => now - at < 15 * 60 * 1000);
  loginAttempts.set(key, state);
  return { allowed: now >= state.blockedUntil && state.failures.length < 8, state, key };
}

function recordLoginFailure(request) {
  const { state, key } = loginAllowed(request);
  state.failures.push(Date.now());
  const delay = Math.min(60_000, 1_000 * 2 ** Math.max(0, state.failures.length - 3));
  state.blockedUntil = Date.now() + delay;
  loginAttempts.set(key, state);
}

function clearLoginFailures(request) {
  loginAttempts.delete(clientBucket(request));
}

function validateEmail(email) {
  const normalized = cleanText(email, 254).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)) throw new Error("invalid_email");
  return normalized;
}

function safeUrlPath(request) {
  try {
    return new URL(request.url, "http://local.invalid").pathname;
  } catch {
    return "/invalid";
  }
}

async function hibpApiKey() {
  try {
    return (await readFile(HIBP_KEY_FILE, "utf8")).trim();
  } catch (error) {
    if (error?.code === "ENOENT") return "";
    throw error;
  }
}

async function boundedFetch(url, options = {}, limit = 1024 * 1024) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal, redirect: "error" });
    const contentLength = Number(response.headers.get("content-length") ?? "0");
    if (contentLength > limit) throw new Error("remote_response_too_large");
    const text = await response.text();
    if (Buffer.byteLength(text, "utf8") > limit) throw new Error("remote_response_too_large");
    return { response, text };
  } finally {
    clearTimeout(timeout);
  }
}

async function checkEmailBreaches(email) {
  if (DISABLE_EXTERNAL_CHECKS) throw new Error("external_checks_disabled");
  const key = await hibpApiKey();
  if (!key) throw new Error("hibp_not_configured");
  const url = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`;
  const { response, text } = await boundedFetch(url, {
    headers: { "hibp-api-key": key, "user-agent": "CyberTarcza-Local/1.0" },
  });
  if (response.status === 404) return [];
  if (response.status === 429) throw new Error("hibp_rate_limited");
  if (!response.ok) throw new Error("hibp_unavailable");
  const data = JSON.parse(text);
  if (!Array.isArray(data)) throw new Error("invalid_hibp_response");
  return data.slice(0, 200).map((item) => ({
    name: cleanText(item.Name, 100),
    title: cleanText(item.Title, 160),
    domain: cleanText(item.Domain, 160),
    breachDate: cleanText(item.BreachDate, 20),
    pwnCount: Number.isSafeInteger(item.PwnCount) ? item.PwnCount : 0,
    dataClasses: Array.isArray(item.DataClasses) ? item.DataClasses.slice(0, 30).map((value) => cleanText(value, 80)) : [],
    verified: Boolean(item.IsVerified),
  }));
}

async function checkPasswordExposure(password) {
  if (DISABLE_EXTERNAL_CHECKS) throw new Error("external_checks_disabled");
  if (typeof password !== "string" || password.length < 1 || password.length > 512) throw new Error("invalid_password_check");
  const digest = createHash("sha1").update(password, "utf8").digest("hex").toUpperCase();
  const prefix = digest.slice(0, 5);
  const suffix = digest.slice(5);
  const { response, text } = await boundedFetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { "Add-Padding": "true", "user-agent": "CyberTarcza-Local/1.0" },
  }, 256 * 1024);
  if (!response.ok) throw new Error("pwned_passwords_unavailable");
  for (const line of text.split("\r\n")) {
    const [candidate, count] = line.split(":");
    if (candidate === suffix) return Number.parseInt(count, 10) || 0;
  }
  return 0;
}

async function serveStatic(path, response) {
  const file = STATIC.get(path);
  if (!file) return false;
  const [name, contentType] = file;
  const body = await readFile(join(PUBLIC, name));
  setSecurityHeaders(response, contentType);
  if (!["/", "/index.html", "/sw.js"].includes(path)) response.setHeader("Cache-Control", "public, max-age=3600");
  response.statusCode = 200;
  response.end(body);
  return true;
}

async function handle(request, response) {
  const method = request.method ?? "GET";
  const path = safeUrlPath(request);

  if (method === "GET" && path === "/healthz") {
    json(response, 200, { ok: true });
    return;
  }

  if (method === "GET" && path === "/api/status") {
    const session = getSession(request);
    json(response, 200, { initialized: await store.exists(), authenticated: Boolean(session), csrf: session?.csrf ?? null });
    return;
  }

  if (method === "POST" && path === "/api/setup") {
    if (setupInProgress || await store.exists()) return json(response, 409, { error: "already_initialized" });
    const body = await readBody(request);
    if (typeof body.password !== "string" || body.password.length < 16 || body.password !== body.confirmation) {
      return json(response, 400, { error: "master_password_requirements" });
    }
    setupInProgress = true;
    try {
      const key = await store.setup(body.password);
      try {
        const session = createSession(key);
        json(response, 201, { ok: true, csrf: session.csrf }, { "Set-Cookie": sessionCookie(session.id) });
      } finally {
        clearKey(key);
      }
    } finally {
      setupInProgress = false;
    }
    return;
  }

  if (method === "POST" && path === "/api/login") {
    const rate = loginAllowed(request);
    if (!rate.allowed) return json(response, 429, { error: "temporarily_locked" }, { "Retry-After": "60" });
    const body = await readBody(request);
    try {
      const key = await store.unlock(body.password);
      try {
        clearLoginFailures(request);
        const session = createSession(key);
        json(response, 200, { ok: true, csrf: session.csrf }, { "Set-Cookie": sessionCookie(session.id) });
      } finally {
        clearKey(key);
      }
    } catch (error) {
      if (error?.message !== "invalid_credentials") throw error;
      recordLoginFailure(request);
      json(response, 401, { error: "invalid_credentials" });
    }
    return;
  }

  if (method === "POST" && path === "/api/logout") {
    const session = requireSession(request, response, true);
    if (!session) return;
    destroySession(session.id);
    json(response, 200, { ok: true }, { "Set-Cookie": sessionCookie("", 0) });
    return;
  }

  if (method === "GET" && path === "/api/dashboard") {
    const session = requireSession(request, response);
    if (!session) return;
    const vault = await store.read(session.key);
    const totalWeight = CONTROLS.reduce((sum, item) => sum + item.weight, 0);
    const completed = new Set(vault.completedControls);
    const score = Math.round(CONTROLS.filter((item) => completed.has(item.id)).reduce((sum, item) => sum + item.weight, 0) / totalWeight * 100);
    json(response, 200, {
      controls: CONTROLS,
      vault,
      score,
      euProfiles: EU_PROFILES,
      complianceSummary: buildComplianceSummary(vault.compliance),
      complianceDeadlines: buildDeadlineList(vault.compliance),
    });
    return;
  }

  if (method === "GET" && path === "/api/compliance") {
    const session = requireSession(request, response);
    if (!session) return;
    const vault = await store.read(session.key);
    json(response, 200, {
      profiles: EU_PROFILES,
      compliance: vault.compliance,
      summary: buildComplianceSummary(vault.compliance),
      deadlines: buildDeadlineList(vault.compliance),
    });
    return;
  }

  if (method === "PUT" && path === "/api/compliance/profiles") {
    const session = requireSession(request, response, true);
    if (!session) return;
    const body = await readBody(request);
    const knownProfiles = new Set(EU_PROFILES.map((profile) => profile.id));
    const enabled = new Set(Array.isArray(body.enabled) ? body.enabled.filter((id) => knownProfiles.has(id)) : []);
    const retention = Number.parseInt(body.settings?.retentionDays, 10);
    const compliance = await store.mutate(session.key, "eu_profiles_updated", (vault) => {
      vault.compliance.profiles = Object.fromEntries(EU_PROFILES.map((profile) => [profile.id, enabled.has(profile.id)]));
      vault.compliance.settings = {
        ...vault.compliance.settings,
        organisation: cleanText(body.settings?.organisation, 120),
        productName: cleanText(body.settings?.productName, 120) || vault.compliance.settings.productName,
        supportUntil: cleanText(body.settings?.supportUntil, 40),
        retentionDays: Number.isInteger(retention) ? Math.min(3650, Math.max(30, retention)) : vault.compliance.settings.retentionDays,
      };
      return vault.compliance;
    });
    json(response, 200, { compliance });
    return;
  }

  if (method === "POST" && path === "/api/compliance/rights") {
    const session = requireSession(request, response, true);
    if (!session) return;
    const body = await readBody(request);
    const record = await store.mutate(session.key, "eu_rights_request_added", (vault) => {
      if (vault.compliance.rightsRequests.length >= 200) throw new Error("compliance_record_limit");
      const created = createRightRequest(body);
      vault.compliance.rightsRequests.push(created);
      return created;
    });
    json(response, 201, { record });
    return;
  }

  if (method === "PATCH" && path.startsWith("/api/compliance/rights/")) {
    const session = requireSession(request, response, true);
    if (!session) return;
    const id = path.slice("/api/compliance/rights/".length);
    const body = await readBody(request);
    if (!RECORD_STATUSES.includes(body.status)) return json(response, 400, { error: "invalid_record_status" });
    const record = await store.mutate(session.key, "eu_rights_request_updated", (vault) => {
      const found = vault.compliance.rightsRequests.find((item) => item.id === id);
      if (!found) throw new Error("compliance_record_not_found");
      found.status = body.status;
      found.notes = cleanText(body.notes ?? found.notes, 1000);
      found.completedAt = ["completed", "rejected"].includes(body.status) ? new Date().toISOString() : null;
      return found;
    });
    json(response, 200, { record });
    return;
  }

  if (method === "POST" && path === "/api/compliance/incidents") {
    const session = requireSession(request, response, true);
    if (!session) return;
    const body = await readBody(request);
    const record = await store.mutate(session.key, "eu_incident_added", (vault) => {
      if (vault.compliance.incidents.length >= 200) throw new Error("compliance_record_limit");
      const created = createIncident(body, vault.compliance.profiles);
      vault.compliance.incidents.push(created);
      return created;
    });
    json(response, 201, { record });
    return;
  }

  if (method === "PATCH" && path.startsWith("/api/compliance/incidents/")) {
    const session = requireSession(request, response, true);
    if (!session) return;
    const id = path.slice("/api/compliance/incidents/".length);
    const body = await readBody(request);
    if (!RECORD_STATUSES.includes(body.status)) return json(response, 400, { error: "invalid_record_status" });
    const record = await store.mutate(session.key, "eu_incident_updated", (vault) => {
      const found = vault.compliance.incidents.find((item) => item.id === id);
      if (!found) throw new Error("compliance_record_not_found");
      found.status = body.status;
      found.description = cleanText(body.description ?? found.description, 2000);
      found.resolvedAt = ["resolved", "completed"].includes(body.status) ? new Date().toISOString() : null;
      if (typeof body.deadlineId === "string") {
        const notification = found.deadlines.find((item) => item.id === body.deadlineId);
        if (notification) notification.metAt = new Date().toISOString();
      }
      return found;
    });
    json(response, 200, { record });
    return;
  }

  if (method === "POST" && path === "/api/compliance/vulnerabilities") {
    const session = requireSession(request, response, true);
    if (!session) return;
    const body = await readBody(request);
    const record = await store.mutate(session.key, "eu_vulnerability_added", (vault) => {
      if (vault.compliance.vulnerabilities.length >= 200) throw new Error("compliance_record_limit");
      const created = createVulnerability(body, vault.compliance.profiles);
      vault.compliance.vulnerabilities.push(created);
      return created;
    });
    json(response, 201, { record });
    return;
  }

  if (method === "PATCH" && path.startsWith("/api/compliance/vulnerabilities/")) {
    const session = requireSession(request, response, true);
    if (!session) return;
    const id = path.slice("/api/compliance/vulnerabilities/".length);
    const body = await readBody(request);
    if (!VULNERABILITY_STATUSES.includes(body.status)) return json(response, 400, { error: "invalid_record_status" });
    const record = await store.mutate(session.key, "eu_vulnerability_updated", (vault) => {
      const found = vault.compliance.vulnerabilities.find((item) => item.id === id);
      if (!found) throw new Error("compliance_record_not_found");
      found.status = body.status;
      found.notes = cleanText(body.notes ?? found.notes, 2000);
      if (typeof body.deadlineId === "string") {
        const notification = found.deadlines.find((item) => item.id === body.deadlineId);
        if (notification) notification.metAt = new Date().toISOString();
      }
      return found;
    });
    json(response, 200, { record });
    return;
  }

  if (method === "POST" && path === "/api/compliance/components") {
    const session = requireSession(request, response, true);
    if (!session) return;
    const body = await readBody(request);
    const component = await store.mutate(session.key, "eu_component_added", (vault) => {
      if (vault.compliance.components.length >= 500) throw new Error("component_limit");
      const created = createComponent(body);
      vault.compliance.components.push(created);
      return created;
    });
    json(response, 201, { component });
    return;
  }

  if (method === "DELETE" && path.startsWith("/api/compliance/components/")) {
    const session = requireSession(request, response, true);
    if (!session) return;
    const id = path.slice("/api/compliance/components/".length);
    await store.mutate(session.key, "eu_component_removed", (vault) => {
      vault.compliance.components = vault.compliance.components.filter((item) => item.id !== id);
    });
    json(response, 200, { ok: true });
    return;
  }

  if (method === "POST" && path === "/api/compliance/evidence") {
    const session = requireSession(request, response, true);
    if (!session) return;
    const body = await readBody(request);
    const evidence = await store.mutate(session.key, "eu_evidence_added", (vault) => {
      if (vault.compliance.evidence.length >= 500) throw new Error("evidence_limit");
      const created = createEvidence(body);
      created.digest = createHash("sha256").update(`${created.profile}\n${created.title}\n${created.reference}\n${created.collectedAt}`).digest("hex");
      vault.compliance.evidence.push(created);
      return created;
    });
    json(response, 201, { evidence });
    return;
  }

  if (method === "POST" && path === "/api/compliance/retention/run") {
    const session = requireSession(request, response, true);
    if (!session) return;
    const removed = await store.mutate(session.key, "eu_retention_executed", (vault) => {
      const cutoff = Date.now() - vault.compliance.settings.retentionDays * 24 * 60 * 60 * 1000;
      const before = {
        scans: vault.scans.length,
        rights: vault.compliance.rightsRequests.length,
        incidents: vault.compliance.incidents.length,
        vulnerabilities: vault.compliance.vulnerabilities.length,
      };
      vault.scans = vault.scans.filter((item) => new Date(item.at).getTime() >= cutoff);
      vault.compliance.rightsRequests = vault.compliance.rightsRequests.filter((item) => !item.completedAt || new Date(item.completedAt).getTime() >= cutoff);
      vault.compliance.incidents = vault.compliance.incidents.filter((item) => !item.resolvedAt || new Date(item.resolvedAt).getTime() >= cutoff);
      vault.compliance.vulnerabilities = vault.compliance.vulnerabilities.filter((item) => item.status !== "closed" || new Date(item.discoveredAt).getTime() >= cutoff);
      return {
        scans: before.scans - vault.scans.length,
        rights: before.rights - vault.compliance.rightsRequests.length,
        incidents: before.incidents - vault.compliance.incidents.length,
        vulnerabilities: before.vulnerabilities - vault.compliance.vulnerabilities.length,
      };
    });
    json(response, 200, { removed });
    return;
  }

  if (method === "GET" && path === "/api/compliance/export") {
    const session = requireSession(request, response);
    if (!session) return;
    const vault = await store.read(session.key);
    jsonDownload(response, "cybertarcza-eu-evidence.json", buildComplianceExport(vault));
    return;
  }

  if (method === "GET" && path === "/api/compliance/sbom") {
    const session = requireSession(request, response);
    if (!session) return;
    const vault = await store.read(session.key);
    jsonDownload(response, "cybertarcza-sbom.cdx.json", buildCycloneDx(vault.compliance));
    return;
  }

  if (method === "GET" && path === "/api/privacy/export") {
    const session = requireSession(request, response);
    if (!session) return;
    const vault = await store.read(session.key);
    jsonDownload(response, "cybertarcza-personal-data.json", {
      format: "cybertarcza-data-subject-export-v1",
      generatedAt: new Date().toISOString(),
      identities: vault.identities,
      assets: vault.assets,
      scans: vault.scans,
      rightsRequests: vault.compliance.rightsRequests,
    });
    return;
  }

  if (method === "DELETE" && path === "/api/privacy/data") {
    const session = requireSession(request, response, true);
    if (!session) return;
    const body = await readBody(request);
    if (body.confirmation !== "USUŃ MOJE DANE") return json(response, 400, { error: "erasure_confirmation_required" });
    await store.mutate(session.key, "personal_data_erased", (vault) => {
      vault.identities = [];
      vault.assets = [];
      vault.scans = [];
      const profiles = { ...vault.compliance.profiles };
      const settings = { ...vault.compliance.settings };
      const components = [...vault.compliance.components];
      vault.compliance = defaultCompliance();
      vault.compliance.profiles = profiles;
      vault.compliance.settings = settings;
      vault.compliance.components = components;
    });
    json(response, 200, { ok: true });
    return;
  }

  if (method === "POST" && path === "/api/controls") {
    const session = requireSession(request, response, true);
    if (!session) return;
    const body = await readBody(request);
    if (!CONTROLS.some((item) => item.id === body.id) || typeof body.completed !== "boolean") return json(response, 400, { error: "invalid_control" });
    await store.mutate(session.key, "control_updated", (vault) => {
      const values = new Set(vault.completedControls);
      if (body.completed) values.add(body.id);
      else values.delete(body.id);
      vault.completedControls = [...values];
    });
    json(response, 200, { ok: true });
    return;
  }

  if (method === "POST" && path === "/api/assets") {
    const session = requireSession(request, response, true);
    if (!session) return;
    const body = await readBody(request);
    const type = ["computer", "phone", "router", "iot", "other"].includes(body.type) ? body.type : "other";
    const name = cleanText(body.name, 80);
    const notes = cleanText(body.notes, 240);
    if (!name) return json(response, 400, { error: "asset_name_required" });
    const asset = { id: randomUUID(), type, name, notes, createdAt: new Date().toISOString() };
    await store.mutate(session.key, "asset_added", (vault) => {
      if (vault.assets.length >= 100) throw new Error("asset_limit");
      vault.assets.push(asset);
    });
    json(response, 201, { asset });
    return;
  }

  if (method === "DELETE" && path.startsWith("/api/assets/")) {
    const session = requireSession(request, response, true);
    if (!session) return;
    const id = path.slice("/api/assets/".length);
    await store.mutate(session.key, "asset_removed", (vault) => { vault.assets = vault.assets.filter((item) => item.id !== id); });
    json(response, 200, { ok: true });
    return;
  }

  if (method === "POST" && path === "/api/identities") {
    const session = requireSession(request, response, true);
    if (!session) return;
    const body = await readBody(request);
    const email = validateEmail(body.email);
    const identity = { id: randomUUID(), email, label: cleanText(body.label, 60), createdAt: new Date().toISOString() };
    await store.mutate(session.key, "identity_added", (vault) => {
      if (vault.identities.length >= 50) throw new Error("identity_limit");
      if (vault.identities.some((item) => item.email === email)) throw new Error("identity_exists");
      vault.identities.push(identity);
    });
    json(response, 201, { identity });
    return;
  }

  if (method === "DELETE" && path.startsWith("/api/identities/")) {
    const session = requireSession(request, response, true);
    if (!session) return;
    const id = path.slice("/api/identities/".length);
    await store.mutate(session.key, "identity_removed", (vault) => { vault.identities = vault.identities.filter((item) => item.id !== id); });
    json(response, 200, { ok: true });
    return;
  }

  if (method === "POST" && path === "/api/check-email") {
    const session = requireSession(request, response, true);
    if (!session) return;
    const body = await readBody(request);
    const email = validateEmail(body.email);
    const breaches = await checkEmailBreaches(email);
    await store.mutate(session.key, "email_checked", (vault) => {
      vault.scans.push({ id: randomUUID(), type: "email", email, count: breaches.length, at: new Date().toISOString() });
      vault.scans = vault.scans.slice(-100);
    });
    json(response, 200, { email, breaches });
    return;
  }

  if (method === "POST" && path === "/api/check-password") {
    const session = requireSession(request, response, true);
    if (!session) return;
    const body = await readBody(request);
    const count = await checkPasswordExposure(body.password);
    json(response, 200, { exposed: count > 0, count });
    return;
  }

  if (method === "GET" && path === "/api/export") {
    const session = requireSession(request, response);
    if (!session) return;
    const body = await store.exportEncrypted();
    setSecurityHeaders(response, "application/octet-stream");
    response.setHeader("Content-Disposition", "attachment; filename=cybertarcza-backup.vault");
    response.statusCode = 200;
    response.end(body);
    return;
  }

  if (method === "GET" && await serveStatic(path, response)) return;
  json(response, 404, { error: "not_found" });
}

await store.initializeDirectory();
const server = createServer((request, response) => {
  handle(request, response).catch((error) => {
    const known = new Set([
      "json_required", "body_too_large", "invalid_email", "hibp_not_configured",
      "external_checks_disabled", "hibp_rate_limited", "hibp_unavailable",
      "pwned_passwords_unavailable", "asset_limit", "identity_limit", "identity_exists",
      "invalid_rights_request", "invalid_incident", "invalid_vulnerability",
      "invalid_component", "invalid_evidence", "invalid_record_status",
      "compliance_record_limit", "compliance_record_not_found", "component_limit",
      "evidence_limit", "erasure_confirmation_required",
    ]);
    const code = known.has(error?.message) ? error.message : "request_failed";
    const status = [
      "json_required", "body_too_large", "invalid_email", "identity_exists",
      "invalid_rights_request", "invalid_incident", "invalid_vulnerability",
      "invalid_component", "invalid_evidence", "invalid_record_status",
      "erasure_confirmation_required",
    ].includes(code) ? 400 :
      code === "compliance_record_not_found" ? 404 :
      ["asset_limit", "identity_limit", "compliance_record_limit", "component_limit", "evidence_limit"].includes(code) ? 409 :
      ["hibp_not_configured", "external_checks_disabled"].includes(code) ? 503 : 500;
    if (code === "request_failed") console.error("request_failed", error?.message ?? "unknown");
    if (!response.headersSent) json(response, status, { error: code });
    else response.destroy();
  });
});

server.requestTimeout = 15_000;
server.headersTimeout = 10_000;
server.keepAliveTimeout = 5_000;
server.maxHeadersCount = 64;
server.listen(PORT, HOST, () => {
  const address = server.address();
  console.log(`CyberTarcza listening on ${HOST}:${typeof address === "object" && address ? address.port : PORT}`);
});

function shutdown() {
  for (const id of sessions.keys()) destroySession(id);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 5_000).unref();
}

setInterval(() => {
  for (const id of sessions.keys()) {
    const session = sessions.get(id);
    if (!session || Date.now() - session.lastSeen > SESSION_IDLE_MS || Date.now() - session.createdAt > SESSION_MAX_MS) destroySession(id);
  }
}, 60_000).unref();

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
