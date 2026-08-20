import { randomUUID } from "node:crypto";

export const EU_PROFILES = Object.freeze([
  { id: "gdpr", label: "RODO / GDPR", legal: "Rozporządzenie (UE) 2016/679", scope: "Dane osobowe, prawa osób, privacy by design i naruszenia danych", defaultEnabled: true },
  { id: "cra", label: "Cyber Resilience Act", legal: "Rozporządzenie (UE) 2024/2847", scope: "Bezpieczeństwo produktu, podatności, aktualizacje i obowiązki producenta", defaultEnabled: true },
  { id: "data_act", label: "Data Act", legal: "Rozporządzenie (UE) 2023/2854", scope: "Dostęp użytkownika do danych z produktów połączonych i usług powiązanych", defaultEnabled: true },
  { id: "eprivacy", label: "ePrivacy", legal: "Dyrektywa 2002/58/WE", scope: "Prywatność łączności, pamięć urządzenia i zgody", defaultEnabled: true },
  { id: "accessibility", label: "European Accessibility Act", legal: "Dyrektywa (UE) 2019/882", scope: "Dostępność wybranych produktów i usług cyfrowych", defaultEnabled: true },
  { id: "etsi_iot", label: "ETSI EN 303 645", legal: "Europejska norma bazowa cyberbezpieczeństwa konsumenckiego IoT", scope: "Hasła, aktualizacje, ujawnianie podatności, ochrona danych i odporność 11 urządzeń IoT", defaultEnabled: true },
  { id: "en_18031", label: "EN 18031-1/-2/-3", legal: "Normy cyberbezpieczeństwa urządzeń radiowych powiązane z RED", scope: "Ochrona sieci, danych osobowych i przed oszustwem w urządzeniach radiowych", defaultEnabled: false },
  { id: "nis2", label: "NIS2", legal: "Dyrektywa (UE) 2022/2555", scope: "Podmioty kluczowe i ważne w sektorach objętych dyrektywą", defaultEnabled: false },
  { id: "red", label: "RED cyber", legal: "Dyrektywa 2014/53/UE i rozporządzenie delegowane (UE) 2022/30", scope: "Internetowe i wybrane radiowe urządzenia: sieć, prywatność i ochrona przed oszustwem", defaultEnabled: false },
  { id: "dora", label: "DORA", legal: "Rozporządzenie (UE) 2022/2554", scope: "Podmioty finansowe: ryzyko ICT, incydenty, testy i dostawcy", defaultEnabled: false },
  { id: "ai_act", label: "AI Act", legal: "Rozporządzenie (UE) 2024/1689", scope: "Systemy AI, szczególnie wysokiego ryzyka i wymagania przejrzystości", defaultEnabled: false },
  { id: "cybersecurity_act", label: "Cybersecurity Act", legal: "Rozporządzenie (UE) 2019/881", scope: "Dobrowolne unijne programy certyfikacji cyberbezpieczeństwa", defaultEnabled: false },
]);

export const RIGHT_TYPES = Object.freeze([
  "access", "rectification", "erasure", "restriction", "portability", "objection",
  "automated_decision", "connected_data_access", "connected_data_share",
]);

export const INCIDENT_CATEGORIES = Object.freeze([
  "cyber_incident", "personal_data_breach", "actively_exploited_vulnerability",
  "severe_product_incident", "service_disruption", "third_party_incident",
]);

const RECORD_STATUSES = Object.freeze(["open", "in_progress", "contained", "resolved", "rejected", "completed"]);
const VULNERABILITY_STATUSES = Object.freeze(["triage", "coordinated_disclosure", "fix_in_progress", "fix_available", "released", "closed"]);
const SEVERITIES = Object.freeze(["low", "medium", "high", "critical"]);
const PROFILE_IDS = new Set(EU_PROFILES.map((profile) => profile.id));

function text(value, max) {
  if (typeof value !== "string") return "";
  return value.normalize("NFKC").replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, max);
}

function enumValue(value, allowed, fallback = "") {
  return allowed.includes(value) ? value : fallback;
}

function iso(value, fallback = new Date().toISOString()) {
  if (typeof value !== "string") return fallback;
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toISOString() : fallback;
}

function addHours(value, hours) {
  return new Date(new Date(value).getTime() + hours * 60 * 60 * 1000).toISOString();
}

function addDays(value, days) {
  return addHours(value, days * 24);
}

function addCalendarMonths(value, months) {
  const source = new Date(value);
  const result = new Date(source);
  const day = result.getUTCDate();
  result.setUTCDate(1);
  result.setUTCMonth(result.getUTCMonth() + months);
  const lastDay = new Date(Date.UTC(result.getUTCFullYear(), result.getUTCMonth() + 1, 0)).getUTCDate();
  result.setUTCDate(Math.min(day, lastDay));
  return result.toISOString();
}

function deadline(framework, stage, dueAt, rule) {
  return { id: randomUUID(), framework, stage, dueAt: dueAt ?? null, rule: rule ?? "", metAt: null };
}

export function defaultCompliance() {
  return {
    profiles: Object.fromEntries(EU_PROFILES.map((profile) => [profile.id, profile.defaultEnabled])),
    settings: {
      organisation: "",
      productName: "CyberTarcza Local",
      supportUntil: "",
      retentionDays: 365,
    },
    rightsRequests: [],
    incidents: [],
    vulnerabilities: [],
    components: [],
    evidence: [],
  };
}

function normalizeDeadlines(value) {
  return Array.isArray(value) ? value.slice(0, 20).map((item) => ({
    id: typeof item?.id === "string" ? item.id : randomUUID(),
    framework: text(item?.framework, 40),
    stage: text(item?.stage, 80),
    dueAt: item?.dueAt ? iso(item.dueAt, null) : null,
    rule: text(item?.rule, 120),
    metAt: item?.metAt ? iso(item.metAt, null) : null,
  })).filter((item) => item.framework && item.stage) : [];
}

export function normalizeCompliance(value) {
  const defaults = defaultCompliance();
  const profiles = Object.fromEntries(EU_PROFILES.map((profile) => [profile.id, value?.profiles?.[profile.id] === undefined ? defaults.profiles[profile.id] : Boolean(value.profiles[profile.id])]));
  const retention = Number.parseInt(value?.settings?.retentionDays, 10);
  const settings = {
    organisation: text(value?.settings?.organisation, 120),
    productName: text(value?.settings?.productName, 120) || defaults.settings.productName,
    supportUntil: value?.settings?.supportUntil ? iso(value.settings.supportUntil, "") : "",
    retentionDays: Number.isInteger(retention) ? Math.min(3650, Math.max(30, retention)) : defaults.settings.retentionDays,
  };

  const rightsRequests = Array.isArray(value?.rightsRequests) ? value.rightsRequests.slice(-200).map((item) => ({
    id: typeof item?.id === "string" ? item.id : randomUUID(),
    type: enumValue(item?.type, RIGHT_TYPES, "access"),
    subjectRef: text(item?.subjectRef, 160),
    receivedAt: iso(item?.receivedAt),
    dueAt: iso(item?.dueAt),
    status: enumValue(item?.status, RECORD_STATUSES, "open"),
    notes: text(item?.notes, 1000),
    completedAt: item?.completedAt ? iso(item.completedAt, null) : null,
  })) : [];

  const incidents = Array.isArray(value?.incidents) ? value.incidents.slice(-200).map((item) => ({
    id: typeof item?.id === "string" ? item.id : randomUUID(),
    category: enumValue(item?.category, INCIDENT_CATEGORIES, "cyber_incident"),
    title: text(item?.title, 180),
    severity: enumValue(item?.severity, SEVERITIES, "medium"),
    discoveredAt: iso(item?.discoveredAt),
    status: enumValue(item?.status, RECORD_STATUSES, "open"),
    description: text(item?.description, 2000),
    deadlines: normalizeDeadlines(item?.deadlines),
    resolvedAt: item?.resolvedAt ? iso(item.resolvedAt, null) : null,
  })).filter((item) => item.title) : [];

  const vulnerabilities = Array.isArray(value?.vulnerabilities) ? value.vulnerabilities.slice(-200).map((item) => ({
    id: typeof item?.id === "string" ? item.id : randomUUID(),
    product: text(item?.product, 120),
    identifier: text(item?.identifier, 80),
    title: text(item?.title, 180),
    severity: enumValue(item?.severity, SEVERITIES, "medium"),
    exploited: Boolean(item?.exploited),
    discoveredAt: iso(item?.discoveredAt),
    status: enumValue(item?.status, VULNERABILITY_STATUSES, "triage"),
    notes: text(item?.notes, 2000),
    deadlines: normalizeDeadlines(item?.deadlines),
  })).filter((item) => item.product && item.title) : [];

  const components = Array.isArray(value?.components) ? value.components.slice(-500).map((item) => ({
    id: typeof item?.id === "string" ? item.id : randomUUID(),
    name: text(item?.name, 120),
    version: text(item?.version, 80),
    supplier: text(item?.supplier, 120),
    purl: text(item?.purl, 240),
    license: text(item?.license, 120),
    supportUntil: item?.supportUntil ? iso(item.supportUntil, "") : "",
    createdAt: iso(item?.createdAt),
  })).filter((item) => item.name && item.version) : [];

  const evidence = Array.isArray(value?.evidence) ? value.evidence.slice(-500).map((item) => ({
    id: typeof item?.id === "string" ? item.id : randomUUID(),
    profile: PROFILE_IDS.has(item?.profile) ? item.profile : "cra",
    title: text(item?.title, 180),
    reference: text(item?.reference, 240),
    collectedAt: iso(item?.collectedAt),
    digest: text(item?.digest, 128),
  })).filter((item) => item.title) : [];

  return { profiles, settings, rightsRequests, incidents, vulnerabilities, components, evidence };
}

export function createRightRequest(input, now = new Date().toISOString()) {
  const type = enumValue(input?.type, RIGHT_TYPES);
  const subjectRef = text(input?.subjectRef, 160);
  if (!type || !subjectRef) throw new Error("invalid_rights_request");
  const receivedAt = iso(input?.receivedAt, now);
  return {
    id: randomUUID(), type, subjectRef, receivedAt, dueAt: addCalendarMonths(receivedAt, 1),
    status: "open", notes: text(input?.notes, 1000), completedAt: null,
  };
}

export function incidentDeadlines(category, discoveredAt, profiles) {
  const values = [];
  if (category === "personal_data_breach" && profiles.gdpr) {
    values.push(deadline("GDPR", "notification_to_supervisory_authority", addHours(discoveredAt, 72), "72_hours_if_risk"));
  }
  if (profiles.nis2 && ["cyber_incident", "service_disruption", "third_party_incident", "severe_product_incident"].includes(category)) {
    values.push(deadline("NIS2", "early_warning", addHours(discoveredAt, 24), "24_hours"));
    values.push(deadline("NIS2", "incident_notification", addHours(discoveredAt, 72), "72_hours"));
    values.push(deadline("NIS2", "final_report", addCalendarMonths(discoveredAt, 1), "one_month"));
  }
  if (profiles.cra && category === "actively_exploited_vulnerability") {
    values.push(deadline("CRA", "early_warning", addHours(discoveredAt, 24), "24_hours"));
    values.push(deadline("CRA", "full_notification", addHours(discoveredAt, 72), "72_hours"));
    values.push(deadline("CRA", "final_report", null, "14_days_after_corrective_measure_available"));
  }
  if (profiles.cra && category === "severe_product_incident") {
    values.push(deadline("CRA", "early_warning", addHours(discoveredAt, 24), "24_hours"));
    values.push(deadline("CRA", "full_notification", addHours(discoveredAt, 72), "72_hours"));
    values.push(deadline("CRA", "final_report", addCalendarMonths(discoveredAt, 1), "one_month"));
  }
  return values;
}

export function createIncident(input, profiles, now = new Date().toISOString()) {
  const category = enumValue(input?.category, INCIDENT_CATEGORIES);
  const title = text(input?.title, 180);
  if (!category || !title) throw new Error("invalid_incident");
  const discoveredAt = iso(input?.discoveredAt, now);
  return {
    id: randomUUID(), category, title,
    severity: enumValue(input?.severity, SEVERITIES, "medium"),
    discoveredAt, status: "open", description: text(input?.description, 2000),
    deadlines: incidentDeadlines(category, discoveredAt, profiles), resolvedAt: null,
  };
}

export function createVulnerability(input, profiles, now = new Date().toISOString()) {
  const product = text(input?.product, 120);
  const title = text(input?.title, 180);
  if (!product || !title) throw new Error("invalid_vulnerability");
  const discoveredAt = iso(input?.discoveredAt, now);
  const exploited = Boolean(input?.exploited);
  const deadlines = exploited && profiles.cra ? incidentDeadlines("actively_exploited_vulnerability", discoveredAt, profiles) : [];
  return {
    id: randomUUID(), product, title, identifier: text(input?.identifier, 80),
    severity: enumValue(input?.severity, SEVERITIES, "medium"), exploited, discoveredAt,
    status: "triage", notes: text(input?.notes, 2000), deadlines,
  };
}

export function createComponent(input, now = new Date().toISOString()) {
  const name = text(input?.name, 120);
  const version = text(input?.version, 80);
  if (!name || !version) throw new Error("invalid_component");
  return {
    id: randomUUID(), name, version, supplier: text(input?.supplier, 120),
    purl: text(input?.purl, 240), license: text(input?.license, 120),
    supportUntil: input?.supportUntil ? iso(input.supportUntil, "") : "", createdAt: now,
  };
}

export function createEvidence(input, now = new Date().toISOString()) {
  const profile = PROFILE_IDS.has(input?.profile) ? input.profile : "";
  const title = text(input?.title, 180);
  if (!profile || !title) throw new Error("invalid_evidence");
  return { id: randomUUID(), profile, title, reference: text(input?.reference, 240), collectedAt: now, digest: text(input?.digest, 128) };
}

export function buildDeadlineList(compliance, now = new Date().toISOString()) {
  const current = new Date(now).getTime();
  const output = [];
  for (const record of [...compliance.incidents, ...compliance.vulnerabilities]) {
    for (const item of record.deadlines) {
      if (item.metAt) continue;
      const due = item.dueAt ? new Date(item.dueAt).getTime() : null;
      output.push({ ...item, recordId: record.id, recordTitle: record.title, overdue: due !== null && due < current });
    }
  }
  return output.sort((a, b) => {
    if (!a.dueAt) return 1;
    if (!b.dueAt) return -1;
    return new Date(a.dueAt) - new Date(b.dueAt);
  }).slice(0, 100);
}

export function buildComplianceSummary(compliance, now = new Date().toISOString()) {
  const deadlines = buildDeadlineList(compliance, now);
  const week = new Date(now).getTime() + 7 * 24 * 60 * 60 * 1000;
  return {
    enabledProfiles: Object.values(compliance.profiles).filter(Boolean).length,
    openRightsRequests: compliance.rightsRequests.filter((item) => !["completed", "rejected"].includes(item.status)).length,
    openIncidents: compliance.incidents.filter((item) => !["resolved", "completed"].includes(item.status)).length,
    openVulnerabilities: compliance.vulnerabilities.filter((item) => item.status !== "closed").length,
    overdueDeadlines: deadlines.filter((item) => item.overdue).length,
    dueWithinSevenDays: deadlines.filter((item) => item.dueAt && !item.overdue && new Date(item.dueAt).getTime() <= week).length,
    components: compliance.components.length,
    evidence: compliance.evidence.length,
  };
}

export function buildComplianceExport(vault, generatedAt = new Date().toISOString()) {
  return {
    format: "cybertarcza-eu-compliance-v1",
    generatedAt,
    notice: "Operational evidence export; not a certificate, legal opinion or CE declaration.",
    compliance: vault.compliance,
    assets: vault.assets,
    audit: vault.audit,
  };
}

export function buildCycloneDx(compliance) {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: { timestamp: new Date().toISOString(), component: { type: "application", name: compliance.settings.productName, version: "1.0.0" } },
    components: compliance.components.map((item) => ({
      type: "library", "bom-ref": item.purl || `component:${item.id}`, name: item.name, version: item.version,
      ...(item.supplier ? { supplier: { name: item.supplier } } : {}),
      ...(item.purl ? { purl: item.purl } : {}),
      ...(item.license ? { licenses: [{ license: { id: item.license } }] } : {}),
      properties: item.supportUntil ? [{ name: "cybertarcza:support-until", value: item.supportUntil }] : [],
    })),
  };
}

export { RECORD_STATUSES, VULNERABILITY_STATUSES };
