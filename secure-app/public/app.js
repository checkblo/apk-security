const state = {
  csrf: null,
  dashboard: null,
  installPrompt: null,
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

const areaMeta = {
  windows: { label: "Windows", icon: "W", copy: "System i dane" },
  android: { label: "Android", icon: "A", copy: "Xiaomi 14 Pro 5G" },
  router: { label: "Router", icon: "R", copy: "Sieć Vectra" },
  accounts: { label: "Konta", icon: "@", copy: "Tożsamość cyfrowa" },
};

function setBusy(form, busy) {
  const button = $("button[type=submit]", form);
  if (button) button.disabled = busy;
}

function message(text, error = false) {
  const box = $("#global-message");
  box.textContent = text;
  box.classList.toggle("error", error);
  box.classList.remove("hidden");
  clearTimeout(message.timer);
  message.timer = setTimeout(() => box.classList.add("hidden"), 6000);
}

function errorText(code) {
  const values = {
    invalid_credentials: "Nieprawidłowe hasło główne.",
    temporarily_locked: "Zbyt wiele prób. Odczekaj minutę.",
    master_password_requirements: "Hasło musi mieć co najmniej 16 znaków i oba pola muszą być identyczne.",
    hibp_not_configured: "Monitoring e-mail wymaga klucza API HIBP w pliku sekretu. Instrukcja jest w README.",
    hibp_rate_limited: "Limit usługi HIBP został chwilowo przekroczony.",
    hibp_unavailable: "Usługa HIBP jest teraz niedostępna.",
    pwned_passwords_unavailable: "Nie udało się połączyć z Pwned Passwords.",
    external_checks_disabled: "Połączenia zewnętrzne są wyłączone w konfiguracji.",
    identity_exists: "Ten adres jest już zapisany.",
    invalid_rights_request: "Podaj rodzaj wniosku i bezpieczny identyfikator osoby.",
    invalid_incident: "Podaj prawidłową kategorię i tytuł incydentu.",
    invalid_vulnerability: "Podaj produkt i tytuł podatności.",
    invalid_component: "Nazwa i wersja komponentu są wymagane.",
    invalid_evidence: "Wybierz profil i podaj tytuł dowodu.",
    invalid_record_status: "Nieprawidłowy stan rekordu.",
    compliance_record_limit: "Osiągnięto limit rekordów zgodności. Wyeksportuj dane i wykonaj retencję.",
    component_limit: "Osiągnięto limit 500 komponentów SBOM.",
    evidence_limit: "Osiągnięto limit 500 dowodów.",
    erasure_confirmation_required: "Wpisz dokładnie: USUŃ MOJE DANE.",
    invalid_request_protection: "Sesja ochronna wygasła. Zablokuj i odblokuj aplikację ponownie.",
    authentication_required: "Sesja wygasła. Odblokuj aplikację ponownie.",
  };
  return values[code] ?? "Operacja nie powiodła się. Spróbuj ponownie.";
}

async function api(path, options = {}) {
  const method = options.method ?? "GET";
  const headers = { ...(options.headers ?? {}) };
  if (options.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
  if (!["GET", "HEAD"].includes(method) && state.csrf) headers["X-CSRF-Token"] = state.csrf;
  const response = await fetch(path, { ...options, method, headers, credentials: "same-origin", cache: "no-store" });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401) showAuth(true);
    const error = new Error(data.error ?? "request_failed");
    error.code = data.error;
    throw error;
  }
  return data;
}

function showAuth(initialized) {
  $("#auth-shell").classList.remove("hidden");
  $("#app-shell").classList.add("hidden");
  $("#setup-form").classList.toggle("hidden", initialized);
  $("#login-form").classList.toggle("hidden", !initialized);
  $("#auth-message").textContent = "";
  state.csrf = null;
  state.dashboard = null;
}

async function showApp(csrf) {
  state.csrf = csrf;
  $("#auth-shell").classList.add("hidden");
  $("#app-shell").classList.remove("hidden");
  await refreshDashboard();
}

async function refreshDashboard() {
  state.dashboard = await api("/api/dashboard");
  renderAll();
}

function renderAll() {
  renderScore();
  renderAreas();
  renderControls();
  renderAssets();
  renderIdentities();
  renderScans();
  renderCompliance();
}

function renderScore() {
  const score = state.dashboard.score;
  $("#score-ring").style.setProperty("--score", score);
  $("#score-value").textContent = score;
  const label = score >= 90 ? "Bardzo dobre wdrożenie" : score >= 70 ? "Solidna podstawa" : score >= 40 ? "Częściowa ochrona" : "Wymaga konfiguracji";
  $("#score-label").textContent = label;
  $("#score-copy").textContent = score >= 90 ? "Utrzymuj aktualizacje i regularnie sprawdzaj wycieki." : "Uzupełnij brakujące kontrole, zaczynając od kont i kopii danych.";

  const completed = new Set(state.dashboard.vault.completedControls);
  const next = state.dashboard.controls.find((item) => !completed.has(item.id));
  if (next) {
    $("#priority-title").textContent = next.label;
    $("#priority-copy").textContent = next.detail;
  } else {
    $("#priority-title").textContent = "Wszystkie kontrole wykonane";
    $("#priority-copy").textContent = "Raz w miesiącu sprawdź aktualizacje, kopię offline i nowe wycieki.";
  }
}

function renderAreas() {
  const completed = new Set(state.dashboard.vault.completedControls);
  const root = $("#area-cards");
  root.replaceChildren();
  for (const area of Object.keys(areaMeta)) {
    const controls = state.dashboard.controls.filter((item) => item.area === area);
    const done = controls.filter((item) => completed.has(item.id)).length;
    const percent = Math.round(done / controls.length * 100);
    const card = document.createElement("article");
    card.className = "area-card";
    const top = document.createElement("div");
    top.className = "area-card-top";
    const icon = document.createElement("span");
    icon.className = "area-card-icon";
    icon.textContent = areaMeta[area].icon;
    const value = document.createElement("strong");
    value.textContent = `${percent}%`;
    top.append(icon, value);
    const title = document.createElement("h3");
    title.textContent = areaMeta[area].label;
    const copy = document.createElement("p");
    copy.textContent = `${areaMeta[area].copy} · ${done}/${controls.length}`;
    const progress = document.createElement("div");
    progress.className = "progress";
    const bar = document.createElement("span");
    bar.style.width = `${percent}%`;
    progress.append(bar);
    card.append(top, title, copy, progress);
    root.append(card);
  }
}

function renderControls() {
  const completed = new Set(state.dashboard.vault.completedControls);
  const root = $("#control-groups");
  root.replaceChildren();
  for (const area of Object.keys(areaMeta)) {
    const controls = state.dashboard.controls.filter((item) => item.area === area);
    const panel = document.createElement("article");
    panel.className = "control-group panel";
    const head = document.createElement("div");
    head.className = "control-group-head";
    const title = document.createElement("h3");
    title.textContent = areaMeta[area].label;
    const count = document.createElement("span");
    count.className = "control-group-count";
    count.textContent = `${controls.filter((item) => completed.has(item.id)).length} z ${controls.length} wykonane`;
    head.append(title, count);
    panel.append(head);
    for (const control of controls) {
      const row = document.createElement("label");
      row.className = "control-row";
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.checked = completed.has(control.id);
      checkbox.addEventListener("change", async () => {
        checkbox.disabled = true;
        try {
          await api("/api/controls", { method: "POST", body: JSON.stringify({ id: control.id, completed: checkbox.checked }) });
          await refreshDashboard();
        } catch (error) {
          checkbox.checked = !checkbox.checked;
          checkbox.disabled = false;
          message(errorText(error.code), true);
        }
      });
      const text = document.createElement("span");
      const strong = document.createElement("strong");
      strong.textContent = control.label;
      const detail = document.createElement("p");
      detail.textContent = control.detail;
      text.append(strong, detail);
      const weight = document.createElement("span");
      weight.className = "control-weight";
      weight.textContent = `+${control.weight}`;
      row.append(checkbox, text, weight);
      panel.append(row);
    }
    root.append(panel);
  }
}

function renderAssets() {
  const root = $("#asset-list");
  root.replaceChildren();
  for (const asset of state.dashboard.vault.assets) {
    const card = document.createElement("article");
    card.className = "asset-card panel";
    const top = document.createElement("div");
    top.className = "asset-top";
    const icon = document.createElement("span");
    icon.className = "asset-icon";
    icon.textContent = ({ computer: "PC", phone: "TEL", router: "NET", iot: "IoT", other: "?" })[asset.type];
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "mini-button";
    remove.textContent = "Usuń";
    remove.addEventListener("click", () => removeAsset(asset.id));
    top.append(icon, remove);
    const title = document.createElement("h3");
    title.textContent = asset.name;
    const notes = document.createElement("p");
    notes.textContent = asset.notes || "Bez dodatkowej notatki";
    card.append(top, title, notes);
    root.append(card);
  }
}

async function removeAsset(id) {
  try {
    await api(`/api/assets/${encodeURIComponent(id)}`, { method: "DELETE" });
    await refreshDashboard();
  } catch (error) { message(errorText(error.code), true); }
}

function renderIdentities() {
  const root = $("#identity-list");
  root.replaceChildren();
  if (!state.dashboard.vault.identities.length) {
    const empty = document.createElement("p");
    empty.className = "field-help";
    empty.textContent = "Nie dodano jeszcze adresów.";
    root.append(empty);
    return;
  }
  for (const identity of state.dashboard.vault.identities) {
    const row = document.createElement("div");
    row.className = "item-row";
    const text = document.createElement("span");
    const strong = document.createElement("strong");
    strong.textContent = identity.email;
    const label = document.createElement("small");
    label.textContent = identity.label || "adres e-mail";
    text.append(strong, label);
    const actions = document.createElement("span");
    actions.className = "item-actions";
    const scan = document.createElement("button");
    scan.className = "mini-button";
    scan.type = "button";
    scan.textContent = "Sprawdź";
    scan.addEventListener("click", () => scanIdentity(identity.email, scan));
    const remove = document.createElement("button");
    remove.className = "mini-button";
    remove.type = "button";
    remove.textContent = "Usuń";
    remove.addEventListener("click", () => removeIdentity(identity.id));
    actions.append(scan, remove);
    row.append(text, actions);
    root.append(row);
  }
}

async function scanIdentity(email, button) {
  button.disabled = true;
  button.textContent = "Sprawdzam…";
  try {
    const result = await api("/api/check-email", { method: "POST", body: JSON.stringify({ email }) });
    if (result.breaches.length) {
      const names = result.breaches.slice(0, 4).map((item) => item.title || item.name).join(", ");
      message(`Wykryto ${result.breaches.length} naruszeń dla ${email}: ${names}`, true);
    } else {
      message(`Brak znanych naruszeń dla ${email}. To nie gwarantuje, że adres nigdy nie wyciekł.`);
    }
    await refreshDashboard();
  } catch (error) {
    message(errorText(error.code), true);
  } finally {
    button.disabled = false;
    button.textContent = "Sprawdź";
  }
}

async function removeIdentity(id) {
  try {
    await api(`/api/identities/${encodeURIComponent(id)}`, { method: "DELETE" });
    await refreshDashboard();
  } catch (error) { message(errorText(error.code), true); }
}

function renderScans() {
  const root = $("#scan-list");
  root.replaceChildren();
  const scans = [...state.dashboard.vault.scans].reverse().slice(0, 8);
  if (!scans.length) {
    const empty = document.createElement("p");
    empty.className = "field-help";
    empty.textContent = "Brak zapisanych kontroli.";
    root.append(empty);
    return;
  }
  for (const scan of scans) {
    const row = document.createElement("div");
    row.className = "scan-row";
    const label = document.createElement("span");
    label.textContent = scan.email;
    const value = document.createElement("strong");
    value.textContent = `${scan.count} naruszeń · ${new Date(scan.at).toLocaleDateString("pl-PL")}`;
    row.append(label, value);
    root.append(row);
  }
}

const rightLabels = {
  access: "Dostęp", rectification: "Sprostowanie", erasure: "Usunięcie",
  restriction: "Ograniczenie", portability: "Przenoszenie", objection: "Sprzeciw",
  automated_decision: "Decyzja automatyczna", connected_data_access: "Dane produktu — dostęp",
  connected_data_share: "Dane produktu — udostępnienie",
};

const categoryLabels = {
  cyber_incident: "Incydent cyber", personal_data_breach: "Naruszenie danych osobowych",
  actively_exploited_vulnerability: "Aktywnie wykorzystywana podatność",
  severe_product_incident: "Poważny incydent produktu", service_disruption: "Zakłócenie usługi",
  third_party_incident: "Incydent dostawcy",
};

const stageLabels = {
  notification_to_supervisory_authority: "Zgłoszenie do organu nadzorczego",
  early_warning: "Wczesne ostrzeżenie", incident_notification: "Zgłoszenie incydentu",
  full_notification: "Pełne zgłoszenie", final_report: "Raport końcowy",
};

function localDate(value) {
  return value ? new Date(value).toLocaleString("pl-PL", { dateStyle: "medium", timeStyle: "short" }) : "termin zależny od działania";
}

function dateOnly(value) {
  return value ? String(value).slice(0, 10) : "";
}

function emptyList(root, text) {
  const item = document.createElement("p");
  item.className = "field-help";
  item.textContent = text;
  root.append(item);
}

function serviceRow({ title, meta, badge, danger = false, actionLabel, onAction }) {
  const row = document.createElement("div");
  row.className = "service-row";
  const content = document.createElement("div");
  const heading = document.createElement("strong");
  heading.textContent = title;
  const details = document.createElement("small");
  details.textContent = meta;
  content.append(heading, details);
  const actions = document.createElement("span");
  actions.className = "item-actions";
  if (badge) {
    const status = document.createElement("span");
    status.className = `status-badge${danger ? " overdue" : ""}`;
    status.textContent = badge;
    actions.append(status);
  }
  if (actionLabel && onAction) {
    const button = document.createElement("button");
    button.className = "mini-button";
    button.type = "button";
    button.textContent = actionLabel;
    button.addEventListener("click", async () => {
      button.disabled = true;
      try { await onAction(); } catch (error) { message(errorText(error.code), true); }
      finally { button.disabled = false; }
    });
    actions.append(button);
  }
  row.append(content, actions);
  return row;
}

function renderCompliance() {
  const compliance = state.dashboard.vault.compliance;
  const summary = state.dashboard.complianceSummary;
  $("#eu-summary-profiles").textContent = summary.enabledProfiles;
  $("#eu-summary-incidents").textContent = summary.openIncidents;
  $("#eu-summary-rights").textContent = summary.openRightsRequests;
  $("#eu-summary-overdue").textContent = summary.overdueDeadlines;
  $("#eu-summary-overdue").classList.toggle("danger-text", summary.overdueDeadlines > 0);

  const profilesRoot = $("#eu-profile-list");
  profilesRoot.replaceChildren();
  for (const profile of state.dashboard.euProfiles) {
    const label = document.createElement("label");
    label.className = "profile-row";
    const input = document.createElement("input");
    input.type = "checkbox";
    input.value = profile.id;
    input.checked = Boolean(compliance.profiles[profile.id]);
    const text = document.createElement("span");
    const strong = document.createElement("strong");
    strong.textContent = profile.label;
    const small = document.createElement("small");
    small.textContent = `${profile.legal} · ${profile.scope}`;
    text.append(strong, small);
    label.append(input, text);
    profilesRoot.append(label);
  }
  $("#eu-organisation").value = compliance.settings.organisation;
  $("#eu-product-name").value = compliance.settings.productName;
  $("#eu-support-until").value = dateOnly(compliance.settings.supportUntil);
  $("#eu-retention-days").value = compliance.settings.retentionDays;

  const profileSelect = $("#eu-evidence-profile");
  const selectedProfile = profileSelect.value;
  profileSelect.replaceChildren();
  for (const profile of state.dashboard.euProfiles) {
    const option = document.createElement("option");
    option.value = profile.id;
    option.textContent = profile.label;
    option.selected = profile.id === selectedProfile;
    profileSelect.append(option);
  }

  const deadlineRoot = $("#eu-deadline-list");
  deadlineRoot.replaceChildren();
  if (!state.dashboard.complianceDeadlines.length) emptyList(deadlineRoot, "Brak aktywnych terminów zgłoszeniowych.");
  for (const deadline of state.dashboard.complianceDeadlines) {
    const incident = compliance.incidents.find((item) => item.id === deadline.recordId);
    const kind = incident ? "incidents" : "vulnerabilities";
    const record = incident ?? compliance.vulnerabilities.find((item) => item.id === deadline.recordId);
    deadlineRoot.append(serviceRow({
      title: `${deadline.framework}: ${stageLabels[deadline.stage] ?? deadline.stage}`,
      meta: `${deadline.recordTitle} · ${localDate(deadline.dueAt)} · ${deadline.rule}`,
      badge: deadline.overdue ? "po terminie" : "otwarty",
      danger: deadline.overdue,
      actionLabel: "Oznacz wykonanie",
      onAction: () => updateComplianceRecord(kind, deadline.recordId, record.status, deadline.id),
    }));
  }

  renderRights(compliance.rightsRequests);
  renderIncidents(compliance.incidents);
  renderVulnerabilities(compliance.vulnerabilities);
  renderComponents(compliance.components);
  renderEvidence(compliance.evidence);
}

function renderRights(records) {
  const root = $("#eu-rights-list");
  root.replaceChildren();
  if (!records.length) return emptyList(root, "Brak wniosków.");
  for (const record of [...records].reverse().slice(0, 20)) {
    const closed = ["completed", "rejected"].includes(record.status);
    root.append(serviceRow({
      title: `${rightLabels[record.type] ?? record.type}: ${record.subjectRef}`,
      meta: `Otrzymano ${localDate(record.receivedAt)} · termin ${localDate(record.dueAt)}`,
      badge: record.status,
      actionLabel: closed ? null : "Zakończ",
      onAction: () => updateComplianceRecord("rights", record.id, "completed"),
    }));
  }
}

function renderIncidents(records) {
  const root = $("#eu-incidents-list");
  root.replaceChildren();
  if (!records.length) return emptyList(root, "Brak incydentów.");
  for (const record of [...records].reverse().slice(0, 20)) {
    const closed = ["resolved", "completed"].includes(record.status);
    root.append(serviceRow({
      title: record.title,
      meta: `${categoryLabels[record.category] ?? record.category} · ${record.severity} · ${record.deadlines.length} terminów`,
      badge: record.status,
      actionLabel: closed ? null : "Rozwiąż",
      onAction: () => updateComplianceRecord("incidents", record.id, "resolved"),
    }));
  }
}

function renderVulnerabilities(records) {
  const root = $("#eu-vulnerabilities-list");
  root.replaceChildren();
  if (!records.length) return emptyList(root, "Brak podatności.");
  for (const record of [...records].reverse().slice(0, 20)) {
    root.append(serviceRow({
      title: `${record.product}: ${record.title}`,
      meta: `${record.identifier || "bez CVE"} · ${record.severity}${record.exploited ? " · aktywnie wykorzystywana" : ""}`,
      badge: record.status,
      actionLabel: record.status === "closed" ? null : "Zamknij",
      onAction: () => updateComplianceRecord("vulnerabilities", record.id, "closed"),
    }));
  }
}

function renderComponents(records) {
  const root = $("#eu-components-list");
  root.replaceChildren();
  if (!records.length) return emptyList(root, "Dodaj zależności produktu, aby zbudować SBOM.");
  for (const record of [...records].reverse().slice(0, 30)) {
    root.append(serviceRow({
      title: `${record.name} ${record.version}`,
      meta: [record.supplier, record.license, record.purl].filter(Boolean).join(" · ") || "brak metadanych",
      actionLabel: "Usuń",
      onAction: async () => {
        await api(`/api/compliance/components/${encodeURIComponent(record.id)}`, { method: "DELETE" });
        await refreshDashboard();
      },
    }));
  }
}

function renderEvidence(records) {
  const root = $("#eu-evidence-list");
  root.replaceChildren();
  if (!records.length) return emptyList(root, "Brak zapisanych dowodów.");
  for (const record of [...records].reverse().slice(0, 30)) {
    root.append(serviceRow({
      title: record.title,
      meta: `${record.profile.toUpperCase()} · SHA-256 ${record.digest.slice(0, 12)}… · ${localDate(record.collectedAt)}`,
    }));
  }
}

async function updateComplianceRecord(kind, id, status, deadlineId) {
  await api(`/api/compliance/${kind}/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: JSON.stringify({ status, ...(deadlineId ? { deadlineId } : {}) }),
  });
  await refreshDashboard();
  message("Rejestr zgodności został zaktualizowany.");
}

function navigate(section) {
  $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.section === section));
  $$(".view").forEach((view) => view.classList.toggle("active", view.id === `section-${section}`));
  window.scrollTo({ top: 0, behavior: "smooth" });
}

async function installPwa() {
  if (!state.installPrompt) {
    message("W przeglądarce wybierz „Zainstaluj aplikację” lub „Dodaj do ekranu głównego”.");
    return;
  }
  state.installPrompt.prompt();
  await state.installPrompt.userChoice;
  state.installPrompt = null;
  $("#install-app").classList.add("hidden");
}

$("#setup-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  setBusy(form, true);
  $("#auth-message").textContent = "Tworzenie klucza szyfrującego…";
  try {
    const result = await api("/api/setup", { method: "POST", body: JSON.stringify({ password: $("#setup-password").value, confirmation: $("#setup-confirmation").value }) });
    form.reset();
    await showApp(result.csrf);
  } catch (error) {
    $("#auth-message").textContent = errorText(error.code);
  } finally { setBusy(form, false); }
});

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  setBusy(form, true);
  $("#auth-message").textContent = "Sprawdzanie klucza…";
  try {
    const result = await api("/api/login", { method: "POST", body: JSON.stringify({ password: $("#login-password").value }) });
    form.reset();
    await showApp(result.csrf);
  } catch (error) {
    $("#auth-message").textContent = errorText(error.code);
  } finally { setBusy(form, false); }
});

$("#logout").addEventListener("click", async () => {
  try { await api("/api/logout", { method: "POST", body: "{}" }); } catch {}
  showAuth(true);
});

$("#asset-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  setBusy(form, true);
  try {
    await api("/api/assets", { method: "POST", body: JSON.stringify({ type: $("#asset-type").value, name: $("#asset-name").value, notes: $("#asset-notes").value }) });
    form.reset();
    await refreshDashboard();
    message("Urządzenie dodane do zaszyfrowanego sejfu.");
  } catch (error) { message(errorText(error.code), true); }
  finally { setBusy(form, false); }
});

$("#identity-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  setBusy(form, true);
  try {
    await api("/api/identities", { method: "POST", body: JSON.stringify({ email: $("#identity-email").value, label: $("#identity-label").value }) });
    form.reset();
    await refreshDashboard();
  } catch (error) { message(errorText(error.code), true); }
  finally { setBusy(form, false); }
});

$("#password-check-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const input = $("#password-check");
  const resultBox = $("#password-result");
  setBusy(form, true);
  resultBox.className = "result-box muted";
  resultBox.textContent = "Sprawdzanie metodą k-anonimowości…";
  try {
    const result = await api("/api/check-password", { method: "POST", body: JSON.stringify({ password: input.value }) });
    resultBox.className = `result-box ${result.exposed ? "danger" : "safe"}`;
    resultBox.textContent = result.exposed
      ? `To hasło pojawiło się w znanych wyciekach ${result.count.toLocaleString("pl-PL")} razy. Zmień je wszędzie, gdzie było używane.`
      : "Nie znaleziono tego hasła w bazie znanych wycieków. Nadal musi być długie i unikalne.";
  } catch (error) {
    resultBox.className = "result-box danger";
    resultBox.textContent = errorText(error.code);
  } finally {
    input.value = "";
    setBusy(form, false);
  }
});

$("#eu-settings-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  setBusy(form, true);
  try {
    const enabled = $$('input[type="checkbox"]', $("#eu-profile-list")).filter((input) => input.checked).map((input) => input.value);
    await api("/api/compliance/profiles", {
      method: "PUT",
      body: JSON.stringify({ enabled, settings: {
        organisation: $("#eu-organisation").value,
        productName: $("#eu-product-name").value,
        supportUntil: $("#eu-support-until").value,
        retentionDays: Number.parseInt($("#eu-retention-days").value, 10),
      } }),
    });
    await refreshDashboard();
    message("Zakres usług UE i retencja zostały zapisane.");
  } catch (error) { message(errorText(error.code), true); }
  finally { setBusy(form, false); }
});

$("#eu-rights-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  setBusy(form, true);
  try {
    await api("/api/compliance/rights", { method: "POST", body: JSON.stringify({
      type: $("#eu-right-type").value, subjectRef: $("#eu-right-subject").value,
      receivedAt: $("#eu-right-received").value, notes: $("#eu-right-notes").value,
    }) });
    form.reset();
    await refreshDashboard();
    message("Wniosek został zapisany z miesięcznym terminem obsługi.");
  } catch (error) { message(errorText(error.code), true); }
  finally { setBusy(form, false); }
});

$("#eu-incident-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  setBusy(form, true);
  try {
    await api("/api/compliance/incidents", { method: "POST", body: JSON.stringify({
      category: $("#eu-incident-category").value, title: $("#eu-incident-title").value,
      severity: $("#eu-incident-severity").value, discoveredAt: $("#eu-incident-discovered").value,
      description: $("#eu-incident-description").value,
    }) });
    form.reset();
    await refreshDashboard();
    message("Incydent został zarejestrowany, a właściwe terminy zostały wyliczone.");
  } catch (error) { message(errorText(error.code), true); }
  finally { setBusy(form, false); }
});

$("#eu-vulnerability-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  setBusy(form, true);
  try {
    await api("/api/compliance/vulnerabilities", { method: "POST", body: JSON.stringify({
      product: $("#eu-vulnerability-product").value, title: $("#eu-vulnerability-title").value,
      identifier: $("#eu-vulnerability-id").value, severity: $("#eu-vulnerability-severity").value,
      exploited: $("#eu-vulnerability-exploited").checked, notes: $("#eu-vulnerability-notes").value,
    }) });
    form.reset();
    await refreshDashboard();
    message("Podatność została dodana do procesu skoordynowanego ujawniania.");
  } catch (error) { message(errorText(error.code), true); }
  finally { setBusy(form, false); }
});

$("#eu-component-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  setBusy(form, true);
  try {
    await api("/api/compliance/components", { method: "POST", body: JSON.stringify({
      name: $("#eu-component-name").value, version: $("#eu-component-version").value,
      supplier: $("#eu-component-supplier").value, purl: $("#eu-component-purl").value,
      license: $("#eu-component-license").value, supportUntil: $("#eu-component-support").value,
    }) });
    form.reset();
    await refreshDashboard();
    message("Komponent został dodany do SBOM.");
  } catch (error) { message(errorText(error.code), true); }
  finally { setBusy(form, false); }
});

$("#eu-evidence-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  setBusy(form, true);
  try {
    await api("/api/compliance/evidence", { method: "POST", body: JSON.stringify({
      profile: $("#eu-evidence-profile").value, title: $("#eu-evidence-title").value,
      reference: $("#eu-evidence-reference").value,
    }) });
    form.reset();
    await refreshDashboard();
    message("Dowód i jego skrót SHA-256 zostały zapisane w szyfrowanym sejfie.");
  } catch (error) { message(errorText(error.code), true); }
  finally { setBusy(form, false); }
});

$("#eu-run-retention").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    const result = await api("/api/compliance/retention/run", { method: "POST", body: "{}" });
    await refreshDashboard();
    const count = Object.values(result.removed).reduce((sum, value) => sum + value, 0);
    message(`Retencja wykonana. Usunięto ${count} zakończonych rekordów poza okresem przechowywania.`);
  } catch (error) { message(errorText(error.code), true); }
  finally { button.disabled = false; }
});

$("#eu-erasure-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  if (!window.confirm("Ta operacja trwale usunie dane osobowe i rejestry spraw z sejfu. Kontynuować?")) return;
  setBusy(form, true);
  try {
    await api("/api/privacy/data", { method: "DELETE", body: JSON.stringify({ confirmation: $("#eu-erasure-confirmation").value }) });
    form.reset();
    await refreshDashboard();
    message("Dane osobowe zostały usunięte. Profile i SBOM pozostały zachowane.");
  } catch (error) { message(errorText(error.code), true); }
  finally { setBusy(form, false); }
});

$$('.nav-item').forEach((item) => item.addEventListener("click", () => navigate(item.dataset.section)));
$$('[data-jump]').forEach((item) => item.addEventListener("click", () => navigate(item.dataset.jump)));
$("#install-app").addEventListener("click", installPwa);
$("#pwa-install-secondary").addEventListener("click", installPwa);

window.addEventListener("beforeinstallprompt", (event) => {
  event.preventDefault();
  state.installPrompt = event;
  $("#install-app").classList.remove("hidden");
});

if ("serviceWorker" in navigator) navigator.serviceWorker.register("/sw.js").catch(() => {});

(async function boot() {
  try {
    const status = await api("/api/status");
    if (status.authenticated) await showApp(status.csrf);
    else showAuth(status.initialized);
  } catch {
    $("#auth-message").textContent = "Nie udało się połączyć z lokalną usługą CyberTarcza.";
  }
})();
