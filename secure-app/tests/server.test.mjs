import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

function cookieFrom(response) {
  return response.headers.get("set-cookie")?.split(";", 1)[0] ?? "";
}

test("setup, CSRF protection, encrypted dashboard and logout", { timeout: 30_000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "cybertarcza-api-"));
  const port = 31_000 + Math.floor(Math.random() * 2_000);
  const origin = `http://127.0.0.1:${port}`;
  const child = spawn(process.execPath, [join(process.cwd(), "secure-app", "server.mjs")], {
    cwd: process.cwd(),
    env: { ...process.env, PORT: String(port), HOST: "127.0.0.1", APP_ORIGIN: origin, COOKIE_SECURE: "0", DISABLE_EXTERNAL_CHECKS: "1", DATA_FILE: join(directory, "vault.json") },
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("server_start_timeout")), 10_000);
      child.stdout.on("data", (chunk) => {
        if (chunk.toString().includes("CyberTarcza listening")) { clearTimeout(timer); resolve(); }
      });
      child.once("exit", (code) => { clearTimeout(timer); reject(new Error(`server_exited_${code}`)); });
    });

    const status = await fetch(`${origin}/api/status`);
    assert.equal(status.status, 200);
    assert.equal((await status.json()).initialized, false);

    const password = "bezpieczne testowe haslo glowne sklada sie z wielu slow";
    const setup = await fetch(`${origin}/api/setup`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ password, confirmation: password }),
    });
    assert.equal(setup.status, 201);
    const setupData = await setup.json();
    const cookie = cookieFrom(setup);
    assert.ok(cookie.startsWith("ct_session="));
    assert.ok(setupData.csrf);

    const blocked = await fetch(`${origin}/api/controls`, {
      method: "POST",
      headers: { "content-type": "application/json", cookie, origin },
      body: JSON.stringify({ id: "account-passkeys", completed: true }),
    });
    assert.equal(blocked.status, 403);

    const changed = await fetch(`${origin}/api/controls`, {
      method: "POST",
      headers: { "content-type": "application/json", cookie, origin, "x-csrf-token": setupData.csrf },
      body: JSON.stringify({ id: "account-passkeys", completed: true }),
    });
    assert.equal(changed.status, 200);

    const dashboard = await fetch(`${origin}/api/dashboard`, { headers: { cookie } });
    assert.equal(dashboard.status, 200);
    const dashboardData = await dashboard.json();
    assert.ok(dashboardData.vault.completedControls.includes("account-passkeys"));
    assert.ok(dashboardData.score > 0);
    assert.equal(dashboardData.vault.schema, 2);
    assert.equal(dashboardData.vault.compliance.profiles.gdpr, true);

    const protectedHeaders = { "content-type": "application/json", cookie, origin, "x-csrf-token": setupData.csrf };
    const profiles = await fetch(`${origin}/api/compliance/profiles`, {
      method: "PUT", headers: protectedHeaders,
      body: JSON.stringify({ enabled: ["gdpr", "cra", "data_act", "nis2"], settings: { organisation: "Test UE", productName: "IoT Shield", retentionDays: 30 } }),
    });
    assert.equal(profiles.status, 200);

    const rights = await fetch(`${origin}/api/compliance/rights`, {
      method: "POST", headers: protectedHeaders,
      body: JSON.stringify({ type: "access", subjectRef: "OSOBA-123", receivedAt: "2026-01-31T12:00:00.000Z" }),
    });
    assert.equal(rights.status, 201);
    assert.equal((await rights.json()).record.dueAt, "2026-02-28T12:00:00.000Z");

    const incident = await fetch(`${origin}/api/compliance/incidents`, {
      method: "POST", headers: protectedHeaders,
      body: JSON.stringify({ category: "severe_product_incident", title: "INCYDENT-TAJNY", severity: "high", discoveredAt: "2026-02-10T08:30:00.000Z" }),
    });
    assert.equal(incident.status, 201);
    assert.equal((await incident.json()).record.deadlines.length, 6);

    const vulnerability = await fetch(`${origin}/api/compliance/vulnerabilities`, {
      method: "POST", headers: protectedHeaders,
      body: JSON.stringify({ product: "IoT Shield", title: "PODATNOSC-TAJNA", exploited: true, discoveredAt: "2026-03-01T00:00:00.000Z" }),
    });
    assert.equal(vulnerability.status, 201);
    const vulnerabilityData = await vulnerability.json();
    assert.equal(vulnerabilityData.record.deadlines.length, 3);

    const component = await fetch(`${origin}/api/compliance/components`, {
      method: "POST", headers: protectedHeaders,
      body: JSON.stringify({ name: "KOMPONENT-TAJNY", version: "1.2.3", purl: "pkg:generic/test@1.2.3", license: "MIT" }),
    });
    assert.equal(component.status, 201);

    const evidence = await fetch(`${origin}/api/compliance/evidence`, {
      method: "POST", headers: protectedHeaders,
      body: JSON.stringify({ profile: "cra", title: "DOWOD-TAJNY", reference: "RAPORT-1" }),
    });
    assert.equal(evidence.status, 201);
    assert.match((await evidence.json()).evidence.digest, /^[a-f0-9]{64}$/);

    const compliance = await fetch(`${origin}/api/compliance`, { headers: { cookie } });
    assert.equal(compliance.status, 200);
    const complianceData = await compliance.json();
    assert.equal(complianceData.summary.openIncidents, 1);
    assert.equal(complianceData.summary.components, 1);
    assert.equal(complianceData.deadlines.length, 9);

    const sbom = await fetch(`${origin}/api/compliance/sbom`, { headers: { cookie } });
    assert.equal(sbom.status, 200);
    assert.match(sbom.headers.get("content-disposition"), /cybertarcza-sbom\.cdx\.json/);
    assert.equal((await sbom.json()).components[0].name, "KOMPONENT-TAJNY");

    const privacyExport = await fetch(`${origin}/api/privacy/export`, { headers: { cookie } });
    assert.equal(privacyExport.status, 200);
    assert.equal((await privacyExport.json()).rightsRequests[0].subjectRef, "OSOBA-123");

    const encryptedBytes = await readFile(join(directory, "vault.json"));
    for (const secret of ["OSOBA-123", "INCYDENT-TAJNY", "PODATNOSC-TAJNA", "KOMPONENT-TAJNY", "DOWOD-TAJNY"]) {
      assert.equal(encryptedBytes.includes(Buffer.from(secret)), false);
    }

    const closedVulnerability = await fetch(`${origin}/api/compliance/vulnerabilities/${vulnerabilityData.record.id}`, {
      method: "PATCH", headers: protectedHeaders, body: JSON.stringify({ status: "closed" }),
    });
    assert.equal(closedVulnerability.status, 200);
    const retention = await fetch(`${origin}/api/compliance/retention/run`, {
      method: "POST", headers: protectedHeaders, body: "{}",
    });
    assert.equal(retention.status, 200);
    assert.equal((await retention.json()).removed.vulnerabilities, 1);

    const refusedErasure = await fetch(`${origin}/api/privacy/data`, {
      method: "DELETE", headers: protectedHeaders, body: JSON.stringify({ confirmation: "USUN" }),
    });
    assert.equal(refusedErasure.status, 400);

    const erasure = await fetch(`${origin}/api/privacy/data`, {
      method: "DELETE", headers: protectedHeaders, body: JSON.stringify({ confirmation: "USUŃ MOJE DANE" }),
    });
    assert.equal(erasure.status, 200);
    const afterErasure = await fetch(`${origin}/api/dashboard`, { headers: { cookie } });
    const afterErasureData = await afterErasure.json();
    assert.equal(afterErasureData.vault.assets.length, 0);
    assert.equal(afterErasureData.vault.compliance.rightsRequests.length, 0);
    assert.equal(afterErasureData.vault.compliance.incidents.length, 0);
    assert.equal(afterErasureData.vault.compliance.components.length, 1);

    const logout = await fetch(`${origin}/api/logout`, {
      method: "POST",
      headers: { "content-type": "application/json", cookie, origin, "x-csrf-token": setupData.csrf },
      body: "{}",
    });
    assert.equal(logout.status, 200);
    const after = await fetch(`${origin}/api/dashboard`, { headers: { cookie } });
    assert.equal(after.status, 401);
  } finally {
    child.kill("SIGTERM");
    await new Promise((resolve) => child.once("exit", resolve));
    await rm(directory, { recursive: true, force: true });
  }
});
