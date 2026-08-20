import test from "node:test";
import assert from "node:assert/strict";
import {
  buildComplianceSummary,
  buildCycloneDx,
  createComponent,
  createIncident,
  createRightRequest,
  createVulnerability,
  defaultCompliance,
  normalizeCompliance,
} from "../lib/eu-compliance.mjs";

test("GDPR, NIS2 and CRA operational deadlines are calculated", () => {
  const compliance = defaultCompliance();
  compliance.profiles.nis2 = true;

  const breach = createIncident({
    category: "personal_data_breach",
    title: "Testowe naruszenie",
    discoveredAt: "2026-01-01T10:00:00.000Z",
  }, compliance.profiles);
  assert.equal(breach.deadlines.length, 1);
  assert.equal(breach.deadlines[0].framework, "GDPR");
  assert.equal(breach.deadlines[0].dueAt, "2026-01-04T10:00:00.000Z");

  const severe = createIncident({
    category: "severe_product_incident",
    title: "Poważny incydent produktu",
    discoveredAt: "2026-02-10T08:30:00.000Z",
  }, compliance.profiles);
  assert.deepEqual(severe.deadlines.map((item) => item.framework), ["NIS2", "NIS2", "NIS2", "CRA", "CRA", "CRA"]);
  assert.equal(severe.deadlines[0].dueAt, "2026-02-11T08:30:00.000Z");
  assert.equal(severe.deadlines[1].dueAt, "2026-02-13T08:30:00.000Z");
  assert.equal(severe.deadlines[2].dueAt, "2026-03-10T08:30:00.000Z");

  const vulnerability = createVulnerability({
    product: "Urządzenie IoT",
    title: "Podatność testowa",
    exploited: true,
    discoveredAt: "2026-03-01T00:00:00.000Z",
  }, compliance.profiles);
  assert.equal(vulnerability.deadlines.length, 3);
  assert.equal(vulnerability.deadlines[2].dueAt, null);
});

test("rights workflow, migration and CycloneDX export remain bounded", () => {
  const request = createRightRequest({
    type: "access",
    subjectRef: "SPRAWA-42",
    receivedAt: "2026-01-31T12:00:00.000Z",
  });
  assert.equal(request.dueAt, "2026-02-28T12:00:00.000Z");

  const migrated = normalizeCompliance({ profiles: { gdpr: false }, rightsRequests: [request] });
  assert.equal(migrated.profiles.gdpr, false);
  assert.equal(migrated.profiles.cra, true);
  assert.equal(migrated.rightsRequests.length, 1);

  migrated.components.push(createComponent({
    name: "node",
    version: "24.0.0",
    supplier: "OpenJS Foundation",
    purl: "pkg:generic/node@24.0.0",
    license: "MIT",
  }));
  const sbom = buildCycloneDx(migrated);
  assert.equal(sbom.bomFormat, "CycloneDX");
  assert.equal(sbom.specVersion, "1.6");
  assert.equal(sbom.components[0].purl, "pkg:generic/node@24.0.0");

  const summary = buildComplianceSummary(migrated, "2026-02-01T00:00:00.000Z");
  assert.equal(summary.openRightsRequests, 1);
  assert.equal(summary.components, 1);
});
