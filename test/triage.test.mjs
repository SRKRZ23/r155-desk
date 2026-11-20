// Tests for first-pass triage and the two renderings (Jira comment ADF, Confluence audit page).
import test from 'node:test';
import assert from 'node:assert/strict';
import { DEMO_INVENTORY } from '../src/domain/inventory.js';
import { assessRisk } from '../src/domain/iso21434.js';
import { auditPageStorage, triageCommentAdf, triageText } from '../src/domain/triage.js';

const TEXT = 'Researcher report: heap overflow in OpenSSL before 3.0.8 reachable over Wi-Fi\nExternal researcher reports a heap overflow in the TLS handshake of OpenSSL before 3.0.8. Reachable from the infotainment Wi-Fi hotspot without authentication. Public proof of concept exists.';

test('triageText: component, entry interface, most exposed ECU and suggestions', () => {
  const t = triageText(TEXT, DEMO_INVENTORY);
  assert.deepEqual(t.reportedInterfaces, ['wifi']);
  assert.equal(t.components.length, 1);
  assert.equal(t.components[0].component, 'OpenSSL');
  assert.equal(t.mostExposed.ecuId, 'IVI-2');
  assert.equal(t.mostExposed.exposure.kind, 'direct');
  assert.equal(t.suggestion.factors.windowOfOpportunity, 'easy');
});

test('triageText: unknown text gives no components and no most-exposed ECU', () => {
  const t = triageText('Printer on floor 3 is jammed', DEMO_INVENTORY);
  assert.equal(t.components.length, 0);
  assert.equal(t.mostExposed, null);
});

test('comment ADF lists affected ECUs with exposure, the fixed ECU, and never a risk value', () => {
  const adf = triageCommentAdf(triageText(TEXT, DEMO_INVENTORY), DEMO_INVENTORY);
  const text = JSON.stringify(adf);
  assert.equal(adf.type, 'doc');
  assert.match(text, /Directly reachable over Wi-Fi/);
  assert.match(text, /IVI-2 -> CGW-1|CGW-1 -> ADAS-2/);
  assert.match(text, /TCU-4 3\.0\.13/);
  assert.match(text, /278,500 vehicles/);
  assert.doesNotMatch(text, /\/5/);
});

test('audit page escapes HTML and contains the four ISO 21434 sections', () => {
  const result = assessRisk({ impacts: { safety: 'severe' }, factors: { elapsedTime: 'le1week', expertise: 'proficient', knowledge: 'public', windowOfOpportunity: 'easy', equipment: 'standard' }, discoveredAt: '2026-11-20' });
  const html = auditPageStorage({
    issue: { key: 'SECOPS-1', summary: '<script>alert(1)</script>' },
    siteUrl: 'https://x.atlassian.net',
    assessment: { component: 'OpenSSL', affectedVersions: '<3.0.8', impacts: { safety: 'severe' }, factors: { elapsedTime: 'le1week' }, result, blastRadius: { affectedEcus: ['IVI-2'], exposure: [{ ecuId: 'IVI-2', note: 'Directly reachable over Wi-Fi.' }], vehicleLines: ['AM-S1'], fleetExposure: 182000, markets: ['EU'] }, savedBy: 'acc', savedAt: '2026-11-20T00:00:00Z', discoveredAt: '2026-11-20' },
    inventory: DEMO_INVENTORY,
  });
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /&lt;script&gt;/);
  assert.match(html, /&lt;3\.0\.8/);
  for (const h of ['1. Affected item', '2. Impact rating', '3. Attack feasibility', '4. Risk determination']) assert.ok(html.includes(h), h);
  assert.match(html, /5\/5 \(Critical\)/);
  assert.match(html, /182,000/);
});

test('graph objects: one per ECU and per vehicle line, searchable text, stable ids', async () => {
  const { inventoryToGraphObjects } = await import('../src/domain/graph-objects.js');
  const objs = inventoryToGraphObjects(DEMO_INVENTORY, { baseUrl: 'https://x.atlassian.net/jira/settings/apps/a/b', updatedAt: '2026-11-21T00:00:00Z' });
  assert.equal(objs.length, DEMO_INVENTORY.ecus.length + DEMO_INVENTORY.vehicleLines.length);
  const ivi = objs.find((o) => o.id === 'ecu:IVI-2');
  assert.match(ivi['atlassian:document'].content.text, /OpenSSL 3\.0\.7/);
  assert.match(ivi['atlassian:document'].content.text, /Aurora S1/);
  assert.equal(ivi.url, 'https://x.atlassian.net/jira/settings/apps/a/b#ecu-IVI-2');
  assert.equal(new Set(objs.map((o) => o.id)).size, objs.length);
  assert.equal(ivi.updateSequenceNumber, Date.parse('2026-11-21T00:00:00Z'));
});
