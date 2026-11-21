// Tests for interface exposure, attack-path search, factor suggestions and inventory import.
import test from 'node:test';
import assert from 'node:assert/strict';
import { isImpactRated } from '../src/domain/iso21434.js';
import {
  DEMO_INVENTORY, detectInterfaces, exposureOf, findAffectedAssets, suggestFactors,
  importInventory, inventoryToCsv, parseCsv, validateInventory,
} from '../src/domain/inventory.js';

const REPORT = 'External researcher reports a heap overflow in the TLS handshake of OpenSSL before 3.0.8. Reachable from the infotainment Wi-Fi hotspot without authentication. Public proof of concept exists.';

test('impact is "not rated" until a category is chosen', () => {
  assert.equal(isImpactRated({}), false);
  assert.equal(isImpactRated({ safety: '' }), false);
  assert.equal(isImpactRated({ privacy: 'negligible' }), true);
});

test('detectInterfaces finds Wi-Fi and ignores the English word "can"', () => {
  assert.deepEqual(detectInterfaces(REPORT), ['wifi']);
  assert.deepEqual(detectInterfaces('An attacker can send frames'), []);
  assert.deepEqual(detectInterfaces('Malformed CAN frames over OBD'), ['obd', 'can']);
  assert.deepEqual(detectInterfaces('exploitable over LTE and Bluetooth'), ['bluetooth', 'cellular']);
});

test('exposure: IVI-2 is direct over Wi-Fi, ADAS-2 is indirect via the gateway', () => {
  assert.equal(exposureOf('IVI-2', ['wifi']).kind, 'direct');
  const adas = exposureOf('ADAS-2', ['wifi']);
  assert.equal(adas.kind, 'indirect');
  assert.deepEqual(adas.path, ['IVI-2', 'CGW-1', 'ADAS-2']);
  assert.equal(adas.hops, 2);
  assert.equal(exposureOf('ADAS-2', []).kind, 'unknown');
});

test('exposure: no path when the entry ECU is not connected', () => {
  const isolated = {
    vehicleLines: [{ id: 'L', fleet: 1, markets: [] }],
    ecus: [
      { id: 'A', interfaces: ['Wi-Fi'], connectsTo: [], vehicleLines: ['L'], components: [{ name: 'x', version: '1' }] },
      { id: 'B', interfaces: ['CAN'], connectsTo: [], vehicleLines: ['L'], components: [{ name: 'x', version: '1' }] },
    ],
  };
  assert.equal(exposureOf('B', ['wifi'], isolated).kind, 'none');
});

test('blast radius orders direct exposure first and counts directly exposed vehicles', () => {
  const r = findAffectedAssets({ component: 'OpenSSL', affectedVersions: '<3.0.8', reportedInterfaces: ['wifi'] });
  assert.deepEqual(r.ecus.map((e) => e.ecuId), ['IVI-2', 'ADAS-2', 'TCU-4']);
  assert.equal(r.directlyExposedEcuCount, 1);
  assert.equal(r.fleetExposure, 278500);
  assert.equal(r.directFleetExposure, 278500); // IVI-2 is in both S1 and X3
  assert.equal(r.ecus[2].exposure, null); // not affected -> no exposure computed
});

test('suggestFactors: public PoC over Wi-Fi, direct = easy window, proficient attacker', () => {
  const { factors, reasons } = suggestFactors({ text: REPORT, exposureKind: 'direct', reportedInterfaces: ['wifi'] });
  assert.deepEqual(factors, { elapsedTime: 'le1week', expertise: 'proficient', knowledge: 'public', windowOfOpportunity: 'easy', equipment: 'standard' });
  assert.match(reasons.elapsedTime, /proof of concept/);
});

test('suggestFactors: indirect path raises expertise and narrows the window', () => {
  const { factors } = suggestFactors({ text: REPORT, exposureKind: 'indirect', reportedInterfaces: ['wifi'] });
  assert.equal(factors.expertise, 'expert');
  assert.equal(factors.windowOfOpportunity, 'moderate');
  assert.equal(factors.elapsedTime, 'le1month');
});

test('CSV round trip: demo inventory exported and re-imported gives the same blast radius', () => {
  const csv = inventoryToCsv(DEMO_INVENTORY);
  const { inventory, problems } = importInventory(csv);
  assert.deepEqual(problems, []);
  assert.equal(inventory.ecus.length, DEMO_INVENTORY.ecus.length);
  const a = findAffectedAssets({ component: 'OpenSSL', affectedVersions: '<3.0.8', reportedInterfaces: ['wifi'] }, inventory);
  assert.equal(a.fleetExposure, 278500);
  assert.equal(a.ecus.find((e) => e.ecuId === 'ADAS-2').exposure.kind, 'indirect');
});

test('CSV parser handles quotes, commas and escaped quotes', () => {
  assert.deepEqual(parseCsv('a,"b,c","d ""e"""\n1,2,3\n'), [['a', 'b,c', 'd "e"'], ['1', '2', '3']]);
});

test('import rejects bad input with readable problems', () => {
  assert.match(importInventory('{bad json').problems[0], /Invalid JSON/);
  assert.match(importInventory('foo,bar\n1,2').problems[0], /Missing CSV column/);
  const problems = validateInventory({ vehicleLines: [], ecus: [{ id: 'X', vehicleLines: ['NOPE'], components: [], connectsTo: ['Y'] }] });
  assert.ok(problems.some((p) => /unknown vehicle line NOPE/.test(p)));
  assert.ok(problems.some((p) => /no software components/.test(p)));
  assert.ok(problems.some((p) => /unknown ECU Y/.test(p)));
});

test('detectComponents: version found in a later mention, "A through B" becomes a closed range', async () => {
  const { detectComponents, versionInRange } = await import('../src/domain/inventory.js');
  const text = 'Supplier advisory: curl SOCKS5 heap overflow (CVE-2023-38545) in the telematics update client\nTier-1 B reports that the TCU-4 update client uses curl 7.69.0 through 8.3.0, affected by CVE-2023-38545.';
  assert.deepEqual(detectComponents(text), [{ component: 'curl', affectedVersions: '>=7.69.0 <=8.3.0' }]);
  assert.ok(versionInRange('7.88.1', '>=7.69.0 <=8.3.0'));
  assert.ok(!versionInRange('8.4.0', '>=7.69.0 <=8.3.0'));
  // "linux" inside another word is not a match; the CVE number is not a version
  assert.deepEqual(detectComponents('Bug in mylinuxtool and CVE-2024-1234'), []);
});
