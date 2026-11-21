// Unit tests for the pure domain logic (no Forge runtime needed): `node --test test/`
import test from 'node:test';
import assert from 'node:assert/strict';
import { assessRisk, attackPotential, feasibilityFromPotential, overallImpact, RISK_MATRIX } from '../src/domain/iso21434.js';
import { compareVersions, versionInRange, findAffectedAssets, detectComponents } from '../src/domain/inventory.js';

const easyAttack = { elapsedTime: 'le1day', expertise: 'proficient', knowledge: 'public', windowOfOpportunity: 'unlimited', equipment: 'standard' };
const hardAttack = { elapsedTime: 'gt6months', expertise: 'multipleExperts', knowledge: 'strictlyConfidential', windowOfOpportunity: 'difficult', equipment: 'multipleBespoke' };

test('overall impact is the worst category', () => {
  assert.equal(overallImpact({ safety: 'moderate', financial: 'major', operational: 'negligible', privacy: 'moderate' }), 'major');
  assert.equal(overallImpact({}), 'negligible');
});

test('attack potential sums factors and rejects unknown values', () => {
  assert.equal(attackPotential(easyAttack), 3);
  assert.equal(attackPotential(hardAttack), 19 + 8 + 11 + 10 + 9);
  assert.throws(() => attackPotential({ ...easyAttack, equipment: 'laser' }), /equipment/);
  assert.throws(() => attackPotential({ elapsedTime: 'le1day' }), /expertise/);
});

test('feasibility bands follow Annex G boundaries', () => {
  assert.equal(feasibilityFromPotential(0), 'high');
  assert.equal(feasibilityFromPotential(9), 'high');
  assert.equal(feasibilityFromPotential(10), 'medium');
  assert.equal(feasibilityFromPotential(13), 'medium');
  assert.equal(feasibilityFromPotential(14), 'low');
  assert.equal(feasibilityFromPotential(19), 'low');
  assert.equal(feasibilityFromPotential(20), 'veryLow');
});

test('risk matrix is monotonic in impact and feasibility', () => {
  const impacts = ['negligible', 'moderate', 'major', 'severe'];
  const feas = ['veryLow', 'low', 'medium', 'high'];
  for (let i = 0; i < impacts.length; i += 1) {
    for (let f = 0; f < feas.length; f += 1) {
      const v = RISK_MATRIX[impacts[i]][feas[f]];
      if (i > 0) assert.ok(v >= RISK_MATRIX[impacts[i - 1]][feas[f]]);
      if (f > 0) assert.ok(v >= RISK_MATRIX[impacts[i]][feas[f - 1]]);
    }
  }
});

test('assessRisk: severe safety impact + easy remote attack = 5, deadlines from discovery date', () => {
  const r = assessRisk({ impacts: { safety: 'severe' }, factors: easyAttack, discoveredAt: '2026-11-20' });
  assert.equal(r.riskValue, 5);
  assert.equal(r.feasibility, 'high');
  assert.deepEqual(r.worstCategories, ['safety']);
  assert.equal(r.triageDue, '2026-11-21');
  assert.equal(r.remediationDue, '2026-12-04');
});

test('assessRisk: severe impact but very hard attack = 2', () => {
  const r = assessRisk({ impacts: { safety: 'severe' }, factors: hardAttack, discoveredAt: '2026-11-20' });
  assert.equal(r.feasibility, 'veryLow');
  assert.equal(r.riskValue, 2);
});

test('version comparison and ranges', () => {
  assert.equal(compareVersions('3.0.7', '3.0.8'), -1);
  assert.equal(compareVersions('7.1', '7.1.0'), 0);
  assert.equal(compareVersions('5.10.120', '5.9.999'), 1);
  assert.ok(versionInRange('3.0.7', '<3.0.8'));
  assert.ok(!versionInRange('3.0.13', '<3.0.8'));
  assert.ok(versionInRange('3.0.7', '>=3.0.0 <3.0.8'));
  assert.ok(versionInRange('7.1.0', '=7.1'));
  assert.ok(versionInRange('1.0', ''));
  assert.ok(!versionInRange('1.0', 'garbage'));
});

test('findAffectedAssets separates affected and patched ECUs and sums fleet exposure', () => {
  const r = findAffectedAssets({ component: 'OpenSSL', affectedVersions: '<3.0.8' });
  assert.equal(r.ecus.length, 3); // IVI-2, TCU-4, ADAS-2 run OpenSSL
  assert.equal(r.affectedEcuCount, 2); // TCU-4 has 3.0.13 (fixed)
  assert.deepEqual(r.vehicleLines.map((l) => l.id).sort(), ['AM-S1', 'AM-X3']);
  assert.equal(r.fleetExposure, 182000 + 96500);
});

test('findAffectedAssets matches aliases case-insensitively', () => {
  const r = findAffectedAssets({ component: 'qnx', affectedVersions: '' });
  assert.deepEqual(r.ecus.map((e) => e.ecuId).sort(), ['ADAS-2', 'IVI-2']);
});

test('detectComponents pulls component + range out of free text', () => {
  const found = detectComponents('Researcher report: heap overflow in OpenSSL before 3.0.8 reachable over Wi-Fi; also seen on QNX Neutrino 7.1');
  assert.deepEqual(found, [
    { component: 'OpenSSL', affectedVersions: '<3.0.8' },
    { component: 'QNX Neutrino RTOS', affectedVersions: '=7.1' },
  ]);
});
