/**
 * Backend entry points.
 *
 *  - `resolver`: functions the issue panel (UI Kit frontend) calls with `invoke(...)`.
 *  - `findAffectedAssetsAction`, `assessRiskAction`, `getAssessmentAction`: Rovo actions. The same actions
 *    are used by the R155 Triage agent and exposed to external AI clients through the `rovo:mcp` module.
 *
 * The risk maths lives in src/domain (pure functions with unit tests); this file only wires it to Forge.
 */
import Resolver from '@forge/resolver';
import { assessRisk, ATTACK_POTENTIAL_FACTORS, IMPACT_CATEGORIES, IMPACT_LEVELS } from './domain/iso21434.js';
import { detectComponents, findAffectedAssets } from './domain/inventory.js';
import { getAssessment, getIssue, saveAssessment } from './jira.js';

// ---------------------------------------------------------------------------------------------
// Issue panel resolver
// ---------------------------------------------------------------------------------------------
const resolver = new Resolver();

/** Everything the panel needs on first render: issue text, detected components and any saved assessment. */
resolver.define('loadPanel', async ({ context }) => {
  const issueKey = context.extension.issue.key;
  const [issue, saved] = await Promise.all([getIssue(issueKey), getAssessment(issueKey)]);
  const detected = detectComponents(`${issue.summary}\n${issue.description}`);
  return { issue, detected, saved };
});

/** Saves the assessment the user confirmed in the panel, with who saved it and when. */
resolver.define('saveAssessment', async ({ payload, context }) => {
  const issueKey = context.extension.issue.key;
  const { component, affectedVersions, impacts, factors, discoveredAt } = payload;
  // Recompute on the server: the stored result must not depend on numbers sent by the browser.
  const result = assessRisk({ impacts, factors, discoveredAt });
  const blastRadius = findAffectedAssets({ component, affectedVersions });
  const previous = await getAssessment(issueKey);
  const entry = {
    component,
    affectedVersions,
    impacts,
    factors,
    discoveredAt,
    result,
    blastRadius: {
      affectedEcus: blastRadius.ecus.filter((e) => e.affected).map((e) => e.ecuId),
      vehicleLines: blastRadius.vehicleLines.map((l) => l.id),
      fleetExposure: blastRadius.fleetExposure,
      markets: blastRadius.markets,
    },
    savedBy: context.accountId,
    savedAt: new Date().toISOString(),
  };
  // Keep a short audit trail of earlier versions so an auditor can see how the rating evolved.
  const history = [...(previous?.history || []), ...(previous?.current ? [previous.current] : [])].slice(-20);
  return saveAssessment(issueKey, { current: entry, history });
});

export const handler = resolver.getDefinitions();

// ---------------------------------------------------------------------------------------------
// Rovo actions (also MCP tools)
// ---------------------------------------------------------------------------------------------

/** Issue key from the explicit input, or from the issue the user is looking at when they chat. */
function issueKeyFrom(payload) {
  return payload.issueKey || payload.context?.jira?.issueKey || null;
}

export async function findAffectedAssetsAction(payload) {
  if (!payload.component) return { error: 'Input "component" is required, e.g. "OpenSSL".' };
  return findAffectedAssets({ component: payload.component, affectedVersions: payload.affectedVersions || '' });
}

export async function assessRiskAction(payload) {
  const impacts = Object.fromEntries(IMPACT_CATEGORIES.map((c) => [c, payload[c] || 'negligible']));
  for (const [c, v] of Object.entries(impacts)) {
    if (!IMPACT_LEVELS.includes(v)) return { error: `Impact "${c}" must be one of ${IMPACT_LEVELS.join(', ')}; got "${v}".` };
  }
  const factors = Object.fromEntries(Object.keys(ATTACK_POTENTIAL_FACTORS).map((f) => [f, payload[f]]));
  try {
    return assessRisk({ impacts, factors, discoveredAt: payload.discoveredAt });
  } catch (e) {
    return { error: e.message };
  }
}

export async function getAssessmentAction(payload) {
  const issueKey = issueKeyFrom(payload);
  if (!issueKey) return { error: 'No issue given. Pass "issueKey" (for example SECOPS-12) or ask from an open issue.' };
  const [issue, saved] = await Promise.all([getIssue(issueKey), getAssessment(issueKey)]);
  const detected = detectComponents(`${issue.summary}\n${issue.description}`);
  const blastRadius = detected.map((d) => findAffectedAssets(d));
  return {
    issue: { key: issue.key, summary: issue.summary, status: issue.status, created: issue.created },
    savedAssessment: saved?.current || null,
    detectedComponents: detected,
    blastRadius,
    note: saved ? 'A saved assessment exists; the blast radius below is recomputed from the current inventory.' : 'Not assessed yet.',
  };
}
