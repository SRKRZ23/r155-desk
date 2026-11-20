/**
 * Backend entry points.
 *
 *  - `handler`: resolver functions called from the UI Kit frontends (issue panel and admin page).
 *  - `*Action`: Rovo actions. The same actions are used by the R155 Triage agent and exposed to external AI
 *    clients through the `rovo:mcp` module.
 *  - `onIssueCreated`: trigger that posts an internal first-look note when a new ticket names a known component.
 *
 * The domain logic lives in src/domain (pure functions with unit tests); this file only wires it to Forge.
 */
import Resolver from '@forge/resolver';
import { assessRisk, ATTACK_POTENTIAL_FACTORS, IMPACT_CATEGORIES, IMPACT_LEVELS, isImpactRated } from './domain/iso21434.js';
import { detectInterfaces, findAffectedAssets, importInventory, inventoryToCsv, DEMO_INVENTORY } from './domain/inventory.js';
import { auditPageStorage, triageCommentAdf, triageText } from './domain/triage.js';
import {
  addInternalComment, currentUserIsJiraAdmin, getAssessment, getAutoTriage, getIssue, saveAssessment, setAutoTriage,
} from './jira.js';
import { getInventory, getSettings, resetInventory, saveInventory, saveSettings } from './storage.js';
import { publishAuditPage } from './confluence.js';

const issueText = (issue) => `${issue.summary}\n${issue.description}`;

function inventorySummary(inv) {
  return {
    oem: inv.oem,
    source: inv.source || 'imported',
    importedAt: inv.importedAt || null,
    vehicleLines: inv.vehicleLines.length,
    ecus: inv.ecus.length,
    components: inv.ecus.reduce((n, e) => n + e.components.length, 0),
    fleet: inv.vehicleLines.reduce((n, l) => n + Number(l.fleet || 0), 0),
  };
}

async function requireAdmin() {
  if (!(await currentUserIsJiraAdmin())) throw new Error('Only Jira administrators can change R155 Desk settings or the inventory.');
}

// ---------------------------------------------------------------------------------------------
// Resolvers
// ---------------------------------------------------------------------------------------------
const resolver = new Resolver();

/** Everything the issue panel needs on first render. The inventory is sent so the panel can recompute locally. */
resolver.define('loadPanel', async ({ context }) => {
  const issueKey = context.extension.issue.key;
  const [issue, saved, inventory, settings] = await Promise.all([getIssue(issueKey), getAssessment(issueKey), getInventory(), getSettings()]);
  return {
    issue,
    saved,
    inventory,
    triage: triageText(issueText(issue), inventory),
    confluenceSpaceKey: settings.confluenceSpaceKey || null,
  };
});

/** Saves the assessment the analyst confirmed. Everything is recomputed on the server from the stored inventory. */
resolver.define('saveAssessment', async ({ payload, context }) => {
  const issueKey = context.extension.issue.key;
  const { component, affectedVersions, impacts, factors, discoveredAt, reportedInterfaces = [] } = payload;
  if (!isImpactRated(impacts)) throw new Error('Rate at least one impact category before saving.');
  const result = assessRisk({ impacts, factors, discoveredAt });
  const inventory = await getInventory();
  const blast = findAffectedAssets({ component, affectedVersions, reportedInterfaces }, inventory);
  const previous = await getAssessment(issueKey);
  const entry = {
    component,
    affectedVersions,
    reportedInterfaces,
    impacts,
    factors,
    discoveredAt,
    result,
    blastRadius: {
      affectedEcus: blast.ecus.filter((e) => e.affected).map((e) => e.ecuId),
      exposure: blast.ecus.filter((e) => e.affected).map((e) => ({ ecuId: e.ecuId, kind: e.exposure.kind, note: e.exposure.note })),
      vehicleLines: blast.vehicleLines.map((l) => l.id),
      fleetExposure: blast.fleetExposure,
      markets: blast.markets,
    },
    confluencePage: previous?.current?.confluencePage || null,
    savedBy: context.accountId,
    savedAt: new Date().toISOString(),
  };
  // Keep a short audit trail of earlier versions so an auditor can see how the rating evolved.
  const history = [...(previous?.history || []), ...(previous?.current ? [previous.current] : [])].slice(-20);
  return saveAssessment(issueKey, { current: entry, history });
});

/** Creates or updates the Confluence audit record for the saved assessment. */
resolver.define('publishAudit', async ({ context }) => {
  const issueKey = context.extension.issue.key;
  const [settings, saved, issue, inventory] = await Promise.all([getSettings(), getAssessment(issueKey), getIssue(issueKey), getInventory()]);
  if (!settings.confluenceSpaceKey) throw new Error('No Confluence space is configured. A Jira admin can set one on the R155 Desk admin page.');
  if (!saved?.current) throw new Error('Save the assessment first.');
  const a = saved.current;
  const page = await publishAuditPage({
    spaceKey: settings.confluenceSpaceKey,
    title: `R155 assessment ${issue.key}: ${a.component} ${a.affectedVersions || ''}`.trim(),
    storage: auditPageStorage({ issue, siteUrl: context.siteUrl, assessment: a, history: saved.history, inventory }),
    existingPageId: a.confluencePage?.id,
  });
  const updated = { ...saved, current: { ...a, confluencePage: { ...page, publishedAt: new Date().toISOString() } } };
  await saveAssessment(issueKey, updated);
  return updated.current.confluencePage;
});

// Admin page -----------------------------------------------------------------------------------
resolver.define('loadAdmin', async () => {
  const [inventory, settings] = await Promise.all([getInventory(), getSettings()]);
  return { summary: inventorySummary(inventory), settings, csvTemplate: inventoryToCsv(DEMO_INVENTORY) };
});

resolver.define('previewImport', async ({ payload }) => {
  const { inventory, problems } = importInventory(payload.text);
  return { problems, summary: inventory ? inventorySummary(inventory) : null };
});

resolver.define('saveImport', async ({ payload }) => {
  await requireAdmin();
  const { inventory, problems } = importInventory(payload.text);
  if (!inventory) return { problems };
  await saveInventory(inventory);
  return { problems: [], summary: inventorySummary(inventory) };
});

resolver.define('resetInventory', async () => {
  await requireAdmin();
  await resetInventory();
  return { summary: inventorySummary(DEMO_INVENTORY) };
});

resolver.define('saveSettings', async ({ payload }) => {
  await requireAdmin();
  return saveSettings(payload);
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
  const inventory = await getInventory();
  return findAffectedAssets(
    { component: payload.component, affectedVersions: payload.affectedVersions || '', reportedInterfaces: detectInterfaces(payload.entryInterface || '') },
    inventory,
  );
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
  const [issue, saved, inventory] = await Promise.all([getIssue(issueKey), getAssessment(issueKey), getInventory()]);
  const triage = triageText(issueText(issue), inventory);
  return {
    issue: { key: issue.key, summary: issue.summary, status: issue.status, created: issue.created },
    savedAssessment: saved?.current || null,
    entryInterfacesInReport: triage.reportedInterfaceLabels,
    blastRadius: triage.components,
    mostExposedEcu: triage.mostExposed,
    suggestedFactors: triage.suggestion,
    note: 'Exposure: direct = the ECU itself has the reported interface; indirect = reachable only through other ECUs (path given). Suggested factors are a starting point with reasons, not a rating.',
  };
}

// ---------------------------------------------------------------------------------------------
// Trigger: internal first-look note on new tickets
// ---------------------------------------------------------------------------------------------
export async function onIssueCreated(event) {
  const issueKey = event?.issue?.key;
  if (!issueKey) return;
  const settings = await getSettings();
  if (!settings.autoComment) return;
  const projectKey = event.issue.fields?.project?.key || issueKey.split('-')[0];
  if (settings.projectKeys.length && !settings.projectKeys.includes(projectKey)) return;
  if (await getAutoTriage(issueKey)) return; // already done (events can be delivered more than once)

  const [issue, inventory] = await Promise.all([getIssue(issueKey, { asApp: true }), getInventory()]);
  const triage = triageText(issueText(issue), inventory);
  if (!triage.components.some((c) => c.affectedEcuCount > 0 || c.ecus.length > 0)) return; // nothing we know about

  await addInternalComment(issueKey, triageCommentAdf(triage, inventory));
  await setAutoTriage(issueKey, {
    at: new Date().toISOString(),
    components: triage.components.map((c) => ({ component: c.component, affectedVersions: c.affectedVersions, affectedEcuCount: c.affectedEcuCount, fleetExposure: c.fleetExposure })),
  });
}
