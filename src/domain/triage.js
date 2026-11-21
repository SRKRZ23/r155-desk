/**
 * First-pass triage of a report text against an inventory, plus the two renderings of an assessment:
 * an Atlassian Document Format (ADF) comment for Jira and a Confluence storage-format audit page.
 * Pure functions (no Forge calls), so they are unit tested and shared by the panel, the actions and the trigger.
 */
import { detectComponents, detectInterfaces, findAffectedAssets, INTERFACE_CLASSES, suggestFactors } from './inventory.js';
import { FACTOR_LABELS, IMPACT_CATEGORIES } from './iso21434.js';

const EXPOSURE_RANK = { direct: 0, indirect: 1, unknown: 2, none: 3 };

/**
 * Detects components and entry interfaces in the text, computes the blast radius for each component and
 * suggests attack-potential factors for the most exposed affected ECU.
 */
export function triageText(text, inventory) {
  const reportedInterfaces = detectInterfaces(text);
  const components = detectComponents(text, inventory).map((d) => findAffectedAssets({ ...d, reportedInterfaces }, inventory));
  const affected = components.flatMap((c) => c.ecus.filter((e) => e.affected));
  const best = affected.sort((a, b) => EXPOSURE_RANK[a.exposure.kind] - EXPOSURE_RANK[b.exposure.kind])[0];
  const exposureKind = best?.exposure.kind || 'unknown';
  return {
    reportedInterfaces,
    reportedInterfaceLabels: reportedInterfaces.map((id) => INTERFACE_CLASSES.find((c) => c.id === id).label),
    components,
    mostExposed: best ? { ecuId: best.ecuId, exposure: best.exposure } : null,
    suggestion: suggestFactors({ text, exposureKind, reportedInterfaces }),
  };
}

// ---------------------------------------------------------------------------------------------
// ADF (Jira comment)
// ---------------------------------------------------------------------------------------------
const t = (text, marks) => (marks ? { type: 'text', text, marks } : { type: 'text', text });
const strong = (text) => t(text, [{ type: 'strong' }]);
const para = (...content) => ({ type: 'paragraph', content });
const bullets = (items) => ({ type: 'bulletList', content: items.map((c) => ({ type: 'listItem', content: [para(...c)] })) });

/** Internal triage note posted on a new ticket. Only facts from the inventory; no risk value (a human rates impact). */
export function triageCommentAdf(triage, inventory) {
  const content = [
    para(strong('R155 Desk: automatic first look'), t(` (inventory: ${inventory.oem || 'imported'}; for analysts only)`)),
  ];
  for (const c of triage.components) {
    const affected = c.ecus.filter((e) => e.affected);
    content.push(para(
      strong(`${c.component} ${c.affectedVersions}`),
      t(`: ${c.affectedEcuCount} affected ECU(s), ${c.fleetExposure.toLocaleString('en-US')} vehicles in the field, markets ${c.markets.join(', ') || 'none'}.`),
    ));
    if (affected.length) {
      content.push(bullets(affected.map((e) => [strong(e.ecuName), t(` ${e.installedVersion}: ${e.exposure.note}`)])));
    }
    const fixed = c.ecus.filter((e) => !e.affected);
    if (fixed.length) content.push(para(t(`Not affected (version outside range): ${fixed.map((e) => `${e.ecuId} ${e.installedVersion}`).join(', ')}.`)));
  }
  content.push(para(t(
    triage.reportedInterfaces.length
      ? `Entry point named in the report: ${triage.reportedInterfaceLabels.join(', ')}.`
      : 'The report names no entry interface: ask the reporter how the issue is reached.',
  )));
  content.push(para(t('Next: rate impact and confirm attack potential in the R155 Assessment panel. Nothing was rated automatically.')));
  return { type: 'doc', version: 1, content };
}

// ---------------------------------------------------------------------------------------------
// Confluence audit record (storage format = XHTML)
// ---------------------------------------------------------------------------------------------
const FACTOR_TITLES = {
  elapsedTime: 'Elapsed time', expertise: 'Specialist expertise', knowledge: 'Knowledge of the item',
  windowOfOpportunity: 'Window of opportunity', equipment: 'Equipment',
};
const esc = (s) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

/** Audit record for one assessed issue, in Confluence storage format. */
export function auditPageStorage({ issue, siteUrl, assessment, history = [], inventory }) {
  const r = assessment.result;
  const b = assessment.blastRadius || {};
  const rows = (pairs) => pairs.map(([k, v]) => `<tr><th>${esc(k)}</th><td>${v}</td></tr>`).join('');
  const factorRows = Object.entries(assessment.factors || {}).map(([f, v]) => [FACTOR_TITLES[f] || f, esc(FACTOR_LABELS[f]?.[v] || v)]);
  const impactRows = IMPACT_CATEGORIES.map((c) => [c[0].toUpperCase() + c.slice(1), esc(assessment.impacts?.[c] || 'not rated')]);
  const issueLink = siteUrl ? `<a href="${esc(`${siteUrl}/browse/${issue.key}`)}">${esc(issue.key)}</a>` : esc(issue.key);
  const exposureList = (b.exposure || []).map((e) => `<li><strong>${esc(e.ecuId)}</strong>: ${esc(e.note)}</li>`).join('');
  const historyRows = history.map((h) => `<tr><td>${esc(h.savedAt)}</td><td>${esc(h.result?.riskValue)}/5</td><td>${esc(h.result?.explanation)}</td></tr>`).join('');

  return [
    `<p>Cybersecurity assessment record for ${issueLink} (${esc(issue.summary)}). Generated by R155 Desk from the saved assessment; edit the assessment in Jira, not here.</p>`,
    '<h2>1. Affected item</h2>',
    `<table><tbody>${rows([
      ['Component', esc(`${assessment.component} ${assessment.affectedVersions || '(all versions)'}`)],
      ['Affected ECUs', esc((b.affectedEcus || []).join(', ') || 'none')],
      ['Vehicle lines', esc((b.vehicleLines || []).join(', ') || 'none')],
      ['Vehicles in the field', esc(Number(b.fleetExposure || 0).toLocaleString('en-US'))],
      ['Markets', esc((b.markets || []).join(', ') || 'none')],
      ['Inventory', esc(inventory?.oem || 'imported')],
    ])}</tbody></table>`,
    exposureList ? `<h3>Reachability from the reported entry point</h3><ul>${exposureList}</ul>` : '',
    '<h2>2. Impact rating (ISO/SAE 21434, clause 15.5)</h2>',
    `<table><tbody>${rows(impactRows)}</tbody></table>`,
    '<h2>3. Attack feasibility (attack-potential approach, Annex G)</h2>',
    `<table><tbody>${rows([...factorRows, ['Attack potential', esc(r.attackPotential)], ['Feasibility', esc(r.feasibility)]])}</tbody></table>`,
    '<h2>4. Risk determination and treatment</h2>',
    `<table><tbody>${rows([
      ['Risk value', `<strong>${esc(r.riskValue)}/5 (${esc(r.riskLabel)})</strong>`],
      ['Treatment decision', esc(r.treatment)],
      ['Triage due', esc(r.triageDue)],
      ['Remediation due', esc(r.remediationDue || 'none (risk retained)')],
      ['Reasoning', esc(r.explanation)],
    ])}</tbody></table>`,
    '<h2>5. Record</h2>',
    `<table><tbody>${rows([['Assessed by (account id)', esc(assessment.savedBy)], ['Saved at (UTC)', esc(assessment.savedAt)], ['Discovered', esc(assessment.discoveredAt)]])}</tbody></table>`,
    historyRows ? `<h3>Earlier ratings</h3><table><tbody><tr><th>Saved at</th><th>Risk</th><th>Reasoning</th></tr>${historyRows}</tbody></table>` : '',
    '<p><em>Method: risk matrix and attack-potential values follow the example tables in ISO/SAE 21434 Annexes G and H; deadlines follow the organisation\'s response policy configured in R155 Desk.</em></p>',
  ].join('\n');
}
