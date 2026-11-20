/**
 * Small helpers around the Jira REST API, used by both the issue-panel resolver and the Rovo actions.
 * All calls run as the current user (`asUser`), so Jira's own permission checks apply: a user who
 * cannot see an issue cannot read or change its assessment through this app either.
 */
import api, { route } from '@forge/api';

/** Issue property key under which the assessment is stored on the Jira issue itself. */
export const PROPERTY_KEY = 'r155-desk-assessment';

/** Flattens Atlassian Document Format (the rich-text JSON Jira uses for descriptions) to plain text. */
export function adfToText(node) {
  if (!node) return '';
  if (typeof node === 'string') return node;
  if (node.type === 'text') return node.text || '';
  const inner = (node.content || []).map(adfToText).join(node.type === 'doc' ? '\n' : '');
  return ['paragraph', 'heading', 'listItem', 'codeBlock'].includes(node.type) ? `${inner}\n` : inner;
}

async function readJson(response, what) {
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`${what} failed: HTTP ${response.status} ${body.slice(0, 200)}`);
  }
  // Some Jira endpoints (e.g. PUT issue property) answer 200/201 with an EMPTY body, so parse only if there is text.
  const text = await response.text();
  return text ? JSON.parse(text) : null;
}

/** Reads the issue's key, summary, description (as text) and creation date. */
export async function getIssue(issueKey) {
  const res = await api.asUser().requestJira(route`/rest/api/3/issue/${issueKey}?fields=summary,description,created,status`);
  const json = await readJson(res, `Reading issue ${issueKey}`);
  return {
    key: json.key,
    summary: json.fields.summary || '',
    description: adfToText(json.fields.description).trim(),
    created: json.fields.created,
    status: json.fields.status?.name,
  };
}

/** Returns the saved assessment, or null when the issue has not been assessed yet. */
export async function getAssessment(issueKey) {
  const res = await api.asUser().requestJira(route`/rest/api/3/issue/${issueKey}/properties/${PROPERTY_KEY}`);
  if (res.status === 404) return null;
  const json = await readJson(res, `Reading assessment of ${issueKey}`);
  return json.value;
}

/** Saves the assessment as an issue property (overwrites the previous one; history is kept inside it). */
export async function saveAssessment(issueKey, value) {
  const res = await api.asUser().requestJira(route`/rest/api/3/issue/${issueKey}/properties/${PROPERTY_KEY}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(value),
  });
  await readJson(res, `Saving assessment of ${issueKey}`);
  return value;
}
