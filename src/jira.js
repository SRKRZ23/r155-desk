/**
 * Helpers around the Jira REST API, used by the issue panel, the admin page, the Rovo actions and the
 * issue-created trigger.
 *
 * User-initiated calls run as the current user (`asUser`), so Jira's own permission checks apply: a user who
 * cannot see an issue cannot read or change its assessment through this app either. The trigger has no
 * user, so it runs as the app (`asApp`) and only reads the new issue and adds one internal note to it.
 */
import api, { route } from '@forge/api';

/** Issue property keys stored on the Jira issue itself. */
export const PROPERTY_KEY = 'r155-desk-assessment';
export const AUTOTRIAGE_KEY = 'r155-desk-autotriage';

const client = (asApp) => (asApp ? api.asApp() : api.asUser());

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

/** Reads the issue's key, summary, description (as text), project and creation date. */
export async function getIssue(issueKey, { asApp = false } = {}) {
  const res = await client(asApp).requestJira(route`/rest/api/3/issue/${issueKey}?fields=summary,description,created,status,project`);
  const json = await readJson(res, `Reading issue ${issueKey}`);
  return {
    key: json.key,
    summary: json.fields.summary || '',
    description: adfToText(json.fields.description).trim(),
    created: json.fields.created,
    status: json.fields.status?.name,
    projectKey: json.fields.project?.key,
  };
}

async function getProperty(issueKey, key, asApp) {
  const res = await client(asApp).requestJira(route`/rest/api/3/issue/${issueKey}/properties/${key}`);
  if (res.status === 404) return null;
  const json = await readJson(res, `Reading ${key} of ${issueKey}`);
  return json.value;
}

async function setProperty(issueKey, key, value, asApp) {
  const res = await client(asApp).requestJira(route`/rest/api/3/issue/${issueKey}/properties/${key}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(value),
  });
  await readJson(res, `Saving ${key} of ${issueKey}`);
  return value;
}

/** Returns the saved assessment, or null when the issue has not been assessed yet. */
export const getAssessment = (issueKey) => getProperty(issueKey, PROPERTY_KEY, false);
/** Saves the assessment as an issue property (overwrites the previous one; history is kept inside it). */
export const saveAssessment = (issueKey, value) => setProperty(issueKey, PROPERTY_KEY, value, false);
export const getAutoTriage = (issueKey) => getProperty(issueKey, AUTOTRIAGE_KEY, true);
export const setAutoTriage = (issueKey, value) => setProperty(issueKey, AUTOTRIAGE_KEY, value, true);

/**
 * Adds a comment as the app. In Jira Service Management the `sd.public.comment` property keeps it
 * internal (agents only), so a customer or researcher never sees the triage note. In other projects
 * Jira ignores the property and the comment is a normal comment.
 */
export async function addInternalComment(issueKey, adfBody) {
  const res = await api.asApp().requestJira(route`/rest/api/3/issue/${issueKey}/comment`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ body: adfBody, properties: [{ key: 'sd.public.comment', value: { internal: true } }] }),
  });
  return readJson(res, `Commenting on ${issueKey}`);
}

/** True when the current user is a Jira administrator. Used to protect the admin page's write resolvers. */
export async function currentUserIsJiraAdmin() {
  const res = await api.asUser().requestJira(route`/rest/api/3/mypermissions?permissions=ADMINISTER`);
  const json = await readJson(res, 'Checking admin permission');
  return Boolean(json?.permissions?.ADMINISTER?.havePermission);
}
