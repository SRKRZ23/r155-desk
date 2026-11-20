/**
 * Publishes an assessment as an audit record page in Confluence (REST API v2), as the current user.
 * The app is Jira-first and Confluence-optional (see `app.compatibility` in manifest.yml): this works only
 * after the app is also connected to Confluence on the site, and only in a space the user can write to.
 * The page is created once per issue and updated in place afterwards (its id is kept in the assessment).
 */
import api, { route } from '@forge/api';

async function json(res, what) {
  const text = await res.text();
  if (!res.ok) throw new Error(`${what} failed: HTTP ${res.status} ${text.slice(0, 200)}`);
  return text ? JSON.parse(text) : null;
}

async function spaceIdForKey(spaceKey) {
  const res = await api.asUser().requestConfluence(route`/wiki/api/v2/spaces?keys=${spaceKey}`);
  const body = await json(res, `Looking up Confluence space ${spaceKey}`);
  const space = body?.results?.[0];
  if (!space) throw new Error(`Confluence space "${spaceKey}" was not found or you cannot see it.`);
  return space.id;
}

/** Creates or updates the page; returns { id, url }. */
export async function publishAuditPage({ spaceKey, title, storage, existingPageId }) {
  if (existingPageId) {
    const getRes = await api.asUser().requestConfluence(route`/wiki/api/v2/pages/${existingPageId}`);
    if (getRes.status !== 404) {
      const page = await json(getRes, 'Reading the existing audit page');
      const putRes = await api.asUser().requestConfluence(route`/wiki/api/v2/pages/${existingPageId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({
          id: existingPageId,
          status: 'current',
          title,
          body: { representation: 'storage', value: storage },
          version: { number: page.version.number + 1, message: 'Updated from R155 Desk' },
        }),
      });
      const updated = await json(putRes, 'Updating the audit page');
      return { id: updated.id, url: `${updated._links.base}${updated._links.webui}` };
    }
  }
  const spaceId = await spaceIdForKey(spaceKey);
  const res = await api.asUser().requestConfluence(route`/wiki/api/v2/pages`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ spaceId, status: 'current', title, body: { representation: 'storage', value: storage } }),
  });
  const created = await json(res, 'Creating the audit page');
  return { id: created.id, url: `${created._links.base}${created._links.webui}` };
}
