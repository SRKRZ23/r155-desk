/**
 * Teamwork Graph connector: keeps the vehicle / ECU inventory in Teamwork Graph so Rovo Search and Rovo Chat
 * can use it. An admin connects "R155 Desk inventory" once in Atlassian Administration; the connection id is
 * stored, the inventory is ingested, and every later inventory import or reset is pushed again.
 */
import { graph } from '@forge/teamwork-graph';
import { kvs } from '@forge/kvs';
import { inventoryToGraphObjects } from './domain/graph-objects.js';
import { getInventory } from './storage.js';

const CONNECTIONS_KEY = 'twg-connections';
const LINKS_KEY = 'site-links';
const BATCH = 100;

/** The admin page stores the site URL and its own URL so graph objects can link back to something real. */
export async function rememberSiteLinks(links) {
  await kvs.set(LINKS_KEY, links);
}

async function ingest(connectionId, inventory) {
  const links = (await kvs.get(LINKS_KEY)) || {};
  const objects = inventoryToGraphObjects(inventory, { baseUrl: links.adminUrl || links.siteUrl });
  let accepted = 0;
  const rejected = [];
  for (let i = 0; i < objects.length; i += BATCH) {
    const res = await graph.setObjects({ connectionId, objects: objects.slice(i, i + BATCH) });
    accepted += res.results?.accepted?.length ?? 0;
    rejected.push(...(res.results?.rejected ?? []));
    if (!res.success) console.error('Teamwork Graph ingestion failed', { connectionId, error: res.error });
  }
  if (rejected.length) console.error('Teamwork Graph rejected objects', { connectionId, rejected: rejected.slice(0, 5) });

  // Remove ECUs / vehicle lines that are no longer in the inventory, so Rovo never cites stale hardware.
  const idsKey = `twg-ids:${connectionId}`;
  const current = objects.map((o) => o.id);
  const stale = ((await kvs.get(idsKey)) || []).filter((id) => !current.includes(id));
  if (stale.length) {
    const del = await graph.deleteObjectsByExternalId({ connectionId, objectType: 'atlassian:document', externalIds: stale });
    if (!del.success) console.error('Teamwork Graph delete failed', { connectionId, error: del.error });
  }
  await kvs.set(idsKey, current);
  console.log('Teamwork Graph ingestion', { connectionId, sent: objects.length, accepted, rejected: rejected.length });
  return { sent: objects.length, accepted, rejected: rejected.length };
}

/** Connector lifecycle handler (manifest: graph:connector > datasource > onConnectionChange). */
export async function onConnectionChange(request) {
  const { action, connectionId } = request || {};
  const connections = new Set((await kvs.get(CONNECTIONS_KEY)) || []);
  if (action === 'DELETED') {
    // Atlassian removes the ingested objects itself; only forget the connection.
    connections.delete(connectionId);
    await kvs.set(CONNECTIONS_KEY, [...connections]);
    return { success: true };
  }
  connections.add(connectionId);
  await kvs.set(CONNECTIONS_KEY, [...connections]);
  await ingest(connectionId, await getInventory());
  return { success: true };
}

/** Push the current inventory to every active connection (after an import or a reset). */
export async function syncInventoryToGraph() {
  const connections = (await kvs.get(CONNECTIONS_KEY)) || [];
  const inventory = await getInventory();
  const results = [];
  for (const id of connections) results.push(await ingest(id, inventory));
  return { connections: connections.length, results };
}
