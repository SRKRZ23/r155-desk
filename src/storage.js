/**
 * App storage (Forge Key-Value Store, scope `storage:app`).
 *
 * Two keys per installation:
 *  - `inventory`: the vehicle / ECU / software inventory imported by an admin (falls back to the demo OEM)
 *  - `settings`:  admin settings (auto-comment on new tickets, project filter, Confluence space)
 *
 * The inventory is stored as one JSON value. A few hundred ECU/component rows fit easily; the importer
 * refuses anything close to the per-value size limit instead of silently truncating it.
 */
import { kvs } from '@forge/kvs';
import { DEMO_INVENTORY } from './domain/inventory.js';

const INVENTORY_KEY = 'inventory';
const SETTINGS_KEY = 'settings';
const MAX_INVENTORY_BYTES = 200 * 1024;

export const DEFAULT_SETTINGS = {
  autoComment: true, // post an internal triage note when a new ticket names a known component
  projectKeys: [], // empty = every project the app can see
  confluenceSpaceKey: '', // where "Publish audit record" creates pages; empty = feature off
};

export async function getInventory() {
  const stored = await kvs.get(INVENTORY_KEY);
  return stored || DEMO_INVENTORY;
}

export async function saveInventory(inventory) {
  const size = Buffer.byteLength(JSON.stringify(inventory), 'utf8');
  if (size > MAX_INVENTORY_BYTES) {
    throw new Error(`Inventory is ${Math.round(size / 1024)} KB; the limit is ${MAX_INVENTORY_BYTES / 1024} KB. Split it by vehicle line.`);
  }
  await kvs.set(INVENTORY_KEY, { ...inventory, importedAt: new Date().toISOString() });
}

export async function resetInventory() {
  await kvs.delete(INVENTORY_KEY);
}

export async function getSettings() {
  return { ...DEFAULT_SETTINGS, ...((await kvs.get(SETTINGS_KEY)) || {}) };
}

export async function saveSettings(input) {
  const settings = {
    autoComment: Boolean(input.autoComment),
    projectKeys: String(input.projectKeys || '')
      .split(/[,\s]+/)
      .map((k) => k.trim().toUpperCase())
      .filter((k) => /^[A-Z][A-Z0-9_]{0,19}$/.test(k)),
    confluenceSpaceKey: String(input.confluenceSpaceKey || '').trim().slice(0, 255),
  };
  await kvs.set(SETTINGS_KEY, settings);
  return settings;
}
