/**
 * Turns the vehicle / ECU inventory into Teamwork Graph `atlassian:document` objects (pure function, tested).
 * One object per ECU (its software bill of materials, interfaces and network links) and one per vehicle line.
 * Once ingested by the connector, Rovo Search and Rovo Chat can answer questions such as
 * "which ECUs run QNX?" or "what is in the Aurora X3?" from the organisation's own inventory.
 */

const doc = ({ id, displayName, text, url, updatedAt, labels }) => ({
  schemaVersion: '1.0',
  id,
  updateSequenceNumber: Date.parse(updatedAt) || Date.now(),
  displayName,
  url,
  createdAt: updatedAt,
  lastUpdatedAt: updatedAt,
  // Inventory content is shared with everyone on the site who can use Rovo; there are no per-user ACLs in it.
  permissions: [{ accessControls: [{ principals: [{ type: 'EVERYONE' }] }] }],
  'atlassian:document': {
    type: { category: 'DOCUMENT', mimeType: 'text/plain' },
    content: { mimeType: 'text/plain', text },
    labels,
  },
});

export function inventoryToGraphObjects(inventory, { baseUrl, updatedAt = new Date().toISOString() } = {}) {
  const url = (anchor) => `${baseUrl || 'https://example.invalid/r155-desk'}#${encodeURIComponent(anchor)}`;
  const lineById = new Map(inventory.vehicleLines.map((l) => [l.id, l]));
  const objects = [];

  for (const e of inventory.ecus) {
    const lines = e.vehicleLines.map((id) => lineById.get(id)).filter(Boolean);
    const text = [
      `ECU ${e.id}: ${e.name}. Supplier: ${e.supplier || 'unknown'}.`,
      `Software components: ${e.components.map((c) => `${c.name} ${c.version}`).join('; ')}.`,
      `Interfaces: ${(e.interfaces || []).join(', ') || 'none'}. Connected to: ${(e.connectsTo || []).join(', ') || 'none'}.`,
      `Used in vehicle lines: ${lines.map((l) => `${l.name} (${l.id}, ${Number(l.fleet).toLocaleString('en-US')} vehicles, markets ${l.markets.join(', ')})`).join('; ') || 'none'}.`,
    ].join('\n');
    objects.push(doc({
      id: `ecu:${e.id}`,
      displayName: `ECU ${e.id}: ${e.name} (software bill of materials)`,
      text,
      url: url(`ecu-${e.id}`),
      updatedAt,
      labels: ['r155-desk', 'ecu', ...e.components.map((c) => c.name.toLowerCase().replace(/[^a-z0-9]+/g, '-'))],
    }));
  }

  for (const l of inventory.vehicleLines) {
    const ecus = inventory.ecus.filter((e) => e.vehicleLines.includes(l.id));
    objects.push(doc({
      id: `line:${l.id}`,
      displayName: `Vehicle line ${l.id}: ${l.name}`,
      text: [
        `Vehicle line ${l.id}: ${l.name}. Vehicles in the field: ${Number(l.fleet).toLocaleString('en-US')}. Markets: ${l.markets.join(', ')}.`,
        `ECUs: ${ecus.map((e) => `${e.id} (${e.components.map((c) => `${c.name} ${c.version}`).join(', ')})`).join('; ')}.`,
      ].join('\n'),
      url: url(`line-${l.id}`),
      updatedAt,
      labels: ['r155-desk', 'vehicle-line'],
    }));
  }
  return objects;
}
