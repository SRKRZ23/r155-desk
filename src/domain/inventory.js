/**
 * Vehicle / ECU / software inventory and the matching logic that answers
 * "which ECUs and vehicle lines run the component named in this vulnerability report,
 *  and can the reported entry point (Wi-Fi, Bluetooth, cellular...) actually reach them?".
 *
 * In a real deployment the inventory is imported by an admin (CSV or JSON, see importInventory).
 * Until then the fictional demo OEM below ("Aurora Motors") is used. The matching code does not care
 * where the data comes from.
 */

/** Demo inventory. Fleet numbers are vehicles in the field per line (fictional). */
export const DEMO_INVENTORY = {
  oem: 'Aurora Motors (fictional demo OEM)',
  source: 'demo',
  vehicleLines: [
    { id: 'AM-S1', name: 'Aurora S1 (compact EV)', markets: ['EU', 'JP', 'KR'], fleet: 182000 },
    { id: 'AM-X3', name: 'Aurora X3 (mid-size SUV)', markets: ['EU', 'UK'], fleet: 96500 },
    { id: 'AM-V7', name: 'Aurora V7 (delivery van)', markets: ['EU'], fleet: 41200 },
  ],
  ecus: [
    {
      id: 'IVI-2', name: 'Infotainment head unit (IVI-2)', supplier: 'Tier-1 A', interfaces: ['Wi-Fi', 'Bluetooth', 'USB', 'Ethernet'],
      connectsTo: ['CGW-1'], vehicleLines: ['AM-S1', 'AM-X3'],
      components: [
        { name: 'QNX Neutrino RTOS', aliases: ['qnx', 'qnx neutrino', 'qnx sdp'], version: '7.1.0' },
        { name: 'BlueZ', aliases: ['bluez'], version: '5.64' },
        { name: 'OpenSSL', aliases: ['openssl'], version: '3.0.7' },
      ],
    },
    {
      id: 'TCU-4', name: 'Telematics control unit (TCU-4)', supplier: 'Tier-1 B', interfaces: ['LTE', 'GNSS', 'Ethernet', 'CAN'],
      connectsTo: ['CGW-1'], vehicleLines: ['AM-S1', 'AM-X3', 'AM-V7'],
      components: [
        { name: 'Linux kernel', aliases: ['linux', 'linux kernel'], version: '5.10.120' },
        { name: 'OpenSSL', aliases: ['openssl'], version: '3.0.13' },
        { name: 'curl', aliases: ['curl', 'libcurl'], version: '7.88.1' },
        { name: 'BusyBox', aliases: ['busybox'], version: '1.35.0' },
      ],
    },
    {
      id: 'CGW-1', name: 'Central gateway (CGW-1)', supplier: 'Tier-1 C', interfaces: ['CAN-FD', 'Automotive Ethernet', 'DoIP', 'OBD'],
      connectsTo: ['IVI-2', 'TCU-4', 'ADAS-2', 'BMS-3'], vehicleLines: ['AM-S1', 'AM-X3', 'AM-V7'],
      components: [
        { name: 'AUTOSAR Classic stack', aliases: ['autosar', 'microsar'], version: '4.4.0' },
        { name: 'lwIP', aliases: ['lwip'], version: '2.1.2' },
        { name: 'wolfSSL', aliases: ['wolfssl'], version: '5.5.4' },
      ],
    },
    {
      id: 'BMS-3', name: 'Battery management system (BMS-3)', supplier: 'Tier-1 D', interfaces: ['CAN'],
      connectsTo: ['CGW-1'], vehicleLines: ['AM-S1'],
      components: [{ name: 'AUTOSAR Classic stack', aliases: ['autosar', 'microsar'], version: '4.3.1' }],
    },
    {
      id: 'ADAS-2', name: 'ADAS domain controller (ADAS-2)', supplier: 'Tier-1 E', interfaces: ['Automotive Ethernet', 'CAN-FD'],
      connectsTo: ['CGW-1'], vehicleLines: ['AM-X3'],
      components: [
        { name: 'QNX Neutrino RTOS', aliases: ['qnx', 'qnx neutrino', 'qnx sdp'], version: '7.1.0' },
        { name: 'OpenSSL', aliases: ['openssl'], version: '3.0.7' },
      ],
    },
  ],
};

// ---------------------------------------------------------------------------------------------
// Versions
// ---------------------------------------------------------------------------------------------

/** Compares dotted numeric versions: returns -1, 0 or 1. Non-numeric parts compare as 0. */
export function compareVersions(a, b) {
  const pa = String(a).split('.').map((n) => parseInt(n, 10) || 0);
  const pb = String(b).split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i += 1) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

/**
 * Checks a version against a simple range such as "<3.0.8", ">=3.0.0 <3.0.8", "=7.1.0" or "7.1.0".
 * An empty range means "all versions" (the report did not say which versions are affected).
 */
export function versionInRange(version, range) {
  if (!range || !String(range).trim()) return true;
  return String(range)
    .trim()
    .split(/\s+/)
    .every((clause) => {
      const m = clause.match(/^(<=|>=|<|>|=)?v?([0-9][0-9.]*)$/);
      if (!m) return false;
      const cmp = compareVersions(version, m[2]);
      switch (m[1] || '=') {
        case '<': return cmp < 0;
        case '<=': return cmp <= 0;
        case '>': return cmp > 0;
        case '>=': return cmp >= 0;
        default: return cmp === 0;
      }
    });
}

// ---------------------------------------------------------------------------------------------
// Entry points (interfaces) and exposure
// ---------------------------------------------------------------------------------------------

/**
 * Interface classes. `pattern` recognises the class both in free report text and in inventory
 * interface names. `remote` = reachable without touching the vehicle; `proximity` = needs to be near it;
 * `physical` = needs physical access to a port or the vehicle network.
 */
export const INTERFACE_CLASSES = [
  { id: 'wifi', label: 'Wi-Fi', reach: 'proximity', pattern: /wi-?fi|wlan|hotspot|802\.11/i },
  { id: 'bluetooth', label: 'Bluetooth', reach: 'proximity', pattern: /bluetooth|\bble\b/i },
  { id: 'cellular', label: 'Cellular (LTE/5G)', reach: 'remote', pattern: /\blte\b|cellular|\b[45]g\b|\bsms\b|modem/i },
  { id: 'gnss', label: 'GNSS', reach: 'proximity', pattern: /gnss|\bgps\b/i },
  { id: 'usb', label: 'USB', reach: 'physical', pattern: /\busb\b/i },
  { id: 'obd', label: 'OBD / diagnostics', reach: 'physical', pattern: /\bobd|\bdoip\b|diagnostic/i },
  { id: 'ethernet', label: 'Automotive Ethernet', reach: 'physical', pattern: /ethernet/i },
  // Case-sensitive on purpose: the English word "can" must not be read as the CAN bus.
  { id: 'can', label: 'CAN', reach: 'physical', pattern: /\bCAN(-FD)?\b|\bCAN bus\b/ },
];

/** Interface classes named in a free-text report. */
export function detectInterfaces(text) {
  const t = String(text || '');
  return INTERFACE_CLASSES.filter((c) => c.pattern.test(t)).map((c) => c.id);
}

/** Interface classes an ECU exposes, derived from its interface names. */
export function ecuInterfaceClasses(ecu) {
  return INTERFACE_CLASSES.filter((c) => (ecu.interfaces || []).some((name) => c.pattern.test(name))).map((c) => c.id);
}

/**
 * How can an attacker who uses one of the reported interfaces reach this ECU?
 *  - direct:   the ECU itself exposes a reported interface
 *  - indirect: another ECU exposes it and the in-vehicle network connects the two (shortest path given)
 *  - none:     no ECU in the inventory exposes the reported interface with a path to this one
 *  - unknown:  the report names no interface, so the entry point must be clarified
 */
export function exposureOf(ecuId, reportedInterfaces, inventory = DEMO_INVENTORY) {
  const byId = new Map(inventory.ecus.map((e) => [e.id, e]));
  const target = byId.get(ecuId);
  if (!target) return { kind: 'none', note: `ECU ${ecuId} is not in the inventory.` };
  if (!reportedInterfaces?.length) return { kind: 'unknown', note: 'The report names no entry interface.' };

  const label = (id) => INTERFACE_CLASSES.find((c) => c.id === id)?.label || id;
  const direct = ecuInterfaceClasses(target).filter((c) => reportedInterfaces.includes(c));
  if (direct.length) {
    return { kind: 'direct', via: direct, note: `Directly reachable over ${direct.map(label).join(', ')}.` };
  }

  // Breadth-first search from every ECU that exposes a reported interface, over undirected links.
  const neighbours = (id) => {
    const out = new Set(byId.get(id)?.connectsTo || []);
    for (const e of inventory.ecus) if ((e.connectsTo || []).includes(id)) out.add(e.id);
    return [...out].filter((n) => byId.has(n));
  };
  const entries = inventory.ecus.filter((e) => ecuInterfaceClasses(e).some((c) => reportedInterfaces.includes(c)));
  const prev = new Map(entries.map((e) => [e.id, null]));
  const queue = entries.map((e) => e.id);
  while (queue.length) {
    const id = queue.shift();
    if (id === ecuId) break;
    for (const n of neighbours(id)) {
      if (!prev.has(n)) {
        prev.set(n, id);
        queue.push(n);
      }
    }
  }
  if (!prev.has(ecuId)) {
    return { kind: 'none', note: 'No ECU exposing the reported interface is connected to this ECU.' };
  }
  const path = [];
  for (let at = ecuId; at; at = prev.get(at)) path.unshift(at);
  const entry = byId.get(path[0]);
  const via = ecuInterfaceClasses(entry).filter((c) => reportedInterfaces.includes(c));
  return {
    kind: 'indirect',
    via,
    path,
    hops: path.length - 1,
    note: `Not directly exposed. Reachable only after compromising ${path[0]} over ${via.map(label).join(', ')}, then ${path.slice(1).join(' -> ')} (${path.length - 1} hop(s)).`,
  };
}

// ---------------------------------------------------------------------------------------------
// Components and blast radius
// ---------------------------------------------------------------------------------------------

const normalise = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();

function componentMatchesName(component, query) {
  const q = normalise(query);
  if (!q) return false;
  return [component.name, ...(component.aliases || [])].some((n) => {
    const name = normalise(n);
    return name === q || name.includes(q) || q.includes(name);
  });
}

const EXPOSURE_ORDER = { direct: 0, indirect: 1, unknown: 2, none: 3 };

/**
 * Blast radius for a component and an optional affected-version range: which ECUs run it, whether each
 * is in range, how each can be reached from the reported interfaces, the vehicle lines, markets and the
 * number of vehicles in the field.
 */
export function findAffectedAssets({ component, affectedVersions, reportedInterfaces = [] }, inventory = DEMO_INVENTORY) {
  const hits = [];
  for (const ecu of inventory.ecus) {
    for (const c of ecu.components) {
      if (!componentMatchesName(c, component)) continue;
      const affected = versionInRange(c.version, affectedVersions);
      hits.push({
        ecuId: ecu.id,
        ecuName: ecu.name,
        supplier: ecu.supplier,
        interfaces: ecu.interfaces,
        component: c.name,
        installedVersion: c.version,
        affected,
        exposure: affected ? exposureOf(ecu.id, reportedInterfaces, inventory) : null,
        vehicleLines: ecu.vehicleLines,
      });
    }
  }
  hits.sort((a, b) => (b.affected - a.affected) || (EXPOSURE_ORDER[a.exposure?.kind] ?? 9) - (EXPOSURE_ORDER[b.exposure?.kind] ?? 9));
  const affectedHits = hits.filter((h) => h.affected);
  const lineIds = [...new Set(affectedHits.flatMap((h) => h.vehicleLines))];
  const lines = inventory.vehicleLines.filter((l) => lineIds.includes(l.id));
  const directlyExposed = affectedHits.filter((h) => h.exposure?.kind === 'direct');
  const directLineIds = [...new Set(directlyExposed.flatMap((h) => h.vehicleLines))];
  return {
    component,
    affectedVersions: affectedVersions || 'not specified (all versions)',
    reportedInterfaces,
    ecus: hits,
    affectedEcuCount: affectedHits.length,
    directlyExposedEcuCount: directlyExposed.length,
    notAffectedEcuCount: hits.length - affectedHits.length,
    vehicleLines: lines,
    fleetExposure: lines.reduce((sum, l) => sum + l.fleet, 0),
    directFleetExposure: inventory.vehicleLines.filter((l) => directLineIds.includes(l.id)).reduce((s, l) => s + l.fleet, 0),
    markets: [...new Set(lines.flatMap((l) => l.markets))],
  };
}

/**
 * Scans free text (an issue summary + description, a researcher's email) for component names in the
 * inventory and a nearby version or range, e.g. "OpenSSL before 3.0.8" or "QNX Neutrino 7.1".
 * Returns candidate { component, affectedVersions } pairs to pre-fill the assessment.
 */
export function detectComponents(text, inventory = DEMO_INVENTORY) {
  const haystack = String(text || '');
  const lower = haystack.toLowerCase();
  const seen = new Map();
  for (const ecu of inventory.ecus) {
    for (const c of ecu.components) {
      for (const alias of [c.name, ...(c.aliases || [])]) {
        const at = lower.indexOf(alias.toLowerCase());
        if (at === -1 || seen.has(c.name)) continue;
        // Look at the 40 characters after the name for a version expression.
        const tail = haystack.slice(at + alias.length, at + alias.length + 40);
        const before = tail.match(/(?:before|prior to|<)\s*v?([0-9]+(?:\.[0-9]+)+)/i);
        const through = tail.match(/(?:through|up to|<=)\s*v?([0-9]+(?:\.[0-9]+)+)/i);
        const exact = tail.match(/v?([0-9]+(?:\.[0-9]+)+)/);
        let affectedVersions = '';
        if (before) affectedVersions = `<${before[1]}`;
        else if (through) affectedVersions = `<=${through[1]}`;
        else if (exact) affectedVersions = `=${exact[1]}`;
        seen.set(c.name, { component: c.name, affectedVersions });
      }
    }
  }
  return [...seen.values()];
}

// ---------------------------------------------------------------------------------------------
// Suggested attack-potential factors (a starting point the analyst confirms, never a verdict)
// ---------------------------------------------------------------------------------------------

/**
 * Suggests attack-potential factors from the report text and the best exposure among affected ECUs.
 * Each suggestion carries a one-line reason so the analyst (and an auditor) can see why.
 */
export function suggestFactors({ text, exposureKind, reportedInterfaces = [] }) {
  const t = String(text || '');
  const publicExploit = /proof[- ]of[- ]concept|\bpoc\b|public exploit|exploit (is )?(publicly )?available|metasploit/i.test(t);
  const publicAdvisory = /\bcve-\d{4}-\d+|advisory|publicly disclosed|public/i.test(t);
  const reach = INTERFACE_CLASSES.filter((c) => reportedInterfaces.includes(c.id)).map((c) => c.reach);
  const remote = reach.includes('remote');
  const proximity = reach.includes('proximity');
  const indirect = exposureKind === 'indirect';

  const factors = {};
  const reasons = {};

  if (publicExploit) {
    factors.elapsedTime = indirect ? 'le1month' : 'le1week';
    reasons.elapsedTime = indirect
      ? 'A public proof of concept exists, but chaining it through another ECU adds development time.'
      : 'A public proof of concept exists, so building a working attack takes days, not months.';
  } else {
    factors.elapsedTime = indirect ? 'le6months' : 'le1month';
    reasons.elapsedTime = 'No public exploit is mentioned, so the attacker must develop one.';
  }

  factors.expertise = indirect ? 'expert' : publicExploit ? 'proficient' : 'expert';
  reasons.expertise = indirect
    ? 'Pivoting from one ECU to another needs knowledge of the in-vehicle network.'
    : publicExploit ? 'Reusing a published exploit needs a proficient attacker, not an expert.' : 'Writing a new exploit for an embedded target needs an expert.';

  factors.knowledge = publicAdvisory || publicExploit ? 'public' : 'restricted';
  reasons.knowledge = factors.knowledge === 'public'
    ? 'The flaw is described publicly (advisory or proof of concept).'
    : 'No public description is mentioned; details are assumed restricted.';

  if (remote && !indirect) {
    factors.windowOfOpportunity = 'unlimited';
    reasons.windowOfOpportunity = 'Reachable remotely over the cellular link at any time.';
  } else if (proximity && !indirect) {
    factors.windowOfOpportunity = 'easy';
    reasons.windowOfOpportunity = 'Needs radio proximity (for example a parking lot), which is easy to obtain.';
  } else if (indirect) {
    factors.windowOfOpportunity = 'moderate';
    reasons.windowOfOpportunity = 'The target is only reachable after a first ECU is compromised.';
  } else {
    factors.windowOfOpportunity = 'moderate';
    reasons.windowOfOpportunity = 'Physical or unclear access; assume limited access time.';
  }

  factors.equipment = reach.includes('physical') ? 'specialized' : 'standard';
  reasons.equipment = factors.equipment === 'standard'
    ? 'A laptop with a standard radio is enough.'
    : 'Physical access to vehicle buses usually needs specialised tools.';

  return { factors, reasons };
}

// ---------------------------------------------------------------------------------------------
// Import (CSV or JSON) and validation
// ---------------------------------------------------------------------------------------------

/** Column order of the CSV import template (one row per component installed on an ECU). */
export const CSV_COLUMNS = ['vehicle_line_id', 'vehicle_line_name', 'fleet', 'markets', 'ecu_id', 'ecu_name', 'supplier', 'interfaces', 'connects_to', 'component', 'version', 'aliases'];

/** Minimal RFC 4180 CSV parser (quoted fields, escaped quotes, commas and newlines inside quotes). */
export function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  const s = String(text || '').replace(/\r\n?/g, '\n');
  for (let i = 0; i < s.length; i += 1) {
    const ch = s[i];
    if (quoted) {
      if (ch === '"' && s[i + 1] === '"') { field += '"'; i += 1; } else if (ch === '"') quoted = false; else field += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ',') { row.push(field); field = ''; } else if (ch === '\n') { row.push(field); rows.push(row); row = []; field = ''; } else field += ch;
  }
  if (field !== '' || row.length) { row.push(field); rows.push(row); }
  return rows.filter((r) => r.some((c) => c.trim() !== ''));
}

const list = (v) => String(v || '').split(';').map((x) => x.trim()).filter(Boolean);

/** Builds an inventory from CSV rows. One row per (vehicle line, ECU, component); rows merge by id. */
export function inventoryFromCsv(text) {
  const rows = parseCsv(text);
  if (!rows.length) throw new Error('The CSV is empty.');
  const header = rows[0].map((h) => h.trim().toLowerCase());
  const missing = CSV_COLUMNS.filter((c) => !header.includes(c) && c !== 'aliases' && c !== 'connects_to');
  if (missing.length) throw new Error(`Missing CSV column(s): ${missing.join(', ')}`);
  const col = (r, name) => (header.indexOf(name) >= 0 ? (r[header.indexOf(name)] || '').trim() : '');

  const lines = new Map();
  const ecus = new Map();
  rows.slice(1).forEach((r) => {
    const lineId = col(r, 'vehicle_line_id');
    const ecuId = col(r, 'ecu_id');
    if (lineId && !lines.has(lineId)) {
      lines.set(lineId, { id: lineId, name: col(r, 'vehicle_line_name') || lineId, fleet: Number(col(r, 'fleet')) || 0, markets: list(col(r, 'markets')) });
    }
    if (!ecuId) return;
    if (!ecus.has(ecuId)) {
      ecus.set(ecuId, { id: ecuId, name: col(r, 'ecu_name') || ecuId, supplier: col(r, 'supplier'), interfaces: list(col(r, 'interfaces')), connectsTo: list(col(r, 'connects_to')), vehicleLines: [], components: [] });
    }
    const ecu = ecus.get(ecuId);
    if (lineId && !ecu.vehicleLines.includes(lineId)) ecu.vehicleLines.push(lineId);
    const name = col(r, 'component');
    if (name && !ecu.components.some((c) => c.name === name && c.version === col(r, 'version'))) {
      ecu.components.push({ name, version: col(r, 'version'), aliases: list(col(r, 'aliases')) });
    }
  });
  return { oem: 'Imported inventory', source: 'csv', vehicleLines: [...lines.values()], ecus: [...ecus.values()] };
}

/** Returns a list of human-readable problems; an empty list means the inventory is usable. */
export function validateInventory(inv) {
  const problems = [];
  if (!inv || !Array.isArray(inv.vehicleLines) || !Array.isArray(inv.ecus)) return ['Expected an object with "vehicleLines" and "ecus" arrays.'];
  if (!inv.ecus.length) problems.push('No ECUs found.');
  const lineIds = new Set(inv.vehicleLines.map((l) => l.id));
  const ecuIds = new Set();
  for (const l of inv.vehicleLines) {
    if (!l.id) problems.push('A vehicle line has no id.');
    if (!(Number(l.fleet) >= 0)) problems.push(`Vehicle line ${l.id}: fleet must be a number.`);
  }
  for (const e of inv.ecus) {
    if (!e.id) { problems.push('An ECU has no id.'); continue; }
    if (ecuIds.has(e.id)) problems.push(`Duplicate ECU id ${e.id}.`);
    ecuIds.add(e.id);
    for (const l of e.vehicleLines || []) if (!lineIds.has(l)) problems.push(`ECU ${e.id} refers to unknown vehicle line ${l}.`);
    if (!(e.components || []).length) problems.push(`ECU ${e.id} has no software components.`);
    for (const c of e.components || []) if (!c.name || !c.version) problems.push(`ECU ${e.id}: every component needs a name and a version.`);
  }
  for (const e of inv.ecus) for (const n of e.connectsTo || []) if (!ecuIds.has(n)) problems.push(`ECU ${e.id} connects to unknown ECU ${n}.`);
  return problems.slice(0, 25);
}

/** Parses pasted text as JSON (starts with "{") or CSV, normalises it and validates it. */
export function importInventory(text) {
  const trimmed = String(text || '').trim();
  let inv;
  if (trimmed.startsWith('{')) {
    try {
      inv = JSON.parse(trimmed);
    } catch (e) {
      return { inventory: null, problems: [`Invalid JSON: ${e.message}`] };
    }
    inv.source = 'json';
    inv.ecus = (inv.ecus || []).map((e) => ({ connectsTo: [], interfaces: [], vehicleLines: [], ...e, components: (e.components || []).map((c) => ({ aliases: [], ...c })) }));
  } else {
    try {
      inv = inventoryFromCsv(trimmed);
    } catch (e) {
      return { inventory: null, problems: [e.message] };
    }
  }
  const problems = validateInventory(inv);
  return { inventory: problems.length ? null : inv, problems };
}

/** The demo inventory as CSV, used as the downloadable template on the admin page. */
export function inventoryToCsv(inv = DEMO_INVENTORY) {
  const esc = (v) => (/[",\n]/.test(String(v)) ? `"${String(v).replace(/"/g, '""')}"` : String(v));
  const out = [CSV_COLUMNS.join(',')];
  for (const e of inv.ecus) {
    for (const lineId of e.vehicleLines) {
      const l = inv.vehicleLines.find((x) => x.id === lineId);
      for (const c of e.components) {
        out.push([l.id, l.name, l.fleet, l.markets.join(';'), e.id, e.name, e.supplier, e.interfaces.join(';'), (e.connectsTo || []).join(';'), c.name, c.version, (c.aliases || []).join(';')].map(esc).join(','));
      }
    }
  }
  return out.join('\n');
}
