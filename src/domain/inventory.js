/**
 * Vehicle / ECU / software inventory and the matching logic that answers
 * "which ECUs and vehicle lines run the component named in this vulnerability report?".
 *
 * In a real deployment this inventory comes from the OEM's SBOM / configuration management system.
 * For the demo it is a fictional OEM ("Aurora Motors") seeded below; the matching code does not care
 * where the data comes from.
 */

/** Demo inventory. Fleet numbers are vehicles in the field per line (fictional). */
export const DEMO_INVENTORY = {
  oem: 'Aurora Motors (fictional demo OEM)',
  vehicleLines: [
    { id: 'AM-S1', name: 'Aurora S1 (compact EV)', markets: ['EU', 'JP', 'KR'], fleet: 182000, typeApproval: 'UN R155 / R156', sop: '2024-07' },
    { id: 'AM-X3', name: 'Aurora X3 (mid-size SUV)', markets: ['EU', 'UK'], fleet: 96500, typeApproval: 'UN R155 / R156', sop: '2025-02' },
    { id: 'AM-V7', name: 'Aurora V7 (delivery van)', markets: ['EU'], fleet: 41200, typeApproval: 'UN R155 / R156', sop: '2023-11' },
  ],
  ecus: [
    {
      id: 'IVI-2', name: 'Infotainment head unit (IVI-2)', supplier: 'Tier-1 A', interfaces: ['Wi-Fi', 'Bluetooth', 'USB', 'Ethernet'],
      vehicleLines: ['AM-S1', 'AM-X3'],
      components: [
        { name: 'QNX Neutrino RTOS', aliases: ['qnx', 'qnx neutrino', 'qnx sdp'], version: '7.1.0' },
        { name: 'BlueZ', aliases: ['bluez'], version: '5.64' },
        { name: 'OpenSSL', aliases: ['openssl'], version: '3.0.7' },
      ],
    },
    {
      id: 'TCU-4', name: 'Telematics control unit (TCU-4)', supplier: 'Tier-1 B', interfaces: ['LTE', 'GNSS', 'Ethernet', 'CAN'],
      vehicleLines: ['AM-S1', 'AM-X3', 'AM-V7'],
      components: [
        { name: 'Linux kernel', aliases: ['linux', 'linux kernel'], version: '5.10.120' },
        { name: 'OpenSSL', aliases: ['openssl'], version: '3.0.13' },
        { name: 'curl', aliases: ['curl', 'libcurl'], version: '7.88.1' },
        { name: 'BusyBox', aliases: ['busybox'], version: '1.35.0' },
      ],
    },
    {
      id: 'CGW-1', name: 'Central gateway (CGW-1)', supplier: 'Tier-1 C', interfaces: ['CAN-FD', 'Automotive Ethernet', 'DoIP'],
      vehicleLines: ['AM-S1', 'AM-X3', 'AM-V7'],
      components: [
        { name: 'AUTOSAR Classic stack', aliases: ['autosar', 'microsar'], version: '4.4.0' },
        { name: 'lwIP', aliases: ['lwip'], version: '2.1.2' },
        { name: 'wolfSSL', aliases: ['wolfssl'], version: '5.5.4' },
      ],
    },
    {
      id: 'BMS-3', name: 'Battery management system (BMS-3)', supplier: 'Tier-1 D', interfaces: ['CAN'],
      vehicleLines: ['AM-S1'],
      components: [{ name: 'AUTOSAR Classic stack', aliases: ['autosar', 'microsar'], version: '4.3.1' }],
    },
    {
      id: 'ADAS-2', name: 'ADAS domain controller (ADAS-2)', supplier: 'Tier-1 E', interfaces: ['Automotive Ethernet', 'CAN-FD'],
      vehicleLines: ['AM-X3'],
      components: [
        { name: 'QNX Neutrino RTOS', aliases: ['qnx', 'qnx neutrino', 'qnx sdp'], version: '7.1.0' },
        { name: 'OpenSSL', aliases: ['openssl'], version: '3.0.7' },
      ],
    },
  ],
};

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

const normalise = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();

function componentMatchesName(component, query) {
  const q = normalise(query);
  if (!q) return false;
  return [component.name, ...component.aliases].some((n) => {
    const name = normalise(n);
    return name === q || name.includes(q) || q.includes(name);
  });
}

/**
 * Finds affected ECUs and vehicle lines for a component name and an optional affected-version range.
 * Returns ECU hits (with the installed version and whether it is in range), the vehicle lines involved
 * and the total fleet exposure, so a triager sees the blast radius immediately.
 */
export function findAffectedAssets({ component, affectedVersions }, inventory = DEMO_INVENTORY) {
  const hits = [];
  for (const ecu of inventory.ecus) {
    for (const c of ecu.components) {
      if (!componentMatchesName(c, component)) continue;
      hits.push({
        ecuId: ecu.id,
        ecuName: ecu.name,
        supplier: ecu.supplier,
        interfaces: ecu.interfaces,
        component: c.name,
        installedVersion: c.version,
        affected: versionInRange(c.version, affectedVersions),
        vehicleLines: ecu.vehicleLines,
      });
    }
  }
  const affectedHits = hits.filter((h) => h.affected);
  const lineIds = [...new Set(affectedHits.flatMap((h) => h.vehicleLines))];
  const lines = inventory.vehicleLines.filter((l) => lineIds.includes(l.id));
  return {
    component,
    affectedVersions: affectedVersions || 'not specified (all versions)',
    ecus: hits,
    affectedEcuCount: affectedHits.length,
    notAffectedEcuCount: hits.length - affectedHits.length,
    vehicleLines: lines,
    fleetExposure: lines.reduce((sum, l) => sum + l.fleet, 0),
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
      for (const alias of [c.name, ...c.aliases]) {
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
