# R155 Desk

Automotive vulnerability triage for Jira Service Management, with the fleet in context.

R155 Desk is an Atlassian Forge app for vehicle manufacturers and suppliers who must run a cyber security
management system under **UN R155** and assess vulnerabilities with **ISO/SAE 21434**. When a researcher or
supplier reports a flaw in a software component, it answers the questions a product security team needs
first: which ECUs run it, in which version, in how many vehicles and markets, how the ECU is reached from the
reported entry point, and what the risk is. It then records the decision as evidence an auditor can read.

Demo video: https://youtu.be/mSKWD3ofvyA

## What it does

| Part | Forge module | What happens |
|---|---|---|
| First look | `trigger` on `avi:jira:created:issue` | A new ticket that names a component from the inventory gets an internal note: affected ECUs, version range, vehicles, markets, entry point and reachability. Nothing is rated automatically. |
| R155 Assessment panel | `jira:issuePanel` (UI Kit) | Component and version range detected from the ticket text, blast radius, reachability per ECU (direct, via other ECUs with the path, or no path), impact rating (S/F/O/P), attack potential pre-filled with a reason per factor, risk value 1 to 5, treatment, triage and remediation deadlines. Saved on the issue with a history of earlier ratings. |
| Audit record | Confluence REST API (optional app) | One click creates or updates a Confluence page with the affected item, reachability, impact, feasibility, risk, treatment, who decided and when. |
| R155 Triage agent | `rovo:agent` + 3 `action`s | Assesses the ticket in Rovo Chat. The risk value always comes from the app's engine, never from the language model. |
| MCP tools | `rovo:mcp` | The same three actions (`get-r155-assessment`, `find-affected-assets`, `assess-cyber-risk`) for Rovo Studio agents and MCP clients. |
| Inventory in Teamwork Graph | `graph:connector` | ECUs (with their software bill of materials) and vehicle lines (with fleet and markets) become documents that Rovo Search and Rovo Chat can find. |
| Admin page | `jira:adminPage` | Import your own inventory as CSV or JSON with a preview of validation problems, reset to the demo data, choose projects for the first look and the Confluence space. Every write checks Jira admin permission on the server. |

The bundled inventory is a fictional demo manufacturer ("Aurora Motors"): 3 vehicle lines, 5 ECUs.

## How the risk is computed

Pure, unit-tested functions in `src/domain`:

- **Impact**: worst of safety, financial, operational and privacy ratings (ISO/SAE 21434 clause 15).
- **Attack feasibility**: attack-potential approach, Annex G example scores for elapsed time, expertise,
  knowledge of the item, window of opportunity and equipment; bands 0-9 high, 10-13 medium, 14-19 low, 20+ very low.
- **Risk value**: Annex H example risk matrix (impact x feasibility, 1 to 5).
- **Deadlines**: the organisation's response policy (defaults in `iso21434.js`; not part of the standard).
- **Reachability**: breadth-first search over the in-vehicle network (`connects_to`) from every ECU that exposes
  the interface named in the report (Wi-Fi, Bluetooth, cellular, USB, OBD, Ethernet, CAN).

Organisations tailor these tables; they are exported constants so they can be changed in one place.

## Inventory format (CSV)

One row per vehicle line, ECU and software component. Lists inside a cell are separated by `;`.

```csv
vehicle_line_id,vehicle_line_name,fleet,markets,ecu_id,ecu_name,supplier,interfaces,connects_to,component,version,aliases
AM-S1,Aurora S1 (compact EV),182000,EU;JP;KR,IVI-2,Infotainment head unit (IVI-2),Tier-1 A,Wi-Fi;Bluetooth;USB;Ethernet,CGW-1,OpenSSL,3.0.7,openssl
```

The admin page has a "Load template" button with the full demo inventory.

## Run it yourself

```bash
npm install
npm test                         # 26 unit tests, no Atlassian site needed
forge deploy -e development
forge install --site <your-site>.atlassian.net --product jira -e development
forge install --site <your-site>.atlassian.net --product confluence -e development   # optional, for audit records
```

Then open a Jira issue, select the R155 Assessment app icon under the title, and open Jira settings > Apps >
R155 Desk to import an inventory or set the Confluence space. To use the Teamwork Graph connector, connect
"R155 Desk inventory" in Atlassian Administration > Apps > your site > Connected apps > r155-desk > Connections.

## Data and privacy

Assessments are stored as Jira issue properties; the inventory and settings in Forge storage. The app has no
external backend and no egress. See [PRIVACY.md](PRIVACY.md).

## Limits

- The bundled inventory is fictional. Real use needs an export from your configuration or SBOM system.
- Component detection uses names and aliases from the inventory and simple version expressions
  ("before 3.0.8", "7.69.0 through 8.3.0"); the analyst can always correct component and range in the panel.
- Attack-potential suggestions are a starting point with stated reasons, not a rating.

Built for Codegeist 2026 (Atlassian). MIT licence.
