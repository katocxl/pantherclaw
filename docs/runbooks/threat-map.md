# The threat map

**Milestone:** M28 ([G0 M28](../g0/M28.md)). **Audience:** security, SOC and audit teams. **Edition:** see below.

The threat map shows, for every MITRE ATLAS and ATT&CK Enterprise technique, which PantherClaw controls are mapped to it and the evidence for them. Every view, export and command carries this statement, word for word:

> This map shows the PantherClaw controls mapped to each technique and the evidence for them. A mapped control covers the technique, not every way of carrying it out. Techniques outside PantherClaw need other tools. It is not a score or a guarantee.

The map has no score, percentage or total. Never describe it as proof that an organization is defended against a technique.

## Editions and permissions

| What | Edition |
|---|---|
| Matrix, technique pages, gaps and labels in the console | Every edition |
| The same reads with an API key or access token (`pclaw threats`, scripts) | Team and above |
| Signed report, Navigator export, MCP tool `technique_coverage`, gaps in the posture queue | Team and above |
| History and drop alerts | Business and above |

- `threatmap.read` reads the map. Org Admin, Security Admin, Responder, Auditor and Investigator hold it.
- The report also needs `evidence.export`.
- A person signed in to the console reads on every edition. An API key or access token below Team gets `EDITION_REQUIRED`: "Reading the threat map with an API key or access token needs Team or higher; the console shows it on every edition."

## Reading the matrix

- Two frameworks: ATLAS and ATT&CK Enterprise. Columns are tactics; each cell is a technique, listed under every tactic it belongs to. Sub-techniques are on the technique's page.
- Each cell has four lane marks and one colour:

| Colour | Status | When |
|---|---|---|
| Green | EVIDENCED | Prevent or Detect is EVIDENCED, and Test is not FAILED |
| Amber | PARTIAL | Prevent, Detect or Respond is EVIDENCED or PARTIAL, and the technique is not green |
| Red | GAP | Nothing better: only your own rules (STATED), no shipped control, or a technique on the "No PantherClaw control yet" list |
| Grey | OUTSIDE | Outside PantherClaw: another kind of tool covers it |

- Tactic headers show counts per status. A technique under two tactics counts in both. There is no total.
- Filter by agent or environment. Prevent and Seen follow the filter; Detect, Respond and Test are always organization-wide, and the page says so.

## Lanes

- **Prevent:** the authority, gateway, sandbox or credential controls mapped to the technique, and your routes in scope. EVIDENCED when a mapped control applies and every route is ENFORCED within the coverage TTL (24 h). Route counts show enforced, partial, observe-only, unknown and stale. An active agent with no coverage record counts as one unknown route.
- **Detect:** mapped built-in rules, behaviour and content kinds, and rules you installed from the Hub and left unchanged. EVIDENCED when one is licensed, enabled, not suppressed and its input arrived in the last 7 days. Rules that listen only for audit events count while the detection engine is reading your organization's events. Your own custom rules are listed as "Your rule (stated)"; they make the lane STATED, never evidence.
- **Respond:** your active automations whose trigger names a mapped PantherClaw rule (`event.attrs["rule"] in [...]` or `== "..."` on `alert.raised` or `alert.inferred`). EVIDENCED when that rule is enabled and licensed; an automation with a `contain` step also needs the automation-playbooks edition. Hub playbooks that would fire show as a gap until installed.
- **Test:** library scenarios mapped to the technique and your own `pclaw redteam run` results. PASSED needs a pass within 30 days that the server observed at every step, on the library's current version of the scenario. A failure within 30 days is FAILED and turns a green technique amber. Older results are STALE. A reported pass, a changed scenario, a scenario that maps no technique and campaigns never count. A test never makes anything green.
- **Seen (30 days):** alerts raised with the technique, refusals by mapped controls and holds by mapped controls. These are counts of what happened, not a measure of what was stopped.

## Gaps and fixes

Every amber or red lane gives a reason and a fix:

| Fix | What to do |
|---|---|
| ENABLE_RULE | Re-enable the auto-disabled built-in rule (`EnableRule`), or publish your custom rule |
| END_SUPPRESSION | End the organization-wide suppression of the rule |
| SEND_EVENTS | Get the rule's input events flowing (the page names the kinds) |
| UPGRADE_EDITION | The rule or step needs Team or Business |
| TURN_ON_SETTING | Turn on behaviour analytics or content signals |
| ROUTE_THROUGH_GATEWAY | Put the named agents' connections behind the gateway, enforced |
| ENABLE_PLAYBOOK | Enable the draft or paused automation |
| INSTALL_HUB_ITEM | Install the named playbook from the Hub |
| RUN_SCENARIO | `pclaw redteam run --technique <ID>` |
| NONE | PantherClaw ships no control for this technique |

On Team, rule, playbook and test gaps also appear in the posture queue under the `threatmap` source, one finding per fix target. Route and edition gaps stay with the coverage source and the plan page.

## Outside PantherClaw and No PantherClaw control yet

- **Outside PantherClaw** (grey): techniques that need an endpoint, a network, a mailbox, a person, model training or infrastructure PantherClaw does not see. Each names the kind of tool that covers it, such as EDR or email security.
- **No PantherClaw control yet** (red): techniques an AI agent could carry out through a platform PantherClaw sits in front of, for which PantherClaw ships no control. Each says why. They are listed apart so they are never mistaken for "outside".
- The full list for both frameworks is in [MITRE_MAPPING.md](../security/MITRE_MAPPING.md).

## `pclaw threats`

Team or higher, with an API key or access token. Every text output ends with the statement.
- `pclaw threats matrix [--framework atlas|attack] [--agent ID | --environment ID] [--json]`: counts per tactic, then techniques by status. `--framework` defaults to `atlas`.
- `pclaw threats technique ID [--agent ID | --environment ID] [--json]`: lanes, evidence and gaps. The framework follows the id (`AML.` ids are ATLAS).
- `pclaw threats gaps [--framework atlas|attack] [--agent ID | --environment ID] [--page-size N] [--page-token T] [--json]`. `--framework` defaults to `atlas`. Text lists every page; `--json` prints one page.
- `pclaw threats export navigator --framework atlas|attack [--agent ID | --environment ID] --out FILE`. `--out` must not exist yet.
- `pclaw threats export report --framework atlas|attack [--environment ID]`: creates a signed pack, like `pclaw pack create`.
- `pclaw threats history --framework atlas|attack [--environment ID] [--days N] [--json]` (Business). `--days` defaults to 30, at most 400.
- Below Team, the command prints the server's `EDITION_REQUIRED` message as is; use the console.

## Exports

- **Navigator layer:** ATT&CK Enterprise only: layer format 4.5, domain `enterprise-attack`, for ATT&CK Navigator 5.3.2. ATLAS has no current Navigator data (MITRE's ATLAS Navigator data is deprecated and stops at an older ATLAS release), so `pclaw threats export navigator --framework atlas` answers `NAVIGATOR_NOT_AVAILABLE`; use the console or `pclaw threats matrix --framework atlas`. One entry per technique and tactic with a fixed colour (green `#2e7d32`, amber `#f9a825`, red `#c62828`, grey `#9e9e9e`) and a comment "Prevent … · Detect … · Respond … · Test …" plus the first gap. The statement is the layer's description. No score, gradient or numeric metadata. Merge it with your other tools' layers in Navigator.
- **Signed report:** pack scope `threat_map` with `threat_map.json`: framework, scope, time, statement, catalogue version and digest, mapping digest, every input and the mapping used, and each technique's lanes and gaps.

## Offline verification

`pclaw verify FILE --trust trust.json` checks the signature and statement as for every pack, then re-runs the evaluator on the pack's own inputs and mapping and requires every technique and tactic count to match. Any difference fails. A pack checked by a pclaw release with another mapping or MITRE catalog than the one that built it shows the threat-map part as not available while its signature still verifies; check that part with the pclaw version that built the pack. A `pclaw` older than M28 fails a threat-map pack's `pack.statement` check and does not re-derive the map; verify with M28 or later.

## History and drop alerts (Business)

- A job saves the map once a day (it checks hourly by default, `threat_map.snapshot_interval`) per organization, per environment with active agents, and per framework, kept for 400 days.
- When a lane falls from EVIDENCED, or a test from PASSED to FAILED, the job writes `audit.threatmap.lane_lost` and the built-in rule `pc.threatmap.lane_lost` raises one alert per technique, lane, scope and day.
- `pclaw threats history` and the console show status counts per day and each technique's changes.

## MITRE versions

The catalogues are pinned in `tools/mitre/pins.json`: first ATT&CK Enterprise v20.0 (STIX, from `mitre-attack/attack-stix-data`) and ATLAS 2026.10 (`dist/v6`, from `mitre-atlas/atlas-data`). Moving a version is a reviewed pull request (`task mitre:update`). If MITRE deprecates or revokes a mapped technique, CI fails until the mapping is updated. Ids MITRE dropped from a release stay accepted only in stored custom rules, so those keep parsing; PantherClaw's own content may not use them.
