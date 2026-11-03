# ADR-0055 — MITRE ATT&CK and ATLAS threat map: lanes from evidence, no score

**Status:** Accepted (2026-11-03; founder decisions Q1–Q4 and the founder decision of 2026-11-03 on API reads and on techniques with no control; the [G0 M28](../g0/M28.md) brief records them).

**Context.** Security teams describe threats in MITRE ATT&CK and ATLAS. PantherClaw's detections carried ATLAS ids from a hand-written list on 5 of 20 built-in rules, no ATT&CK id appeared anywhere, and the alert ledger dropped the ids, so OCSF exports never carried `attacks[]`. A coverage map is easy to read as a score or as a claim about how well an organization is defended, which would break F797 and F801.

**Decision.**
1. **A pinned catalogue** (HR-682). ATT&CK Enterprise and ATLAS official releases, first ATT&CK v20.0 and ATLAS 2026.10, pinned by version and sha256, generated into `internal/threatmap/catalog` with ids, names, tactics, parents, platforms, flags and URLs only. MITRE's text is not copied; pages link to MITRE. Updates are reviewed pull requests. Ids MITRE dropped stay accepted only in stored custom rules.
2. **Every technique has a place** (HR-683, Q1). Both matrices in full. Each technique is mapped to a PantherClaw control, Outside PantherClaw with the kind of tool that covers it, or No PantherClaw control yet, shown red with why. A test fails the build otherwise, and when MITRE deprecates or revokes a mapped id.
3. **Mappings live on the artifact** (HR-683, HR-685). Detection rules carry `attack` beside `atlas`, or a one-line reason they map none; library scenarios and campaigns carry ids with a one-line why, or a one-line reason they map none, and a scenario with a reason never feeds the Test lane; Hub rules may carry ids; behaviour and content kinds, Prevent controls, Outside and No-control entries are Go tables. Customer scenarios carry none.
4. **Four lanes from evidence** (HR-680, HR-689). Prevent, Detect and Respond are EVIDENCED, PARTIAL, GAP, STATED or NONE_SHIPPED, from live coverage, rule state and automations; Test is PASSED, FAILED, STALE or NOT_RUN from the organization's own server-observed library runs within 30 days. Status: green, amber, red or grey. Tests never raise a status. The organization's own rules are STATED, never evidence.
5. **No score, honest words** (HR-681). A fixed statement goes with every output. Banned words are tested. Counts are per tactic and status, never totalled.
6. **Signals carry techniques** (HR-684). Alerts, incidents, cases and range results hold ids end to end into OCSF and the six SIEM packs.
7. **Proof and exports** (HR-688). A signed pack scope `threat_map`, re-derived offline by `pclaw verify`; an ATT&CK Navigator layer with colour and comment only; `pclaw threats`; a read-only MCP tool. HR-655, HR-656 and HR-657 are amended to admit the Investigator on the one technique read.
8. **Editions and access** (HR-686, Q2). The matrix, technique pages, gaps and labels on every edition in the console; reads with an API key or access token, the report, the Navigator export, the MCP tool and posture gaps on Team; history and drop alerts on Business (HR-687). A new permission, `threatmap.read`.
9. **The Test lane uses the organization's own range runs** (Q3). No hosted runner.

**Consequences.**
- A first map is mostly grey and red: most ATT&CK Enterprise techniques need an endpoint, a network, a mailbox or a person, and some agent-reachable techniques have no PantherClaw control yet. That is the honest reading.
- A green technique says a mapped control acted with evidence, not that every way of carrying out the technique is covered.
- A reader of the map learns which techniques are unwatched (R-72).
- A MITRE release that changes a mapped id fails CI until the mapping is updated.
- A `pclaw verify` older than M28 checks a threat-map pack's signature and file digests, but expects the general evidence statement, so its `pack.statement` check fails, and it never re-derives the map. Verify with `pclaw` M28 or later. A pack built with another catalogue reads as not available.

**Alternatives.** A coverage score or percentage (F797); ATT&CK limited to cloud, SaaS and identity, or ATLAS only (Q1 B, C); all of it on Team, or all on every edition (Q2 B, C); a hosted test runner (Q3 B); forcing every agent-reachable technique into a mapping or Outside (founder decision 2026-11-03); copying MITRE's descriptions (MITRE's terms, and it would go stale); mapping the organization's other tools (they merge Navigator layers instead).
