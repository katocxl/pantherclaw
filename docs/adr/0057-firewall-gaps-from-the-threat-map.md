# ADR-0057 — Gaps from the threat map

**Status:** Accepted (2026-11-05; founder decisions FD4–FD7, answers E, S, C and P of 2026-11-04, and the founder decision of 2026-11-05 that agent identity protection and the runtime firewall are defined apart; the [G0 M30](../g0/M30.md) brief records them).

**Context.** The M28 threat map ([ADR-0055](0055-mitre-threat-map.md)) names every agent-reachable technique that has no PantherClaw control. Several of them are acts the gateway or the server already sees: a copied MCP access token used from another machine, injected text hidden by an encoding, bulk reads through granted operations, data shared with an outside account by a policy or visibility change, an agent rewriting its own settings or memory, and a retrieval store poisoned by another agent. The map also read an automation as covering every alert of its rule when its trigger tested more than the rule, and it could not count refusals a connector makes after the decision (F-M28-1, F-M28-2).

**Decision.** M30 adds controls where PantherClaw already sees the act. Each new check can only refuse or hold; none widens what a grant allows. The controls fall in two groups (founder, 2026-11-05).

*Agent identity protection (Badge): is this really that client?*
1. **DPoP-bound MCP tokens** (HR-700..702, FD4). A client whose metadata document asks for bound tokens gets tokens bound to its key (RFC 9449, `cnf.jkt`) at the token endpoint and the ID-JAG exchange. At use, each call carries a fresh proof: key, method, URL, token hash, time, an organization nonce and a single-use id. A bound token is never accepted as a bearer token. Standard clients keep the 5-minute bearer (R-69 amended).

*Runtime firewall: may this agent do this, here, now?*
2. **Decoding before content signals** (HR-703, every edition). Injection phrases and secret formats are also matched on text decoded from base64, hex, URL and backslash escapes, HTML entities, look-alike letters and invisible characters, three layers deep, within the body bound. Past the bound the scan is incomplete (`decode_bound`) and holds in ACTIVE.
3. **A vector-store connector** (HR-704, HR-705, FD7). `pc.vectorstore` on pgvector: a fixed table layout the admin creates, provenance columns filled only from the verified permit, writes by agents outside the connection's writer list held for a person (`VECTOR_WRITE_NOT_WRITER`), and an endpoint that cannot change after create.
4. **Read limits and alerts** (HR-706, HR-709, FD6). A count rule can count reads or writes only, off until a grant names it; the INFERRED rules `pc.reads.enumeration` and `pc.exfil.scheduled_sends` alert and never hold.
5. **Share checks** (HR-707, HR-708, answer S). Package share extractors read who an action shares with; a share to the public or to an account the organization has not listed holds for a person, and an empty list holds every cross-account share. Adding an owned account loosens the check, so it is a protected change.
6. **Agent configuration and memory** (HR-710..713, FD5, answer C). Scans report these files by digest only; a changed digest writes `agent.config_changed` and raises an alert that holds nothing; `pclaw hook` asks the gateway before a write to a listed path (cooperative, R-74); the sandbox binds them read-only and copy-out leaves their changes out unless they are applied after being shown.

*The map and the model path.*
7. **Threat-map honesty** (HR-714, HR-715). An automation whose trigger tests more than the rule reads PARTIAL `NARROWED_TRIGGER`. A Prevent control that refuses after the decision names its outcome codes, and Seen counts those refusals (`prevent.query_scope`). `prevent.mcp_token_binding` names no reason codes: its refusals are OAuth authentication errors, not decisions.
8. **M29 follow-ups** (HR-716, HR-717, answer P). Prompt capture per model connection, off by default, on only as a protected change on Business; an approved hold resumes through the edge only for the exact request it was given for.

Each control is mapped on the threat map, and the techniques it covers leave the "No PantherClaw control yet" list.

**Consequences.**
- A stolen bound token is useless without the client's key. Standard clients, which cannot hold a key, still carry a 5-minute bearer token (R-69).
- Decoding raises the cost of hiding text, not the ceiling: content signals still know listed phrases and formats only (R-68).
- The vector store holds data the gateway never creates: the admin runs the DDL that `pclaw connections vectorstore ddl` prints.
- An organization that lists no owned accounts holds every cross-account share, which is noisy by design until it lists them.
- Outside the sandbox, a configuration write that skips the hook is seen only afterwards, by its digest (R-74).
- Campaigns through a model connection are deferred (D945d): `StartCampaign` needs a simulated model relay today.

**Alternatives.** Bound tokens for every client (standard MCP clients hold no key, FD4); read limits on by default (FD6); refusing rather than holding unlisted shares (answer S); storing configuration contents to show diffs (FD5); holding on configuration drift (answer C); a vector store other than pgvector (FD7).
