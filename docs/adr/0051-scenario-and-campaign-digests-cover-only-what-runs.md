# ADR-0051 — Scenario and campaign digests cover only what runs

**Status:** Accepted (2026-11-03; the founder's decision of 2026-11-03 on this follow-up; closes the open item D546 of the [G0 M25](../g0/M25.md) brief).

**Context.** `rtdomain.Digest` and `campaign.Digest` hashed the RFC 8785 JSON of the whole parsed file. The server accepts a library scenario only with the library's digest (HR-467) and a library campaign only with its own (HR-608), and a compliance report takes a result's tags from the library only for the digest the library shipped (HR-602). So a tag or wording change (`title`, `threats`, `rules`, `asi`, `asi_why`) gave a new digest: results recorded under the old digest stopped matching the library and stopped counting, although nothing that runs had changed. G0 M25 left this open, to be decided before v1.0 (D546).

**Decision.**
1. **Scenarios** (HR-661). The digest is the SHA-256 (hex) of the RFC 8785 JSON of `{apiVersion, requires, harness_only, steps}`, with the same JSON names and each step whole (`id`, `do`, `with`, `save`, `expect`). Spelling and defaults in the YAML still do not change it.
2. **Campaigns** (HR-661). The same over `{apiVersion, task, plants, attempts, script}`.
3. **Left out.** For a scenario: `id`, `title`, `category`, `suite`, `tier`, `attacker`, `threats`, `rules`, `asi`, `asi_why`. For a campaign: `id`, `title`, `technique`, `tier`, `threats`, `asi`, `rules`. Tests list every member of the scenario, step, expectation, campaign, plant, attempt and script types as covered or left out, and fail on a member in neither list, so a new member cannot ship without a decision.
4. **Set digest unchanged.** `SetDigest` stays as it is: sorted `id:digest` lines.
5. **Switch now.** There is no list of legacy digests, and the library is regenerated (`task range:library`).

**Consequences.**
- A tag or wording change keeps results mapped. The library still has to be regenerated after one, because it holds the tags and the tier.
- A change to anything that runs (a step, an expectation, a saved value, a requirement, a plant, an attempt, the script) changes the digest, and a test shows this for each member kept. The server refuses the edited file as not the library's.
- Digests stored before the switch no longer match, so results recorded before it don't map to the library and don't count toward a compliance report; a baseline comparison reports their scenarios as changed and still compares them (HR-226). Running the range again counts it.
- The id, tier and tags are outside the digest. They still come from the library built into the server, as before (HR-467, T-204, T-260).
- `pclaw redteam run` and `pclaw redteam campaign run` compute digests locally. With a `pclaw` from before the switch and a server after it, or the reverse, the server refuses every library scenario (`RANGE_SCENARIO_NOT_LIBRARY`) and campaign (`CAMPAIGN_NOT_LIBRARY`): upgrade both together.

**Alternatives.** Keeping the whole-file digest: a tag fix would unmap every result. Keeping a list of legacy digests: the founder chose to switch now with none.
