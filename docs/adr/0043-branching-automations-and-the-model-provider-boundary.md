# ADR-0043 — Branching automations and the model-provider boundary

**Status:** Accepted (2026-10-29; G0 M21 founder decisions G16 and G17, answered with the recommended option each time; the [G0 M21 brief](../g0/M21.md) records them with the coordinator's design decisions D300–D305).

**Context.** M11's automations run their steps in a fixed line. A step can be skipped by a guard, but a definition cannot choose between paths, so customers duplicate automations or push branching into guards that the validator and the inspector cannot reason about. The definition's validator checks authority for the definition as a whole and references only against "earlier" steps; the engine tracks its position as an index into the step list, and every running execution is pinned to an immutable version whose stored JSON the engine re-parses. Separately, PantherClaw has never called a language model: plain-language search is a deterministic parser and nothing leaves the server (M11 founder decision F5, HR-295). Customers asked to draft policies, automations and queries from a sentence (F181, F304), and the founder decided a model may help, only optionally and only to draft (G16).

**Decision.**
1. **Branching as a v2 format** (HR-530..534).
   - A new `apiVersion: automations.pantherclaw.dev/v2` with `nodes:`: `branch` (if/else), `switch` (ordered cases and a required default) and `join` (`ALL` or `ANY`). Paths are mutually exclusive; there is no parallel execution.
   - v1 parsing is frozen; a v1 definition is lifted in memory to a linear graph, so stored v1 versions and running v1 executions behave exactly as before.
   - The validator works on the graph: unreachable nodes, unterminated paths and cycles are errors; references must hold on every path; authority and irreversible waits are checked per path, and the whole-definition ceiling check is kept, the stricter applying; at most 40 nodes, 64 paths and depth 20.
   - Each terminal node declares its outcome and `finish_when`. Compensation covers only the effectful nodes on the taken path, in reverse order.
   - Run state gains a node pointer and path; attempts gain a node id and visit, backfilled from the step id without touching identity columns. No execution is re-pointed to another version or state.
   - Simulation and replay show both branches when a guard cannot be evaluated.
2. **A model-provider boundary** (HR-541..545).
   - A port `internal/model/ports.Provider.Draft`, first adapter the Anthropic Messages API with the customer's own key and a per-organization model id. Off by default, Business edition, enabled per organization; a platform kill switch; self-hosted deployments keep it off unless their environment allows it.
   - The model is an **external processor** (trust boundary TB13). It receives only a fixed task kind, the user's own text, the target JSON schema and a catalogue of names the user may see. It never receives records, payloads, evidence or untrusted text, and it has no tools.
   - Calls go to a host fixed per adapter, through the egress client, HTTPS on 443, with a 30-second timeout, a 64 KiB response cap and per-organization rate and daily budget caps. Every call is audited without its text. The key is envelope-encrypted per organization and write-only.
   - **Only the reviewed structured form executes.** The output is parsed strictly into an existing structured type (a search query or built-in, a policy bundle, an automation definition); anything else is refused. Vague terms come back as ambiguities with proposed thresholds that the reviewer confirms. Policy and automation drafts are DRAFT versions that pass the M11.1 gate like any other; a drafted query is re-resolved under the viewer's permissions, shown, and never run. `Interpret` and `Ask` stay deterministic, and HR-295 is unchanged.

**Consequences.**
- Automations can express real decisions while every path is validated, inspected and simulated; authors of v1 definitions need to do nothing.
- Two engine paths (step index for v1, node pointer for v2) coexist until no v1 execution is running; the migration must be tested against waiting v1 executions.
- Per-path checks can refuse a v2 definition whose whole-definition check would pass; this is intended.
- Customers who enable drafting send their own words and the names they can see to their own model vendor, under their own agreement with that vendor (a data-processing agreement is theirs to hold), and possibly outside the region named in their PantherClaw order form. The threat model records the boundary, the DPA note and this residency caveat.
- A compromised or wrong model can at worst produce a draft a person rejects, or a query a person declines to run.

**Alternatives.** Optional `next` fields on v1 steps (blurs the frozen v1 format); rewriting stored v1 definitions (breaks the version freeze); parallel branches (needs concurrent attempts and a new compensation order; later); a model that may run queries or publish drafts (breaks F181's "only the reviewed structured form executes"); folding the model into `Interpret` (would change HR-295 for every user); a model hosted by PantherClaw (the founder chose bring-your-own-key, G16); no model at all (the alternative the founder declined).
