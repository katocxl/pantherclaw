# ADR-0037 — Data-flow holds, external policy checks and evidence-backed suggestions

**Status:** Accepted (2026-10-29; G0 M16 founder decisions F5–F8, answered with the recommended option each time; the [G0 M16 brief](../g0/M16.md) records them with the coordinator's design decisions D70–D92).

**Context.** Each action is decided on its own. Destination classes and disclosure limits (HR-079) govern where an agent sends data, and M14's data scoping governs what it reads, but nothing connects a sensitive read to a later disclosure: an alert-only detection reports the pattern after the fact. Customers want their own judgement in the decision path (their data classifications, their Open Policy Agent policies, identity-risk signals from their identity provider) without letting any outside source widen what PantherClaw allows (ADR-0004, ADR-0019). Posture findings show unused authority but leave people to work out the fix and what it would break.

**Decision.**
1. **Data-flow holds** (F5, F6; HR-430..434).
   - Every allowed read records the class of the data it returned, from the package's declared response classes, capped by a `data_classes` obligation and raised by a classification fact.
   - "Confidential or higher" (F5) means `pii` and `secret`: the classes are `public < internal < pii < secret`, and `pii` is the first class above `internal` (D71).
   - The window is the rest of the run tree (F6): reads count across every run that shares the run's root.
   - An external disclosure after a sensitive read in the tree is held for approval (`DATA_FLOW_HOLD`) unless a flow allowance on the grant covers the classes and destinations. Flows only narrow under delegation, and none means none. Monitor mode records the would-hold. Read history keeps classes and ids, never content.
2. **Outside signals only restrict** (F7, F8; HR-435..441).
   - **Classification facts** carry provenance (source and method) and can only raise a read's class.
   - **The external policy check (OPA)** is synchronous and restrict-only, and fails closed. Endpoints are HTTPS, allow-listed in server configuration, called through the egress guards and activated with a step-up. `deny` denies, `hold` requires approval, `allow` passes a checklist item only. Any failure, including a timeout of at most 1 s or more than 16 calls in flight, is CANNOT_AUTHORIZE. Disclosure-capable content is sent only as its length; reasons are shown to people only. Replay and simulation do not call it. Business edition.
   - **Identity-risk facts** are written only by the Shared Signals receiver through a built-in provider, exposed to policy as `principal.risk`, absent after 24 hours, and never allow.
3. **Evidence-backed suggestions** (HR-442..445). Unused-authority findings become suggestions with a 30-day evidence window, observed operations, coverage limits, an expected effect computed only from recorded transactions ("not collected" is never zero), affected owners and an uncertainty that is never LOW when a route lacked coverage. A person can dismiss a suggestion or draft a policy from it; drafts go through the M11.1 publication gate, and nothing is published automatically. Business edition.

**Consequences.**
- Read-then-disclose becomes a decision, not just an alert; agents that legitimately move sensitive data need a flow allowance on their grant (flows declared by task templates are a follow-up).
- `pc.transactions` gains a read class, and the pipeline reads the run tree's recent sensitive reads on disclosures, adding one indexed query to those decisions.
- An external check adds network latency to the actions it covers and makes them unavailable while the endpoint is down; customers choose which operations it covers.
- Outside sources can make PantherClaw stricter, never looser, so their compromise can at worst deny or hold work.
- Suggestions save analysis time but never act; their evidence and uncertainty are visible so a person can judge them.

**Alternatives.** Counting every `access: read` as sensitive (holds too much, F5); a sliding time window (easy to wait out, F6); an external check that can allow, or fails open (an outage or compromise would widen authority, F7); risk signals that can lift restrictions (F8); per-run rather than per-tree read history (a child run would escape the hold); suggestions applied automatically (would bypass the publication gate).
