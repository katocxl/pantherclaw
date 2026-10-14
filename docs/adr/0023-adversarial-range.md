# ADR-0023 — The adversarial range: range agents, simulated connections and a local gate

**Status:** Proposed (2026-10-14; G0 M12 founder decisions F1–F4, answered with the recommended option; accepted with the [G0 M12 brief](../g0/M12.md))

**Context.** M12 delivers an adversarial range: a scenario engine that runs at least 30 attacks against the product and produces signed evidence of which controls held. A range that can reach real targets is itself a threat (T-038), and a range whose traffic the system treats differently proves nothing about real traffic (T-094). HR-120 says red-team runs are server-enforced to simulator-only environments and that receipts carry `simulated: true`; until M12 the receipts' `simulated` field was always false and nothing enforced the rule. The product also has no CI (EX-004), so a regression gate cannot wait for GitHub workflows. Scenario files and attack payloads are untrusted input, and some attacks (a credential-shaped string in an allowed payload) need a control that did not exist.

**Decision.**
1. **Range agents** (F2, HR-220). An agent is marked `range_agent` when it is created; the mark is immutable (not in the `pc_app` column grant). Every run of a range agent is `simulated`, set by the server. Range agents are capped at 5 per organization in every edition and do not count toward the agent limit (F4). A real agent never becomes a range agent, and the reverse.
2. **Simulated connections and the handshake** (HR-221). A connection marked `simulated` must point at a loopback or private IP literal, and cannot be a connector container. The simulators answer `GET /.well-known/pantherclaw-sim?nonce=<hex>` with their kind and the nonce; the gateway checks it, without credentials, before the first dispatch and again when the last success is older than 10 minutes. Without it the gateway refuses locally (`simulator_unverified`) and sends nothing.
3. **Isolation** (HR-222). The server refuses to let a simulated run reach a real connection or the reverse (`SIMULATION_MISMATCH`, both ways). The policy engine's input never contains the mark, so real policies and packages are tested as written. Simulated activity debits no envelope budget, quarantines nothing, feeds no coverage and is labelled SIMULATED wherever a person sees it.
4. **Server-derived assurance** (HR-224). A runner records results through `RangeService`; the server derives each step's observed decision from its own transaction records and its value wins over the runner's claim. A report is an evidence pack of a new scope, `range`, with an `assurance` item; `pclaw verify` re-derives the server-observed verdicts offline. The report says it is tested-control evidence against simulated targets, never a compliance certification.
5. **Outbound credential check** (F3, HR-225). The gateway scans the outgoing action on every face. A secret it holds is refused locally (`secret_in_payload`); a known credential format raises findings (kind and location, never the value) that make the server add a REQUIRE_APPROVAL reason `SECRET_IN_PAYLOAD`. Findings can only add requirements.
6. **A local gate under EX-004** (F1, HR-226). `task range` runs every scenario against simulators on the local test stack (`SANDBOX=1 task range` adds the sandbox scenarios); pull requests touching authority, gateway, sandbox, packages or the range run it and report it. `pclaw redteam run --baseline <pack>` exits 1 on any regression. A `range` job is added to the disabled `ci.yml` and switches on with the other workflows before the first release tag.
7. **Scenarios are data** (HR-223). YAML parsed strictly into a closed step catalogue; scenarios name connection roles, never hosts.

**Consequences.**
- Real policies, grants and packages are exercised exactly as customers use them; the only difference is the mark the server alone sees.
- New columns (`range_agent` on agents, `simulated` on runs, transactions and connections) and two tables (`redteam_runs`, `redteam_results`) are needed.
- A person who operates the gateway can answer the handshake from a proxy (R-23); the handshake stops mistakes, not that attacker.
- The credential check knows only held secrets and listed formats (R-24).
- Until CI returns, the gate depends on sessions running and reporting `task range`; the founder's merge review is the control that the report exists.

**Alternatives considered.**
- A mark on the run chosen by the caller: rejected. A caller that can claim `simulated` can also decline it, so the server derives it from the agent.
- A separate range organization: rejected. Real policies and packages would have to be copied, and drift between the copy and the original would make the results meaningless.
- Policy conditions on the mark (`simulated == true`): rejected. It is exactly the test detection T-094 describes.
- Waiting for CI to gate the range: rejected by the founder (F1); the local gate runs now.
