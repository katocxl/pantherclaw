# ADR-0049 — Behaviour profiles on PantherClaw's own transactions

**Status:** Accepted (2026-11-01; G0 M27 design decisions D500–D502 and D506, the rulings D514, D516, D524, D526, D547 and D548, founder decisions H4 and V6; the [G0 M27](../g0/M27.md) brief records them).

**Context.** Static rules miss slow misuse. A profile of what an agent normally does can show drift, but it is inference, and it is coded here on simulated history. Boundary F787 says PantherClaw is not a log warehouse: it stores attributable actions and their consequences, not unrestricted log collection. F800 bars destructive automatic response by default. HR-030, HR-034 and HR-240 keep decisions off anything a detection infers.

**Decision.**
1. **Own transactions only** (D502, D506, V6(a), HR-641). A job reads `pc.transactions`, not the ledger, never payloads, and no outside logs. `internal/authority` and `internal/approvals` import nothing from `internal/behavior`. This fits F787: these are the attributable actions PantherClaw already holds. F787 is unchanged.
2. **Only allowed actions are known** (D526, HR-643). An action makes a tool, connection, hour or sequence known only when it was allowed with a FINAL decision. Holds, denials and retries are counted apart. Too little history is INSUFFICIENT_HISTORY and infers nothing; no profile is NOT_COLLECTED, never zero. The rollup is paged and capped, and a cap that bites says so.
3. **Profiles are inference, and they say so** (D502, HR-644). Every profile, context and alert is labelled INFERRED and UNVALIDATED, and says that a quiet result is not a clean one. Behaviour alerts have basis INFERRED and attention of at most ALERT. It extends `pc.drift.behavior` and F399, using `BehaviorProfile`, not `cohorts.Baseline`.
4. **Simulated history is apart** (D502, D524, HR-642). It lives in `pc.behavior_simulated_actions`, range agents only, enforced by the database, and is compared only with simulated activity. A simulated signal is a Test signal (HR-222).
5. **Inference never contains** (D500, D514, D516, D526, H4, HR-640). `reflex.alert` gains `basis`. A contain step runs only on a CONFIRMED alert (OBSERVED or RULE_MATCH), for every automation, library or custom. Otherwise it skips with `UNCONFIRMED_SIGNAL`, and a definition on `alert.inferred` that would contain is refused. Custom detection rules are capped at INFERRED. This is stricter than F800.
6. **Inference never decides** (D501, D526, HR-645, HR-646). Approval context shows beside the approval, outside the binding, compared with the agent's allowed actions before the held action, never with a stored profile. No decision reads it. HR-030, HR-034 and HR-240 are unchanged.

**Consequences.**
- A customer's own SOAR acting on exported alerts is outside PantherClaw's control. Exports carry `basis`, so it can tell an inference apart.
- A person contains every inferred incident, so response is slower than it could be. Inferred built-in detections that an automation used to contain are now contained by a person, and custom rules declared OBSERVED or RULE_MATCH now raise INFERRED alerts.
- Profiles do not exist for what PantherClaw never saw. An agent outside the gateway has no profile, and the arguments of its actions are not read.
- The agent shapes its own baseline. Thresholds are guesses until real history exists, and the product says so.

**Alternatives.** Ingesting outside logs (V6(b), against F787); automatic containment on a strong inference (H4, F800); confirmed custom rules driving containment (a two-person path is a follow-up); putting "never done X" inside the approval binding (a decision would then rest on inference); comparing approval context with the stored profile (a hold and its retries could make the action look usual); reading the ledger (D502 chose `pc.transactions`); reusing `cohorts.Baseline` (it is not what N13 needs).
