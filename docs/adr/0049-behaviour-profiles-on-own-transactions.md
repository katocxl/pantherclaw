# ADR-0049 — Behaviour profiles on PantherClaw's own transactions

**Status:** Accepted (2026-11-01; G0 M27 design decisions D500–D502 and D506, founder decisions H4 and V6; the [G0 M27](../g0/M27.md) brief records them).

**Context.** Static rules miss slow misuse. A profile of what an agent normally does can show drift, but it is inference, and it is coded here on simulated history. Boundary F787 says PantherClaw is not a log warehouse: it stores attributable actions and their consequences, not unrestricted log collection. F800 bars destructive automatic response by default. HR-030, HR-034 and HR-240 keep decisions off anything a detection infers.

**Decision.**
1. **Own transactions only** (D502, D506, V6(a), HR-642). Profiles read `pc.transactions`, not the ledger, and no outside logs. This fits F787: these are the attributable actions PantherClaw already holds. F787 is unchanged.
2. **Profiles are inference, and they say so** (D502, HR-644). `definition_status` gains UNVALIDATED (F801). Thresholds stay unvalidated until real data exists. It extends `pc.drift.behavior` and F399, using `BehaviorProfile`, not `cohorts.Baseline`.
3. **Simulated history is labelled** (D502, HR-643). A labelled generator, split from real history (F630, HR-222).
4. **Inference never contains** (D500, H4, HR-640). `reflex.alert` gains `basis`. A contain step runs only on CONFIRMED alerts, for every automation, library or custom, and validation refuses one on an INFERRED alert. This is stricter than F800.
5. **Inference never decides** (D501, HR-641). "Never done X" shows beside the approval display, outside the binding, labelled inference. No decision reads it. HR-030, HR-034 and HR-240 are unchanged.

**Consequences.**
- A customer's own SOAR acting on exported alerts is outside PantherClaw's control.- A person still contains every inferred incident, so response is slower than it could be.
- Profiles do not exist for what PantherClaw never saw. An agent outside the gateway has no profile.
- Thresholds are guesses until real history exists, and the product says so.

**Alternatives.** Ingesting outside logs (V6(b), against F787); automatic containment on a strong inference (H4, F800); putting "never done X" inside the approval binding (a decision would then rest on inference); reading the ledger (D502 chose `pc.transactions`); reusing `cohorts.Baseline` (it is not what N13 needs).
