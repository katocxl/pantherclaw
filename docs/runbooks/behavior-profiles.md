# Runbook — Behaviour profiles and containing on confirmed alerts

**Milestone:** M27 ([G0 M27](../g0/M27.md) D500–D502, D506, D514, D516, D524, D526, D548; [ADR-0049](../adr/0049-behaviour-profiles-on-own-transactions.md)). **Audience:** security teams, approvers and automation authors. **Edition:** profiles Business and above (`BehaviorAnalytics()`); the containment rule applies on every edition.

A behaviour profile is an inference about what an agent usually does. It is never evidence of misuse, and no decision reads it.

## Alerts and containment

- Every alert (`reflex.alert`) carries a `basis`: OBSERVED, RULE_MATCH, INFERRED or HYPOTHESIS. An incident opened by a signal carries the signal's basis; a person's change to an incident carries none.
- A **CONFIRMED** alert is one whose basis is OBSERVED or RULE_MATCH. Nothing else is.
- A `contain` step runs only when its trigger is one CONFIRMED alert or incident, in every automation, library or custom. On anything else (an inferred alert, an incident a person reopened, a threshold, a schedule, a manual run, any other event) the step skips with `UNCONFIRMED_SIGNAL` and acts on nothing. The rest of the execution goes on, so the case still opens.
- A `revoke_grant` step beyond its own grants (TRIGGER_GRANT, CEILING_AGENTS) skips with `INFERRED_SIGNAL` when its trigger is an inferred alert or incident. On other triggers it runs as before.
- Event `alert.raised` means every alert, any basis. Event `alert.inferred` means only alerts whose basis isn't confirmed; a missing or unknown basis counts as inferred. A definition that starts on `alert.inferred` and names a step that would contain, in `do` or in compensation, is refused with `CONTAIN_ON_INFERRED`.
- A threshold in an automation that can contain counts only CONFIRMED alerts and incidents.
- Validation warns `CONTAIN_NEEDS_CONFIRMED_ALERT` for a contain step under any trigger other than an `alert.raised` or `incident.opened` event. The definition still validates, but the step would always skip.
- Custom detection rules (`org.*`) are capped at INFERRED unless two people confirmed the version that is running: a person asks with `RequestCustomRuleConfirmation`, and another person with `detection.manage` confirms it with a security key. Publishing another version, disabling the rule or `WithdrawCustomRuleConfirmation` ends it at once ([HR-666](../security/HARDENING_RULES.md), Business). A rule with basis OBSERVED or RULE_MATCH in its content is still refused when created, tested or published (`RULE_INVALID`), and a rule published earlier with a confirmed basis raises INFERRED alerts: a confirmation is the only path. So no automation contains on an unconfirmed custom rule's alert; a person can.
- These detections have basis INFERRED, so a person contains them:
  - built-in: budget_splitting, delegation_depth_anomaly, drift_behavior, probing_denial_burst, sequence_read_then_disclose, tools_description_injection;
  - Hub rules, installed as custom rules (INFERRED unless two people confirm a version, HR-666): detect-external-disclosure-repeat, detect-held-merge-then-shell, detect-merge-denial-burst, detect-refund-burst, detect-refund-cap-probing, detect-first-production-deploy, detect-secret-outbound-refused, detect-shell-merge-attempt.
- The `scoped_incident_containment` template keeps its shape. Its contain step now skips an inferred alert.
- **A customer's own SOAR or script acting on exported alerts is outside PantherClaw's control.** Exports carry `basis`, so it can tell an inference apart. Filter on it before acting.

## Behaviour profiles

- Permission `behavior.read`: Org Admin, Security Admin, Agent Owner, Approver, Responder and Auditor. Reads are scoped to the agents you can see and hold names, ids and counts only, never arguments or payloads.
- Reads: `BehaviorService.GetAgentProfile(agent_id, origin)` and `GetBehaviorContext(approval_id)`.
- An hourly job, one per organization, builds profiles from the organization's own `pc.transactions`, never the ledger and never payloads. It looks at operation names, connection ids, destination class, hour, run sequence and allowed spend per currency.
- Only an allowed action shapes a profile: a FINAL decision (ALLOW or ALLOW_WITH_OBLIGATIONS, transaction state FINAL). FINAL is the decision's state, not proof that the action ran. Holds, denials, refusals, open transactions and their retries are counted apart and never make anything known.
- A profile covers 30 days. States:
  - COLLECTED;
  - INSUFFICIENT_HISTORY: under 50 known actions or 7 active days. It infers nothing;
  - NOT_COLLECTED: no profile yet. Never shown as zero.
- Deviations: new tool, new destination, unusual hour, new sequence, volume spike (over 3 times the busiest hour seen and at least 20 actions in the hour), spend spike.
- Each deviation raises an alert: source `behavior`, rule `pc.drift.behavior.<kind>`, basis INFERRED, attention at most ALERT. It never contains automatically.
- Every profile, context and alert carries this label: "Inferred from this agent's own recorded actions. The thresholds are unvalidated. This is not evidence of misuse, and a quiet result is not a clean one: the agent shapes its own baseline, and activity outside PantherClaw and the arguments of its actions are not seen."
- The thresholds (`SpikeFactor`, `MinActions` and the rest) are unvalidated. None was checked against a real incident.

### Limits

- The newest two minutes are left for the next run, since a transaction may not have committed yet.
- Each run compares a page of at most 20,000 actions per origin since its cursor, oldest first, and moves the cursor only over that page. The next run carries on.
- Each agent's baseline reads at most 20,000 known actions, the newest.
- A run profiles at most 2,000 agents per origin, never-profiled agents first, then the least recently profiled.
- At most 200 signals per run and origin, and at most 20 per agent. The rest raise the owned failure `behavior.signal_overflow` with their count.
- When a cap bites, the run raises the owned failure BEHAVIOR_CAP_REACHED (kind `behavior.cap_reached`, one open per origin), and the profile says `truncated`.
- Migration `00303` builds the index `transactions_behavior` concurrently, outside a transaction, so writes go on during the build.

## Approval context

- `GetBehaviorContext` shows, beside an approval, what is new about the held action ("never used this tool" and so on). It compares with the agent's known actions in the 30 days before the held action, computed when read, never with the stored profile. The hold, its retries and a later rollup never make the action look usual.
- The caller needs `behavior.read` on the agent and must be able to read the approval: an eligible decider, the run's launcher or principal, or `approval.read` on the agent's scope. Otherwise the answer is NOT_FOUND.
- It is outside the binding. The approval display, its digest and the decision are the same with or without it, and no decision reads it.
- An approval with no transaction, such as a restoration request, has no context: NOT_FOUND.

## Simulated history

- Made-up history lives in `pc.behavior_simulated_actions`, apart from real transactions. The database refuses a row that isn't `simulated` or whose agent isn't a range agent.
- Simulated profiles compare only with simulated activity, and real only with real.
- A simulated signal is a Test signal: capped at ALERT, never pages and opens no incident.
- There is no RPC or CLI for the generator in M27. It is a package used by tests and the exit run.
