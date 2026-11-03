# Runbook — Response playbooks from the Hub

**Milestone:** M27 ([G0 M27](../g0/M27.md) D508, D539, D550, D554); containment playbooks after M27 (HR-665). **Audience:** security teams and automation authors. **Edition:** the six response playbooks run on Team; the containment playbooks need Business.

The Hub library has six response playbooks and two containment playbooks under `hub/items/automation/playbook-*`. **None of the six contains, revokes or pauses launches.** Each signal-started response playbook opens a case for a person as its first step and says it contains nothing. A person suspends, revokes or rotates. The two containment playbooks (Business) suspend a run, and only the run a CONFIRMED alert names (see below).

## The six playbooks

| Playbook | Starts on | What a person does |
|---|---|---|
| Leaked key | `alert.raised` on its named rules | The alert names a key's instance. Revoke or rotate the key. |
| Poisoned MCP server | `alert.raised` on its named rules | The alert names a connection. Disable the connection. |
| Rogue sub-agent | `alert.raised` on `pc.authority.self_issue` | Read the case and revoke the right grant. |
| Compromised laptop | `incident.opened`, HIGH or CRITICAL | Suspend the runs, rotate keys and check the machine. |
| Data-flow hold escalation | `action.held` with DATA_FLOW_HOLD | Decide the held action. |
| Offboarded owner | started by hand with the agent | Name a new owner. |

## Why the six contain nothing

The six stay as they were in M27. Containment in the library lives only in the two containment playbooks (below).
- Leaked key and poisoned MCP server: their alerts name a key's instance or a connection. Revoking a key or disabling a connection is a person's action.
- Rogue sub-agent: its alert covers a refused delegation, a refused issue and a refused revision alike. A refused revision names the grant the caller chose, possibly another agent's, so revoking the named grant could let an attacker choose whose grant is revoked.
- Compromised laptop: no built-in incident names a run, and an organization's own rule raises INFERRED at most, so it cannot suspend a run.

## Containment playbooks (Business)

Alerts carry their event kind, and the run where one exists (HR-665). A refused delegation names the run that tried to delegate. A drift found during a call names that call's run, which the server takes from its own record of the call on the same connection, never from the gateway.

| Playbook | Starts on | What it does |
|---|---|---|
| Rogue sub-agent, contain (`pc.playbook.rogue-sub-agent-contain`) | `alert.raised` on `pc.authority.self_issue`, the one confirmed rule that raises on event kind `audit.grant.delegate_refused`, with a run | Suspends that run (SUSPEND_RUN on TRIGGER_RUN) |
| Poisoned MCP server, contain (`pc.playbook.poisoned-mcp-server-contain`) | `alert.raised` on `pc.tools.drift`, the one confirmed rule that raises on event kind `audit.package.transitioned`, with a run | Suspends that run (SUSPEND_RUN on TRIGGER_RUN) |

- Each contains only on a CONFIRMED alert (OBSERVED or RULE_MATCH); on any other alert the step skips with `UNCONFIRMED_SIGNAL`.
- A refused issue, a refused revision and a drift found by the periodic check name no run, so neither starts on them. A drift report that names a call on another connection is still quarantined, but names no run.
- A containment playbook opens no case. The response playbook for the same rules does.
- Like every contain step, they need Business (HR-284). On Team they fail validation. A Hub install makes a draft, as for the six.

## Install and enable

1. Install the item from the Hub. It makes a draft automation `hub-playbook-*` with no review date and no `authority.revocable`.
2. A person sets the review date, validates and enables it. Rollout starts wherever they choose.

## Details

- Data-flow hold escalation starts only when DATA_FLOW_HOLD is the hold's deciding reason. A hold that another approval requirement decides first carries DATA_FLOW_HOLD only among its other reasons, which the trigger can't read. It reminds approvers after 30 minutes, escalates, then waits up to 24 hours for a decision. It never decides.
- No playbook uses the `revoke_grant` step or publishes a policy. Offboarding drafts and simulates a restriction of unused grants and asks the owner to name a new owner.
- Each playbook ships tests for NORMAL, DENIED, TIMEOUT and DUPLICATE.
- The range run `TestRange_ScenariosPlaybooks` (part of `task range`) drives each signal-started response playbook from the audit event the producing code writes, through the detection engine. It checks that every one opens its case and nothing is contained, revoked or suspended.
- Your own automations follow the same engine rule: a contain step runs only on a CONFIRMED alert ([behavior-profiles.md](behavior-profiles.md)).
