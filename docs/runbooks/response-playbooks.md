# Runbook — Response playbooks from the Hub

**Milestone:** M27 ([G0 M27](../g0/M27.md) D508, D539, D550, D554). **Audience:** security teams and automation authors. **Edition:** all six run on Team.

The Hub library has six response playbooks under `hub/items/automation/playbook-*`. **None of them contains, revokes or pauses launches in M27.** Each signal-started playbook opens a case for a person as its first step and says it contains nothing. A person suspends, revokes or rotates.

## The six playbooks

| Playbook | Starts on | What a person does |
|---|---|---|
| Leaked key | `alert.raised` on its named rules | The alert names a key's instance. Revoke or rotate the key. |
| Poisoned MCP server | `alert.raised` on its named rules | The alert names a connection. Disable the connection. |
| Rogue sub-agent | `alert.raised` on `pc.authority.self_issue` | Read the case and revoke the right grant. |
| Compromised laptop | `incident.opened`, HIGH or CRITICAL | Suspend the runs, rotate keys and check the machine. |
| Data-flow hold escalation | `action.held` with DATA_FLOW_HOLD | Decide the held action. |
| Offboarded owner | started by hand with the agent | Name a new owner. |

## Why none contains

A playbook may contain only a subject its real alerts carry, on a CONFIRMED alert (OBSERVED or RULE_MATCH). No built-in alert does that today:
- Leaked key and poisoned MCP server: their alerts name a key's instance or a connection, not a run. Revoking a key or disabling a connection is a person's action.
- Rogue sub-agent: its alert covers a refused delegation, a refused issue and a refused revision alike, and the trigger can't tell them apart. A refused revision names the grant the caller chose, possibly another agent's, so revoking the named grant could let an attacker choose whose grant is revoked.
- Compromised laptop: no built-in incident names a run, and an organization's own rule raises a CONFIRMED incident only for a version two people confirmed (HR-666). The playbook suspends nothing either way; a person does.

Containment comes back to the library when alerts carry the source event and the run where one exists.

## Install and enable

1. Install the item from the Hub. It makes a draft automation `hub-playbook-*` with no review date and no `authority.revocable`.
2. A person sets the review date, validates and enables it. Rollout starts wherever they choose.

## Details

- Data-flow hold escalation starts only when DATA_FLOW_HOLD is the hold's deciding reason. A hold that another approval requirement decides first carries DATA_FLOW_HOLD only among its other reasons, which the trigger can't read. It reminds approvers after 30 minutes, escalates, then waits up to 24 hours for a decision. It never decides.
- No playbook uses the `revoke_grant` step or publishes a policy. Offboarding drafts and simulates a restriction of unused grants and asks the owner to name a new owner.
- Each playbook ships tests for NORMAL, DENIED, TIMEOUT and DUPLICATE.
- The range run `TestRange_ScenariosPlaybooks` (part of `task range`) drives each signal playbook from the audit event the producing code writes, through the detection engine. It checks that every one opens its case and nothing is contained, revoked or suspended.
- Your own automations follow the same engine rule: a contain step runs only on a CONFIRMED alert ([behavior-profiles.md](behavior-profiles.md)).
