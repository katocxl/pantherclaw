# Approvals: reaching the right person

How approval requests reach deciders beyond the approval page itself. The approval page (`<server URL>/approvals`) stays the only place where a person approves or declines, alone or as a batch (HR-175/176).

## M36: fatigue, deputies, digests, groups, Web Push and the editor

G0 M36; [ADR-0063](../adr/0063-telemetry-and-approval-reach.md); HR-789..794. Nothing in this section approves, declines or releases a hold: an unanswered hold stays held, then expires (HR-789).

### Approval fatigue (Team)

`ApprovalService.GetApprovalFatigue` shows, per decider, over 1 hour, 24 hours or 7 days: the peak approvals per hour, the median seconds from the first notice to approve, the approve share, approvals between 22:00 and 06:00 in the person's time zone (UTC when none is set) and the longest streak of approvals without a decline.

Every 15 minutes PantherClaw flags a decider when, in the last hour, they approved 30 or more requests, or their median time to approve was under 5 seconds over at least 10 approvals, or, in the last 24 hours, they approved every request over at least 50. The flag clears after 4 hours. It is audited as `approval.fatigue_flagged`, and the built-in detection `pc.approvals.fatigue` raises a MEDIUM alert (alert only).

With the org's fatigue routing set to ROUTE (the default), a flagged decider is routed and notified last: other eligible deciders first, the flagged person only at the final escalation step, or at an earlier step when every decider there is flagged, so no step goes untold. `ApprovalService.SetApprovalFatigueRouting` (permission `waitlist.manage`, audited) sets it to OFF to keep routing unchanged. A flag never changes who is eligible (HR-791).

### Deputies

A person going away names a deputy with `SetApprovalDeputy`: a start and an end at most 30 days later. Windows of the same person cannot overlap. The deputy must be an ACTIVE member with `approval.respond` and not the person. People with `waitlist.manage` can set a deputy for someone else. `CancelApprovalDeputy` ends it; `ListApprovalDeputies` lists them. Both are audited (`approval.deputy_set`, `approval.deputy_cancelled`).

During the window, a request routed to the person is also routed to the deputy, but only when the deputy is already eligible for that request. Otherwise the deputy is skipped and `approval.deputy_not_eligible` is audited. A deputy never becomes eligible because of the window (founder decision FQ36-3; HR-790).

### Preferences, digests and quiet hours

Each person sets their own preferences with `NotificationService.SetMyNotificationPreferences`:

- **Delivery:** IMMEDIATE (the default) or DIGEST every 15, 30 or 60 minutes.
- **Quiet hours:** a start and an end (HH:MM) in an IANA time zone.

Digests and quiet hours delay only that person's direct messages, pushes and emails. Routing and escalation to other deciders go on as before, so holds do not stall (HR-792). A digest is one `approval.digest` notification, "N approvals are waiting for you", with a link to the approval page.

### Approval groups

`ApprovalService.ListApprovalGroups` groups waiting requests by variant, agent, run or operation, with a count, up to 25 request ids and whether the group can be approved as a batch. It is read only: open the approval page to decide.

### Web Push (Team)

A person can receive approval notices on a browser or phone:

1. The client reads the deployment's public key from `NotificationService.GetWebPushKey`.
2. The browser subscribes with that key, and the client registers the subscription with `RegisterPushSubscription`. The endpoint must be https on a known push service (`fcm.googleapis.com`, `updates.push.services.mozilla.com`, `notify.windows.com`, `web.push.apple.com`).
3. `ListMyPushSubscriptions` and `RemovePushSubscription` manage them. A push service that answers 404 or 410 removes the subscription.

A push carries only a title ("Approval waiting" or "N approvals waiting") and the approval page link, encrypted to the subscription (HR-793). The push service still sees when a notice is sent (R-90). The installable console app comes in M40.

The VAPID key (key purpose `web_push`) is one per deployment. Operators set the contact sent in the VAPID token (`mailto:` or a URL) as `notifications.web_push_subject` in the server configuration; without it the server's public URL is sent.

### The VS Code extension

Developers can see their agent's waiting approvals, coverage and recent decisions in VS Code through `integrations/vscode-extension/` (founder decision FQ36-4; HR-794). It runs the signed-in `pclaw` on the machine and holds no token:

```bash
pclaw login --server https://pantherclaw.example.com --org ORG_ID
pclaw editor status --agent AGENT_ID --json
pclaw editor open approval APPROVAL_ID
```

Set `pantherclaw.agent` in VS Code (or write the agent id to `.pantherclaw/agent` in a trusted workspace) and, when pclaw is not on PATH, the machine setting `pantherclaw.pclawPath`. **Open in console** opens the approval page in the browser. The extension has no approve, decline or edit action.
