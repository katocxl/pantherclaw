# Slack: approval cards and agent posts

**Milestone:** M14 ([G0 M14](../g0/M14.md) D22–D25; [ADR-0028](../adr/0028-business-connectors-and-data-scoping.md)). **Audience:** an Org Admin setting up Slack. Command flags below follow the brief; the M14 exit status records any change.

Slack is used in two independent ways:
- **Approval cards** (`slack_app` notification channel, Team edition): PantherClaw posts a card when an approval is pending and closes it when the request ends. **Nothing is decided in Slack** (HR-313): the card's only control is a link to the authenticated approval page.
- **Agent posts** (`pc.slack` package, Community): agents post messages to allowed channels, decided by the gateway like any other action (HR-316).

Use **two different Slack apps** (or at least two bot tokens) for the two: the approval bot belongs to PantherClaw's server, the agent bot to a gateway connection.

## 1. Create the Slack app for approval cards

At api.slack.com/apps, **Create New App → From scratch** in your workspace:
1. **OAuth & Permissions → Bot Token Scopes:** `chat:write`, plus `channels:read` (public channels) or `groups:read` (private channels). Nothing else.
2. **Interactivity & Shortcuts: leave it off.** PantherClaw has no Slack inbound endpoint; buttons are plain links.
3. Do not enable Event Subscriptions or slash commands.
4. Install the app to the workspace and copy the **Bot User OAuth Token** (`xoxb-…`) into a file outside the repository.
5. Invite the bot to the approvals channel (`/invite @<bot>`). Use an **internal** channel: externally shared (Slack Connect) channels are refused.

## 2. Add the channel to PantherClaw

Adding the channel takes two steps (HR-315). First, create it; it is stored PENDING_ACTIVATION, with the token sealed:

```bash
pclaw channel create approvals-slack --kind slack_app --slack-channel <channel id, e.g. C0123456789> \
  --data-level minimal --bot-token-file slack-bot.token
```

Delete the token file afterwards. While the channel is pending it receives nothing, routing skips it, and an update cannot unpause it.

Then an Org Admin with `notification.manage` opens `https://<pantherclaw public url>/notifications/channels/<channel id>/confirm` in the browser and touches their security key. The page calls `auth.test` and `conversations.info`, shows the workspace, bot and channel it found (the channel must exist, the bot must be a member, and the channel must not be externally shared), and activates the channel on confirmation. The channel checks run on this page, not at create time. If the channel's configuration changed after the page was shown, the confirmation is refused: reload and check again. Cards are posted only for approval requests created after activation; older pending requests get no card.

The token is never logged and is sent only to `chat.postMessage`, `chat.update`, `auth.test` and `conversations.info` on `https://slack.com/api`. To replace it, update the channel with the new token file (never type a token into a web form); the channel goes back to PENDING_ACTIVATION and stops delivering until it is confirmed again on the same page. The new token must belong to the same Slack workspace; for another workspace, create a new channel. The reconciler also re-checks the channel: if it becomes externally shared, it returns to PENDING_ACTIVATION and the admins are told.

Subscribe the channel to escalation steps exactly like an email or webhook channel; there is no separate Slack routing.

## 3. What a card shows

| Data level | Fields |
|---|---|
| `minimal` (default) | "Approval needed", request kind, consequence level, expires at, short request id |
| `summary` | the above plus the operation id (for example `payments.refund.create`), the agent display name and the environment; never a rendered template title |

Never parameters, amounts, the principal, untrusted text or approver identities (HR-314). Channel members can still see this metadata (R-46): choose the channel accordingly.

Lifecycle: the card is posted when the request is PENDING, at most once per request and channel (a card row is claimed before posting; if Slack's answer is lost the card is marked UNKNOWN, shown in delivery health, and never reposted: the approval page is authoritative). A reconciler runs every minute and updates every open card whose request reached a final state (approved, declined, expired, invalidated, cancelled, superseded or voided) to a closed card ("Approved", "Declined", …) without the button and without names, including after an edition downgrade; it handles cards of active channels only, oldest first, and a card whose close fails five times with a permanent Slack error (`invalid_auth`, `account_inactive`, `token_revoked`, `channel_not_found`, `not_in_channel`, `message_not_found`, `is_archived`) becomes ORPHANED and shows in delivery health; transient errors (429, timeouts, 5xx) are retried with backoff and never orphan a card. When a request reopens, the old card is closed before the new one posts. An escalation adds a thread reply "Escalated (step n)". Deliveries use the normal queue with retries (Slack's 429 `Retry-After` is honoured). A failed delivery never approves, declines or expires anything.

Reactions, replies and anything posted to the server count for nothing. To approve, open the link and decide on the approval page with your security key.

## 4. Agent posts with `pc.slack`

| Operation | Call | Notes |
|---|---|---|
| `slack.message.post` | `chat.postMessage`, form-encoded (`channel`, `text`, optional `thread_ts`, and always `unfurl_links=false`, `unfurl_media=false`, so Slack fetches no links) | irreversible; `text` is a `content` parameter under disclosure limits, at most 4000 bytes; `ok: true` required |
| `slack.channel.read` | `conversations.info` | read |

Set up a second Slack app for the agent (scope `chat:write`, plus `channels:read`/`groups:read` for the external-channel fact), then:

```bash
pclaw connection create slack --kind http --gateway <gateway id> --package pc.slack --base-url https://slack.com/api \
  --access pantherclaw_held --header Authorization --scheme Bearer --default-mode enforce
pclaw seal --connection <connection id> --from-file agent-bot.token --fingerprint <broker key fingerprint>
```

The token must match `^xoxb-[A-Za-z0-9-]{20,}$` or nothing is sent. Every grant (or envelope) for posts must carry a destination bound listing the channel ids; without one, a post is DENIED `DESTINATION_SET_REQUIRED`. Before each post the gateway reads whether the channel is externally shared (`slack.channel.external`, at most 300 s old); a post there is an `external_disclosure` consequence, which the internal-analysis and research-disclosure templates deny. The internal-analysis and research-disclosure templates take the agent and channels with `pclaw template apply … --agent <agent> --slack-channel C…` (`--agent` required, because their Slack rules apply per agent; `--slack-channel` repeatable); other channels are forbidden (`SLACK_CHANNEL_NOT_ALLOWED`), and an unread external-channel fact fails closed.

## 5. Development

`pantherclaw-sim slack` serves the four methods with a Bearer check, flags for externally shared and not-in-channel channels, and faults (429, `invalid_auth`, `channel_not_found`); `GET /__sim/messages` lists what was posted. A loopback base URL is accepted only in dev and tests. The card lifecycle is tested in Team integration tests with the simulator and the real approvals service; `TestE2E_M14_SlackApprovalCards` (Community) checks the edition refusal, that no Slack inbound route exists, and `pc.slack` posts. Range scenario RT-045 forges approvals through Slack with the simulator changes `reaction`, `reply` and `interaction_post` (a forged `block_actions` payload to every plausible interaction path) and expects the request to stay PENDING; RT-046 covers exfiltration.

## 6. Troubleshooting

| Symptom | Cause | Action |
|---|---|---|
| Channel create refused: external | The channel is shared with another organization | Use an internal channel |
| Channel create refused: not in channel | The bot was not invited | `/invite @<bot>` and retry |
| `EDITION_REQUIRED` | Slack approvals need Team | Apply a Team licence |
| Delivery failing `invalid_auth` | The token was revoked or rotated | Replace the token (step-up) |
| An agent post FAILED with a Slack error code | Slack answered `ok: false` | Read the code (for example `not_in_channel`) and fix the channel |
