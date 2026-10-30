# ADR-0042 — Integrations breadth: Ed25519 webhooks, export destinations, target-confirmed rotation, connectors and ticket sync

**Status:** Accepted (2026-10-29; G0 M20 founder decisions G12–G15, answered with the recommended option each time; the [G0 M20 brief](../g0/M20.md) records them with the coordinator's design decisions D250–D280).

**Context.**
- **Webhooks.** Outbound webhooks are signed only with per-destination HMAC secrets (Standard Webhooks `v1,`), so every receiver holds a secret that could also forge deliveries.
- **Evidence.** Evidence packs, proof bundles and organization exports can only be downloaded by a person; nothing pushes them to the customer's storage.
- **Key rotation.** Rotating a GitHub App private key is a runbook. Nothing checks that the new key works before agents depend on it, or that the old key is really gone afterwards. GitHub offers no API to create or delete App keys.
- **Connectors.** They cover GitHub, Stripe, Slack and Postgres only. Customers on GitLab, Jira, Microsoft Teams and AWS have no governed route, and AWS needs SigV4 signing, which the gateway's header placement cannot express.
- **Tickets and approvals.** Incidents and cases do not reach the ticket systems teams work in, and approval notices reach people personally only by email.

**Decision.**
1. **Ed25519 webhooks** (G13; HR-510..512).
   - Each organization has one `webhooks` signing key, published in its own JWKS at `/.well-known/pantherclaw/orgs/{org}/webhook-jwks.json` with its ACTIVE and RETIRING keys.
   - A destination opts in (`hmac+ed25519`) and then receives `v1a,` next to `v1,`. HMAC stays the default and is always sent.
   - A rotated key verifies for 24 hours, then is gone. Inbound events stay HMAC.
2. **Export destinations** (HR-513..516; Business).
   - HTTPS PUT and S3-compatible destinations, modelled on SIEM destinations: step-up activation, egress guards, data-class filters, health.
   - They push packs, proof bundles and organization exports. Above 2 GiB, a push streams parts into a multipart upload, and the upload is always aborted on failure.
   - Every push leaves a delivery receipt. A retention removal after a push sends a signed removal notice and never claims the remote copy is gone.
   - SigV4 is implemented in-house.
3. **Target-confirmed rotation of the GitHub App key** (G14; HR-517..520).
   - A person seals the new key as a CANDIDATE. The gateway tests it at GitHub inside a lease, and the candidate is never in gateway configuration before that.
   - Activation is a Custody protected change with a step-up, and it requires a passed test.
   - Rollback is possible until confirmation starts or for 24 hours.
   - The old key is REVOKED only after the gateway sees GitHub refuse it. Until then the rotation stays open with a posture finding.
   - The server never holds either key (HR-060).
4. **Connectors** (G12; HR-521..526; Team).
   - The packages are `pc-gitlab`, `pc-jira`, `pc-teams` and `pc-aws`, each with facts and a simulator.
   - GitLab deploys are consequences under M17's verification model.
   - Customer-visible Jira projects and external Teams channels count as external disclosure.
   - Two new credential kinds:
     - `oauth_client` (Teams, through a Bot Framework bot): a token minted per dispatch and never placed raw.
     - `aws_sigv4`: the sealed base key is used only for a narrowed `sts:AssumeRole` session of at most 15 minutes, per dispatch.
   - Packages may declare a validated `coverage:` block, which never widens authority. The http mapping gains fixed headers and AWS encodings, set only by the signed package.
5. **Ticket sync with Jira** (G15; HR-527, HR-528; Business).
   - Sync runs through gateway leases, so the Jira credential stays sealed to the gateway.
   - Each field has one owner. PantherClaw owns state, severity, containment and restoration; Jira owns assignee, labels, its priority and comments.
   - An inbound change to a PantherClaw-owned field is dropped, entered and audited. A "Done" is only noted.
   - The sync actor holds no permission on response, restoration, approvals or the kill switch, and its package cannot import them.
   - A ticket status never restores authority.
6. **Approval channels** (HR-529).
   - Slack DMs go to eligible deciders whose Slack identity was found by a verified org-domain email and confirmed by the person. HR-315 gains `users.lookupByEmail`, `conversations.open` and the `im:write` scope.
   - Teams uses link-only Adaptive Cards through a `teams_app` channel activated with a step-up, never in a shared channel.
   - Both carry a link only and never take a decision.

**Consequences.**
- Receivers can verify webhooks with a public key. A destination that opts in still gets HMAC, so moving to Ed25519 never breaks a receiver.
- Evidence reaches customer storage with a provable record of each push. A removal after a push cannot reach the customer's copy, so PantherClaw says so instead of pretending.
- Rotation depends on a person deleting the old key on GitHub. An unconfirmed rotation stays visible instead of being closed on trust.
- Two new broker credential kinds and two mapping options widen the gateway's dispatch code, which the range and golden tests guard. AWS starts with ECS and IAM read only.
- Ticket sync adds a gateway lease purpose and per-field ownership. The ticket system becomes a place to work on incidents, never a way to change authority.
- Approval notices reach people where they work. The decision still happens only on the authenticated approval page.

**Alternatives.**
- Ed25519 instead of HMAC, or a key shared by every organization (breaks receivers; one org's key would verify another's deliveries).
- An AWS SDK dependency for S3 and the AWS connector (a large module tree for one signer).
- Raising the database-staged export cap instead of streaming.
- Activating a new key without a target test, or revoking the old key on the person's word.
- A server-held Jira token (an exception to HR-060).
- Letting a ticket status close a case or propose a restoration.
- Decisions inside Slack or Teams (not equivalent to the authenticated approval).
