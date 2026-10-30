# Runbooks

Operational procedures. Each runbook is completed (from stub to tested procedure) in the milestone named in its header, and exercised at least once before v1.0.

| Runbook | Milestone | Purpose |
|---|---|---|
| [key-rotation.md](key-rotation.md) | M1 / M6 / M7 / M13 | Rotate signing keys, DEKs, KEKs, gateway broker keys and sealed credentials; the internal CA; the epoch bump after a restore |
| [gateway.md](gateway.md) | M6 | Enroll, renew, check and revoke gateways |
| [kill-switch.md](kill-switch.md) | M6 | Engage and restore the org-wide emergency stop |
| [sandbox.md](sandbox.md) | M9 | Run an agent in the containment sandbox, read its closures, apply its changes (patch only), clean up |
| [evidence-verification.md](evidence-verification.md) | M7 | Verify bundles and packs offline; investigate an evidence integrity failure and resume checkpointing |
| [anchoring.md](anchoring.md) | M7 | Turn on, watch and update the anchored global root (Rekor v2 and RFC 3161) |
| [retention.md](retention.md) | M7 | Set up the retention role and job; set retention periods, legal holds and payload capture |
| [coverage-records.md](coverage-records.md) | M9 | Read and explain coverage records, the freshness contract, exclusions and credential-overreach findings |
| [backup-restore.md](backup-restore.md) | M13 | Nightly encrypted backups, KEK escrow, the restore drill with measured RPO and RTO, a real restore |
| [incident-response.md](incident-response.md) | M10 | Alerts → incidents → cases → containment → restoration; a security incident in PantherClaw itself |
| [siem-export.md](siem-export.md) | M10 | Add, verify, watch and rotate OCSF 1.9 SIEM export destinations (Business) |
| [shared-signals.md](shared-signals.md) | M10 | Receive CAEP and RISC events from the IdP; the two-person identity playbook (Business) |
| [automations.md](automations.md) | M11 | Enable automations with the security-key ceremony; pause, resume, cancel, retire, revoke authority; the kill switch; inbound sources and destinations; a compromised publisher |
| [dmca-takedown.md](dmca-takedown.md) | M0 | Handle copies that violate the licence or trademark |
| [release.md](release.md) | M1 | Cut, verify and publish a release (G2/G3) |
| [workload-identity.md](workload-identity.md) | M3 | Enroll workloads, set up GitHub Actions and Kubernetes attestation, run pull-request bots safely |
| [github-app.md](github-app.md) | M8 | Connect a GitHub App: per-action installation tokens, sealing and rotating the App key |
| [github-live.md](github-live.md) | M8 | Run the manual, opt-in GitHub check against a sandbox org (`task test:github-live`) |
| [range.md](range.md) | M12 | Run the adversarial range: set up range agents and simulators, run scenarios, read reports, the baseline gate, `task range` |
| [stripe.md](stripe.md) | M14 | Connect Stripe in test mode with a restricted key; refunds, payment intents and transfers; the simulator and the live test (`task test:stripe-live`) |
| [postgres.md](postgres.md) | M14 | Connect a read-only Postgres role with a manifest; structured queries and aggregates; data scoping by record and class (Team) |
| [slack.md](slack.md) | M14 | Slack approval cards with a link button only (Team); agent posts with `pc.slack` and external-channel checks |
| [teams.md](teams.md) | M20 | Agent posts to Microsoft Teams with `pc.teams`: the bot, its pinned home tenant, external-channel checks |
| [authzen.md](authzen.md) | M14 | Register an AuthZEN enforcement point, wire your proxy, read decisions (`PARTIAL` routes) |
| [a2a.md](a2a.md) | M14 | Connect peer agents over A2A: pinned cards, drift quarantine, enrolled peers with delegated runs, the receiver helper |
| [frameworks.md](frameworks.md) | M14 | Wrap LangChain/LangGraph, OpenAI Agents SDK, CrewAI, Vercel AI SDK and MCP TypeScript tools; refusal codes and holds |
| [comp-plans.md](comp-plans.md) | UI | Grant and revoke complimentary plans from the operator command line (hosted deployments) |
| [billing-webhooks.md](billing-webhooks.md) | UI | Billing webhook failures: a stale plan, refused or out-of-order events; protection is never affected |
| [hosted-oidc-outage.md](hosted-oidc-outage.md) | UI | Hosted OIDC provider outage: sign-in is down, enforcement is unaffected |
| [deploy.md](deploy.md) | M13 | Deploy hosted staging (L3): host layout, sign-in through an SSH tunnel, deploy with a readiness wait and rollback, the G3 record, health and certificates |
| [observability.md](observability.md) | M13 | Export traces and metrics over OTLP/HTTP, the loopback admin listener, security-event log lines and `restore reapply` |
| [support-access.md](support-access.md) | M13 | Customer-approved support access (hosted, Enterprise) and break-glass (Business and above) |
| [data-requests.md](data-requests.md) | M13 | Export an organization, delete it with a 7-day window and a signed deletion record, the lapse lifecycle, account deletion |
| [installation.md](installation.md) | M13 | Verified releases with `install.sh`, a single node with `pclaw up`, the Helm chart, FIPS builds |
| [m13-exit.md](m13-exit.md) | M13 | Run the M13 exit journey: locally on every change, and once on hosted staging for the exit (`PC_E2E_STAGING_URL`) |
| [org-move.md](org-move.md) | M13 | Move the repositories to the GitHub organization: rewrite the module path, the repository links and the image names in one change (F8) |
