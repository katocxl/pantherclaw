# PantherClaw — Product Components, Positioning and First Market

**Status (2026-10-09):** **Accepted** by the founder: component brand names (§3), first market and delivery order ([ADR-0017](adr/0017-coding-agents-first-and-proven-coverage.md)), identity federation ([ADR-0018](adr/0018-federated-workload-identity-and-represented-principals.md)), standards at the edges ([ADR-0019](adr/0019-standards-at-the-edges.md)), one product sold in editions, and the pricing unit (§7). **Open:** licence wording for the pricing unit and trademark clearance (§9).

This document says how PantherClaw is explained, demonstrated and sold to security teams. It groups the 20 pillars of [FEATURES.md](FEATURES.md) into seven product components that an IT administrator can recognise. It never changes product behaviour: FEATURES.md, ARCHITECTURE.md and PAP/1 stay authoritative for what is built. Where it conflicts with "Where customers start" in the reference specification (§2), this document wins. Everything here is planned scope, not a claim that it is built.

## 1. Positioning

**Category:** agent transaction firewall (reference specification §2).

**One line:** PantherClaw verifies which AI agent is acting and for whom, gives it only the access its current task needs, and puts its actions behind a firewall that proves, route by route, where it cannot be bypassed, with evidence your auditors can check.

**The question the whole product is designed around** (incumbents answer parts of it; we make all of it the unit of design):

> Can this agent run perform this action, for this task, through this route, right now — and can we prove the boundary held?

**Works with, never replaces.** PantherClaw is not an identity provider, a secrets vault, an agent builder, a log warehouse or a prompt filter (FEATURES "Product boundaries"). People keep signing in through Okta, Entra ID or Google. CI and Kubernetes keep issuing workload identities. SIEMs keep the logs. PantherClaw connects those identities to an exact task and action, and enforces the boundary.

**How not to pitch it.** Never "we combine five vendors' products". That invites a feature-by-feature comparison with five mature roadmaps. Pitch one promise: verified identity, task-bound access and an enforced boundary, proven per route.

## 2. The operating loop

Security teams use PantherClaw as a loop. Each stage is one or two components.

| Stage | What the team does | Components |
|---|---|---|
| **Know** | Find every agent, give it an owner, verify it | Badge |
| **Grant** | Give each task just enough access; set org rules and limits | Pass · Guardrails |
| **Enforce** | Route every consequential action through a checkpoint; keep keys away from agents | Checkpoint · Stash |
| **Respond** | Spot trouble, see the blast radius, stop it, recover | Reflex |
| **Prove** | Show what was authorised, sent and achieved, and that controls held under attack | Trail |

Findings from Respond and Prove feed back into Grant: unused access is removed, policies are tightened, bypass routes are closed.

## 3. The seven components at a glance

Naming follows one rule: a short brand word the admin remembers, always shown with its tagline and, where needed, the plain category it belongs to ("PantherClaw Checkpoint — control every action", an agent firewall). Brand names chosen by the founder on 2026-10-09.

| Component | Tagline | Category | Question it answers | Main owner | Pillars | Main milestones |
|---|---|---|---|---|---|---|
| **Badge** | Know every agent | Agent identity | Which agents do we have, who is accountable, and is this request really from that agent, acting for whom? | IAM / platform | 1, 2, 3, 4 | M3 |
| **Pass** | Grant temporary access | Task-scoped access and approvals | Who allowed this agent to do what, on which resources, for which task, until when? | Agent owners, IAM, business approvers | 5A, 7 | M4, M5 |
| **Guardrails** | Set the boundaries | Policy and limits | What may agents never do, what limits apply across a task, and what changes if we tighten a rule? | Security engineering | 5B, 5C, 8 | M4, M11 |
| **Checkpoint** | Control every action | Agent firewall | Does every route from this agent to our systems go through the checkpoint? | Platform / security engineering | 6A, 6C, 6D, 16 | M4, M6, M8, M9 |
| **Stash** | Keep credentials safe | Credential custody | Which secrets can each agent reach, and could it use them outside the firewall? | IAM / PAM / platform | 6B | M6, M8 |
| **Reflex** | Stop threats instantly | Detection and response | What happened, under whose authority, what else can this agent reach, and is it stopped? | SOC / incident response | 9, 10, 11, 12, 13, 14 | M6, M7, M10 |
| **Trail** | Prove what happened | Evidence and assurance | Who authorised what, what was sent, what actually happened, and did controls hold? | GRC, audit, security leadership | 15, 17 | M7, M12 |

**Root — Manage it all** (the platform, included with every component, not sold separately): Governed Automations (5D), Deployments (18), Performance (19) and Management (20).

Two features sit in a different component from their pillar, because that is where buyers look for them: the containment sandbox (PN-008.1, pillar 10) belongs to **Checkpoint**, and credential-reach findings (F048, pillar 2) belong to **Stash**.

**Claim boundary for "instantly":** Reflex's tagline is marketing shorthand. The real promise is a performance target, not a guarantee: containment reaches every gateway in under 1 second at p99 (PN-011.3), with gateways failing closed after 2 seconds without a heartbeat; requests already dispatched complete (ARCHITECTURE §15–16). Contracts, security questionnaires and technical documents state the measured figure, never "instant" (F801).

## 4. Components in detail

Each component lists what an administrator does with it, the result they can show their manager or auditor, what it works with, and who else sells something similar. Competitor notes come from an October 2026 market review whose vendor claims were not independently verified.

### 4.1 Badge — "Know every agent" (agent identity)

- **What you do:** find shadow agents on laptops and in GitHub (`pclaw scan`, organisation scan); claim each one and assign an owner and a backup; admit new agent instances, either by confirming a key fingerprint or automatically from a trusted CI or Kubernetes identity; retire agents and review the access they leave behind.
- **What you can show:** the share of active agents with an owner and a verified identity, the verification level of each, and the shadow agents found and resolved.
- **Works with:** your identity provider for people (Okta, Entra ID, Google, any OIDC); GitHub Actions and Kubernetes for workloads (M3); GitLab CI, cloud workload identity, SPIFFE and Microsoft Entra Agent ID as further presets (PN-002.3, Next). A service that starts a run for a signed-in user proves that user with the user's own identity-provider token (PN-002.8, M3).
- **Inside:** Inventory, Discovery, Lifecycle, Identity & Authority Protocol (PAP/1).
- **Similar offerings:** Microsoft Entra Agent ID, Okta/Auth0, CyberArk, Astrix, Aembit. **Our difference:** we don't run another directory. We bind the identities you already have to each individual run and to the exact actions it takes.

### 4.2 Pass — "Grant temporary access" (task-scoped access and approvals)

- **What you do:** issue task grants from templates ("fix this repository: read, branch, open a pull request; merging needs a reviewer"); handle access requests instead of switching guardrails off; approve exact actions, with a security key for high-consequence ones; inspect the delegation chain when an agent hands work to a sub-agent.
- **What you can show:** no standing agent privileges; every grant has an accountable grantor and an expiry; approvals cover one exact action and lapse when anything material changes; time to decision.
- **Works with:** approvals through the API, the CLI and the approval page first, Slack approval cards with a link to the approval page, never a decision in Slack (M14, Team); WebAuthn security keys and passkeys.
- **Inside:** Task grants & delegation, Agent Waitlist (approvals, access requests, step-up).
- **Similar offerings:** Keycard, Descope, Auth0 asynchronous authorisation, CyberArk just-in-time access, Permit.io consent flows. **Our difference:** grants belong to a run that only PantherClaw can create; a sub-agent can only receive a narrower grant; approvals are bound to the exact action and die on any material change.

### 4.3 Guardrails — "Set the boundaries" (policy and limits)

- **What you do:** start from templates (coding to production, support, refunds, diagnostics, release); set budgets, counts, rates and sequences ("no external message after reading customer data in the same task"); test a policy and simulate it against recorded activity before enforcing it; roll it out to a pilot group first; grant exceptions that expire.
- **What you can show:** every decision explained by the exact rule and value that decided it; zero overspend under concurrent agents; each policy change simulated before publication.
- **Works with:** OPA as an extra, restrict-only check ([ADR-0004](adr/0004-cel-policy-engine.md)); gateways you already run, registered as enforcement points, which ask for decisions through OpenID AuthZEN with the agent's own proof (PN-023, M14; those routes count as Partly protected); data scoping of reads by record and data class (M14, Team); trusted external facts and risk signals (F366, Next).
- **Inside:** Decision pipeline & policy engine, Policy lifecycle, Agent Controls.
- **Similar offerings:** AWS AgentCore policies, Cerbos, Permit.io, Pomerium, OPA. **Our difference:** limits are reserved atomically across parallel runs and sub-agents; missing evidence gives "Cannot authorise", never a guess; the same rule applies whether the agent uses MCP, a direct API or a hook (F099).

### 4.4 Checkpoint — "Control every action" (agent firewall)

- **What you do:** put the gateway in front of MCP servers and APIs; install the Claude Code or Agent SDK integration; run agents in the containment sandbox, whose only network route is the gateway; review what each tool really does (tool packages); switch routes from Watching to Enforced; read the coverage card for each agent.
- **What you can show:** the protection level of each agent and route (§5), with its expiry date, and the bypass routes closed.
- **Works with:** any MCP client (spec 2026-07-28 and 2025-11-25), REST APIs, Claude Code and the Claude Agent SDK, LangChain/LangGraph, the OpenAI Agents SDK, CrewAI, the Vercel AI SDK and the MCP TypeScript SDK (M14), Python/TypeScript/Go SDKs, Stripe (test mode), Postgres and Slack as reviewed connectors (M14), other agents over A2A (M14), and target-side verifier middleware for your own services.
- **Inside:** Gateway & dispatch, Connections & connectors, Reviewed tool packages, Coverage & Bypass Resistance, plus the containment sandbox.
- **Similar offerings:** Pomerium, Permit.io, Aembit and agentgateway MCP/HTTP gateways; AuthZed SpiceBox and Astrix hooks for coding agents; the sandboxes built into coding agents. **Our difference:** the gateway forwards exactly what was authorised (it rebuilds the request), commits each dispatch on the server, labels cooperative routes honestly as Partly protected, and proves route closure with probes that expire.

### 4.5 Stash — "Keep credentials safe" (credential custody)

- **What you do:** seal target credentials into the gateway (`pclaw seal`); replace personal access tokens and SSH keys with per-action GitHub App tokens; compare what each credential can do with what the task needs; revoke or rotate with a preview of who depends on it.
- **What you can show:** no reusable secrets in agent processes for covered targets; credential-overreach findings closed.
- **Works with:** GitHub App installation tokens first (M8), Stripe restricted test keys (M14; live keys refused), Postgres read-only roles and Slack bot tokens (M14); enterprise vaults as credential sources later (a `KeyProvider`-style adapter, recorded in [UPGRADES.md](UPGRADES.md) when scheduled).
- **Inside:** Credential custody (access modes, sealed credentials, access-source inspection, revocation completeness), credential-reach findings.
- **Similar offerings:** CyberArk, Aembit, Arcade, Keycard, HashiCorp Vault. **Our difference:** a credential is opened only for an authorised, committed action and never reaches the agent, and we don't need to become your vault.

### 4.6 Reflex — "Stop threats instantly" (detection and response)

- **What you do:** work the operations queue; inspect a run end to end; see the breach radius (what happened vs what grants allow vs what raw credentials allow); suspend one run, agent, grant or connection; engage the org kill switch, which needs two people to restore; send events to your SIEM; restore access through a reviewed workflow.
- **What you can show:** time to contain; containment confirmed per route rather than assumed; incidents closed with evidence.
- **Works with:** SIEMs via OCSF 1.9, SOAR tools, Slack and signed webhooks; your identity provider's Shared Signals (CAEP/RISC) events, so a disabled user or revoked session reaches that person's agent grants (PN-024, M10).
- **Inside:** Sessions, Containment, Monitoring, Threat Detection, Investigation, Breach Radius.
- **Similar offerings:** CrowdStrike (with SGNL), Astrix, Pomerium. **Our difference:** responses act on authority itself (grants, runs, credentials, connections) and confirm each route, instead of only raising alerts.

### 4.7 Trail — "Prove what happened" (evidence and assurance)

- **What you do:** open the three receipts for any action (decision, execution, effect); verify them offline with `pclaw verify`; replay a decision under a proposed policy; export evidence packs; run the red-team range against your own policies and fail CI when a change lets a blocked attack through.
- **What you can show:** signed, chain-verified evidence anchored in a public transparency log; red-team assurance reports; unknown outcomes reconciled rather than hidden.
- **Works with:** auditors' own tooling (open PAP/1 receipt format, Apache-2.0 verifier), Sigstore Rekor, OpenTelemetry for operations data.
- **Inside:** Proof, Adversarial Sandbox (red-team range).
- **Similar offerings:** Pomerium's attested audit trails; SIEM and log platforms. **Our difference:** decision, execution and effect are separate records; tested-control reports never claim compliance certification.

## 5. Protection and verification levels in plain language

The API keeps the four coverage states of invariant 10 and the attestation levels of PAP/1. Customer-facing text uses these names:

| Admin sees | Coverage state | Typical setup | Market term |
|---|---|---|---|
| **Not covered** | `UNKNOWN` | Nothing connected for this route | — |
| **Watching** | `OBSERVE_ONLY` | Monitor mode, discovery | Observed |
| **Partly protected** | `PARTIAL` | Gateway on some routes; hooks or SDK calls without credential custody | Integrated |
| **Enforced** | `ENFORCED` | Every material route mediated or proven blocked (sandbox probes, custody, target verifier), with an expiry | Constrained / Verified |

| Admin sees | Attestation level |
|---|---|
| **Owner-confirmed** | L1: enrollment token plus owner fingerprint confirmation |
| **Platform-verified** | L2: a workload token from a trusted issuer (GitHub Actions, Kubernetes, then further presets) |
| **Infrastructure-attested** | L3: SPIFFE X.509 SVID or cloud instance identity (Next) |

Setup alone never earns "Enforced" (F460), and "Enforced" downgrades automatically when its evidence expires.

## 6. First market: coding and DevOps agents

**Decision:** [ADR-0017](adr/0017-coding-agents-first-and-proven-coverage.md). Refunds and support remain the engine's test harness and the second market.

**Who buys:** platform-engineering and security teams at companies where coding agents (Claude Code, the Claude Agent SDK, CI agents) read private repositories, run shell commands, call MCP servers and APIs, open pull requests and can reach deployments.

**Why they buy:** the agents hold personal access tokens and SSH keys, a hook can be skipped, and nobody can show an auditor who approved the merge that shipped to production.

**First 30 minutes** (F335 target, measured, not guaranteed):

1. `pclaw up` starts a local node; `pclaw init` finds Claude Code and the MCP configurations.
2. The agent enrols. The owner confirms its fingerprint; a CI agent can instead be admitted automatically by its GitHub Actions identity.
3. Apply the "coding to production" template: read, branch and open pull requests freely; merging needs an independent reviewer; a deployment consequence needs a release approver.
4. Connect the GitHub App and remove the personal access token.
5. `pclaw sandbox run` the agent. The coverage card shows the repository routes as Enforced.
6. Guided tests: one allowed action, one held for approval, one blocked.

**Flagship demo — "three routes, three stops":**

1. The agent tries to merge through the GitHub MCP server without a reviewer. Policy holds it for an approval.
2. It tries the same merge with a direct `curl` to the GitHub API. The sandbox's only route out is the gateway, which maps the request to the same action and returns the same decision (F099).
3. It pushes with a personal access token or SSH key it found. The sandbox holds no reusable credentials and its egress is closed, so the push fails, and probe evidence shows the route closed.

Each attempt produces a signed receipt that `pclaw verify` checks offline. This is the v0.1.0 preview exit (BUILD_GUIDE §8).

**Open question:** coding agents ship their own sandboxes. A vendor sandbox could count as the containment boundary if the same closure probes can run inside it and verify it (F454). That needs design work and is not committed.

## 7. How PantherClaw is sold (accepted 2026-10-09)

1. **One product, one licence.** The components are how we explain, demonstrate and navigate PantherClaw. They are not separate products at launch. The value is the whole loop, and selling parts invites point comparisons.
2. **Editions gate scale, retention, integrations and enterprise operations, never safety** (unchanged from FEATURES "Editions at a glance"). Every edition gets the full loop for its agent limit.
3. **Depth per component by edition**, derived from the edition column of FEATURES.md:

| Component | Community (≤ 5 agents) | Team | Business | Enterprise |
|---|---|---|---|---|
| Badge | Inventory, local scan, PAP/1 L1/L2, lifecycle | + GitHub organisation scan | — | + SCIM, multi-org, federation presets (PN-002.3) |
| Pass | Grants, delegation, approvals with WebAuthn, waitlist | + batch review, SLA metrics, Slack approvals | — | — |
| Guardrails | CEL policy, templates, budgets and limits, policy tests | + historical simulation, shadow and pilot rollout | + external facts and signals (Next) | — |
| Checkpoint | Gateway (MCP, HTTP), sandbox, coverage, Claude Code integration | + customer-defined actions, meaning workbench | — | — |
| Stash | Sealed credentials, access modes, GitHub App tokens | — | — | — |
| Reflex | Core detections, graduated containment, kill switch, search | + cases, breach radius | + advanced and custom detections, OCSF export, SOAR | — |
| Trail | Signed receipts, `pclaw verify`, replay, community scenarios | + transparency anchoring, evidence packs, assurance reports, CI gate | + full scenario library | — |
| Root (platform) | Self-hosted single node; CLI and API | + governed automations; the hosted control plane and web console (from v1.0) | — | + FIPS build, HA, hybrid fleet, customer-approved support access |

4. **Pricing unit: one agent record counts once, and each edition includes an allowance of running instances.** One accountable agent, such as "Claude Code, engineering" with an instance on every developer laptop and CI job, counts as one governed agent until its instances exceed the edition's allowance. This matches the accountability model (F574) and avoids per-seat pricing. Follow-ups:
   - **Licence wording.** The BSL Additional Use Grant defines an Agent as any distinct "software agent, automated workload, automation, or execution identity". Read literally, every running instance counts toward the Community limit of 5. Aligning the grant with this decision needs an amendment for future versions ([ADR-0007](adr/0007-licensing-bsl-apache-split.md)) and, ideally, legal review. Until it is amended, the licence text governs.
   - **Allowance numbers** per edition are not set yet.
   - **Hosted plans** (G0 UI, 2026-10-20): on the hosted control plane each organization holds a plan, paid through a merchant-of-record payment provider. A lapsed plan never turns protection off: gateways keep enforcing, safety actions keep working, and evidence stays readable and exportable for at least 30 days (retention after a lapse is decided in M13). Complimentary plans exist only with hosted billing and never override a self-hosted licence.
   - **Metering:** `internal/billing` limits today count agents only (`MaxAgents`); the instance allowance is a field of the per-organization plan limits delivered in milestone UI (PN-012.2); metering against it beyond agent counts follows in M13.

## 8. Competitive map

From the October 2026 review (14 vendors; claims as reported, unverified). The component column shows where each one overlaps PantherClaw.

| Vendor | Approach | Overlaps | Where PantherClaw differs |
|---|---|---|---|
| Permit.io | Policy-first MCP and HTTP egress gateway with consent | Guardrails, Checkpoint | Atomic task budgets, server-side dispatch commit, proven coverage |
| Aembit | Identity-first credential gateway | Badge, Stash | Task-bound authority and per-route enforcement evidence |
| Arcade | Tool-execution runtime with managed OAuth | Stash, Checkpoint | Independent security layer around any runtime, including Arcade |
| Pomerium | Zero-trust ingress and egress proxy, attested audit | Checkpoint, Trail | Exact re-serialised dispatch, effect receipts, red-team proof |
| Keycard | Distributed authorisation and credential brokering | Pass, Stash | Complete mediation and sequence-aware limits |
| AWS AgentCore | Cedar gateway policies, temporal limits | Guardrails | Cross-cloud and outside AgentCore's trust boundary |
| Cerbos + agentgateway | Separate decision (Cerbos) and enforcement (Envoy ext_authz) | Guardrails | Native identity, custody, containment and lifecycle |
| CrowdStrike / SGNL | Continuous identity and business-context authorisation | Badge, Reflex | Developer adoption, vendor neutrality, demonstrable enforcement |
| AuthZed SpiceBox | SpiceDB permissions plus local sandbox for coding agents | Checkpoint, Guardrails | Not tied to one agent; custody, approvals and evidence |
| Descope, Okta/Auth0 | Agent-aware identity, consent, token vaults | Badge, Pass | Integrate with them; we enforce what the workload executes |
| Microsoft Entra Agent ID | Agent identities, sponsors, lifecycle | Badge | Federate with it; enforce outside Microsoft environments |
| CyberArk | PAM for agents, just-in-time access | Stash, Pass | PAM principles applied per task and per action |
| Astrix | Discovery, posture, hook-based blocking | Badge, Reflex | Mediation that cannot be skipped, with route-closure evidence |

Strategic threats to watch: CrowdStrike/SGNL and Microsoft for enterprise agent identity. Vendors to study while building the first version: Permit.io, Keycard, Pomerium, AuthZed/SpiceBox and AWS AgentCore.

## 9. Open decisions

| # | Decision | Status |
|---|---|---|
| 1 | Brand names for the seven components and the platform | Accepted 2026-10-09: Badge, Pass, Guardrails, Checkpoint, Stash, Reflex, Trail; Root for the platform (§3) |
| 2 | Sell as one product with editions, not separate component SKUs | Accepted 2026-10-09 (§7 items 1–3) |
| 3 | Pricing unit for coding agents | Accepted 2026-10-09 (§7 item 4) |
| 4 | [ADR-0019](adr/0019-standards-at-the-edges.md): AuthZEN endpoint, Shared Signals receiver | Accepted 2026-10-09 |
| 5 | Amend the licence's Agent definition and set per-edition instance allowances | Open (§7 item 4) |
| 6 | Trademark clearance for the component names before any marketing spend ([UPGRADES.md](UPGRADES.md) "Trademark") | Open. Highest risk: **Checkpoint** (Check Point Software sells firewalls, the same class of goods) and **Guardrails** (Guardrails AI, and widely used generically by AWS, NVIDIA and others, so weak as a mark) |
