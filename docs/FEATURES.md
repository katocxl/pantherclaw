# PantherClaw — Product Features (revised)

PantherClaw is an AI Agent Identity & Runtime Authorization Firewall. It gives every agent workload a verifiable identity and binds each consequential action to an explicit task grant and a deterministic policy decision. It routes that action through a gateway that dispatches only what was authorized, and keeps signed, independently verifiable evidence of what was decided, what was dispatched and what actually happened. This document turns all 802 catalog requirements (F001–F802) into consolidated, testable backend capabilities grouped into 20 commercially framed pillars, which roll up into seven product components ([PRODUCT.md](PRODUCT.md)). It also adds new PantherClaw features (PN-001–PN-026) and the web console, hosted-account and plan rows F803–F830 of milestone UI. Version 1.0 is a Go backend with a Connect-RPC API and the `pclaw` CLI, plus the web console of milestone UI. Each backend row states what the backend must deliver, and the console exposes it. Everything here is planned scope, not a claim that the behaviour is built. Behaviour detail lives in the catalog ([`reference/PantherClaw_Feature_Catalog_F001-F802.md`](reference/PantherClaw_Feature_Catalog_F001-F802.md)), [`ARCHITECTURE.md`](ARCHITECTURE.md) and [`protocol/PAP-1.md`](protocol/PAP-1.md); where they are more specific, they take precedence.

## How to read this

Each pillar table has the columns `ID | Feature | What the backend delivers | Phase | Edition | Milestone | Source`.

**Phase**

- `MVP`: in v1.0 (milestones M1–M14 and UI, delivered in the order given below the milestone table).
- `Next`: planned after 1.0.
- `Later`: wanted, but not scheduled.

**Edition** (the lowest edition that includes the row; each higher edition includes everything below it)

- `Community`: the public, BSL 1.1-licensed core. Free production use for ≤ 5 governed agents in 1 organisation, with no hosted, embedded or competing offering.
- `Team`, `Business`, `Enterprise`: unlocked by Ed25519-signed licence keys. Enterprise-only code lives in the private `pantherclaw-enterprise` repository.
- The PAP/1 spec, verifier libraries, SDKs and the Claude Code integration are Apache-2.0 whatever the edition.

**Milestone**

| Milestone | Scope |
| --- | --- |
| M1 | Platform |
| M1.5 | Walking skeleton |
| M2 | Tenancy & service auth |
| M3 | Agents & PAP/1 identity |
| M4 | Authority core: tool packages, ActionIR, grants, budgets, CEL policy engine, decision pipeline |
| M5 | Human approvals, WebAuthn step-up, Agent Waitlist |
| M6 | Gateway: MCP proxy, HTTP proxy, credential broker, dispatch, kill switch, monitor/enforce modes, Claude Code hook |
| M7 | Effects, reconciliation, evidence ledger, replay, packs |
| M8 | Coding-agent integrations: Go SDK and target verifier, core Python and TypeScript clients, Claude Agent SDK, GitHub App connector, `pclaw init` |
| M9 | Coverage & containment sandbox |
| M10 | Detection, investigation, response, breach radius, SIEM (OCSF), search |
| M11 | Policy lifecycle & automations (part 2: automations) |
| M11.1 | Policy lifecycle (M11 part 1): staged publication with scenario tests, validation and diffs, simulation, shadow and pilot rollout, rollback, exceptions, three task templates |
| M12 | Adversarial red-team range |
| M13 | Commercial & production hardening |
| M14 | Framework SDKs & business connectors (framework wrappers, Stripe test mode, Slack, Postgres) |
| UI | Web console, hosted accounts, self-serve organizations, per-organization plans, onboarding, website and interactive demo ([G0 UI](g0/UI.md)) |
| post-1.0 | Not yet scheduled to a milestone |

Milestone numbers are identifiers, not delivery order. Delivery order ([ADR-0017](adr/0017-coding-agents-first-and-proven-coverage.md)): M1 … M9, M12, then the v0.1.0 preview, then M11.1, M10, M11, M14, UI, M13 and v1.0 (UI moved ahead of M13 by the founder on 2026-10-20).

**Component**

Every pillar belongs to one of seven product components (Badge, Pass, Guardrails, Checkpoint, Stash, Reflex, Trail) or to Root, the platform. Each pillar heading names its component. The components are how PantherClaw is explained and sold; they change no behaviour. See [PRODUCT.md](PRODUCT.md).

**IDs**

- A row that consolidates catalog features uses the lowest F-ID it consolidates as its row ID. Its Source cell lists every F-ID it realises; ranges such as `F471–F479` are inclusive.
- New features are numbered `PN-###`. Rows that are parts of one new feature carry a dotted suffix (`PN-002.4`).
- A PN row's Source lists the catalog F-IDs it helps realise, or `new` when there is no catalog counterpart.

**Coverage language**

- Protection claims are always scoped to a workload, target, effect and set of routes, and they expire: `UNKNOWN`, `OBSERVE_ONLY`, `PARTIAL` or `ENFORCED`.
- Cooperative integrations, where the agent itself calls PantherClaw (the SDK authorize call, the Claude Code hook, `canUseTool`), are `PARTIAL` unless PantherClaw holds the credentials or the target verifies action tokens.
- "Non-bypassable" applies only to routes that pillar 16 shows as `ENFORCED` with current evidence.

## Editions at a glance

*Proposed packaging. Pricing TBD.* Security invariants (no self-authorization, fail-closed decisions, exact approvals, two-person kill-switch restore, signed receipts) are in every edition. Editions gate scale, retention, integrations and enterprise operations, not safety.

| Capability | Community | Team | Business | Enterprise |
| --- | --- | --- | --- | --- |
| Licence | BSL 1.1 core, free production use within limits | Signed licence key | Signed licence key | Signed licence key |
| Governed agents | ≤ 5 | ≤ 50 | ≤ 500 | Unlimited |
| Organisations & hierarchy | 1 org; org → environments | 1 org; teams | 1 org; business units → teams | Multiple orgs; full hierarchy; delegated administration |
| Environments (proposed) | 2 | 3 | Unlimited | Unlimited |
| Evidence retention | 7 days | 30 days | 1 year | Custom |
| Human sign-in | Generic OIDC login | Generic OIDC login | Generic OIDC login | Generic OIDC + SCIM provisioning |
| Core firewall: PAP/1 identity, grants, CEL policy, gateway, waitlist, WebAuthn approvals, kill switch, signed receipts, `pclaw verify` | Yes | Yes | Yes | Yes |
| Discovery | Local `pclaw scan` | + GitHub organisation scan | + GitHub organisation scan | + GitHub organisation scan |
| Policy simulation, shadow & pilot rollout; governed automations | — | Yes | Yes | Yes |
| Investigation cases & breach radius | Search & evidence explorer | Cases, breach radius | + posture queue, automation exposure | + posture queue, automation exposure |
| Transparency anchoring (Rekor v2 + RFC 3161) | — | Yes | Yes | Yes |
| SIEM export (OCSF 1.9) & SOAR response requests | — | — | Yes | Yes |
| Threat detections | Core built-ins | Core built-ins | Advanced built-ins + custom rules | Advanced built-ins + custom rules |
| Red-team range | Community scenarios | Community scenarios | Full library (≥ 30 scenarios) | Full library (≥ 30 scenarios) |
| Deployment | Self-hosted single node | + hybrid (hosted control plane, from v1.0); SaaS post-1.0 | + hybrid (hosted control plane, from v1.0); SaaS post-1.0 | + hybrid fleet management, multi-org |
| FIPS 140-3 build | — | — | — | Yes |
| Customer-approved support access | — | — | — | Yes |
| High availability | — | — | — | Yes (post-1.0) |

## 1. Agent Inventory

**Component:** Badge.

**Why customers buy this:** You cannot govern agents you cannot name. PantherClaw keeps one accountable record per agent (owner, purpose, environment, authority and open issues), so every action traces back to someone responsible.

| ID | Feature | What the backend delivers | Phase | Edition | Milestone | Source |
| --- | --- | --- | --- | --- | --- | --- |
| F003 | Shared record model | Agents, Runs, Resources, Grants, Policies and Actions are first-class API resources with stable UUIDv7 IDs. People, tools, connections, approvals, incidents and receipts attach by reference, never by copy. | MVP | Community | M3 | F003 |
| F016 | Accountable ownership & claiming | Each agent records its organisation, owning team, accountable owner and backup owner. Owners claim unclaimed agents explicitly; claiming is audited and grants no authority by itself. | MVP | Community | M3 | F016 |
| F017 | Agent summary API | One call answers who owns the agent, its permitted purpose, environment, execution context, active authority, protected paths and outstanding issues, each linked to evidence. | MVP | Community | M3 | F017, F018 |
| F019 | Agent sub-resources | Per-agent endpoints for runs, authority, resources, change history and evidence, filterable by time range and environment. | MVP | Community | M3 | F019 |
| F025 | Automations as actors | Automation execution identities appear in inventory and exposure queries just as agents do. No hidden administrator identity acts on resources. | MVP | Team | M11 | F025 |
| F574 | One owner, many teams | Each agent has exactly one accountable owner. Other teams use it only through their own grants. Ownership transfers are recorded and never move authority. | MVP | Community | M3 | F574, F575 |
| F600 | Fleet cohorts | Agents are grouped by team, task type and environment, with shared baselines, owner queues and change summaries. Small fleets need no cohort setup. | MVP | Team | M11 | F600, F601 |
| F602 | Large-fleet administration | Delegated administration, exception groups, bulk simulation, verified rollout and aggregated findings. The 10 / 1,000 / 100,000-agent patterns are design targets, not proven capacity. | Next | Enterprise | post-1.0 | F602, F606 |
| F624 | Explicit empty states | Inventory distinguishes "no agents connected", "identity verified, no actions observed" and "collection failed", and suggests a safe test or health check. | MVP | Community | M3 | F624, F625 |

## 2. Discovery (shadow agents)

**Component:** Badge (credential-reach findings, F048, are shown under Stash).

**Why customers buy this:** Much agent risk sits in agents nobody registered. Discovery finds MCP configs, agent frameworks, CI workflows and stray keys on developer machines and in GitHub. It queues each finding for an owner before that agent can hold governed authority.

| ID | Feature | What the backend delivers | Phase | Edition | Milestone | Source |
| --- | --- | --- | --- | --- | --- | --- |
| PN-001.1 | Local shadow-agent scan | `pclaw scan` finds MCP configs (Claude Desktop, Claude Code, Cursor, VS Code, Windsurf/Devin Desktop, Zed, JetBrains Junie and AI Assistant, OpenAI Codex CLI, Google Gemini CLI), agent-framework projects and secrets held in the environment or in MCP server env values, headers and OAuth client secrets, including PantherClaw `pck_` keys. Secrets are reported redacted; results stay local unless submitted. | MVP | Community | M3 | F015, F445 |
| PN-001.2 | GitHub organisation scan | Through the GitHub App, inventories installed Apps, Actions workflows and committed `.mcp.json` files across an org. Each finding becomes a candidate agent or an equivalent route. | MVP | Team | M8 | F015, F448 |
| PN-001.3 | Continuous discovery | Scheduled re-scans (in CI and on GitHub) are compared against inventory to flag new, changed and vanished agents and routes. | Next | Team | post-1.0 | new |
| F015 | Unclaimed-agent queue | Scan findings and unknown workloads seen at the gateway become `DISCOVERED` agents, each with an ADMISSION waitlist entry. They hold no grants until claimed, admitted and verified. | MVP | Community | M3 | F015 |
| F048 | Credential-reach findings | Compares a connection's technical permissions (e.g., delete, export) with what the task grant needs. Excess reach is reported as an exposure finding, never treated as extra permission. | MVP | Community | M9 | F048, F328 |
| F352 | Tool & resource discovery | After a connection is added, enumerates its tools and resources. New tools enter TOOL_REVIEW and cannot serve covered actions until a reviewed package is active. Needs a reviewed path for unpinned tools and resources (founder 2026-10-28). | Next | Community | post-1.0 | F352 |
| F357 | Observation-only discovery | Monitor-mode traffic and read-only connections populate inventory and activity, but always carry `OBSERVE_ONLY` and never an enforcement label. | MVP | Community | M6 | F357 |
| F450 | Honest discovery limits | Every inventory result lists which sources were scanned and which were not. Anything missing is reported as "not observed", never as "does not exist". | MVP | Community | M9 | F450 |
| F692 | New-agent intake automation | A governed workflow proposes candidate owners, inspects tools, drafts a baseline grant and runs safe tests. Humans confirm identity and any production access. | MVP | Team | M11 | F692 |

## 3. Lifecycle

**Component:** Badge.

**Why customers buy this:** Agents get promoted, suspended and retired, and authority must follow those changes instead of lingering. Lifecycle states make every transition explicit and attributable, and a suspended agent can resume only through governed restoration.

| ID | Feature | What the backend delivers | Phase | Edition | Milestone | Source |
| --- | --- | --- | --- | --- | --- | --- |
| F020 | Lifecycle state machine | `DISCOVERED → CLAIMED → VERIFIED → OBSERVED → PARTIALLY_PROTECTED → PROTECTED`, plus `SUSPENDED` and `RETIRED`. Transitions are table-driven conditional updates, and each state has a next required action. | MVP | Community | M3 | F020 |
| F021 | Scope-qualified protection | `PROTECTED` is derived only from current coverage records for named paths. Mixed paths yield `PARTIALLY_PROTECTED`, and status downgrades automatically when coverage expires. | MVP | Community | M9 | F021 |
| F022 | Lifecycle actions | Test identity, inspect access, tighten grants, suspend and retire via the API. Each action is authorised, audited and returns the resulting state. | MVP | Community | M3 | F022 |
| F023 | Retirement | Blocks new runs and enrolments, revokes workload keys and preserves history. Opens a residual-access review of remaining credentials and grants. | MVP | Community | M3 | F023 |
| F024 | Explicit change history | Ownership, identity, authority and coverage changes are append-only events with actor and reason. Summaries are derived from them and never edited silently. | MVP | Community | M3 | F024 |
| F333 | Production promotion gate | Promotion to production requires an owner, verified identity, passing required tests, working approval routing, coverage evidence and declared failure behaviour. Readiness is stated per operation, never globally. | MVP | Community | M11 | F333, F334 |
| F563 | Governed restoration | Restoring a suspended agent, run, connection or automation is a RESTORATION waitlist entry that needs a reason and the required independent review. Closing an incident never resumes anything. | MVP | Community | M5 | F563, F567 |
| F564 | Restoration preconditions | Before a restoration can be approved, the reviewer must see re-verified identity, connection health, remediation and test results, and any remaining grants and waiting approvals. | MVP | Community | M10 | F564, F565, F566 |
| F568 | Staged restoration | Restore a bounded cohort or task scope first. Re-run permitted and prohibited test actions before widening. | MVP | Team | M10 | F568, F569 |
| F570 | No stale replay | Restoration never replays denied, expired, missed irreversible or ambiguous actions. Corrective and compensating work needs fresh authorization. | MVP | Community | M10 | F570, F572 |
| F571 | Residual-impact follow-up | Historical impact questions stay open and owned after new access is contained or restored. | MVP | Team | M10 | F571 |

## 4. Identity & Authority Protocol (PAP/1)

**Component:** Badge.

**Why customers buy this:** Model names, display names and shared API keys are not identity. PAP/1 proves which workload instance is acting, for whom and in which run, using bound keys that resist replay. It is an open spec, so targets and auditors can verify it themselves.

| ID | Feature | What the backend delivers | Phase | Edition | Milestone | Source |
| --- | --- | --- | --- | --- | --- | --- |
| PN-002.1 | Workload keys & enrollment (L1) | Each workload instance generates an Ed25519 key locally. A single-use enrollment token (≤ 15 min) plus owner fingerprint confirmation admits it. Token reuse is rejected and audited. Desktop workloads are capped at L1. | MVP | Community | M3 | F029, F032 |
| PN-002.2 | Platform attestation (L2) | Accepts workload tokens from configured trusted issuers with pinned issuer, keys, audience and binding claims. Presets: GitHub Actions OIDC (fork PRs rejected) and Kubernetes service-account tokens plus image digest. Matching claims may auto-admit. | MVP | Community | M3 | F028, F029, F031 |
| PN-002.3 | Federated workload identity | Further issuer presets (GitLab CI, cloud workload identity, SPIFFE JWT-SVIDs, Microsoft Entra Agent ID) on the same pinned-claims framework, plus L3 attestation from SPIFFE X.509 SVIDs and cloud instance identity. | Next | Enterprise | post-1.0 | F029 |
| PN-002.4 | Key-bound tokens & DPoP | Workload tokens (≤ 10 min) carry `cnf.jkt`. Every request carries a proof over method, URI, token and raw-body hash, using a server nonce. Replayed `(jkt, jti)` pairs are rejected. | MVP | Community | M3 | F032, F037 |
| PN-002.5 | Server-minted run context | Only the authority creates runs (`StartRun`), bound to instance, launcher, principal and grant. Workload-supplied context is labelled and cannot enlarge authority. Any mismatch is denied as tampering. | MVP | Community | M4 | F049, F050 |
| PN-002.6 | Action tokens (target-enforced mode) | For targets running verifier middleware, the gateway attaches a single-use token (≤ 60 s) bound to action hash, body hash, operation and target. Only then can cooperative routes count as `ENFORCED`. | MVP | Community | M6 | F417 |
| PN-002.7 | Open protocol | The PAP/1 spec, ActionIR schema, error codes, JWKS discovery and test vectors are published under Apache-2.0, with Go, Python and TypeScript verifier libraries. | MVP | Community | M8 | new |
| PN-002.8 | Represented principal from the customer IdP | `StartRun` accepts the represented user as an RFC 8693 subject token from a configured OIDC provider, with the launcher as actor. The run records both; the token proves who is represented and grants nothing. | MVP | Community | M3 | F027, F030 |
| F026 | Stable identity, per-run context | Agent identity persists across releases for ownership and history. Each run gets its own server-minted identity context and grant. | MVP | Community | M3 | F026 |
| F027 | Actor attribution | Records launcher, represented principal, calling application and executor separately. A scheduler is recorded as the launcher, never as the business principal. | MVP | Community | M3 | F027, F030, F064 |
| F028 | Release & configuration identity | Each instance records one release digest, marked declared or attested; a change from the declared release is drift and opens a review. Separate code, image and configuration identities come later. | MVP | Community | M3 | F028 |
| F031 | Verification metadata | The identity API returns verification method, attestation level, last verification time, required trust level and any unresolved ambiguity. | MVP | Community | M3 | F031 |
| F033 | Identity drift | Changes to release, schema, host or execution context trigger reassessment of affected capabilities. A different actor with the same name never inherits sensitive authority. | MVP | Community | M3 | F033, F034 |
| F035 | Ambiguous identity resolution | Ambiguous actors stay as separate records until an authorized user merges them with evidence. Merge history is retained. | MVP | Community | M3 | F035 |
| F036 | Existing human identity | Humans sign in through the customer's OIDC provider; the CLI uses device flow. SCIM provisioning is Enterprise. PantherClaw never becomes a human identity provider. | MVP | Community | M2 | F036 |
| F037 | Point-of-use identity checks | Instance, application, launcher, principal, executor and approver are verified at the point their authority is used. Unverifiable identity yields `CANNOT_AUTHORIZE` and no new sensitive authority. | MVP | Community | M4 | F037, F633 |

## 5. Authorization (task grants & policy)

**Components:** Pass (5A), Guardrails (5B, 5C) and Root (platform, 5D).

**Why customers buy this:** Agents should hold exactly the authority a task needs, for as long as it needs it. Task grants, inherited guardrails and a deterministic CEL policy engine decide every covered action and explain exactly why. This pillar is the authority core, so it is split into four sub-tables.

### 5A. Task grants & delegation

**Component:** Pass.

| ID | Feature | What the backend delivers | Phase | Edition | Milestone | Source |
| --- | --- | --- | --- | --- | --- | --- |
| F038 | Task grants | Grants bind agent, represented principal, task, stable resources and target set. Each records the grantor and the authority that allowed that grantor to delegate. | MVP | Community | M4 | F038, F039, F040, F041 |
| F042 | Grant boundaries | Permitted operations, parameter constraints, destinations, amounts, budgets and required approvals are validated structured fields, stored as immutable revisions. | MVP | Community | M4 | F042, F043 |
| F044 | Grant validity | Environment, validity window, revisions, expiry and revocation state. Expiry is enforced at use time; task close stops new authority; extension needs fresh review. | MVP | Community | M4 | F044, F053 |
| F045 | Delegation to child agents | Creating a child and delegating to it are separate actions. Delegation is denied unless the parent grant allows it and depth remains. Each child has its own identity and grant. | MVP | Community | M4 | F045, F055, F056, F061 |
| F054 | No self-authorization; invariants | Product invariants, org-protected controls, environment/target controls and task grants are distinct levels. Tenants cannot override invariants, including that agents never create, expand, approve or attest their own authority. | MVP | Community | M4 | F054, F588, F589 |
| F057 | Non-expanding delegation | A child grant is a subset of its parent in operations, scope and expiry. Revoking a parent invalidates every dependent grant for new actions. | MVP | Community | M4 | F057, F058, F060 |
| F046 | Effective authority | Computes grant ∩ principal bounds ∩ org guardrails ∩ policy ∩ containment ∩ limits. Shows the grantor's ceiling, the delegated scope and what the run can use now. | MVP | Community | M4 | F046, F047 |
| F062 | Authority lineage | Traces an action through the original authorizer, grant issuance, each delegation, restricting policies and the current boundary. Each hop shows scope, issuer, expiry and revocation dependencies. | MVP | Community | M4 | F062, F063 |
| F576 | Inherited guardrails | Org guardrails set the ceiling, and business units, teams and environments can only narrow it. Grants are issued only inside the inherited envelope; exceptions need designated authority. | MVP | Community | M4 | F576–F580 |

### 5B. Decision pipeline & policy engine

**Component:** Guardrails.

| ID | Feature | What the backend delivers | Phase | Edition | Milestone | Source |
| --- | --- | --- | --- | --- | --- | --- |
| F069 | Six-value decisions | Every decision is one of `ALLOW`, `ALLOW_WITH_OBLIGATIONS`, `REQUIRE_APPROVAL`, `REQUIRE_STEP_UP`, `DENY` or `CANNOT_AUTHORIZE`. Each has a readable five-way presentation: Allow, Constrain, Hold, Deny, Cannot authorize. | MVP | Community | M4 | F069, F070 |
| F081 | 10-step decision pipeline | Scope & coverage, identity, containment, authority (every ancestor grant), exact meaning, current facts, boundaries, requirements, final binding, observe. CEL evaluation fails closed. | MVP | Community | M4 | F081–F087 |
| F092 | Deterministic composition | Prohibitions win and cannot be overridden locally. Limits intersect to the tightest. Compatible requirements combine; conflicts deny with the exact conflict; no applicable grant means deny. | MVP | Community | M4 | F092–F095 |
| F076 | Cannot authorize ≠ deny | Missing or stale evidence, unknown classification, unsupported obligations or custody, or a missing required external check return `CANNOT_AUTHORIZE` with the reason. They are never reported as a business-policy deny. | MVP | Community | M4 | F076, F096, F368, F629 |
| F071 | Obligations & requirement types | Approval and step-up are tracked separately. Obligations state their timing: before execution, after dispatch, or before dependent work. Allow-once is single-use, read-only is enforced, and warnings never replace blocking. | MVP | Community | M4 | F071–F075 |
| F066 | Action card | Each decision returns action, target, material values, principal, task, environment, decision, reason, grant constraints, expiry and execution state. Parameters, stable IDs and fact provenance are expandable. | MVP | Community | M4 | F066, F067 |
| F078 | Explainable decisions | A checklist of passed, failed, missing and not-applicable conditions, decisive one first. Includes the offending parameter, a permitted alternative, and the policy, grant and fact versions used at decision time. | MVP | Community | M4 | F078, F079, F080 |
| F099 | Effect-based consistency | Decisions key on the reviewed effect, not the tool name or protocol. The same effect via MCP, HTTP, SDK or hook gets the same decision. | MVP | Community | M4 | F099, F711 |
| F179 | CEL policy language | Structured clauses (subjects, environments, task types, resources, operations, parameters, sensitivity, destinations, windows, budgets, evidence, approvals, responses) compile to CEL, render readably and show inherited rules. | MVP | Community | M4 | F179, F180, F182, F183 |
| F366 | External facts & signals | Trusted classifications, external policy checks and risk signals, each with provenance, freshness and failure behaviour. Extensions cannot exceed core authority; external allows never waive custody, coverage or verification. | Next | Business | post-1.0 | F366, F367, F369, F370, F371 |
| F405 | Downstream-consequence rules | Reviewed, bounded rules (e.g., merge to `main` triggers a production deploy) apply consequence-level authority, approvals and windows. Predicted consequences are labelled separately from authorized and confirmed ones. Missing links stop derivation; the model never invents causality. Stored rules evaluated in the decision pipeline in M8, in every edition (G0 M8 design decision 11). | Next | Team | M8/post-1.0 | F405–F413 |

### 5C. Policy lifecycle

**Component:** Guardrails.

| ID | Feature | What the backend delivers | Phase | Edition | Milestone | Source |
| --- | --- | --- | --- | --- | --- | --- |
| F172 | Protect-a-task templates | Templates for customer support, refunds, production diagnostics, release deployment and internal analysis. Each states what it protects, what it excludes and which connections it needs. Refunds, release deployment and production diagnostics ship in M11.1 with baseline scenario tests; customer support and internal analysis follow with M14's connectors. | MVP | Community | M11.1 | F172–F178 |
| F181 | Natural-language drafting | Drafts policies and automation workflows from text, with ambiguities made explicit. Vague terms must become concrete thresholds, and only the reviewed structured form executes. | Next | Team | post-1.0 | F181, F682 |
| F184 | Draft-first versioning | Edits create immutable draft revisions, and saving never publishes. Versions advance from draft to validated to tested to published via the API and `pclaw policy test`. | MVP | Community | M11.1 | F184, F199 |
| F185 | Evidence-backed suggestions | Suggested restrictions carry an evidence window, coverage limits, observed operations, expected effect, affected owners and false-positive uncertainty. Unused authority prompts review, not removal. | Next | Business | post-1.0 | F185, F186 |
| F187 | Historical simulation | `pclaw policy simulate` replays a draft over recorded actions. Newly denied, held, constrained, allowed and unevaluable actions are reported separately by workflow, with an approval-burden forecast; agent replanning is not predicted. | MVP | Team | M11.1 | F187–F192, F287 |
| F193 | Policy scenario tests | Test suites assert the expected decision and decisive reason (valid lookup, threshold hold, grant-limit deny, split budget, stale approval). Production publication is blocked until baseline tests pass. | MVP | Community | M11.1 | F193, F194, F195 |
| F196 | Validation & behavioural diffs | Detects conflicting clauses and gives an example action. Checks that integrations can satisfy the constraints and evidence. Diffs versions by changed outcomes and thresholds. | MVP | Community | M11.1 | F196, F197, F198 |
| F200 | Shadow & pilot rollout | Shadow evaluation on live traffic without enforcement claims, then enforcement for named pilot cohorts first. Per-target states are configured, acknowledged, verified or exception; publishing never implies enforcement. | MVP | Team | M11.1 | F200–F203 |
| F204 | Partial rollout & rollback | Failed targets keep their previous valid controls and are listed with version and owner. Rollback respects current org restrictions and never removes active emergency containment. | MVP | Community | M11.1 | F204–F207, F636 |
| F208 | Temporary exceptions | Exceptions need a target, reason, owner, expiry and eligible approver. They cannot defeat non-overridable controls, and renewal needs fresh review. | MVP | Community | M11.1 | F208, F209, F210 |
| F582 | Protected changes | Changes that can widen authority (policy, tool meaning, consequence rules, custody, coverage exclusions) show the widening and need a distinct publisher where configured. Once active they are fixed and attributable. | MVP | Community | M11 | F582, F586, F587, F590, F592, F593, F599 |
| F595 | Compromised-publisher response | If publishing or signing authority is compromised, affected promotions freeze, exposed versions are listed, and restoration needs independent review. A valid signature never proves the issuer was uncompromised. | MVP | Business | M11 | F595, F596 |
| F762 | Reference workflow packs | Tested policy packs for support resolution, treasury payments, read-only diagnostics, aggregate reporting, research/disclosure and coding-to-production, each with expected allow, hold and deny cases. | MVP | Team | M11 | F762–F767 |

### 5D. Governed automations

**Component:** Root (platform).

| ID | Feature | What the backend delivers | Phase | Edition | Milestone | Source |
| --- | --- | --- | --- | --- | --- | --- |
| F283 | Automation lifecycle & status | Create from template, simulate, test, enable, pause, inspect, retry, revise and retire. Status shows next run, latest verified outcome, budget ceiling and backlog. Workflow graph data links each step to its authority. | MVP | Team | M11 | F283, F662, F663, F751 |
| F652 | Governed automation model | Agent-work and security-work automations follow the same identity, grant, policy, approval, evidence and response rules as manual work. They coordinate existing agents rather than build them. | MVP | Team | M11 | F652, F653, F654, F664 |
| F655 | Versioned definitions | Purpose, owner, identity, principal, trigger, conditions, steps, scope, grant or issuance ceiling, limits, human gates, retry and recovery, evidence destinations and review dates for sensitive authority. | MVP | Team | M11 | F655–F661 |
| F665 | Authentic triggers | Scheduled, event, state-duration, threshold and manual triggers. Each execution records its source and how authenticity was established. External content can never grant authority or redefine a trigger. | MVP | Team | M11 | F665–F671 |
| F672 | Schedule & replay safety | Timezone-aware next run with DST skip/repeat preview, a declared missed-run policy, and no overlapping sensitive runs by default. Duplicate events are blocked, and trigger ancestry is kept. | MVP | Team | M11 | F672–F677 |
| F678 | Workflow definition format | A structured outline (When, If, Under authority, Do, Wait when, If work fails, Finish when) with ordered steps, explicit branches, terminal outcomes and a plain-language summary. | MVP | Team | M11 | F678–F681 |
| F683 | Draft validation | Rejects drafts that lack an owner or verified identity, or that have unbounded scope or budget, missing deadlines or terminal states, unreconciled irreversible steps, approver-less gates, cycles or unsupported capabilities. | MVP | Team | M11 | F683–F690 |
| F691 | Automation templates | Bounded task launch, grant lifecycle (expire or revoke at task close), least-privilege review drafts, audit digests and approved business workflows. Production policy publication remains a human step. | MVP | Team | M11 | F691, F694, F698, F699, F700 |
| F701 | Authority at every execution | Enabling approves the definition only. Each execution re-verifies trigger, owner, identity, principal and scope, gets a grant inside the ceiling (auto-issued only as explicitly approved), and every step is decided separately. | MVP | Team | M11 | F701–F705 |
| F706 | No borrowed or expanded authority | Final rechecks before consequential steps. No reuse of a former owner's authority or expired approvals, and no self-acquired access after a denial. Material changes need review and republication. | MVP | Team | M11 | F706–F709 |
| F710 | Same boundary for automated steps | Automated effectful steps get the same custody, meaning, coverage and verification as manual ones. Pre-enable inspection shows effects and routes. Affected steps stop on quarantine or expiry, and every action traces to its trigger and version. | MVP | Team | M11 | F710, F712, F713, F714 |
| F723 | Automation retries & compensation | Bounded attempts and a deadline; only safe operations retry, with stable step identity. Unknown irreversible outcomes need reconciliation. Partial completion is itemised, and compensation is separately authorized. | MVP | Team | M11 | F723–F728 |
| F738 | Automation tests & rollout | Tests normal, denied, timeout, duplicate and partial cases, plus historical trigger simulation and shadow runs without effectful steps. Volume and approver forecasts; a bounded cohort goes first, and outcomes are verified before widening. | MVP | Team | M11 | F738–F745 |

**Delivery status of the M11 rows and of search (M11 part 2 exit, 2026-10-16; [g0/M11.md](g0/M11.md) exit status).** The rows stay the planned scope; this list says what the backend delivers now. *Delivered*: built and tested by the HR-270..HR-293, HR-295, HR-296, T-120..T-130 and `TestE2E_M11_*` tests, through the API and `pclaw`; the screens come in the UI phase. *Partly*: the part named is built, the rest is planned where stated.

- **Delivered:** every row marked M11 except F678 and F762, in this section and elsewhere: F025, F221, F262, F283, F333, F533, F562, F582, F595, F600, F652, F655, F665, F672, F683, F691, F692, F693, F697, F701, F706, F710, F715, F718, F723, F729, F732, F734, F738.
- **Partly:** F678 (definitions are linear steps with guards, gates and waits; explicit branches wait for the full branching engine, Next). F762 (the read-only diagnostics pack, F764, and the coding-to-production pack, F767; support resolution F762, treasury payments F763, aggregate reporting F765 and research and disclosure F766 are delivered by M14, see the M14 delivery status under 6C).
- **Delivered, universal search** (§23 of the traceability table, F304–F321):
  - F304 gains quick find and rule-based plain-language questions (F305; no AI model, nothing leaves the server, founder decision F5);
  - F317 gains opening a case from results and export (F318), suggestions (F320) and evidence-grounded answers (F321);
  - incident correlation (F316, a source of F241) is a built-in search query.

  M10 delivered the structured search, the built-in queries F306–F315 and result integrity.

## 6. Non-bypassable Transaction Boundary

**Components:** Checkpoint (6A, 6C, 6D) and Stash (6B).

**Why customers buy this:** A decision only matters if the action cannot route around it. The gateway holds credentials, re-serialises exactly what was authorized and commits dispatch on the server side. Anything it cannot mediate is labelled as partial coverage rather than counted as protected.

### 6A. Gateway & dispatch

**Component:** Checkpoint.

| ID | Feature | What the backend delivers | Phase | Edition | Milestone | Source |
| --- | --- | --- | --- | --- | --- | --- |
| PN-003.1 | Dispatch permits & commit point | An ALLOW returns a single-use signed permit (≈ 5 s) carrying the containment epoch. `BeginDispatch` commits atomically only if the permit is unexpired and the epoch is current; otherwise nothing is sent. | MVP | Community | M6 | F088, F089 |
| PN-003.2 | Authorize what you forward | The gateway re-serialises the outbound request from the authorized ActionIR and injects credentials. The target receives exactly what was decided, so parser differentials cannot smuggle extra effects. | MVP | Community | M6 | F386 |
| PN-003.3 | Egress guards | No redirects, a dial-time IP deny list (SSRF), DNS-rebinding protection, Host/SNI taken from the connection, size and decompression caps, and secret-echo scanning. | MVP | Community | M6 | new |
| PN-003.4 | Sealed credentials | Target credentials are sealed with HPKE X-Wing (ML-KEM-768 + X25519 hybrid) via `pclaw seal`, and opened in gateway memory only at dispatch time. Agents never see them. | MVP | Community | M6 | F419, F432 |
| PN-003.5 | HTTP API proxy | A per-connection reverse proxy for REST targets. Requests map to ActionIR through tool packages and follow the same decision, permit, egress and receipt path as MCP. | MVP | Community | M6 | F444 |
| PN-015.1 | MCP gateway | Supports MCP 2026-07-28 (stateless Streamable HTTP, with `Mcp-Method`/`Mcp-Name` header–body consistency) and 2025-11-25. Rejects batches and binds sessions to the workload key. `pclaw mcp proxy` is a stdio shim for off-the-shelf clients. | MVP | Community | M6 | F443 |
| PN-015.2 | Reviewed tool surface | Clients receive reviewed tool descriptions from the active package, never live server text. Holds surface as MCP pending results or tasks. Elicitation and sampling are declined; a policy gate for them comes later. | MVP | Community | M6 | F384 |
| PN-014 | Claude Code & Agent SDK integration | Apache-2.0 plugin with a PreToolUse hook for the Bash and PowerShell tools (with Windows path normalisation) and Agent SDK `canUseTool`. Labelled `PARTIAL` unless credentials are in PantherClaw custody. | MVP | Community | M6/M8 | F761 |
| PN-016.1 | SDKs | Apache-2.0 Python, TypeScript and Go SDKs: PAP/1 client, DPoP, ActionIR canonicaliser and wait handles, with a cross-language conformance suite. SDK-only (cooperative) use is labelled `PARTIAL`. | MVP | Community | M8 | new |
| PN-016.2 | Target verifier middleware | Target-side middleware checks PAP/1 action tokens (signature, audience, expiry, body hash, single use), so a customer's own service, such as a deployment API, enforces decisions itself. | MVP | Community | M8 | F417 |
| PN-016.3 | Framework wrappers | Wrappers for LangChain/LangGraph, the OpenAI Agents SDK, CrewAI, the Vercel AI SDK and the MCP TypeScript SDK, built on the core clients and the conformance suite. | MVP | Community | M14 | new |
| PN-023 | AuthZEN decision endpoint | Third-party enforcement points (Envoy `ext_authz`, agent gateways) request decisions through OpenID AuthZEN. They skip permits and `BeginDispatch`, so their routes are `PARTIAL`; budget-consuming allows are never released early. | MVP | Community | M14 | new |
| F127 | Pre- and post-dispatch gates | All pre-execution checks complete before dispatch, and effects are observed afterwards. Dependent work waits for the qualifying state. Later verification never legitimises a prohibited action. | MVP | Community | M6 | F127–F130 |
| F131 | Retries are not permission | Stable `action_id` and semantic dedupe keys; the same ID with a different hash is denied as tampering. Unknown irreversible outcomes park in reconciliation. Retries reassess current authority, and earlier attempts stay visible. | MVP | Community | M7 | F131, F136, F137, F138 |
| F132 | Changed-request reauthorization | Any change to parameters, payee, destination, target, represented user or task needs a new decision. Expired approvals cannot authorize execution. | MVP | Community | M6 | F132, F133 |
| F642 | Typed failures | Errors distinguish policy denial, authentication failure (`PAP-Error` codes), tool failure, enforcement failure and uncertain execution, each with its own remedy. | MVP | Community | M6 | F642 |

### 6B. Credential custody

**Component:** Stash.

| ID | Feature | What the backend delivers | Phase | Edition | Milestone | Source |
| --- | --- | --- | --- | --- | --- | --- |
| F416 | Access modes | Each connection uses target-enforced, narrow temporary, PantherClaw-held, externally constrained runtime, agent-held reusable or combined access, recorded on every execution receipt. Agent-held access is `PARTIAL` or `UNKNOWN` unless its routes are closed. | MVP | Community | M6 | F416–F422 |
| F423 | Access source inspection | Shows custodian, target account, scope, audience, expiry, issuer, affected agents, verification basis and residual routes, linked to grants and transactions. Raw secrets are never revealed. | MVP | Community | M6 | F423, F425, F432 |
| F424 | Access management | Preview dependants, test a connection's custody, revoke or rotate sealed credentials, and remove an agent's direct access by an attested revoke, which closes its bypass routes. Target-confirmed rotation comes later. | MVP | Community | M6 | F424, F429 |
| F426 | Revocation completeness | Identity, privilege, credential or target changes trigger reassessment. Revocation reports both the delegated permission removed and any target access still usable. | MVP | Community | M6 | F426, F427 |
| F431 | Executor trust assurance | States whether protection assumes a trusted executor or contains a compromised one. Checks the actor can skip (hooks, SDK calls) never justify a stronger assurance claim. | MVP | Community | M6 | F431 |

### 6C. Connections & connectors

**Component:** Checkpoint.

| ID | Feature | What the backend delivers | Phase | Edition | Milestone | Source |
| --- | --- | --- | --- | --- | --- | --- |
| F346 | Capability-declared connections | Each integration declares discovery, observation, enforcement and response support, plus operations, attribution, permissions with reasons, limits, failure behaviour and its last successful test. | MVP | Community | M8 | F346–F350 |
| F351 | Connection lifecycle | Choose capability and environment first, then connect, test, approve capabilities, quarantine, rotate or disconnect. Health shows permissions, tests, delivery failures and dependent agents. | MVP | Community | M8 | F351, F358, F359 |
| PN-017.1 | GitHub App connector | Issues narrow, short-lived installation tokens per authorized action (repository, permission, expiry). Governs reads, branches, PRs, merges and settings. | MVP | Community | M8 | F755 |
| PN-017.2 | Stripe connector (test mode) | Refunds and payments in Stripe test mode with amount, currency, recipient and cumulative limits. Idempotency keys derive from the transaction, and effect checks are settlement-aware. | MVP | Community | M14 | F758 |
| PN-017.4 | Postgres query connector | Read-only queries with row limits and column selection. The connector rejects writes. | MVP | Community | M14 | F759 |
| F756 | Additional resource domains | Cloud/infrastructure, business-application, communication and further host operations, added connector by connector with environment, record scope, recipient and channel coverage declared. | Next | Team | post-1.0 | F756, F757, F760 |

**Delivery status of the M14 rows (M14 exit, 2026-10-20; [g0/M14.md](g0/M14.md) exit status).** The rows stay the planned scope; this list says what the backend delivers on the tested top, in this section and elsewhere. *Delivered*: built and tested by the HR-300..HR-330, T-140..T-150, `TestE2E_M14_*` and RT-039..RT-051 tests, through the API and `pclaw`; the screens come in the UI phase. *Partly*: the part named is built, the rest is planned where stated.
- **Delivered:** PN-017.4 (F759): `pc.postgres`, structured row reads and aggregates over a confirmed manifest of ordinary and partitioned tables (founder decision F3). PN-017.3 (F164–F167): Slack approval cards with a link button only, never a decision in Slack (F4; Team). F101 (F101–F103): record and class scope on gateway-held reads (Team). PN-016.3: the five framework wrappers on the wrapper conformance group. PN-023: the AuthZEN decision endpoint with registered enforcement points (F2; the [ADR-0019](adr/0019-standards-at-the-edges.md) implementation note). F172: the customer-support and internal-analysis templates. F762: the support-resolution (F762), treasury-payments (F763), aggregate-reporting (F765) and research-disclosure (F766) packs, so all six reference packs exist; packs draft no weekly envelope (`pclaw template apply` adds it).
- **Delivered, one live step open:** PN-017.2 (F758): `pc.stripe` in test mode only, with refunds, payment intents and transfers (F5; [ADR-0028](adr/0028-business-connectors-and-data-scoping.md)), tested against the Stripe-shaped simulator; the run against real Stripe test mode (`task test:stripe-live`) waits for the founder's test keys.
- **Partly:** F760: `pc.slack` for agents (F6); the rest of F756 stays post-1.0.
- **Not a row:** peer agent calls over A2A (OWASP ASI07, F1; [ADR-0029](adr/0029-peer-agent-calls-a2a.md)) are delivered: enrolled peers act in delegated child runs, external peers are governed outbound only.

### 6D. Reviewed tool packages & action meaning (ActionIR)

**Component:** Checkpoint.

| ID | Feature | What the backend delivers | Phase | Edition | Milestone | Source |
| --- | --- | --- | --- | --- | --- | --- |
| F361 | Customer-defined actions | An API to define custom actions: name, stable resource identity, material parameters, side effects, reversibility, attribution, result states, failure cases and test scenarios. Claims are limited to the tested scope. | MVP | Team | M4 | F361–F365 |
| F372 | Reviewed tool packages | Owned, versioned, signed packages with a capability manifest, tests and change history. Only `ACTIVE` packages map actions. Widening updates need review, and new sensitive operations never inherit existing grants. | MVP | Community | M4 | F372, F373, F385 |
| F374 | Action definitions (ActionIR) | Each tool maps to a definition covering input meaning, resource types, read/write class, side effects, stable account and target identity, channels, and material parameters with units and currency. | MVP | Community | M4 | F374–F378 |
| F379 | Effects, constraints & prerequisites | Definitions document direct effects, reversibility, safe constraints and transformations, prerequisites, retry safety, ambiguous-outcome handling and required verification. | MVP | Community | M4 | F379–F382 |
| F383 | Definition assurance | Version, evidence basis, reviewers, compatible versions, last behaviour check, validity, expiry and exclusions. Tool text and schemas alone are never trusted. | MVP | Community | M4 | F383, F384 |
| F386 | Strict input interpretation | Strict parsing rejects duplicate keys, unknown fields and confusable identifiers, and amounts must be decimal strings. Ambiguity yields `CANNOT_AUTHORIZE`, never a default. Opaque tools are labelled and carry limited claims. | MVP | Community | M4 | F386, F387, F634 |
| F388 | Meaning workbench | Inspect definitions, evidence, tests, revisions and discrepancies. Declared contracts, provider docs and controlled observations are kept separate, and disagreements stay visible. Periodic safe checks run on isolated resources. | MVP | Team | M4 | F388–F393 |
| F394 | Definition lifecycle | `UNCLASSIFIED → DRAFT → REVIEWED → ACTIVE → STALE / QUARANTINED → RETIRED`. Activation is a separate scoped step. Stale or quarantined meaning stops affected authorization, and retired versions are kept for evidence. | MVP | Community | M4 | F394–F398 |
| F402 | Reviewed restoration of meaning | Quarantined definitions return only with fresh reviewed evidence. Model-proposed mappings stay drafts until validated and activated. | MVP | Community | M4 | F402, F404 |

## 7. Agent Waitlist

**Component:** Pass.

**Why customers buy this:** Some decisions need a human, and agents need a predictable way to wait for them. The Agent Waitlist puts every pending decision into one deadline-driven queue with cryptographically bound approvals: admissions, access requests, held actions, tool reviews, restorations and reconciliations.

| ID | Feature | What the backend delivers | Phase | Edition | Milestone | Source |
| --- | --- | --- | --- | --- | --- | --- |
| PN-004.1 | Unified decision queue | One queue of typed entries (ADMISSION, ACCESS_REQUEST, ACTION_HOLD, TOOL_REVIEW, RESTORATION, RECONCILIATION). Each has a subject, requested scope, evidence, deadline and one state shared across channels. | MVP | Community | M5 | F165 |
| PN-004.2 | Deciders, deadlines & escalation | Routes to currently eligible deciders, then reminds and escalates within the deadline. Expiry or delivery failure resolves to deny, never approve. | MVP | Community | M5 | F167, F168, F635 |
| PN-004.3 | Agent wait handles | Held agents wait through SDK `await`, long-poll, SSE or an MCP pending result, then resubmit the identical action. Evidence waits end at their deadline, with no dispatch in between. | MVP | Community | M5 | F097 |
| PN-004.4 | SLA metrics & load control | Time-to-decision, expiry and escalation rates per entry type and decider. Simulation forecasts demand, and overload prompts narrower rules or safe automatic boundaries. | MVP | Team | M5 | F169, F170 |
| PN-004.5 | Batch review | Batch decisions are allowed only for homogeneous low-risk entries, and each keeps its own scope and audit record. Destructive and high-value entries are always reviewed individually. | MVP | Team | M5 | F171 |
| PN-020.1 | Transaction-bound WebAuthn | High-consequence approvals and step-up are WebAuthn assertions. The challenge is a binding hash of action, decision basis, facts, grant/definition versions, run, instance, key, expiry and display hash. | MVP | Community | M5 | F150, F156 |
| PN-020.2 | Template-only rendering | Approval text renders only from the package's reviewed template, with stable IDs beside readable names. Agent-authored text is quarantined and shown as untrusted. | MVP | Community | M5 | F157 |
| F051 | Access requests | Scope mismatches are flagged without creating rights. A legitimate correction becomes an ACCESS_REQUEST entry for the grant owner instead of disabling a guardrail. | MVP | Community | M5 | F051, F052 |
| F108 | Consent on the effective action | Consent binds the post-constraint effective action. A material transformation needs renewed approval unless the original consent covered that exact transformation. | MVP | Community | M5 | F108 |
| F139 | Consequence-first approval content | Exact action, consequence, target, parameters, destination, value or data, task, principal, agent, requirement basis, eligibility, expiry and reversibility. Earlier similar approvals are shown as context, not precedent. | MVP | Community | M5 | F139–F143 |
| F144 | Approval decisions | Approve the exact action only, decline with a reason and alternative, request evidence until a deadline, or propose a narrower action that gets its own decision. | MVP | Community | M5 | F144–F147 |
| F148 | No approval-driven expansion | Approvals cannot widen policy, approve "all similar" requests or override protected controls; those need governed change workflows. | MVP | Community | M5 | F148, F591 |
| F149 | Approver integrity | Only human sessions approve, never API keys. Eligibility is rechecked at decision and at consumption, and nobody approves their own request. Two-person rules need two users and two WebAuthn credentials. Role removal voids pending approvals. | MVP | Community | M5 | F149, F151, F152, F153 |
| F154 | Invalidation & revalidation | A material change to target, amount, destination, task, grant or parameters voids the approval. Before execution, authority, policy and resource state are rechecked, returning hold, deny or cannot-authorize. | MVP | Community | M5 | F154, F155, F639 |
| F158 | Merge review | Repository approvals show the repository, PR, source commit, destination branch, change summary, required checks and supported deployment consequences. | MVP | Community | M8 | F158 |
| F159 | Consent limits & history | Discloses when the target cannot guarantee a condition all the way through execution. The original consent is kept even after it can no longer authorize. | MVP | Community | M5 | F159, F160 |
| F161 | Approval channels | API and CLI at launch, Slack via PN-017.3, and Teams, ticketing and IDE later. The authenticated in-product approval is authoritative; an external approval needs equivalent binding, expiry and replay resistance. | MVP | Community | M5 | F161, F162, F163 |
| PN-017.3 | Slack approvals | Slack cards carry minimal data and deep-link to the authenticated approval page. High-consequence approvals are never decided inside Slack, and reactions or free-text replies never count as approval. | MVP | Team | M14 | F164, F166 |
| F626 | Empty-queue semantics | Empty results state which scope was checked and include routing health and recent decisions. | MVP | Community | M5 | F626 |
| F693 | Approval-routing automation | A template finds eligible approvers, delivers requests, reminds and escalates within the deadline, and records the resolution and the resulting action outcome. | MVP | Team | M11 | F693 |

## 8. Agent Controls (budgets, limits, sequences, constraints)

**Component:** Guardrails.

**Why customers buy this:** Per-call checks miss damage done in aggregate. Budgets, counts, rates, sequences and safe constraints bound what an agent can do across a task, a run tree or a time period, without race conditions.

| ID | Feature | What the backend delivers | Phase | Edition | Milestone | Source |
| --- | --- | --- | --- | --- | --- | --- |
| F059 | Shared budget groupings | Limits group by task, principal, target account, team or another grouping. Split requests, new run IDs and child grants all draw on the same budget. | MVP | Community | M4 | F059, F116, F117 |
| F100 | Declared constraint support | Packages declare which constraints each tool enforces: row limits, fields, destinations, target sets, amounts. A constraint the tool cannot enforce yields `CANNOT_AUTHORIZE`, never a false claim. | MVP | Community | M4 | F100, F109 |
| F101 | Data-scoping constraints | Field filtering, task-linked record filtering and response redaction, applied only where the connection reliably supports them. | MVP | Team | M14 | F101, F102, F103 |
| F104 | Safe transformations only | A request changes only when the contract declares the transformation safe and the grant allows it. Material business changes (an $85 refund cut to $50) need a new request; shell commands are never rewritten. | MVP | Community | M4 | F104, F105, F106 |
| F107 | Requested vs effective action | Every decision records the requested action, each modification applied, and the resulting effective action. | MVP | Community | M4 | F107 |
| F110 | Value, count, rate & concurrency limits | Per-call and cumulative value limits per run, task or period; counts of writes, recipients, records, delegations or merges; action rate; and maximum concurrent outstanding actions. | MVP | Community | M4 | F110, F111, F112 |
| F113 | Budget state | Available, reserved, spent and unresolved amounts per budget, returned in approvals, runs and automations together with total task exposure. | MVP | Community | M4 | F113, F119 |
| F114 | Race-free reservations | Budgets are reserved atomically before dispatch, using conditional updates in a fixed ancestor-first order, so parallel requests cannot share the remainder. Unknown outcomes keep their reservation until reconciled. | MVP | Community | M4 | F114, F115, F118 |
| F120 | Sequence & prerequisite rules | Review windows after recent changes (e.g., payee bank details), a maximum number of protected operations per task, and verified prerequisites such as a backup before destructive maintenance. | MVP | Community | M4 | F120, F121, F122 |
| F123 | Read-to-disclosure control | External disclosure after sensitive reads in the same task is held unless the reviewed task permits that data flow. Needs run read history; an alert-only detection covers the pattern today (founder 2026-10-28). | Next | Community | post-1.0 | F123 |
| F124 | Trusted history | Rules declare what counts as history: an attempt, an acceptance or a confirmed effect. Explanations show prior transactions, windows and freshness. Agent memory is never history, and missing history yields `CANNOT_AUTHORIZE`. | MVP | Community | M4 | F124, F125, F126 |

## 9. Sessions (runs)

**Component:** Reflex.

**Why customers buy this:** Runs are where intent becomes action. The session record shows a run end to end (task, authority, decisions, approvals, budget and effects) without needing transcripts or the model's reasoning.

| ID | Feature | What the backend delivers | Phase | Edition | Milestone | Source |
| --- | --- | --- | --- | --- | --- | --- |
| F004 | Logical transactions within runs | A run holds many logical transactions. Each keeps its request, authority, decision, human requirements, attempts and effects together, and retries never become new permission. | MVP | Community | M4 | F004 |
| F065 | Parent/child & related runs | Links child runs and known downstream workflows across inspection, investigation and timelines. | MVP | Community | M7 | F065, F228 |
| F224 | Run inspector API | End-to-end run view: declared task, launcher, principal, grant, status and coverage, then actions, decisions, results and authority changes in chronological order. | MVP | Community | M7 | F224, F225, F226 |
| F227 | Run budget & approval history | Budget consumed and approvals requested during the run, with the remaining allocation. | MVP | Community | M7 | F227 |
| F229 | Unresolved-run evidence | Lists missing evidence, telemetry gaps and unresolved effects for the run. | MVP | Community | M7 | F229 |
| F230 | Run response actions | From the run: suspend it, revoke its authority, compare it, open a case or export permitted evidence. | MVP | Community | M10 | F230 |
| F231 | Append-only outcomes | Completed action records never change. Later observations are appended with their provenance. | MVP | Community | M7 | F231 |
| F232 | Task-phase timeline | Groups actions into Gather context, Prepare change, Seek approval, Execute and Verify, based on workflow evidence. Inferred phases are marked as inferred; agent notes carry provenance and no authority. | MVP | Team | M10 | F232, F233 |
| F234 | Typical-run comparison | Diffs a run against a reference period (new destinations, record counts, post-task writes) and states the sample size. Novelty alone is never labelled malicious. | MVP | Business | M10 | F234, F235 |
| F236 | No transcript requirement | Run inspection works from actions and receipts. Full transcripts and hidden model reasoning are never required. | MVP | Community | M7 | F236 |
| F284 | Session timeline data | Time-ordered actions, holds, approvals, authority changes, dispatches, results, evidence gaps and parallel child lanes, ready for timeline rendering. | MVP | Community | M10 | F284 |
| F715 | Automation execution inspector | Trigger, version, initiating principal, execution identity, grant lineage, current step, elapsed time, per-step decisions and attempts, and linked child agents and external workflows. | MVP | Team | M11 | F715, F716, F717 |
| F718 | Automation execution results | Budget and human-gate status, partial effects and unresolved work. States are Succeeded, Partially completed, Failed, Cancelled, Waiting and Needs reconciliation; Succeeded requires completion evidence. | MVP | Team | M11 | F718–F722 |

## 10. Containment

**Component:** Reflex (the containment sandbox, PN-008.1, is sold with Checkpoint).

**Why customers buy this:** When something goes wrong, responders need narrow, fast, confirmed stops, plus a big red button for the whole org. Containment ranges from denying one action to an org-wide kill switch. It tracks confirmation path by path instead of assuming success.

| ID | Feature | What the backend delivers | Phase | Edition | Milestone | Source |
| --- | --- | --- | --- | --- | --- | --- |
| PN-005 | Asymmetric org kill switch | One eligible responder plus step-up engages it, bumping the containment epoch. Restoring needs two people, each with step-up. It pauses automations and revokes target credentials where supported, with p99 propagation under 1 s. | MVP | Community | M6 | new |
| PN-008.1 | Containment sandbox | `pclaw sandbox run` runs an agent in a container whose only network route is the gateway. The container holds no credentials, has a read-only filesystem, runs as non-root and can optionally use gVisor. | MVP | Community | M9 | F420 |
| F013 | Dependency & consequence previews | Before a destructive commitment, returns target count, scope, active dependent runs, waiting actions that would be invalidated, alternative paths and unknown dependencies. Emergency skips are recorded. | MVP | Community | M10 | F013, F263, F264, F604 |
| F077 | Response is not a decision | Quarantine, suspension and termination are recorded as response actions, separate from authorization decisions. | MVP | Community | M6 | F077 |
| F134 | Termination & in-flight work | Requests process or run termination where supported. Shows cancellation capability, request, confirmation and unresolved status for already-dispatched work. Revocation voids waiting approvals. | MVP | Community | M10 | F134, F135, F554 |
| F243 | Prefilled, narrow-first response | From an action or incident, proposes the affected runs, grants and connections and the known business impact. A narrow suspension commits immediately; wider scope shows its consequence first. | MVP | Community | M10 | F243, F556, F557 |
| F288 | Per-path containment confirmation | For each path: request time, operator, control, confirmation evidence, in-flight cancellation, failures, unsupported controls and remaining bypass exposure. Status stays partial while any material path is unresolved. | MVP | Community | M10 | F288, F558, F559, F560 |
| F541 | External (SOAR) response requests | SOAR tools can request supported scoped controls if they hold explicit response permission. Requests are audited with scope and reason, are idempotent, and return confirmed, failed, unsupported or unknown. | MVP | Business | M10 | F541–F544 |
| PN-024 | Shared Signals receiver | Accepts signed CAEP/RISC events from the customer's identity provider. User disabled, sessions revoked or credential compromised finds that person's grants and approvals; a preauthorized playbook suspends them, otherwise a case opens. | MVP | Business | M10 | F426, F562 |
| F545 | External governance preservation | Separation of duties and restoration rules apply to outside workflows too. Each synced incident field has one owner, and a ticket status change cannot restore authority. | Next | Business | post-1.0 | F545, F546 |
| F547 | Graduated response controls | Deny one action, hold consequential writes while reads continue, suspend a run, suspend an agent, or revoke a grant and its dependants. Each discloses remaining authority and shared-credential paths. | MVP | Community | M6 | F547–F551 |
| F552 | Connection & resource containment | Quarantine a connection (alternative connections stay visible), or protect a named resource where resource-level enforcement is supported. | MVP | Community | M10 | F552, F553 |
| F555 | Credential revoke/rotate | Revokes or rotates underlying credentials where supported, under the right authority, disclosing the impact on other workloads that share them. | MVP | Community | M10 | F555 |
| F561 | Future vs historical containment | "New access stopped" is confirmed separately from earlier reads, disclosures and accepted operations. | MVP | Community | M10 | F561 |
| F562 | Preauthorized response playbooks | Automatic run suspension and dependent-grant revocation happen only inside approved playbooks. Cases are opened where criteria do not match; wider credential or fleet action needs its own authority. | MVP | Business | M11 | F562, F695, F696 |
| F697 | Coverage recovery automation | A coverage-recovery template assigns an owner, pauses the affected launches and resumes them when coverage is restored. A diagnose-and-retest step comes later. | MVP | Team | M11 | F697 |
| F729 | Pause, cancel & revoke semantics | Pause stops new triggers according to the declared pending-trigger policy. Cancelling active executions is a separate scoped action, and each control reports its own verified effect. | MVP | Team | M11 | F729, F730, F731, F737 |
| F732 | Resume revalidation | Resuming rechecks authority, policy, resources, approvals and coverage. Missed irreversible work is never replayed automatically. | MVP | Team | M11 | F732, F733 |

## 11. Monitoring

**Component:** Reflex.

**Why customers buy this:** Security teams need signal, not call logs. Monitoring surfaces what needs attention, with freshness and gaps made explicit. New routes run in monitor mode first, and the event stream feeds the customer's SIEM.

| ID | Feature | What the backend delivers | Phase | Edition | Milestone | Source |
| --- | --- | --- | --- | --- | --- | --- |
| PN-013 | Monitor vs enforce per route | Each route runs in monitor mode (observe, record a hypothetical decision, never block) or enforce mode. Monitor is the onboarding default, and monitor records never claim prevention. | MVP | Community | M6 | F098 |
| PN-018 | OCSF SIEM export & signed webhooks | Exports OCSF 1.9 events with stable IDs, actors, decision reason, policy version, effects, coverage and uncertainty. Webhooks are signed per Standard Webhooks, payloads filtered per destination, links permission-checked. | MVP | Business | M10 | F534, F535, F536 |
| F211 | Operations work queue | Ranked items: active incidents and unconfirmed containment, important waiting decisions, protection failures and authority expansion. Each offers scoped actions: assign, suspend, revoke, open approval. | MVP | Community | M10 | F211, F214 |
| F212 | Freshness-qualified summary | Summarises response needs, expiring approvals and coverage changes, stamped with scope and time. "No critical issues" is never presented as an estate-wide safety claim. | MVP | Community | M10 | F212, F213 |
| F215 | Focused live stream | An SSE stream of first sensitive use, significant writes, new or expanded authority and unexpected denials. Routine reads stay searchable, retries are grouped, and a cursor supports pause and resume. | MVP | Community | M10 | F215–F218 |
| F219 | Evidence status & gaps | Every item carries a timestamp, freshness and outcome. Missing telemetry shows as a gap with a last-seen time, never as a quiet interval. | MVP | Community | M10 | F219, F220, F640 |
| F221 | Automation exceptions | Blocked launches, stalled approvals, failed containment, repeated recovery failure and changed authority go to owners, while routine success stays quiet. Usefulness is measured in completed work, not trigger counts. | MVP | Team | M11 | F221, F222, F623, F752, F753 |
| F301 | Posture & operating metrics | Time series for coverage and staleness, consequential outcomes, bypass-route age, exposure by resource group, reconciliation backlog and automation outcomes, each drillable to its records. | MVP | Team | M10 | F301, F302 |
| F537 | Delivery health | Last delivery, delayed and failed records, and retries; stable IDs make retries dedupable. "Configured" is kept separate from "delivery confirmed". Failures that threaten audit coverage surface in Operations. | MVP | Business | M10 | F537–F540, F638 |
| F603 | Evidence-based grouping | Groups by run, identity, authority change, target or connection failure only when the relationship is supported. Retry groups show first and latest, count and whether any attempt executed. Mere similarity is labelled "possible". | MVP | Team | M10 | F603, F613, F614, F615 |
| F607 | Attention levels | Six levels: searchable telemetry, live activity, finding, alert, incident and immediate page. Paging is reserved for credible ongoing harm or critical enforcement loss. | MVP | Team | M10 | F607–F612 |
| F616 | Suppression without evidence loss | Test denials never page production responders. Muting needs a scope and an expiry, and muted conditions stay discoverable. Greater severity, new scope or failed containment reopens them. | MVP | Team | M10 | F616–F619 |
| F620 | Notifications & digests | Notifications say what happened, why it matters, current containment, remaining exposure and the next action, filtered by data permissions. Daily digests summarise decisions and authority changes, with verified delivery. | MVP | Team | M10 | F620, F621, F622 |
| F641 | Owned operational failures | Each failure record names an owner, the affected scope, a deadline and the next diagnostic step. | MVP | Community | M10 | F641 |

## 12. Threat Detection

**Component:** Reflex.

**Why customers buy this:** Agent attacks look like legitimate tool use until you see the sequence. Detections over decisions, dispatches and tool definitions catch tool poisoning, rug pulls, exfiltration patterns and authority abuse, mapped to MITRE ATLAS and the OWASP agentic risks.

| ID | Feature | What the backend delivers | Phase | Edition | Milestone | Source |
| --- | --- | --- | --- | --- | --- | --- |
| PN-006.1 | Detection engine | CEL detection rules over sliding windows of decisions, dispatches, effects and tool definitions, with signed detection content. Each rule maps to MITRE ATLAS and the OWASP Top 10 for Agentic Applications (2026). Custom rules are Business. | MVP | Community | M10 | new |
| PN-006.2 | Tool poisoning & rug pull | Flags instruction-like content in tool descriptions and any drift from the reviewed package definition. Drift quarantines the definition and opens a TOOL_REVIEW entry. | MVP | Community | M10 | new |
| PN-006.3 | Self-authorization & key misuse | Detects attempts by agents to create, expand or approve their own authority, and the same workload key used from a new network. | MVP | Community | M10 | new |
| PN-006.4 | Sequence & probing detections | Read→external-disclosure sequences, denial and probing bursts, approval variant-shopping, and budget splitting across runs or children. The approval variant-shopping rule is Community: it implements HR-037, and hardening rules are never edition-gated (G0 M10 D5). | MVP | Business | M10 | new |
| PN-006.5 | Delegation & automation anomalies | Delegation-depth anomalies, and automation loops detected across trigger ancestry. | MVP | Business | M10 | new |
| F399 | Behaviour & configuration drift | Detects behaviour or target-configuration change even when the tool name and schema are unchanged. Findings show old vs new evidence and the impacted agents, policies, transactions and owners. | MVP | Business | M10 | F399, F400 |
| F401 | Drift invalidation | Drift quarantines affected definitions and rules, invalidates coverage and waiting approvals, and stops dependent automation steps. Unaffected items continue only with verified independence. | MVP | Community | M10 | F401, F403 |
| F648 | Evidence vs inference | Detections keep observed facts, deterministic rule matches, inferred suspicion and causal hypotheses separate. | MVP | Community | M10 | F648 |
| F734 | Automation loop prevention | Trigger ancestry detects self-loops and reciprocal loops. Per-event and per-period action limits apply, and a stopped loop opens one grouped issue. | MVP | Team | M11 | F734, F735, F736 |

## 13. Investigation

**Component:** Reflex.

**Why customers buy this:** After an alert, teams must answer what happened, under whose authority, and what else is affected. Investigation turns any action into an evidence-linked case, backed by permission-safe search and graph data.

| ID | Feature | What the backend delivers | Phase | Edition | Milestone | Source |
| --- | --- | --- | --- | --- | --- | --- |
| F237 | Cases from actions | Opening a suspicious action creates a persistent case with the linked task, run and prior context. The sequence, authority, effects, reach, related-activity and response lenses share one selection and time range. | MVP | Team | M10 | F237, F238 |
| F239 | What actually happened | Shows whether the action was allowed, held, denied, observed, dispatched or effect-confirmed. Traces the launcher, principal, grantor and any delegation. | MVP | Community | M10 | F239, F240 |
| F241 | Preceding context & correlation | Queries recent grant changes, new tools and external-content provenance, plus destinations, resources, credentials, documents, sequences and tool changes shared across runs. | MVP | Team | M10 | F241, F242, F316 |
| F244 | Facts, hypotheses, open questions | Separate case fields for evidence-linked confirmed facts, hypotheses with confidence and alternatives, and open questions. Observed impact is kept apart from potential exposure. | MVP | Team | M10 | F244–F247 |
| F248 | Injection & sensitive-read evidence | Links suspicious external content and sensitive reads to later actions, without asserting causation beyond the evidence. | MVP | Team | M10 | F248, F285 |
| F249 | Case collaboration & handoff | Owners, annotations, evidence preservation, related-action queries, and export or handoff to existing security workflows. Updates add evidence and never overwrite notes or conclusions. | MVP | Team | M10 | F249, F250 |
| F251 | Case closure rules | Closure requires containment state, confirmed or explicitly unresolved impact, a follow-up owner, a disposition and evidence. Operational containment can close while forensic questions stay open. | MVP | Team | M10 | F251, F252 |
| F272 | Activity & causal graph data | Graph APIs for agent–principal–resource activity and for transaction causality (authority, approval, custody, direct and downstream effects). Observed ≠ possible, and causal links need trigger evidence. | MVP | Team | M10 | F272, F273, F279, F280, F281 |
| F289 | Shared graph semantics | Distinct activity, authority, exposure and change modes. One edge vocabulary (endpoints, decision, coverage, execution, effect, evidence basis, revisions, time, expiry) with explicit edge states. Historical edges are kept but excluded from current authority. | MVP | Team | M10 | F289–F292 |
| F293 | Graph scope, filters & provenance | Graphs start from one task, agent, incident or resource group, with filters for time, run, agent, operation, decision, outcome and principal. Gaps survive collapsing, and every edge carries freshness and provenance. | MVP | Team | M10 | F293–F297 |
| F298 | Permission-safe graph tables | Every graph has an equivalent tabular endpoint. Expansion, counts, summaries and exports apply tenant and data permissions, so hidden records cannot be inferred. | MVP | Community | M10 | F298, F300 |
| F304 | Structured & natural-language search | Structured search over permission-scoped evidence (MVP). Natural-language queries (Next) show the generated query, environment, range, timezone and event meaning: attempt or confirmed. | MVP | Community | M10 | F304, F305 |
| F306 | Built-in investigative queries | Production access, why an action was allowed, who can write a resource, payment-capable tools, unused grants, actions for a principal, connection dependencies, widest exposure, denials and recent authority changes. | MVP | Community | M10 | F306–F315 |
| F317 | Search result integrity | Results state scope, evidence range, freshness and omissions. Live results are marked as changing while historical ranges stay stable. Results can be saved or shared within permissions, and every answer links to supporting evidence. | MVP | Community | M10 | F317–F321 |
| F430 | Credential-exposure investigation | After a credential exposure, lists every known dependent identity and route. | MVP | Team | M10 | F430 |
| F627 | Explicit empty results | Empty incident or search results say whether there was nothing in scope, no data collected, or restricted data, with evidence range and coverage. | MVP | Community | M10 | F627, F628 |

## 14. Breach Radius

**Component:** Reflex.

**Why customers buy this:** Before and during an incident, the question is how far an agent could reach. Breach radius separates what actually happened, what grants allow, and what raw credentials allow, and it drives remediation.

| ID | Feature | What the backend delivers | Phase | Edition | Milestone | Source |
| --- | --- | --- | --- | --- | --- | --- |
| F253 | Three exposure views | Computes observed effects, effective reach through grants and policy, and technical credential or bypass reach as three separate views. | MVP | Team | M10 | F253, F254, F255 |
| F256 | Reachable-resource analysis | Resource groups with permitted operations, sensitivity, task limits, downstream delegation, expiry and coverage confidence, plus an agents × read/export/update/delete/transfer/delegate matrix. | MVP | Team | M10 | F256, F286 |
| F257 | Explainable prioritisation | Ranks by consequence, scope, present usability, enforceability, ownership and remediation readiness. There is no unexplained universal score. | MVP | Team | M10 | F257 |
| F258 | Live reach recomputation | Recomputes after grant, policy, resource or coverage changes and labels stale dependencies. Distinguishes usable, conditional, expired and uncertain rights. | MVP | Team | M10 | F258, F261 |
| F259 | Authority-reduction actions | Revoke grants, remove capabilities or isolate connections, with before/after reach and expected workflow disruption previewed. | MVP | Team | M10 | F259, F271 |
| F260 | Reach drill-down | Inspect the targets, authority paths, credential relationships and affected runs behind any reach figure. Shared credentials list every dependent workload. | MVP | Team | M10 | F260, F428 |
| F262 | Automation latent exposure | Shows each automation's current execution reach and its maximum future grant-issuance ceiling, with a pre-enable blast-radius preview and restriction comparison. A quiet schedule is not treated as low risk. | MVP | Business | M11 | F262, F747–F750, F754 |
| F265 | Posture remediation queue | Findings for excessive grants, uncovered paths, unowned agents, unsafe delegation, stale credentials, unused authority and unverified sensitive tools, grouped by root cause with history. | MVP | Business | M10 | F265, F266, F267 |
| F268 | Finding lifecycle & closure | `Open → Assigned → Testing → Remediated`, `Accepted temporarily` or `Evidence incomplete`. Closure requires proof that the change reaches affected paths; dismissing an alert never closes exposure. | MVP | Business | M10 | F268, F269, F270 |
| F274 | Authority, exposure & change graphs | Graph data for verified issuers and grants, effective vs credential reach, narrowed child delegation, and before/after restriction comparison. | MVP | Team | M10 | F274, F275, F276, F282 |
| F299 | Evidence-based containment comparison | Earlier reads and impact questions persist after revocation. Removing an edge alone never proves closure. | MVP | Team | M10 | F299 |

## 15. Proof (evidence)

**Component:** Trail.

**Why customers buy this:** Auditors, insurers and incident reviewers need evidence that stands on its own. Linked signed receipts, a transparency-anchored chain and offline verification prove what was decided, dispatched and observed, and each states its own limits.

| ID | Feature | What the backend delivers | Phase | Edition | Milestone | Source |
| --- | --- | --- | --- | --- | --- | --- |
| PN-007.1 | Signed receipts | Decision, execution and effect receipts are Ed25519-signed JWS over canonical JSON (RFC 8785). Each carries a `simulated` flag and never contains secrets. | MVP | Community | M7 | F514 |
| PN-007.2 | Hash chain & checkpoints | After commit, a per-org chainer links receipts and audit events into a hash chain, with signed Merkle checkpoints per window. Export history and publication identities can be inspected. | MVP | Community | M7 | F509 |
| PN-007.3 | Transparency anchoring | A global root over all org checkpoints is anchored to Sigstore Rekor v2 with an RFC 3161 timestamp, without revealing tenant activity. Later rewriting or insider re-signing becomes detectable. | MVP | Team | M7 | new |
| PN-007.4 | Offline `pclaw verify` | Verifies signatures, chain continuity, consistency proofs and anchors offline, and reports exactly what was checked. Integrity proves neither completeness nor that an external effect occurred. | MVP | Community | M7 | F510, F511 |
| PN-007.5 | Post-quantum dual signature | An optional ML-DSA-65 signature alongside Ed25519 on checkpoints and evidence-pack manifests, which cover every receipt through the Merkle tree (G0 M7 decision 6). Receipts keep `sigs[]` reserved for a later per-receipt signature. | MVP | Enterprise | M7 | new |
| F005 | Append-only, consistent evidence | Later observations are appended, and original decisions and target responses are never rewritten. The same action returns identical evidence through every API path. | MVP | Community | M7 | F005, F465 |
| F068 | Secret-safe evidence | Secrets are removed from all normal views and exports. Restricted evidence needs separate authority and every access is audited; platform admins get no automatic payload access. | MVP | Community | M7 | F068, F514, F516 |
| F461 | Three linked receipts | Decision receipt (identity, grant, action, versions, facts, coverage, reason), execution receipt (effective action, access mode, attempts, dispatch, response) and effect receipt (verifier, level, observed state, limits), linked per transaction. | MVP | Community | M7 | F461–F464 |
| F466 | Evidence explorer API | Inspect receipts, observations, revisions, consent, integrity status and gaps; compare records; drill into grants, approvals, policies, definitions and coverage snapshots; and request reconciliation. | MVP | Community | M7 | F466, F467, F468 |
| F469 | Honest missing evidence | Expired or deleted payloads show as unavailable, while the action's existence is kept. Nothing is reconstructed or invented, and contradictory records are never collapsed into one success label. | MVP | Community | M7 | F469, F470, F521 |
| F471 | Execution states | `REQUESTED`, `BLOCKED`, `WAITING`, `AUTHORIZED`, `DISPATCHED`, `ACCEPTED`, `FAILED`, `CANCELLED`. Permission ≠ dispatch ≠ success ≠ verified effect. | MVP | Community | M7 | F471–F479 |
| F480 | Effect states | Confirmed, none confirmed, partial, propagation pending, conflicting, unverifiable, unknown and compensated. "Verified" always states the result, scope and basis. | MVP | Community | M7 | F480–F488 |
| F489 | Domain & multi-target meaning | Distinguishes, for example, an accepted refund from actual settlement. Multi-target outcomes list which targets reached the expected state and which are partial, pending or unknown. | MVP | Community | M7 | F489, F490 |
| F491 | Verification levels | Transport/acceptance, follow-up state read, domain-effect confirmation and downstream confirmation. Shows required vs achieved level, verifier identity and limits. If required verification is unsupported, authorization stops. | MVP | Community | M7 | F491–F497 |
| F498 | Verifier deadlines & dependent waits | Contradictory observations are kept together. Verifier deadlines yield pending, unknown or unverifiable, and dependent steps wait for the qualifying effect state. | MVP | Community | M7 | F498, F499, F500 |
| F501 | Reconciliation queue | Unknown outcomes become owned RECONCILIATION entries that keep budget reservations. Recovery and compensation are new authorized transactions linked to the original, and never claim an exact reversal. | MVP | Community | M7 | F501, F502, F503, F637 |
| F504 | Decision replay | Replays a decision with its retained inputs, or under a proposed policy, and explains which inputs differ. Reports an incomplete replay when context is missing, and never sends the target action. | MVP | Community | M7 | F504–F508 |
| F414 | Downstream verification | Supported downstream consequences are verified separately from direct acceptance, and follow-on work waits for the required state. | Next | Team | post-1.0 | F414, F415 |
| F512 | Retention categories | Retention is set per category: payload captures, normalised facts (replay inputs, observed values), receipts, approvals and security audit. Versions stay while a retained receipt references them; traces live outside the database. | MVP | Community | M7 | F512, F513, F524 |
| F515 | Permission propagation | Source permissions apply to search, summaries, graphs, counts, packs, exports and channel notifications. | MVP | Community | M7 | F515, F522 |
| F517 | Export & deletion controls | Packs and bundles download with holds and removal records; organization export and deletion run through data requests. Evidence export destinations come later. | MVP | Community | M7 | F517–F520 |
| F525 | Evidence collections & packs | Collections covering decision and execution history, grant lifecycle, policy versions, tests and rollout, approvals, response and coverage. Transaction and incident packs export a selected scope with linked receipts. | MVP | Team | M7 | F525, F526 |
| F527 | Complete, honest packs | Packs include all relevant versions, every effect state (not just successes), containment and recovery evidence, privacy metadata, evidence-pinned graphs and explicit audit gaps. They never claim compliance certification. | MVP | Team | M7 | F527–F532 |
| F533 | Automation evidence | Exports include trigger, workflow version, step transactions, consent and effect receipts. Completion summaries resolve to actual completion evidence. | MVP | Team | M11 | F533 |

**Delivery status of the M7 rows (M7 exit, 2026-10-11; [g0/M7.md](g0/M7.md) exit status).** The rows above stay the planned scope; this list says what the backend delivers now. *Delivered*: built and tested by the HR-190..199, T-070..077 and `TestE2E_M7_*` tests. *Partly*: the part named is built, the rest is planned where stated.

- **Delivered:** PN-007.1, PN-007.2, PN-007.4, PN-007.5 (checkpoints and pack manifests, off by default), F005, F068, F461, F469, F471, F491 (`downstream` is defined, no package uses it; F414 stays post-1.0), F501, F504, F512 (versions are kept while a retained receipt references them; traces live outside the database), F527.
- **Delivered, one live step open:** PN-007.3. Anchoring is tested against a local Rekor v2 log and timestamp authority and against recorded Sigstore responses; the first run against Sigstore's public services publishes an entry and waits for the founder's agreement.
- **Partly:** F466 (the explorer, integrity status, gaps and reconciliation requests; coverage snapshots arrive with M9). F480 (every state except `PARTIAL`, "some intended changes occurred", which needs actions with several targets or verified effect kinds, out of M7's scope; a cooperative channel's effects carry the `PARTIAL` coverage label instead). F489 (domain-effect level and limits text; one result per declared effect kind, multi-target actions later). F498 (deadlines; dependent waits F500 in M11). F515 (packs, bundles and explorer queries follow the caller's permissions; search, graphs and summaries arrive with M10). F517 (download only; holds and removal records; destinations in M10). F525 (transaction, run, agent and time-range packs; incident packs and the other collections in M10 and M11). Payload captures are kept and read, but not yet placed in packs: a pack that asks for them records the gap.
- **Elsewhere, marked M7:** F131 (pillar 6) is delivered: M4's dedupe and tampering checks, and M7's reconciliation, which parks an unknown irreversible outcome until evidence or a person resolves it. In pillar 9, F231 and F236 hold by construction (effect receipts are appended; inspection works from receipts, without transcripts). F065, F224, F227 and F229 (the run inspector, run budget and approval history, unresolved-run evidence) are not in G0 M7's scope; a run's transactions, effects and gaps are reachable through `pclaw txn list --run` and a run's evidence pack. The founder decides their milestone (exit status, founder items).

## 16. Coverage & Bypass Resistance

**Component:** Checkpoint.

**Why customers buy this:** A firewall that can be bypassed is just a log. Coverage records prove, per workload, target and effect, whether every equivalent route is mediated, and they downgrade automatically when that proof expires.

| ID | Feature | What the backend delivers | Phase | Edition | Milestone | Source |
| --- | --- | --- | --- | --- | --- | --- |
| PN-008.2 | Sandbox route-closure evidence | Trusted sidecar probes inside the containment sandbox test that every non-gateway route is closed. Passing results can promote coverage to `ENFORCED`, which expires on schedule. | MVP | Community | M9 | F455, F457 |
| F090 | Uncontrolled-action labelling | Actions outside coverage are labelled observed/uncontrolled, never given an invented allow or deny. A blocked attempt is shown alongside partial coverage when equivalent routes remain. | MVP | Community | M6 | F090, F091 |
| F277 | Bypass & coverage graph data | A per-route graph of MCP, API, Git/SSH, browser and other routes to the same effect, separating tested control from possible or unverified bypass, with the aggregate boundary state. | MVP | Team | M9 | F277, F278 |
| F329 | Scoped coverage card | After onboarding, states which path was tested and names the tools that remain uncovered. | MVP | Community | M9 | F329 |
| F353 | Capability & enforcement tests | Sensitive capabilities need explicit approval. Harmless tests and deliberately prohibited actions verify that stopping works, and tested coverage is published separately. Drift or failed tests become visible coverage changes. | MVP | Community | M9 | F353–F356, F360 |
| F433 | Scoped coverage records | Per workload or cohort, target, account, resource class and effect: channels, equivalent routes, controls, validation, exclusions, time, expiry, invalidating changes, owner and next verification. | MVP | Community | M9 | F433, F434 |
| F435 | Four coverage states | `UNKNOWN`, `OBSERVE_ONLY`, `PARTIAL`, `ENFORCED`. `ENFORCED` applies only when every material route is mediated or proven blocked for the declared boundary and time window. | MVP | Community | M9 | F435–F438 |
| F439 | Coverage freshness | Coverage is kept separate from policy correctness, tool meaning and outcomes, and freshness rules are published. Expiry or a failed refresh downgrades at once; the last valid record and the reason it lapsed are kept. | MVP | Community | M9 | F439–F442 |
| F443 | Equivalent-route inventory | Lists every route that can cause the same effect: MCP/tool, direct API/SDK, host (shell, CLI, Git, SSH, mounted keys, retrievable credentials), delegated agents, CI/CD, webhooks, schedules, queues and target-side identities. | MVP | Community | M9 | F443, F444, F445, F447, F448, F449 |
| F446 | Browser-session routes | Authenticated browser sessions and user contexts are inventoried as equivalent routes. | Later | Business | post-1.0 | F446 |
| F451 | Coverage workbench | Per-route usability, credentials, controls, tests, freshness and exclusions, with links to assign owners (posture findings), remove access, connect controls, run permitted sandbox probes and verify closure. | MVP | Community | M9 | F451, F452 |
| F453 | Coverage invalidation | Credential, identity, build, host, delegation, egress, channel, meaning or test changes trigger reassessment. Stale coverage follows the declared policy and never silently drops the requirement. | MVP | Community | M9 | F453, F456 |
| F454 | Evidence-only promotion | Automated maintenance gathers evidence, proposes routes and re-tests controls. Coverage is promoted only from retained evidence, never from model confidence. | MVP | Team | M9 | F454, F455 |
| F457 | Route-specific closure | Each closure records the tested identity and effect, blocking control, scope and reopen conditions, with before/after comparison. Revoking a token does not close a browser session or SSH key. | MVP | Community | M9 | F457, F458, F459 |
| F460 | No configuration-based badges | Setup alone never yields `ENFORCED` or a protection percentage. Fleet confidence comes from verified coverage, not inventory size, and each integration declares its supported actions and exclusions. | MVP | Community | M9 | F460, F605, F768 |

## 17. Red-team Range (Adversarial Sandbox)

**Component:** Trail.

**Why customers buy this:** Customers need to know their configuration holds before an attacker tests it. The adversarial range runs realistic agent attacks against the tenant's real policies on simulated targets, and gates CI on regressions.

| ID | Feature | What the backend delivers | Phase | Edition | Milestone | Source |
| --- | --- | --- | --- | --- | --- | --- |
| PN-009.1 | Range engine & community scenarios | `pclaw redteam run` runs attack scenarios against the tenant's real policies, grants and packages, using simulated targets. Core scenarios ship publicly. | MVP | Community | M12 | new |
| PN-009.2 | Full scenario library | ≥ 30 scenarios: self-authorization, approval replay, TOCTOU swap, budget races, split payments, delegation escalation, tool poisoning, rug pull, injection→exfiltration, parser differentials, SSRF, DPoP replay, stolen token, cross-tenant ID guessing. | MVP | Business | M12 | new |
| PN-009.3 | Simulator-only execution | Scenarios touch only `pantherclaw-sim` targets with fault injection, and their receipts are marked `SIMULATED`. No real credentials or customer systems are used, and no dangerous real tool is ever probed. | MVP | Community | M12 | F746 |
| PN-009.4 | Assurance reports | Per scenario: expected vs actual decision, decisive control and evidence links. Reports cover functional, boundary, recovery and explanation evidence, and never certify compliance. | MVP | Team | M12 | F769–F772 |
| PN-009.5 | CI regression gate | CI integration fails the pipeline when a policy, grant or package change lets a previously blocked scenario succeed. | MVP | Team | M12 | new |
| PN-009.6 | Custom scenarios | Customers write scenarios for their own tools and workflows on the same simulator harness. | Next | Business | post-1.0 | new |
| F630 | Simulation labelling | Simulated, demo and range data are clearly labelled. They never count as real coverage, blocked work or onboarding proof. | MVP | Community | M12 | F630 |

## 18. Deployments

**Component:** Root (platform).

**Why customers buy this:** Buyers differ on where control and credentials may live. PantherClaw runs self-hosted, with a customer-run gateway, hybrid or as SaaS, and it tracks where each agent is actually deployed.

| ID | Feature | What the backend delivers | Phase | Edition | Milestone | Source |
| --- | --- | --- | --- | --- | --- | --- |
| PN-010.1 | Self-hosted single node | `pclaw up` starts server, worker, gateway and PostgreSQL through Docker Compose profiles, using signed, distroless, non-root images. Supports Community production within licence limits. | MVP | Community | M1 | new |
| PN-010.2 | Customer-run gateway | The gateway runs inside the customer network with no database access and outbound-only mTLS. Target credentials and payloads never leave that network. | MVP | Community | M6 | new |
| PN-010.3 | Hybrid (hosted control plane) | A PantherClaw-hosted control plane and console with customer-run gateways; this is the intended commercial default. Product code in UI; general availability at v1.0 after M13 hardening. | MVP | Team | UI | new |
| PN-010.4 | SaaS | Multi-tenant hosted control plane and gateways. PantherClaw-hosted gateways run as one process per organization on shared hosts, each in its own isolated container with a certificate naming that one organization, provisioned from records by a worker job and a host agent and reached through a per-org hostname with SNI passthrough (Team and above, one per organization). No third-party MCP servers run in hosted gateways. | Next | Team | M19 | new |
| PN-010.5 | Agent deployment inventory | Tracks where each agent runs (environment, image digest, host, release) from enrollment and attestation. A new digest or host triggers identity-drift reassessment. | MVP | Community | M3 | F028, F033 |
| PN-010.6 | Hybrid fleet management | Register, version and health-check many customer gateways across multiple orgs. | Next | Enterprise | post-1.0 | new |
| PN-010.7 | High availability | Redundant control plane and gateways on managed HA PostgreSQL. No single point of failure on the decision path: rate limits, stream caps and A2A ownership hold across replicas, every decision-path cache has a stated staleness bound, the server connects to several database hosts and makes no decision while no read-write primary answers, and workers run with two or more replicas. Database loss without a standby is still a fail-closed outage. | Next | Enterprise | M19 | new |
| PN-019.1 | FIPS 140-3 build | A build variant with `GOFIPS140=v1.0.0` (the pinned validated module, reproducible; G0 M13 D35), using standard-library cryptography only. | MVP | Enterprise | M13 | new |
| PN-019.2 | Post-quantum TLS by default | TLS 1.3 with post-quantum hybrid key exchange, on by default for all listeners and outbound connections. | MVP | Community | M13 | new |
| F523 | Honest residency commitments | Residency and retention commitments match what each deployment mode actually supports. | MVP | Community | M13 | F523 |

## 19. Performance

**Component:** Root (platform).

**Why customers buy this:** Authorization in the hot path has to be fast enough that teams leave it switched on. PantherClaw publishes and tests its latency, propagation and concurrency SLOs, and defines safe degraded behaviour.

| ID | Feature | What the backend delivers | Phase | Edition | Milestone | Source |
| --- | --- | --- | --- | --- | --- | --- |
| PN-011.1 | Transactional path latency | `Authorize` (decision plus permit) p99 ≤ 25 ms; gateway overhead p99 ≤ 35 ms at 1k rps, 2 vCPU, co-located; gateway RSS < 150 MB. Local figures are published in docs/perf/M13.md; the staging run is pending. M19 keeps decision snapshots read-only and retries a busy budget row once inside the Authority, from a fresh snapshot (docs/perf/M19.md); the targets stay targets, not gates. | MVP | Community | M13, M19 | new |
| PN-011.2 | Fast/monitor path latency | Monitor mode with a cached signed policy and asynchronous evidence: p50 < 2 ms, p99 < 5 ms. Conflicts with HR-001 and HR-184; needs an ADR (founder 2026-10-28). | Next | Community | post-1.0 | new |
| PN-011.3 | Revocation propagation | Revocation, suspension and kill-switch events reach gateways at p99 < 1 s. A gateway whose heartbeat is more than 2 s old fails closed. | MVP | Community | M13 | new |
| PN-011.4 | Zero overspend under concurrency | No overspend with 1,000 concurrent reservations against one budget, proven by a race test in CI. | MVP | Community | M13 | F114 |
| PN-011.5 | Degraded modes | When PantherClaw is unreachable, gateways and SDKs fail closed with a clear stop. A pre-authorised, time-limited read continuation (F632) comes later. | MVP | Community | M13 | F631, F632 |
| F773 | Published operating evidence | SLOs were validated on the M1.5 walking skeleton and measured in M13 (docs/perf). Each release states freshness, continuity and operating limits. Nightly k6 and benchstat trends come later. | MVP | Community | M13 | F773 |

## 20. Management (teams, admin, commercial, installation)

**Component:** Root (platform).

**Why customers buy this:** Adoption depends on installing in minutes and administering at scale. Management covers tenancy, roles, licensing, metering, support access and onboarding, plus the API contract the later UI will build on.

| ID | Feature | What the backend delivers | Phase | Edition | Milestone | Source |
| --- | --- | --- | --- | --- | --- | --- |
| PN-022.1 | Platform foundation | Protobuf contracts served over Connect RPC (gRPC and JSON over HTTP), generated OpenAPI, structured redacted logs and OpenTelemetry. The `pclaw` CLI is a first-class API client. | MVP | Community | M1 | new |
| PN-022.2 | Walking skeleton | An end-to-end thin slice (enrolled workload, MCP call, decision, permit, dispatch to a simulator, signed receipt) that runs in CI and sets the first latency baselines. | MVP | Community | M1.5 | new |
| PN-021 | Tenant isolation & service auth | Every tenant row carries `org_id` under forced row-level security, and cross-tenant IDs return not-found. Services use `private_key_jwt` or scoped `pck_` keys that can never approve; gateways use mTLS. | MVP | Community | M2 | new |
| PN-012.1 | Editions & offline licence keys | Ed25519-signed licence documents (org, edition, agent limit, expiry, features) are verified offline against an embedded key. Licence expiry never disables enforcement or evidence. | MVP | Community | M13 | new |
| PN-012.2 | Entitlements, metering & plan limits | Meters governed agents, orgs and retention against entitlements. At the limit, new agent admission is refused with a clear error, while existing protection continues. | MVP | Community | UI | new |
| PN-012.3 | Invitations & membership | Single-use, expiring invitations add users to organisation and team roles. Membership changes are audited. | MVP | Community | UI | new |
| PN-012.4 | Customer-approved support access | Support access is requested for a named task and duration, approved by the customer, visible in scope and audited. Support has no standing access to credentials or restricted payloads. | MVP | Enterprise | M13 | F597, F598 |
| PN-012.5 | Data export & deletion | Tenant-wide export of records and evidence, and verified tenant deletion that keeps a deletion record. | MVP | Community | M13 | new |
| PN-012.6 | Effortless installation | The installer verifies release signatures and attestations. `pclaw up` starts a node, and `pclaw init` detects and configures MCP clients, SDKs and Claude Code hooks. Helm chart for Kubernetes. | MVP | Community | M13 | new |
| F014 | Plain-language API vocabulary | The API and docs use task grant, action definition, reviewed tool package, protection boundary, coverage evidence and transaction evidence. Formal names appear only in advanced evidence fields. | MVP | Community | M1 | F014 |
| F322 | One-workflow developer onboarding | Start from one agent, owner and dev environment: verify identity, list tools and uncovered paths, choose a template, and name resources, operations, limits and duration. | MVP | Community | UI | F322, F323, F324 |
| F325 | Guided first tests | Run a safe action, a permitted action and an out-of-scope action. Then enforce one named path and confirm that the prohibited test is stopped. | MVP | Community | UI | F325, F326, F327 |
| F330 | Developer debugging | Denials return the decision ID, failed boundary, redacted request, effective grant and policy, failing category (identity, scope, approval, context, connection) and recovery links. A case opens with one call. | MVP | Community | M4 | F330, F331, F332 |
| F335 | 30-minute onboarding target | Measured goal: one verified insight and one verified protected path in about 30 minutes, for a supported integration with credentials available. Not a guarantee. | MVP | Community | UI | F335 |
| F336 | Security-team onboarding | Start from one owner, consequential tool and task. Confirm ownership, compare credential reach with authority, connect identity and classification sources, review representative work and simulate a restriction. | MVP | Team | UI | F336–F340 |
| F341 | Onboarding validation | Verify an enforced deny, a working approval and a suspension. Completion requires ownership, usable authority, decision explanation and stopping capability, shown on the customer's own workflow. | MVP | Team | UI | F341, F342, F345 |
| F343 | Dependency-led recommendations | Recommends identity, classification, approval and incident connections based on discovered needs, stating what each enables and what stays unsupported. | Next | Team | post-1.0 | F343, F344 |
| F573 | Organisation hierarchy | Organisation → business unit → team → environment. Small tenants use only organisation and environments; business units are Business, and multiple organisations are Enterprise. | MVP | Community | M2 | F573 |
| F581 | Roles & separation of duties | Default roles: Agent Owner, Policy Author, Policy Publisher, Approver, Responder and Auditor. Platform administration never implies business approval rights or payload access. | MVP | Community | M2 | F581, F583 |
| F584 | Delegated administration | Scoped administrators per business unit, team or fleet segment, each accountable within their scope. | Next | Enterprise | post-1.0 | F584 |
| F585 | Platform audit | Administrators, integrations, privileged changes, evidence access and response actions are recorded in the signed evidence ledger, each under its own permissions. | MVP | Community | M2 | F585 |
| F594 | Break-glass access | Emergency access is narrow, time-limited, step-up authenticated and separately audited. It never waives invariants or fabricates verification. | MVP | Business | M13 | F594 |
| F647 | Material limits always returned | Decision and evidence responses never omit gaps, grant scope, expiry, cumulative budgets, decision reasons, unknown outcomes or requested vs confirmed containment, and each says what to do next. | MVP | Community | M4 | F647, F651 |
| F774 | Outcome metrics | Time to protected work, to understanding a decision and to containment. Also coverage, bypass closure, change assurance, friction, outcome assurance, automation usefulness and operating effort; raw volume is never claimed as value. | Next | Business | post-1.0 | F774–F785 |
| F001 | Work surfaces | Operations, Agents, Policies, Approvals, Investigations, Connections and Automations, with universal search. Posture sits inside Operations, workbenches are embedded in their surfaces, and settings stay outside daily work. | MVP | Team | UI | F001, F002, F008 |
| F006 | Role views & pinned entries | Saved views per role (developer, SOC, security, IAM, platform, CISO, auditor, approver) and pinned Work, Protect, Configure, Operations and Audit entries, all over the same records and permissions. | MVP | Team | UI | F006, F007 |
| F009 | Stable, scoped navigation | Org, team, environment and time range are always visible. Drill-down keeps filters and selection, and live updates never reorder items under review. | MVP | Team | UI | F009, F010, F011 |
| F012 | Accessibility & formats | Keyboard operation and accessible status text; meaning is never carried by colour alone. Tables for ranking, timelines for sequence; fast-comprehension goals are usability targets. | MVP | Team | UI | F012, F223, F303 |
| F643 | Progressive disclosure | One-agent setup comes first. Repeated-work, team and enterprise governance controls appear as needed, with role-appropriate next steps and a layout organised around tasks and consequences. | MVP | Team | UI | F643–F646, F649, F650 |

**Edition note (F001, F006, F009, F012, F643).** These rows describe the web console, which is part of the paid hosted offering (Team; founder decision F2 of G0 UI). The server-rendered approval and confirmation pages, the CLI and the API stay Community.

**Web console, hosted accounts and plans (milestone UI; [G0 UI](g0/UI.md)).** The console, the website and the demo are built in the commercial distribution from the core plus the extension point; the core rows below (accounts, plans, the gate, onboarding progress, test seams) are in this repository.

| ID | Feature | What the backend delivers | Phase | Edition | Milestone | Source |
| --- | --- | --- | --- | --- | --- | --- |
| PN-025 | Website and interactive demo | A static public website and an interactive demo of the real console on simulated data in the browser: no sign-up, no server, its own origin, no cookies. | MVP | Community | UI | new |
| PN-026 | Hosted accounts, self-serve organizations and paid plans | On the hosted control plane people sign in through a hosted OIDC provider, create an organization, choose a plan through a merchant-of-record payment provider and invite teammates. A lapse never weakens enforcement. | MVP | Team | UI | new |
| F803 | Public website | Product, how it works, security, pricing, early access, privacy and terms pages; claims stay within stated boundaries; no third-party scripts or cookies; visits counted from edge logs only, without a script. | MVP | Community | UI | new |
| F804 | Early-access sign-up | A minimal form (email, name, company, role, consent text version) protected without a third-party bot check (honeypot, minimum fill time, rate limit); no raw IP stored; nothing else collected; deleted on request. | MVP | Community | UI | new |
| F805 | Book a demo | A link to an external booking page; no third-party script runs on PantherClaw's pages. | MVP | Community | UI | new |
| F806 | Guided demo tour | A skippable, resumable keyboard tour: a held merge approved by a simulated key, the same merge by direct API call, a found token failing, receipts, the kill switch, a case; each step shown as its role. | MVP | Community | UI | new |
| F807 | Demo isolation | A permanent "Interactive demo · SIMULATED data" banner; state kept in memory only and reset on request; the demo runs on its own origin and calls no API. | MVP | Community | UI | new |
| F808 | Console shell | Operations, Agents, Policies, Approvals, Investigations, Connections and Automations, with universal search and a command menu; settings sit outside daily work. Served by the server at `/app/` under a strict content security policy. | MVP | Team | UI | new |
| F809 | Scope bar and stable lists | Organization, team, environment and time range kept in the URL; drill-down keeps filters; live lists show a "new items" notice instead of reordering items under review. | MVP | Team | UI | new |
| F810 | Role landing views | A default landing page and pinned entries for each role (developer, SOC, security, IAM, platform, CISO, auditor, approver); visibility follows the caller's permissions, and authorization stays on the server. | MVP | Team | UI | new |
| F811 | Approvals in the console | Queue, detail with the binding summary and an untrusted-text box, approve or decline with a security-key binding challenge, batch review; the server confirmation page stays canonical. | MVP | Team | UI | new |
| F812 | Agents surface | Inventory, owners, lifecycle, the admission waitlist, enrollment, runs, grants, cohorts and the promotion gate. | MVP | Team | UI | new |
| F813 | Operations surface | Live feed, posture, the coverage card and the kill switch behind a step-up; designed empty, loading and error states. | MVP | Team | UI | new |
| F814 | Connections surface | Gateways, connections, routes, coverage, packages and credential metadata only; secrets are never shown. | MVP | Team | UI | new |
| F815 | Policies surface | Drafts and publication, validation, scenario tests, simulation, shadow and pilot rollout, exceptions, templates and packs. | MVP | Team | UI | new |
| F816 | Investigations surface | Alerts, incidents, cases, breach radius, containment, reconciliation, the evidence explorer and evidence packs. | MVP | Team | UI | new |
| F817 | Automations surface | Definitions, versions, triggers, the execution inspector and shadow mode. | MVP | Team | UI | new |
| F818 | Untrusted text display | Agent-written text is shown only as text: bidirectional controls stripped, mixed scripts flagged, length clamped, in a labelled box; unsafe rendering is banned by lint rules. | MVP | Team | UI | new |
| F819 | Step-up in the console | High-consequence actions ask for a fresh security-key step-up before the call; no optimistic updates on security actions. | MVP | Team | UI | new |
| F820 | Themes and accessibility | Dark and light themes; WCAG 2.2 AA with no serious or critical automated findings; keyboard-only paths for approvals, the kill switch and onboarding; status always icon, word and colour. | MVP | Team | UI | new |
| F821 | Console settings | Organization, members and roles, sign-in and SSO, security keys, API keys and service accounts, notifications, plan and billing. | MVP | Team | UI | new |
| F822 | Hosted sign-in and organization picker | Signing in without naming an organization: no membership gives an account session (when self-serve is on), one opens it, several show a picker; switching organization signs in again. | MVP | Team | UI | new |
| F823 | Self-serve organization creation | A signed-in account with a verified email creates an organization within per-account limits and rate limits, becomes its admin and records the terms and data-processing versions accepted. | MVP | Team | UI | new |
| F824 | Browser invitations | An invitation link is accepted in the browser after sign-in, only when the verified email equals the invitation's; single use, with expiry. | MVP | Community | UI | new |
| F825 | Plan and usage view | Plan, status, limits, usage (agents, environments, members), period end and complimentary-plan expiry for the caller's organization. | MVP | Community | UI | new |
| F826 | Plan gate that keeps protection on | Without an active plan, configuration changes and new agents or connections answer `PLAN_REQUIRED`; enforcement, safety actions and open approvals keep working, and evidence stays exportable for at least 30 days. | MVP | Team | UI | new |
| F827 | Checkout and billing portal | Choosing a plan opens checkout with a merchant-of-record payment provider; the plan activates from the provider's signed events; invoices and cancellation through the provider's portal. | MVP | Team | UI | new |
| F828 | Complimentary plans | With hosted billing, an operator grants or revokes a complimentary plan from the command line, with a reason and an expiry of at most one year; audited, shown, never overriding a self-hosted licence. | MVP | Community | UI | new |
| F829 | Test access and deployment banner | Development sign-in providers, billing off or faked, and the console's mock mode are adapters chosen by configuration, shown by a permanent banner and refused in production. | MVP | Community | UI | new |
| F830 | Guided hosted onboarding | Resumable steps from sign-in to a first protected path, guided tests and validation, computed on the server from real records; simulated records never complete a step. | MVP | Team | UI | F322, F325, F335, F336, F341 |

## Product boundaries (non-goals, kept verbatim in spirit)

These boundaries constrain every pillar above. A feature request that conflicts with one of them needs an explicit product decision; it is never a silent exception.

| ID | Boundary | What it means for the backend | Source |
| --- | --- | --- | --- |
| F786 | Connected boundary only | Governs only connected, supported enforcement points, and discloses uncontrolled tools, credentials, routes and exclusions. | F786 |
| F787 | Not an identity provider or log warehouse | Uses existing human identity sources. Stores attributable actions and their consequences, not unrestricted log collection. | F787, F788 |
| F789 | No prompt-safety guarantee, no surveillance | Makes no claim that instructions, plans or model outputs are safe. Never requires raw conversations or hidden reasoning for core protection. | F789, F792 |
| F790 | Not an agent builder | Customers bring their own agents. Governed automations coordinate them; they are not an unrestricted builder or orchestration platform. | F790 |
| F791 | No universal rollback | Completed transfers, deletions and disclosures may be irreversible. Compensation is a new, separately authorized action. | F791 |
| F793 | No self-widening authority | Suggestions and automations cannot widen their own response authority. Production permission changes go through governed publication, and a denial never leads to more privilege. | F793, F794, F795 |
| F796 | No guessed command rewriting | Shell commands are never rewritten by guessing what was meant. | F796 |
| F797 | No security theatre | No unrelated threat-feed dashboards or decorative exposure graphs. Scores never replace identity, grants, constraints or required evidence. | F797, F798, F799 |
| F800 | No destructive auto-response by default | Automatic response requires explicit preauthorization. Suspicion alone never triggers org-wide revocation; the kill switch is a human action. | F800 |
| F801 | No unsupported or invented assurance | A connection, graph, demo, short-lived credential, signature or success response proves nothing on its own. Missing, stale, unknown, partial, pending, conflicting and unverifiable states stay visible and owned. | F801, F802 |

## Commercial vocabulary map

| Sales term | Component | Pillar | Anchor features | Claim boundary |
| --- | --- | --- | --- | --- |
| Inventory of agents | Badge | 1 | F003, F016, F017, PN-010.5 | Covers discovered and enrolled agents only |
| Effortless installation | Root | 20 | PN-012.6, PN-010.1, F322, F325 | The 30-minute target is measured, not guaranteed; from M13 `install.sh` verifies checksums and, with `gh`, the build attestation, and `pclaw up` and the Helm chart install a node (G0 M13 D36) |
| Lifecycle | Badge | 3 | F020, F023, F563 | Restoring is a governed action, never automatic |
| Agent controls | Guardrails | 8 | F110, F114, F120, F104 | Enforced on mediated routes |
| Discovery | Badge | 2 | PN-001.1, PN-001.2, F015 | "Not observed" is not "absent" |
| Containment | Reflex | 10 | PN-005, F547, F288, PN-008.1 | Confirmed per path; in-flight requests complete |
| Monitoring | Reflex | 11 | PN-013, F211, F215, PN-018 | Monitor mode never claims prevention |
| Threat detection | Reflex | 12 | PN-006.1–PN-006.5 | Detections are inference, labelled as such |
| Authorisation | Pass, Guardrails | 5 | F038, F081, F092, F179 | Decisions apply to covered actions |
| Investigation | Reflex | 13 | F237, F244, F306 | Answers link to evidence or are not given |
| Concrete identity & authority protocol | Badge | 4 | PN-002.1–PN-002.8 | Attestation level is always stated |
| Non-bypassable transaction boundary | Checkpoint, Stash | 6 | PN-003.1–PN-003.5, PN-015.1, F416 | Only where pillar 16 shows `ENFORCED` |
| Proof | Trail | 15 | PN-007.1–PN-007.4, F461 | Integrity ≠ completeness ≠ business effect |
| Breach radius | Reflex | 14 | F253, F256, F262 | Possible reach is kept separate from observed impact |
| Waitlist | Pass | 7 | PN-004.1–PN-004.5, PN-020.1 | Expiry means deny |
| Deployed | Root | 18 | PN-010.1–PN-010.7 | Hybrid from v1.0 (product code in UI); SaaS post-1.0 |
| Session | Reflex | 9 | F224, F284, PN-002.5 | No transcripts required |
| Performance | Root | 19 | PN-011.1–PN-011.5 | SLOs are targets: M13 optimises with a fixed effort on the staging server and publishes the measured numbers with their test conditions; v1.0 is not blocked on reaching them (G0 M13 F7) |
| Management | Root | 20 | PN-012.1–PN-012.5, F573, F581 | Licence expiry never disables enforcement; support access needs the customer's approval every time and never reads credentials; deletion is verified and recorded in a signed deletion record (G0 M13 D32, D34) |
| Bypass-resistant enforcement | Checkpoint | 16 (with 6, 10) | F435, F443, PN-008.2 | Per route, with current, expiring evidence |
| Red-team range (adversarial sandbox) | Trail | 17 | PN-009.1–PN-009.5 | Simulated targets only; separate from the containment sandbox (PN-008) |

## Traceability

- Every catalog requirement F001–F802 appears in the Source column of at least one row above. Pillars 1–20 cover F001–F785, and the product-boundaries table covers F786–F802. Where a capability spans pillars, an F-ID may appear in several rows; the catalog wording stays authoritative for behaviour.
- The engineering requirements SG01–SG14 (catalog Appendix A, [`security/GATES_AND_REVIEW.md`](security/GATES_AND_REVIEW.md)) are not product features and are tracked separately.
- **How to cite:** tests name the IDs they verify, in the test name or a `Covers:` comment (e.g., `Covers: F114, F118, PN-011.4`). PR descriptions list the F-IDs and PN-IDs they implement or change. A row counts as done only when every ID in its Source cell has at least one passing test, and its PN-ID, if it has one, has at least one too.
- When this file changes, rerun the coverage check below and update the counts.

## Coverage verification

Checked on 2026-10-09 by a script that parsed every table row with a Source column and expanded the ranges, after ADR-0017, ADR-0018 and ADR-0019 added PN-002.8, PN-016.3, PN-023 and PN-024 and moved four rows to M14; row counts updated on 2026-10-20 after G0 UI added PN-025, PN-026 and the new rows F803–F830.

- **Rows:** 370 in total: 360 pillar rows (81 of them PN rows covering 26 new features, PN-001–PN-026; 28 new-feature rows F803–F830) and 10 boundary rows.
- **Coverage:** 802 of 802 catalog IDs (F001–F802) appear in at least one Source cell. None are missing and none are out of range.
- **Format checks:** every row ID matches its convention, and no row ID repeats. Every Phase, Edition and Milestone value is valid. Every "What the backend delivers" cell is ≤ 36 words.

The index below lists which pillars cite each catalog group (catalog numbering).

| Catalog group | IDs | Pillar(s) citing it |
| --- | --- | --- |
| 01. Unified product workspace | F001–F014 | 1, 9, 10, 15, 20 |
| 02. Agent inventory and lifecycle | F015–F025 | 1, 2, 3 |
| 03. Verified identity and actor attribution | F026–F037 | 4, 18 |
| 04. Task grants and effective authority | F038–F054 | 2, 4, 5, 7 |
| 05. Child agents and authority lineage | F055–F065 | 4, 5, 8, 9 |
| 06. Action cards and decision explanations | F066–F080 | 5, 10, 15 |
| 07. Runtime evaluation and final authorization | F081–F099 | 5, 6, 7, 11, 16 |
| 08. Safe constraints and transformations | F100–F109 | 7, 8 |
| 09. Cumulative budgets and reservations | F110–F119 | 8, 19 |
| 10. History, sequence, and timing controls | F120–F130 | 6, 8 |
| 11. Retries, changed requests, and in-flight work | F131–F138 | 6, 10 |
| 12. Exact approvals and stronger authentication | F139–F160 | 7 |
| 13. Approval channels, routing, and workload management | F161–F171 | 7 |
| 14. Task templates and policy editor | F172–F184 | 5 |
| 15. Suggestions, tests, and simulation | F185–F198 | 5 |
| 16. Policy rollout, rollback, and exceptions | F199–F210 | 5 |
| 17. Live Operations | F211–F223 | 11, 20 |
| 18. Run and session inspector | F224–F236 | 9 |
| 19. Unified investigations | F237–F252 | 10, 13 |
| 20. Risk and blast-radius analysis | F253–F262 | 14 |
| 21. Dependency previews and posture remediation | F263–F271 | 10, 14 |
| 22. Evidence-backed graphs and visual analysis | F272–F303 | 5, 9, 10, 11, 13, 14, 16, 20 |
| 23. Universal search and saved queries | F304–F321 | 13 |
| 24. Developer onboarding and debugging | F322–F335 | 2, 3, 16, 20 |
| 25. Security-team onboarding and expansion | F336–F345 | 20 |
| 26. Capability-aware integration catalog and connection lifecycle | F346–F360 | 2, 6, 16 |
| 27. Customer-defined integrations and external signals | F361–F371 | 5, 6 |
| 28. Reviewed tool packages and action definitions | F372–F387 | 6 |
| 29. Tool meaning workbench, assurance, and drift | F388–F404 | 6, 12 |
| 30. Downstream-consequence authorization | F405–F415 | 5, 15 |
| 31. Credential custody and access detail | F416–F432 | 4, 6, 10, 13, 14 |
| 32. Continuous scoped coverage records | F433–F442 | 16 |
| 33. Equivalent routes and coverage maintenance | F443–F460 | 2, 6, 16 |
| 34. Linked transaction receipts and evidence explorer | F461–F470 | 15 |
| 35. Execution lifecycle states | F471–F479 | 15 |
| 36. Effect-result states and safe progression | F480–F490 | 15 |
| 37. Verification levels, sources, deadlines, and reconciliation | F491–F503 | 15 |
| 38. Decision replay and receipt integrity | F504–F511 | 15 |
| 39. Privacy, retention, and evidence permissions | F512–F524 | 15, 18 |
| 40. Evidence collections, packs, and export | F525–F533 | 15 |
| 41. SIEM/SOAR delivery and external response | F534–F546 | 10, 11 |
| 42. Scoped incident response and emergency controls | F547–F562 | 10 |
| 43. Deliberate restoration and recovery | F563–F572 | 3 |
| 44. Organization scope, inheritance, and roles | F573–F585 | 1, 5, 20 |
| 45. Protected changes, emergency authority, and support access | F586–F599 | 5, 7, 20 |
| 46. Fleet organization and bulk administration | F600–F606 | 1, 10, 11, 16 |
| 47. Notifications, attention levels, and suppression | F607–F623 | 11 |
| 48. Empty states and operational failures | F624–F642 | 1, 4, 5, 6, 7, 11, 13, 15, 17, 19 |
| 49. Progressive disclosure and experience quality | F643–F651 | 12, 20 |
| 50. Automation types, inventory, and definition | F652–F664 | 5 |
| 51. Triggers, schedules, authenticity, and replay safety | F665–F677 | 5 |
| 52. Automation editor and draft validation | F678–F690 | 5 |
| 53. Useful automation templates | F691–F700 | 2, 5, 7, 10 |
| 54. Authority at every automation execution | F701–F714 | 5 |
| 55. Automation execution inspector and completion states | F715–F722 | 9 |
| 56. Automation retries, partial completion, pause, and loop prevention | F723–F737 | 5, 10, 12 |
| 57. Automation tests, simulation, shadowing, and rollout | F738–F746 | 5, 17 |
| 58. Automation exposure and owner confidence | F747–F754 | 5, 11, 14 |
| 59. Supported resource domains and concrete governed workflows | F755–F768 | 5, 6, 16 |
| 60. Capability evidence and product outcome measures | F769–F785 | 17, 19, 20 |
| 61. Explicit product boundaries and prohibited shortcuts | F786–F802 | Product boundaries |
