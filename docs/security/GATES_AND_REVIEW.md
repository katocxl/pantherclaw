# PantherClaw — Secure Engineering Gates & Review (SG01–SG14, G0–G4)

This document absorbs the former *Secure Engineering Plan* (v1.0, 2026-10-07) and makes it operational for a solo founder with a $0 budget. It governs how PantherClaw itself is built; it does not add approvals to customers' routine actions.

## 1. Engineering requirements and where they are satisfied

| ID | Requirement | Where implemented | Status |
|---|---|---|---|
| SG01 | Security constraints approved before coding; given to generating models | Per-milestone **G0 brief** (§5); [BUILD_GUIDE.md](../BUILD_GUIDE.md) §3 rules | In progress |
| SG02 | Versioned threat model, maintained | [THREAT_MODEL.md](THREAT_MODEL.md) | Implemented (pending verification) |
| SG03 | Layering, least privilege, zero trust, validation boundaries | [ARCHITECTURE.md](../ARCHITECTURE.md), [SECURITY_BASELINES.md](SECURITY_BASELINES.md) SB-1 | Implemented (pending verification) |
| SG04 | Explicit authentication baseline | SB-2, [PAP-1.md](../protocol/PAP-1.md) | Implemented (pending verification) |
| SG05 | Explicit encryption & key management | SB-3 | Implemented (pending verification) |
| SG06 | Explicit security logging | SB-4 | Implemented (pending verification) |
| SG07 | Dependency & build policy | [DEPENDENCY_POLICY.md](DEPENDENCY_POLICY.md) | Implemented (pending verification) |
| SG08 | Constrained AI-assisted scaffolding | §6 generation brief; generated code follows same gates | In progress |
| SG09 | Continuous automated scanning & failure-path tests | SB-6, `.github/workflows/` | In progress |
| SG10 | Structured model security review | §6 review brief; `ai-review.yml` | In progress |
| SG11 | Independent multi-model review | Claude (claude-code-action) + CodeRabbit (different vendor) | Planned (CodeRabbit install pending) |
| SG12 | Human review at every critical stage | §3 gates; EX-001 for independence | Exception active (EX-001) |
| SG13 | Versioned OWASP/CWE baseline | [OWASP_CWE_MAPPING.md](OWASP_CWE_MAPPING.md) | Implemented (pending verification) |
| SG14 | Findings, exceptions, truthful completion evidence | [FINDINGS.md](FINDINGS.md), §4, private advisories | In progress |

"Implemented (pending verification)" for documents means the artifact exists; "Verified" requires the gate decision referencing an exact revision.

## 2. Decision register (formerly "decisions that must be made before coding")

| Decision | Resolution (2026-10-08) | Record |
|---|---|---|
| Implementation boundaries | Go modular monolith server + separate gateway PEP; layering rules | ARCHITECTURE, ADR-0001/0002 |
| Authentication | SB-2 + PAP/1 | SECURITY_BASELINES, PAP-1 |
| Encryption | SB-3 (stdlib, AES-GCM, HPKE X-Wing, Ed25519, TLS 1.3 PQ hybrid) | ADR-0012 |
| Logging | SB-4 | SECURITY_BASELINES |
| Dependencies | DEPENDENCY_POLICY | ADR-0008 |
| Automated checks | SB-6 table | ADR-0008 |
| Model reviewers | Generator: Claude (Claude Code). Reviewer A: Claude via claude-code-action with security-review brief (separate config/context). Reviewer B: CodeRabbit (different vendor/model) | §6 |
| Review baseline | OWASP Top 10:2025, API Top 10 2023, ASVS 5.0.0, CWE Top 25 2025, Agentic Top 10 2026 | OWASP_CWE_MAPPING |
| Human accountability | Founder (Joshua Kato) holds all roles; independence gap covered by EX-001 | §4 |

## 3. Gates

| Gate | When | Required evidence | Decision by | How recorded |
|---|---|---|---|---|
| **G0** — before implementation | Start of each milestone (and any security-critical component) | G0 brief (§5): scope, threat slice (T-IDs), hardening rules (HR-IDs), constraints, ADRs, tests to write, open decisions | Founder | Entry in §7 + `g0` label on the milestone tracking issue |
| **G1** — before merge | Every PR (suspended by EX-004) | `ci-ok` green; Claude review + CodeRabbit review addressed (disagreements noted); PR security checklist; updated threat/HR/traceability if affected; founder review after ≥ 1 h cooling-off | Founder | PR approval comment "G1: approved <sha>" + squash merge |
| **G2** — release promotion | Every tag | Nightly suites green on the candidate; open findings reviewed; SBOM; changelog; threat-model delta | Founder | `release` environment approval |
| **G3** — production deployment | Deploying to any non-local environment | G2 evidence; artifact digest; target config; rollback plan | Founder | Deployment environment approval |
| **G4** — material change / incident | New boundary, new critical dependency, incident recovery | Updated THREAT_MODEL; re-run affected suites; recovery evidence | Founder | §7 entry + THREAT_MODEL change log |

Material changes to security-critical code after a G1 approval invalidate that approval (new push ⇒ re-review). A failed or unavailable required check blocks the gate; it is never relabeled as passed.

## 4. Exceptions

| ID | Exception | Scope | Owner | Compensating controls | Review | Expiry |
|---|---|---|---|---|---|---|
| **EX-001** | No independent human reviewer (SG12 independence; repo rulesets use 0 required approvals + admin bypass) | All PRs and releases | Founder | Two AI reviewers from different vendors; mandatory CI incl. invariant/adversarial suites; ≥ 1 h cooling-off before self-review; G0 briefs written before code; signed, attested releases; all findings tracked | Every 90 days (next: 2027-01-08) | When a second engineer joins |
| EX-002 | Local commits unsigned until founder configures an SSH agent | Local branches | Founder | `main` only receives GitHub-signed squash merges via PR; rulesets require signed commits on `main` | 30 days | Founder adds signing key + agent |
| EX-003 | Go 1.27.2 adopted inside the 7-day cooldown (DEPENDENCY_POLICY §1.3) to fix GO-2026-6617 / CVE-2026-97032, a remotely triggerable HTTP/2 server crash reachable from the server, gateway and `pclaw` (founder decision 2026-10-09) | Go toolchain only (`go.mod` toolchain lines, Linux test image) | Founder | Official Go security release; toolchain checksums verified through the Go checksum database; image pinned by digest; full CI on the change | — | Lapses on 2026-10-15, when 1.27.2 leaves the cooldown |
| **EX-004** | CI and G1 are suspended for development speed (founder decisions 2026-10-09): every workflow except `release.yml` is disabled, Dependabot opens no PRs and CodeRabbit does not review. The `main` ruleset requires a pull request and nothing else: no status checks, approvals, signed commits or linear history, and it blocks force-pushes and deletion of `main`. Sessions open pull requests and only the founder merges them ([PARALLEL_WORK.md](../PARALLEL_WORK.md)). Supersedes EX-002's signed-commit control | All development on `main` | Founder | Before opening a pull request the session runs `task check` (format, headers, lint, unit tests, secret scan), plus `task test:integration` and `task trace` where the change needs them, and reports the results in the pull request. `release.yml` and the `release-tags` ruleset still guard tags | Before the first release tag | Re-enable the workflows (`gh workflow enable`), restore the ruleset's required checks and signatures, and restore G1, before tagging a release |

Exceptions never override product invariants or turn missing evidence into completed controls.

## 5. G0 brief template

```markdown
### G0 — <milestone/component> — <date>
Scope: <what will be built; what will not>
Threat slice: T-### … (from THREAT_MODEL)
Hardening rules in scope: HR-### …
Product requirements: F### / PN-### …
Contracts: <protos, schemas, migrations touched>
Security constraints: authn/authz, tenancy, crypto, logging, input limits, failure semantics
Dependencies to add (with justification): …
Tests to write first: TestHR###_…, TestT###_…, invariants, races, negative cases
Open decisions (block affected code until resolved): …
Decision: APPROVED / BLOCKED — Joshua Kato
```

## 6. Model briefs (SG08, SG10, SG11)

**Generation brief (given to the coding model with each task):**
> Implement only the named component from the approved G0 brief and ARCHITECTURE revision. Apply the stated tenant boundaries, authority constraints, input/output contracts, approved dependencies, crypto and logging baselines, and failure semantics (DENY / CANNOT_AUTHORIZE / HOLD / UNKNOWN). Identify missing security decisions before writing affected code. Write the tests named in the brief first. Never grant extra authority, disable checks, add unapproved dependencies, log secrets, or use real secrets/customer data.

**Independent review brief (both reviewers):**
> Review the exact revision against the G0 brief, THREAT_MODEL, HARDENING_RULES and SECURITY_BASELINES. (1) Identify insecure patterns in changed code and relevant call paths; (2) propose concrete safer alternatives with trade-offs; (3) explain attack vectors: entry point, attacker capability, preconditions, affected asset, consequence; (4) map to OWASP/CWE categories in OWASP_CWE_MAPPING. Inspect tenancy, authn/authz, input handling, secrets/crypto/logging, dependencies, and the product invariants (approval binding, revocation, budgets, coverage, evidence). For each finding give file/function, evidence, uncertainty, fix, and a verifying test. Report missing context; model confidence is not proof.

Reviewer independence: reviewers see the same brief and revision but not each other's output before producing findings; disagreements are kept and adjudicated by the founder in the PR. Model independence is procedural, not statistical.

## 7. Gate decision log

| Date | Gate | Scope | Revision | Decision | Notes |
|---|---|---|---|---|---|
| 2026-10-08 | G0 | M0 bootstrap (docs, IP/legal, skeleton, CI/CD, repo security) | plan `i-am-building-an-async-swan` | APPROVED (founder approved plan) | Founder decisions: Go; public repo; BSL 1.1 core + Apache SDKs; 4 integrations; solo founder (EX-001) |
| 2026-10-08 | G0 | M1 platform foundation — scope per BUILD_GUIDE §8 M1; threat slice T-003, T-016, T-034, T-041; HR-004, HR-050..057, HR-062, HR-063, HR-104 | initial `main` commit | APPROVED (pending founder confirmation at first M1 PR) | Decisions locked in ADR-0001..0012; full brief and implementation decisions in [g0/M1.md](../g0/M1.md) |
| 2026-10-08 | G0 | M1.5 walking skeleton — scope per BUILD_GUIDE §8 M1.5; threat slice T-010, T-011, T-012, T-021, T-022, T-024, T-031; HR-001, HR-003, HR-004, HR-008, HR-009, HR-070..075, HR-110 | `m15/01-actionir` | APPROVED in principle (founder instruction "M1, then M1.5"; confirmation at first M1.5 PR) | Brief, exit status and open decisions in [g0/M1.5.md](../g0/M1.5.md); measurements in [perf/M1.5.md](../perf/M1.5.md); ADR-0015 proposed |
| 2026-10-08 | G0 | M2 tenancy & service authentication — scope per BUILD_GUIDE §8 M2; threat slice T-003, T-032, T-037, T-043; HR-095, HR-104, HR-050..057 for new tables | `m2/01-schema` | APPROVED (founder answered the four design questions before implementation) | Brief in [g0/M2.md](../g0/M2.md); decisions in ADR-0016 |
| 2026-10-08 | G0 | M4 part 1: tool packages, action definitions, ActionIR mapping, CEL policy engine (domain/app only; runs in parallel with M2); threat slice T-018, T-020, T-023, T-036 (and T-001 scope); HR-023, HR-040..043, HR-100..103, HR-123, HR-124 (HR-007, HR-044 partial) | `m4/01-g0-definitions` | APPROVED (founder, 2026-10-09, confirmed with the part-2 brief: recommended option on decisions 1–4) | Brief and four open decisions (metadata expiry, customer package signing, dev package root, CEL cost defaults) in [g0/M4.md](../g0/M4.md); grants, budgets, facts and the decision pipeline wait for parts 2–3 |
| 2026-10-09 | G0 (plan change) | Coding and DevOps agents as the first market; delivery order M1…M9, M12 → v0.1.0 → M10, M11, M14, M13 → v1.0; M8 narrowed to coding-agent integrations, new M14 for framework SDKs and business connectors; M3 adds trusted-issuer L2 attestation and RFC 8693 subject tokens at `StartRun` | `docs/product-components` | APPROVED (founder, 2026-10-09: "i approve of the decisions") | ADR-0017, ADR-0018, ADR-0019 accepted; one product sold in editions and the pricing unit (agent record plus instance allowance) decided; component brand names accepted (Badge, Pass, Guardrails, Checkpoint, Stash, Reflex, Trail; Root for the platform, [PRODUCT.md](../PRODUCT.md)) |
| 2026-10-09 | G0 | M3 agents & PAP/1 identity — scope per BUILD_GUIDE §8 M3 and ADR-0018 (inventory and lifecycle, enrollment and admission, workload tokens and proofs, trusted-issuer L2 with GitHub Actions and Kubernetes presets, server-minted runs with subject tokens, gateway discovery); threat slice T-001 (run binding), T-004, T-032, T-033, T-035, T-044..T-050; HR-022, HR-090..094, HR-140..148 | `docs/m3-g0-brief` | APPROVED (founder, 2026-10-09: answered the four open decisions, recommended option each time, and confirmed design decisions 5–8) | Brief, the ADR-0018 constraints as HR-140..148 and T-044..T-050, and the four founder decisions (pull-request bots run from a protected-branch workflow; a separate human-only issuer-activation role; Kubernetes clusters in operator configuration; `pclaw scan` stays in M3) in [g0/M3.md](../g0/M3.md); builds on #53 (merged as b0dc16b) |
| 2026-10-09 | G0 | M4 part 2: grants, guardrails (envelopes) and lattice bounds, delegation and revocation, budgets with ancestor debiting, counters, fact providers, the 10-step decision pipeline with checklist, receipts, idempotency and repeat protection, and adapters for the part-1 ports; threat slice T-001, T-008, T-011, T-012, T-023, T-055; HR-005..007, HR-045..049, HR-160, HR-161 | `m4/201-g0-brief` | APPROVED (founder, 2026-10-09: "G0 approved, recommended on all 7") | Brief, the new HR-160, HR-161 and T-055, and seven open decisions in [g0/M4.md](../g0/M4.md): four still open from part 1, restated (package list expiry, customer package signing, a development package key, CEL cost limits) and three new (delegation limits and grant lifetimes, the repeat-protection window, who may issue grants). Slices with migrations stack on M3 #55; API slices wait for M3 |
| 2026-10-09 | G0 | M5 part 1: browser sessions (OIDC authorization code + PKCE), CSRF defences, WebAuthn registration and session-bound step-up, notifications (log, SMTP, Slack deep link, Standard Webhooks) with bounded retries and delivery health; runs in parallel with M3 and M4 part 2; threat slice T-037 (M5 part), T-021 (webhooks), T-041, T-051..T-054; HR-150..159 (groundwork for HR-032, HR-033, HR-035, HR-039) | `docs/m5-g0-brief` | APPROVED (founder, 2026-10-09: "use the recommended", option (a) for all four decisions) | Brief, the new rules HR-150..159 and threats T-051..T-054, and the four decisions (`go-webauthn` v0.18.2; a fresh provider sign-in or a step-up to add a key; all channel kinds in Community up to 3 channels; a counter regression suspends the key) in [g0/M5.md](../g0/M5.md); migrations `00030`+ merge only after M4 part 2's `00020`–`00029` |
| 2026-10-09 | G0 | M5 part 2: approval requests with the binding hash, transaction-bound step-up (WebAuthn `BINDING`), eligibility, independence and the n-person rule, invalidation and expiry at use, HOLD caps and variant history, the server-rendered approval page, decline, evidence requests and narrower proposals, the Agent Waitlist (six entry types, priority, deadlines, routing and escalation through part-1 notifications, wait handles over long-poll and SSE, batch review and SLA metrics for Team), access requests and agent restorations; threat slice T-002, T-005, T-006, T-007, T-026, T-027, T-060..T-063; HR-030..037, HR-039, HR-170..177 | `docs/m5-part2-g0-brief` | APPROVED (founder, 2026-10-10: "Recommended on all 11", option (a) each time) | Brief, the new rules HR-170..177 and threats T-060..T-063, eleven founder decisions (answered) and design decisions 12–22 in [g0/M5.md](../g0/M5.md). The decisions: which approvals need a security key; what a requirement's role means; whether every approval is independent; a step-up by a non-person; approver cooldowns; deadlines; hold caps; escalation defaults; batch limits; who files access requests; who restores agents. Migrations from `00032`; the pipeline and end-to-end slices wait for M4 part 2's slice 216 |
| 2026-10-09 | G0 | M6 gateway & non-bypassable boundary — scope per BUILD_GUIDE §8 M6 (gateway enrollment and mTLS, containment stream, kill switch, connections and modes, credential custody, the package-driven HTTP and MCP faces, action tokens, the Claude Code hook, S01–S13); threat slice T-009, T-010, T-012, T-013, T-015, T-019, T-021, T-022, T-025, T-028, T-030, T-031, T-065..T-069; HR-001, HR-002, HR-008, HR-010, HR-011, HR-020, HR-021, HR-038, HR-060, HR-061, HR-073, HR-076..083, HR-092, HR-113, HR-180..188 | `m6/01-g0-brief` | PENDING (the four open decisions answered by the founder on 2026-10-09, the recommended option each time; approval of the whole brief on its pull request) | Brief, HR-180..188, T-065..T-069 and the PAP-1 §6–§8, §10 clarifications in [g0/M6.md](../g0/M6.md). Decisions: S02/S04/S05, HR-011 and HR-038 stack on M5 part 2; an emergency-stop page with step-up for the kill switch; the connector runtime (HR-084, HR-085) moves to M9; the Claude Code hook fails closed and dogfooding is opt-in. Migrations `00040`–`00049` |
| 2026-10-10 | Process change (EX-004) | Sessions open a pull request and stop; the founder merges every pull request on GitHub. Removes `tools/scripts/land.sh`, the landing queue and the lander (`task land`, `land:serve`, `land:status`), which had replaced the founder's merges earlier the same day | `chore/remove-land-workflow` | APPROVED (founder, 2026-10-10: "just create the prs and i will do the merges myself with the web") | CLAUDE.md, PARALLEL_WORK.md, CONTRIBUTING.md and EX-004 restored to the pull-request-only text |
| 2026-10-10 | G0 | M7 effects, reconciliation & proof — scope per BUILD_GUIDE §8 M7 in two parallel tracks: A (verifiers leased to the gateway, effect states and receipts, execution receipts kept, reconciliation of `UNKNOWN` outcomes with a person-only release, target-log reconciliation, compensation links, the evidence explorer) and B (Merkle tiles and signed checkpoints, the blinded global root anchored in Rekor v2 with an RFC 3161 timestamp, `pclaw verify` offline, decision replay, retention and legal holds, restricted payload capture, evidence packs); threat slice T-029, T-013, T-024, T-043, T-070..T-077; HR-110 (wording), HR-111, HR-112, HR-003 and HR-007 (resolution), HR-190..199 | `docs/m7-brief` | PENDING (the eight open decisions answered by the founder on 2026-10-10, the recommended option each time; approval of the whole brief on its pull request) | Brief, HR-190..199, T-070..T-077 and the PAP-1 §7.4, §9.2–§9.4, §11 clarifications in [g0/M7.md](../g0/M7.md). Decisions: the gateway makes verification reads on leased tasks; evidence resolves an unknown only towards "occurred", and a release needs an independent person with a bound security-key assertion; anchoring with our own standard-library client, configured endpoints, Team edition; retention removes bodies and keeps hashes; replay keeps each evaluation's sealed inputs; ML-DSA-65 co-signs checkpoints and pack manifests only; opt-in payload capture; two parallel tracks. No new dependencies. Migrations `00060`–`00069` |
| 2026-10-10 | Design decision (ADR-0015) | Budget settlement off the hot row, on the M4 budget accounts and counters: (1) asynchronous settlement — outcomes record reservations settled and pending, the sweep job applies them in batches in the HR-048 lock order, and a new `budget_settle` purpose of the audited lister finds the orgs (HR-053, HR-054); (2) a fail-fast lock timeout on budget and counter rows (`authority.budget_lock_timeout`, 100 ms) that answers `CANNOT_AUTHORIZE` `BUDGET_BUSY`. (3) escrow slots stays deferred | `perf/budget-settlement-off-hot-row` | ACCEPTED (founder, 2026-10-10: "Parts 1 and 2") | Answered the open M1.5 decision; implementation notes in [ADR-0015](../adr/0015-budget-settlement-off-the-hot-row.md#as-implemented); `TestHR048_NoOverspendUnder1000ConcurrentAuthorizations` is unchanged and a fail-fast variant is added |
