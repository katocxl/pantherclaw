### G0 — UI — Web console, hosted accounts and plans — 2026-10-20

This brief is written before implementation (G0). It lists planned scope; delivery status is tracked by the UI pull requests and, at the end of the milestone, in an exit status section. It builds on `main` at a9acf15c (M1–M12, the v0.1.0 preview, M11.1, M10, M11 part 2 and M14 complete; the highest migration is 00154, and 00155–00159 stay unused). The founder made fifteen decisions (F0–F14) on 2026-10-20 before the brief was written and confirmed the plan as written (F13); they are recorded at the end. Every other choice is a design decision made by the coordinator (D1–D40 in the coordinator's tracker), summarised below. Parts that live only in the commercial distribution (the distribution built from the core plus the extension point) are described here only as far as the core depends on them.

**Purpose:** PantherClaw has a complete backend, an API and `pclaw`, but no web console and no way for a new customer to start on their own: sign-in needs an existing organization, organizations are created by an operator, invitations are accepted only from the CLI, and editions come from one server-wide licence. The founder moved the UI phase ahead of M13 (F0) and decided that PantherClaw hosts the control plane and the console while customers run the gateway and `pclaw` (the hybrid deployment, F1). Milestone UI delivers the web console over the existing API, hosted accounts with self-serve organizations and browser invitations, per-organization plans with a gate that never weakens protection, onboarding computed from real records, test access without payments or a real sign-in (F9), and a public website with an interactive demo on simulated data (F4, F6). The core gains an extension point so that the commercial distribution adds the console, billing and cloud operations without the public repository naming private code (F2). In product terms this is the console for all seven components and Root's hosted deployment, plans and onboarding ([PRODUCT.md](../PRODUCT.md)).

**Streams.** Each stream is built by its own session, in its own worktree and branch, in parallel; every stream opens a draft pull request and nothing merges until every stream is done and reviewed (F14, D19). Then one top pull request per repository lands the work.

| Stream | Repository | Scope | Migrations |
|---|---|---|---|
| U0 docs: brief and documents | public | this brief, ADR-0030, ADR-0031, the rule, threat and residual-risk rows, FEATURES, BUILD_GUIDE, the traceability order, runbooks | — |
| U1 core-web | public | phase A: the extension contract (D20), the `WhoAmI` fields (D21), the `deployment` setting; phase B: the console mount and policy (D10), browser sessions on Connect and the operations stream (D11), the development-provider refusal (D12), the restyled server pages; HR-340..347, T-160, T-161, RT-060, RT-061 | — |
| U2 core-tenancy | public | phase A: the protos (D21) and migration skeletons; phase B: accounts and self-serve organizations (D8), per-organization plans and the gate (D9), the complimentary-plan command and `billing.mode=off` (D12), onboarding progress (D15), the plan writer and account reader; HR-348..364, T-162..T-166, RT-062..RT-064 | `00160`–`00164` |
| Commercial distribution streams | private | the design system, website, fixtures and demo, console shell and surfaces, onboarding screens, the billing adapters and the commercial binary | — |
| U12 exit | both | the end-to-end journey on the local stack, the demo end-to-end test, accessibility and policy sweeps, budgets, the opt-in sandbox script; the public top pull request `test/ui-exit-core` | — |

Phase markers: `(web-A)`, `(web-B)`, `(tenancy-A)`, `(tenancy-B)`, `(docs-1)` … `(docs final)`. U2 merges U1 phase A before adding `AcceptInvitation` to `access.proto`. Phase A of U1 and U2 pushes the protos, `task gen` output and handlers that return `Unimplemented`, so the commercial streams can generate their clients early.

**Number registry** (reserved by the coordinator on 2026-10-20; take only your stream's numbers; the PR steward checks for collisions):

| Kind | UI | Owner |
|---|---|---|
| Milestone id | `UI`, inserted in the `tools/traceability` order between `M14` and `M13`; the Taskfile's `trace` default moves to `UI` only on the exit branch | U0 (order), exit (default) |
| Migrations | `00160` accounts · `00161` `org_entitlements` and `entitlement_events` · `00162` organization terms acceptance and onboarding · `00163` invitation browser binding · `00164` `billing_links` (D37) · `00165`–`00169` spare. M14's unused `00155`–`00159` stay unused | U2 |
| Hardening rules | HR-340..347 core-web · HR-348..353 tenancy and accounts · HR-354..361 entitlements, the gate, complimentary plans and test seams · HR-362..364 onboarding · HR-365..369 spare (no rows) | this brief |
| Threats | T-160 cookie CSRF on Connect · T-161 console XSS via agent text · T-162 billing event forgery or replay · T-163 entitlement escalation · T-164 self-serve abuse · T-165 invitation theft, email mismatch and account linking · T-166 test seams reaching production · T-167 demo-origin confusion and look-alike phishing · T-168 web supply chain · T-169 spare | this brief |
| Tests | `TestHR340_*`..`TestHR364_*` and `TestT160_*`..`TestT168_*` by the owning stream | U1, U2 |
| Range scenarios | RT-060 cookie CSRF on Connect, RT-061 cross-origin read of the operations stream (U1) · RT-062 plan-gate bypass, RT-063 forged billing event, RT-064 a development seam in a production configuration (U2) | U1, U2 |
| ADR | ADR-0030 (web console, hosted split and extension point), ADR-0031 (hosted accounts, per-organization plans and test seams) | this brief |
| Residual risks | R-47..R-55 | this brief |
| Product rows | PN-025, PN-026, F803–F830 (new feature rows numbered after the catalog) | this brief |
| Error codes | `PLAN_REQUIRED`, `SIGNUP_DISABLED`, `ACCOUNT_ORG_LIMIT`, `INVITATION_EMAIL_MISMATCH`, `AMBIGUOUS_CREDENTIAL`, `DEPLOYMENT_CONFIG` | U1, U2 |
| Permissions | `orgs.create` and `orgs.list_mine` (account sessions only), `invitations.accept` (account and organization browser sessions), `entitlements.read` (every built-in human role), `onboarding.read` (Org Admin, Security Admin, Agent Owner, Developer) | U2 |
| Proto files | U1 owns `access.proto` (`WhoAmI` fields); U2 owns `tenancy.proto` (`CreateOrg`, `ListMyOrgs`), `access.proto` `AcceptInvitation` (after U1 phase A), the new `entitlements.proto` and `onboarding.proto` | as listed |
| Server files | `internal/server/wiring_ui_<web\|tenancy\|entitlements\|onboarding>.go` and `procedures_ui_<same>.go`, one call line each in `server.go`; `internal/extension` and `internal/servercli` (U1) | U1, U2 |

Docs own `docs/**`; the code streams write no docs and report deviations to the coordinator. The runbooks [comp-plans.md](../runbooks/comp-plans.md), [billing-webhooks.md](../runbooks/billing-webhooks.md) and [hosted-oidc-outage.md](../runbooks/hosted-oidc-outage.md) are written by this brief's stream.

**Scope (planned):**
- **Extension point** (U1; ADR-0030). `internal/extension` with the console file system, extra routes under `/v1/ext/` and `/app/ext/`, a start-up check, a plan writer and an account reader; `internal/servercli.Main(args, ext)` shared by `cmd/pantherclaw-server` (an empty set) and the commercial binary.
- **Console mount and browser sessions on Connect** (U1). The console at `/app/` under a strict content security policy with Trusted Types; the session cookie accepted on Connect calls and the operations stream only with same-origin, `PC-CSRF: 1`, POST-only checks; the `deployment` setting and `WhoAmI`'s deployment, session kind and account id; the server pages restyled to the design tokens (dark by default, light through the system preference).
- **Hosted accounts and self-serve organizations** (U2; PN-026, PN-010.3 product code). Global accounts, sign-in without an organization, the organization picker, `CreateOrg` behind `signup.self_serve` (off by default), `ListMyOrgs`, browser invitations (PN-012.3).
- **Per-organization plans** (U2; PN-012.2). `pc.org_entitlements`, idempotent plan events, per-organization `Entitlements`, the `PLAN_REQUIRED` gate with its allow list, limits checked on the server, `EntitlementService.GetEntitlements`; a lapse never weakens enforcement.
- **Test access** (U1, U2; F9). The `deployment` validation, `billing.mode=off`, development sign-in providers refused in production, complimentary plans by operator command; the faked billing adapter and the real provider's adapter are in the commercial distribution.
- **Onboarding** (U2 core, the commercial distribution's screens; F322, F325, F335 UI part, F336, F341). `OnboardingService.GetProgress` computed from records.
- **Console, website and demo** (the commercial distribution; F001, F006, F009, F012, F643 and F803–F830). The seven surfaces, universal search, role views, settings, the website and the interactive demo on simulated data.
- **Documents.** This brief, ADR-0030, ADR-0031, the rule, threat and residual-risk rows, the BUILD_GUIDE §8 order and UI section, the FEATURES rows, the GATES §7 plan-change row, the OWASP V3 level, the traceability order, the runbooks, and the exit status in this brief.

Editions: the console is part of the paid hosted offering (F2); the free self-hosted Community edition keeps the CLI and the API. Core behaviour that self-hosted deployments also use (browser invitations, plan views, complimentary plans, test seams, onboarding progress) is Community; hosted accounts, self-serve organizations and the plan gate are switched on only by hosted configuration.

**Out of scope:**
- hosted staging and production infrastructure, backups and the DR drill, rate limits and quotas, support access, data export and deletion, the Helm chart, the FIPS build, SLOs under load and the threat-model refresh (M13); production deployment and paid sign-up (v1.0);
- re-implementing the server confirmation pages (approval, kill switch, channel and connection confirmations) inside the console;
- linking accounts across issuers; per-organization enterprise SSO through the hosted provider (on the first Enterprise customer);
- usage-based billing; automated issuance of self-hosted Enterprise licences (they stay manual offline licence documents);
- the docs site (M13).

**Threat slice:** the new rows **T-160..T-168** added to [THREAT_MODEL](../security/THREAT_MODEL.md) by this brief, plus:
- T-037 and T-051 (CSRF, session fixation, login CSRF) and HR-150..152 for cookie-authenticated Connect calls and `/app` return paths;
- T-023 and T-034 for the new public sign-up and organization endpoints and per-organization entitlements;
- T-003 for every new table and the global accounts table, T-042 for organization lists and onboarding evidence;
- T-026 and HR-023, HR-034 for every agent-written string the console shows;
- T-040 and HR-130..132 for the console bundle and its build;
- T-071 for onboarding steps presented as proof;
- TB4 (cookie-authenticated Connect calls, the console origin), TB8 (the hosted OIDC provider, the payment provider's events through the extension) and TB12 (the extension point).

*Cookie-authenticated Connect calls* (TB4; D11). The first path where a browser cookie, not a bearer token, authenticates API calls.
- **Spoofing and CSRF:** a cross-site page triggers calls with the victim's cookie. Answered by: SameSite=Strict `__Host-` cookies, same-origin Fetch Metadata or an `Origin` equal to the public origin, the `PC-CSRF: 1` header (which a cross-site simple request cannot set), POST only and a Connect content type; no CORS (HR-342).
- **Tampering:** mixing a bearer token and a cookie so that one is checked and the other used. Answered by: `AMBIGUOUS_CREDENTIAL` (HR-343).
- **Information disclosure:** a cross-origin page reading the operations stream. Answered by: the same checks on the stream and no credential in the URL (HR-344; RT-061).
- **Repudiation:** calls audited as `browser_session` (HR-347).
- **Elevation:** high-consequence calls still need a fresh step-up (HR-156).

*The console origin* (TB4; D10). Agent-written text reaches the viewer's browser.
- **Tampering and elevation (XSS):** answered by the console policy (`script-src 'self'`, Trusted Types required with no policies, no inline code; HR-340), text-only rendering of untrusted strings with bidirectional controls stripped, and lint rules that fail the build on unsafe rendering (D7 in the commercial distribution).
- **Clickjacking:** `frame-ancestors 'none'`.
- **Open redirect:** `/app` return paths only as same-origin paths (HR-345).

*Accounts, organizations and plans* (TB4, TB8; D8, D9).
- **Spoofing:** an account linked to another by email from a different issuer; a forwarded invitation. Answered by: (issuer, subject) keys, no linking by email (HR-348), verified-email equality on acceptance (HR-352).
- **Tampering:** plan state written from a browser, forged or replayed plan events. Answered by: only the plan writer, the operator command and development mode write plans (HR-354); idempotent, ordered, audited events (HR-355); the extension verifies the provider's signatures (commercial distribution).
- **Information disclosure:** organization and member enumeration. Answered by: memberships only through the audited global lister; account sessions see nothing organization-scoped (HR-349, HR-350).
- **Denial of service:** mass sign-ups and organizations. Answered by: per-account limits and rate limits (HR-351).
- **Elevation:** a lapse or a forged status used to switch protection off. Answered by: a lapse never weakens enforcement (HR-357); complimentary and development statuses never through the plan writer (HR-361).

**Hardening rules in scope:** the new rules **HR-340..HR-364** added to [HARDENING_RULES](../security/HARDENING_RULES.md) by this brief, plus HR-023 and HR-034 (untrusted text), HR-033 (deep-link approvals), HR-050..057 (new tables, the global accounts table), HR-063 (licences), HR-104 (mass assignment), HR-130..132 (supply chain), HR-150..159 (browser sessions, CSRF, return paths, step-up, notifications: invitation emails) and HR-004 for every conditional transition.

**Product requirements:**

| Requirement | UI part |
|---|---|
| PN-010.3 | Hybrid hosted control plane: product code (general availability at v1.0) |
| PN-012.2 | Per-organization entitlements and plan limits (U2) |
| PN-012.3 | Invitations accepted in the browser (U2) |
| PN-025 | Website and interactive demo (commercial distribution) |
| PN-026 | Hosted accounts, self-serve organizations and paid plans (U2, commercial distribution) |
| F001, F006, F009, F012, F643 | Console surfaces, role views, scoped navigation, accessibility, progressive disclosure (commercial distribution) |
| F322, F325, F335 (UI part), F336, F341 | Onboarding: progress in the core (U2), screens in the commercial distribution |
| F803–F830 | Website, demo, console, accounts, plans, test access and onboarding rows (FEATURES pillar 20) |

**New rules and threats:**

| Constraint | Rule | Threat |
|---|---|---|
| The console only at `/app/`, under the console policy with Trusted Types | HR-340 | T-161, T-168 |
| Extension routes only under `/v1/ext/` and `/app/ext/`; no shadowing | HR-341 | T-166, T-168 |
| Cookie-authenticated Connect calls: same origin, `PC-CSRF: 1`, POST, Connect content type; no CORS | HR-342 | T-160 |
| Bearer and cookie together refused | HR-343 | T-160 |
| The operations stream: the same checks; no credential in the URL | HR-344 | T-160, T-112 |
| `/app` return paths only as same-origin paths | HR-345 | T-167, T-051 |
| Production refuses development providers and a missing `deployment`; others reported | HR-346 | T-166 |
| Browser-session calls audited; step-up unchanged | HR-347 | T-160 |
| Accounts by (issuer, subject); no linking by email | HR-348 | T-165 |
| Memberships only through the audited lister; account sessions see nothing organization-scoped | HR-349 | T-164, T-003 |
| Account sessions call only the allow list | HR-350 | T-164 |
| `CreateOrg` with self-serve on, a verified email, limits and rate limits; terms recorded | HR-351 | T-164 |
| Invitations need the verified email to match; single use; expiry | HR-352 | T-165 |
| Switching organization is a fresh sign-in | HR-353 | T-165 |
| Plan state only through the plan writer, the operator command or development mode | HR-354 | T-163 |
| Plan events idempotent and ordered; audited | HR-355 | T-162, T-163 |
| The `PLAN_REQUIRED` gate with its allow list | HR-356 | T-163 |
| A lapse never weakens enforcement | HR-357 | T-163 |
| Complimentary plans: operator only, reason, at most one year, audited, visible | HR-358 | T-163 |
| Production refuses billing off or faked; extension start-up errors stop the server | HR-359 | T-166 |
| Plan limits checked on the server at creation | HR-360 | T-163 |
| Complimentary and development statuses never through the plan writer | HR-361 | T-163 |
| Onboarding progress from records, never client flags | HR-362 | T-071 |
| Onboarding evidence only from the caller's organization | HR-363 | T-003 |
| Simulated records never complete a step | HR-364 | T-071, T-090 |

Rules that concern only the commercial distribution (the payment provider's webhook signature and timestamp checks, key-type guards per deployment, the faked billing adapter's availability outside production) are written in the commercial distribution's own security notes, not here.

**Contracts** (U1 phase A pushes D20 and the `WhoAmI` fields first; U2 phase A the other protos and the migration skeletons; every other stream codes against them):

1. **D20: the extension contract** (`internal/extension`, U1; HR-341, HR-359). The path is `internal/extension`, not `internal/platform/extension` as IP_PROTECTION first said, because it names core domain types. Ids are strings to keep the interface stable.
   ```go
   package extension
   type Deployment string // "development" | "staging" | "production"
   type Set struct {
       Console  fs.FS                       // built console (index.html at root); nil = no console
       Mount    func(Deps) ([]Route, error) // extra routes, called after core wiring
       Validate func(Deps) error            // start-up check; an error stops the server (DEPLOYMENT_CONFIG)
   }
   type RouteAuth int
   const (AuthNone RouteAuth = iota; AuthSession; AuthSessionCSRF)
   type Route struct { Pattern string; Auth RouteAuth; Handler http.Handler } // Pattern under "/v1/ext/" or "/app/ext/", else a start-up error
   type Deps struct {
       Log *slog.Logger; Clock clock.Clock; PublicURL string; Deployment Deployment
       Plans    PlanWriter    // implemented by U2
       Accounts AccountReader // implemented by U2
       BillingLinks BillingLinks // U1 adds the interface in phase B; U2 implements (D37)
   }
   type Principal struct { AccountID, OrgID, UserID, Email string } // OrgID "" for account sessions
   func PrincipalFrom(ctx context.Context) (Principal, bool)
   type PlanWriter interface { ApplyPlan(ctx context.Context, orgID string, s PlanSnapshot) error } // idempotent by EventID; only a strictly older EventAt is ignored; audited
   type PlanSnapshot struct { PlanID, Edition string; Status PlanStatus; Limits PlanLimits; Features []string; PeriodEnd time.Time; EventID string; EventAt time.Time }
   type PlanStatus string // "NONE","TRIALING","ACTIVE","PAST_DUE","PAUSED","CANCELED","LAPSED" (COMP and DEV are core-only, refused here)
   type PlanLimits struct { MaxAgents, MaxEnvironments, RetentionDays, InstanceAllowance, MaxMembers int } // 0 = unlimited
   type AccountReader interface { Account(ctx context.Context, accountID string) (Account, error) }
   type Account struct { ID, Email string; EmailVerified bool; DisplayName string }
   type BillingLinks interface {
       RecordCheckout(ctx context.Context, orgID, provider, checkoutRef string, expiresAt time.Time) error
       BindSubscription(ctx context.Context, provider, checkoutRef, subscriptionRef, customerRef string) (orgID string, err error) // checkoutRef must be pending and unexpired; ErrConflict if the org has a different current subscription; marks the checkout consumed
       SubscriptionOrg(ctx context.Context, provider, subscriptionRef string) (orgID string, current bool, err error) // ErrNotFound if unknown
       EndSubscription(ctx context.Context, provider, subscriptionRef string) error
       CurrentSubscription(ctx context.Context, orgID, provider string) (subscriptionRef string, ok bool, err error)
   }
   var ErrNotFound, ErrConflict error
   ```
   - **D37: server-issued checkouts only** (replaces D33's first design). Billing events arrive without an organization context, so a subscription binds to an organization only through a checkout the server recorded: the extension records each checkout it creates (`RecordCheckout`), and the first event of the new subscription binds it to that checkout's organization (`BindSubscription`; the checkout must be pending and unexpired and is then consumed). Organization hints inside the provider's event are never trusted for the binding, and the customer reference is never used to change state. Table `pc.billing_links` (migration 00164) holds checkouts (pending, consumed, expired) and subscriptions (current, ended) with org_id, provider, kind, ref, customer_ref, state, expires_at, created_at and updated_at; (provider, kind, ref) is unique across organizations and a reference never moves to another organization. Cross-organization lookups go only through the audited cross-organization lister with purpose `billing_link_lookup`. Plan changes still reach the core only through `PlanWriter` after the extension has verified the event (HR-354, HR-355).
   - **D36: one current subscription per organization.** At most one current subscription per organization and provider. A new checkout is refused (`ErrConflict`) while the organization has a live subscription (trialing, active, past due or paused) or an unexpired pending checkout; plan changes go through the provider's portal as a subscription update. Events for a subscription that is not the organization's current one are audited and never applied.
   - **D38: refunds and chargebacks.** A full refund or a chargeback sets the plan LAPSED, the extension cancels the provider subscription at once and ends it (`EndSubscription`); later events for an ended subscription are audited and ignored, and an alert asks an operator to review ([runbook](../runbooks/billing-webhooks.md)).
   - **D40 (public part): which events change the plan.** `ApplyPlan` ignores only strictly older events: an event with the same `EventAt` as the last one applied is applied, and idempotency is by event id. Status changes come only from subscription lifecycle events; a payment event only binds the initial checkout.
   - `cmd/pantherclaw-server/main.go` becomes a thin call to `internal/servercli.Main(args []string, ext extension.Set) int`, with every existing subcommand unchanged; the commercial binary calls the same with its set. `internal/server.RunWith(ctx, cfg, ext)`.
   - The commercial distribution's billing routes sit under `/v1/ext/billing/` (the provider's webhook, AuthNone) and `/app/ext/billing/` (checkout and portal, AuthSessionCSRF, JSON in, `{url}` out; the public plan list, AuthSession). Core tests use a fake console file system and fake routes.
2. **D21: proto contracts.**
   - `access.proto` (U1): `WhoAmIResponse` gains `Deployment deployment`, `SessionKind session_kind` and `string account_id`; enums `Deployment {DEPLOYMENT_UNSPECIFIED, DEPLOYMENT_DEVELOPMENT, DEPLOYMENT_STAGING, DEPLOYMENT_PRODUCTION}` and `SessionKind {SESSION_KIND_UNSPECIFIED, SESSION_KIND_BEARER, SESSION_KIND_ORG_BROWSER, SESSION_KIND_ACCOUNT_BROWSER}`.
   - `access.proto` (U2, after merging U1 phase A): `rpc AcceptInvitation(AcceptInvitationRequest{string token}) returns (AcceptInvitationResponse{string org_id})`; permission `invitations.accept` (account and organization browser sessions).
   - `tenancy.proto` (U2): `rpc CreateOrg(CreateOrgRequest{string name; string slug; string terms_version; string dpa_version}) returns (CreateOrgResponse{Org org})`, permission `orgs.create`; `rpc ListMyOrgs(ListMyOrgsRequest{}) returns (ListMyOrgsResponse{repeated OrgSummary orgs})`, permission `orgs.list_mine`; `OrgSummary{string org_id; string name; string slug}`.
   - `entitlements.proto` (U2, new): `service EntitlementService { rpc GetEntitlements(GetEntitlementsRequest{}) returns (GetEntitlementsResponse{Entitlements entitlements}); }`, permission `entitlements.read`. `Entitlements{string plan_id; string edition; PlanStatus status; PlanLimits limits; repeated string features; google.protobuf.Timestamp period_end; google.protobuf.Timestamp comp_until; PlanSource source; PlanUsage usage}`; `PlanLimits{int32 max_agents; int32 max_environments; int32 retention_days; int32 instance_allowance; int32 max_members}` (0 = unlimited); `PlanUsage{int32 agents; int32 environments; int32 members}`; `PlanStatus {PLAN_STATUS_UNSPECIFIED, _NONE, _TRIALING, _ACTIVE, _PAST_DUE, _PAUSED, _CANCELED, _LAPSED, _COMP, _DEV}`; `PlanSource {PLAN_SOURCE_UNSPECIFIED, _LICENCE, _BILLING, _COMP, _DEV}`.
   - `onboarding.proto` (U2, new): `service OnboardingService { rpc GetProgress(GetProgressRequest{}) returns (GetProgressResponse{repeated OnboardingStep steps; bool complete}); }`, permission `onboarding.read`. `OnboardingStep{StepId id; StepState state; google.protobuf.Timestamp done_at; repeated EvidenceRef evidence}`; `StepId {STEP_ID_UNSPECIFIED, STEP_ID_SECURITY_KEY, STEP_ID_INVITE_TEAM, STEP_ID_GATEWAY_ENROLLED, STEP_ID_AGENT_ENROLLED, STEP_ID_FIRST_DECISION, STEP_ID_TEST_ALLOWED, STEP_ID_TEST_HELD, STEP_ID_TEST_DENIED, STEP_ID_APPROVAL_DECIDED, STEP_ID_SUSPENSION_TESTED}`; `StepState {STEP_STATE_UNSPECIFIED, _TODO, _DONE}`; `EvidenceRef{string kind; string id}`. Skipping a step is a console view only (not stored); receipt verification stays a shown `pclaw verify` command (offline; the server cannot see it).
   - Phase A = protos, `task gen` and handlers that return `Unimplemented`; generated code committed.
3. **D10: the console mount** (U1; HR-340, HR-345). With a console in the set: `GET /app/` and `/app/*` serve the bundle with a fallback to `index.html` (`Cache-Control: no-store`); hashed `/app/assets/*` are immutable; every response carries the console policy `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; manifest-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'; trusted-types 'none'` plus the existing page headers; `/` redirects to `/app/`; `/app` is added to the return-path list as a prefix rule (HR-152). Without a console nothing changes.
4. **D11: browser sessions on the Connect API** (U1; HR-342..347; the CSRF review G0 M5 deferred). `rpcauth` accepts the session cookie only with `Sec-Fetch-Site: same-origin` (or the header absent and `Origin` equal to the public origin), `PC-CSRF: 1`, POST and content type `application/json` or `application/proto`; cookie-authenticated GET calls are refused; no CORS; bearer and cookie together → `AMBIGUOUS_CREDENTIAL`; the bearer path is unchanged. Idle refresh on use; the step-up rule (HR-156) applies; audit `credential_type=browser_session`. `/v1/operations/stream` also accepts the cookie under the same checks (the console reads it with a streaming fetch). The server pages' stylesheet is restyled once to the token values (dark by default, light through `prefers-color-scheme`) and kept in sync by hand when the brand changes.
5. **D32: token endpoint authentication** (U1 phase B). Each OIDC provider in `auth.oidc_providers` takes `token_auth: basic | post` (default `basic`): the client secret is sent with HTTP Basic (`client_secret_basic`) or in the form body (`client_secret_post`), the two standard client-secret methods; nothing else is accepted. The relying party's other checks (PKCE S256, nonce, RFC 9207 `iss`; HR-152) are unchanged for every provider.
6. **D31: recent sign-in with the hosted provider.** HR-155 is unchanged and fails closed: adding a security key without another active key (the first key, onboarding step 4) needs a provider sign-in at most 5 minutes old, which the server can establish only if the provider reports `auth_time` and honours `max_age` or `prompt=login`. The local mock provider (L0, L1) sends `auth_time`; whether the hosted provider does is verified at L2, and until then a sign-in without a verifiable `auth_time` never counts as recent.

**Migrations.** `00160` `pc.accounts` and the account event tables (global, no `org_id`: reached only through the audited cross-organization lister and restricted functions; unique (issuer, subject)) · `00161` `pc.org_entitlements` (tenant, forced RLS) and `pc.entitlement_events` (keyed (org_id, event_id)) · `00162` organization terms and data-processing acceptance and onboarding records · `00163` the invitation browser binding · `00164` `pc.billing_links` (checkouts and subscriptions: org_id, provider, kind, ref, customer_ref, state, expires_at, created_at, updated_at; (provider, kind, ref) unique across organizations; at most one current subscription per organization and provider; cross-organization lookups only through the audited lister, purpose `billing_link_lookup`; D36, D37) · `00165`–`00169` spare. Every new tenant table has `org_id`, composite keys, forced RLS, `pc_app` SELECT and INSERT and `pc_audit_ro` SELECT; UPDATE only on the columns a conditional transition needs, named in the header comment. squawk-clean; every down migration restores the previous state.

**Security constraints and design decisions:**

*Hosted accounts and self-serve organizations (U2; D8; ADR-0031)*

5. **D8: accounts.** `pc.accounts`: id (UUIDv7), issuer, subject, email, email_verified, display_name, created_at, last_sign_in_at; unique (issuer, subject) (HR-348). Account tables are reached only through the audited cross-organization lister (HR-349) (D35).
6. **D8: sign-in without an organization.** `/login?idp=` without `org`: the callback resolves the account and lists its memberships through the audited global lister (HR-349). None → an account session if self-serve is on (allowed: account calls, `TenancyService.CreateOrg` and `ListMyOrgs`, `AccessService.AcceptInvitation`, `AccessService.WhoAmI`, allow-listed extension routes; HR-350), else `NOT_A_MEMBER`; one → an organization session; several → a server-rendered organization picker → an organization session. Organization sessions stay organization-scoped (RLS unchanged). No automatic linking of accounts across issuers by email. Switching organization is a fresh sign-in round trip (HR-353).
7. **D8: `CreateOrg`** (HR-351). An account session, a verified email and `signup.self_serve: true` (default false; true only in the hosted configuration; otherwise `SIGNUP_DISABLED`); at most one organization without a plan per account and at most three organizations per account (configurable; `ACCOUNT_ORG_LIMIT`), counted from the account's events (D35); the slug is a display label only, not unique and never used to look an organization up, so it cannot be used to enumerate organizations (D35, T-164); the creator becomes `org_admin`; the terms and data-processing versions and time are recorded; the session is rotated into the new organization; rate-limited per account and address; audited.
8. **D8: browser invitations** (HR-352). `/invite/{token}` → sign in → `AccessService.AcceptInvitation` → the IdP-verified email must equal the invitation email (else `INVITATION_EMAIL_MISMATCH`) → an organization session. Single use; expiry. HR-157 is widened for invitation emails only.

*Per-organization plans (U2; D9; ADR-0031)*

9. **D9: storage.** `pc.org_entitlements`: org_id (primary key), plan_id, edition (community, team, business, enterprise, development), limits {max_agents, max_environments, retention_days, instance_allowance, max_members}, features, status (NONE, TRIALING, ACTIVE, PAST_DUE, PAUSED, CANCELED, LAPSED, COMP, DEV), source (LICENCE, BILLING, COMP, DEV), period_end, comp_until, comp_reason, version, last_event_at, updated_at. `pc.entitlement_events` (keyed (org_id, event_id); received_at, kind) for idempotency. There are no LICENCE rows: self-hosted deployments derive entitlements from the licence (D35).
10. **D9: writers** (HR-354, HR-355, HR-361). Self-hosted: licence-derived, as today, with no row. Hosted: the extension's plan writer (`ApplyPlan`: idempotent by event id, only strictly older events ignored, status changes only from subscription lifecycle events, audited; COMP and DEV refused; D40); the complimentary-plan command (D12); development mode (D12). `Entitlements` becomes per organization (`ent.For(ctx, orgID)`), and the existing gates and limits read it; limits are checked on the server at creation (HR-360).
11. **D9: the gate** (HR-356). With `billing.require_plan: true` (hosted only), organization calls answer `PLAN_REQUIRED` unless the status is TRIALING, ACTIVE, PAST_DUE, COMP or DEV, or the procedure is allow-listed (`WhoAmI`, account calls, `Tenancy.GetOrg` and `UpdateOrg`, `Entitlement.*`, `Onboarding.GetProgress`, the billing extension routes). CANCELED keeps access until `period_end`.
12. **D9: a lapse never turns protection off** (HR-357; PN-012.1, PRODUCT §7). Gateways keep enforcing, `Authorize` keeps deciding, the kill switch and containment keep working, open approvals can still be decided, and evidence stays readable and exportable for 30 days. Blocked: configuration changes and new agents, instances and connections.
13. **D9: reading the plan.** `EntitlementService.GetEntitlements` returns the plan, status, limits, usage (agents, environments, members), period end and complimentary-plan expiry. The plan catalog (names, limits per plan, prices) stays in the commercial distribution.

*Extension point and console (U1; D10, D20; ADR-0030)*

14. **D10: routes and checks** (HR-341). Extension routes are mounted after core wiring; a pattern outside `/v1/ext/` and `/app/ext/`, or one that a core route already serves, is a start-up error. `AuthSession` routes see `PrincipalFrom(ctx)`; `AuthSessionCSRF` routes also need the D11 checks. `Validate` runs before the server listens; its error stops start-up with `DEPLOYMENT_CONFIG` (HR-359).

*Browser sessions (U1; D11)*

15. **D11: `WhoAmI`.** Reports `deployment`, `session_kind` and `account_id` so the console can show a permanent development or staging banner and the account-session screens (HR-346).

*Test access without payment or real sign-in (U1, U2; D12; founder decision F9)*

16. **D12: every seam is an adapter chosen by configuration, visible when active and refused in production; no bypass code exists in the server.**
    - `deployment: development | staging | production` (the hosted configuration requires it; the local default is development). Start-up validation (`DEPLOYMENT_CONFIG`): production refuses `billing.mode` off or fake (HR-359) and OIDC providers marked `dev: true` (HR-346); the commercial distribution's own start-up check also refuses the payment provider's test keys in production and live keys elsewhere. The console shows a permanent DEVELOPMENT or STAGING banner from `WhoAmI`.
    - `billing.mode`: `off` (no gate; every organization DEV with all features; core) · `fake` (in the commercial distribution: a provider-shaped adapter with a local checkout page and signed events that drives the real gate and onboarding) · the real provider (sandbox or live).
    - **Complimentary plans** (HR-358; every deployment, production included): `pantherclaw-server org plan grant --org <id> --plan <plan_id> --until <RFC3339> --reason "<text>"` and `pantherclaw-server org plan revoke --org <id> --reason "<text>"`; source COMP, audited in the ledger, at most one year, shown in the console ("Complimentary plan until …"); never grantable through the API or the browser. This is how the founder and design partners use the real hosted app without paying ([runbook](../runbooks/comp-plans.md)).
    - Sign-in for testing: the existing local mock OIDC server (any username, instant) and the Keycloak development realm (alice, bob) as providers marked `dev: true`; the hosted provider's staging environment at L2 and L3, its production environment at L4.
    - Security keys: a virtual authenticator in browser tests; by hand, the browser's WebAuthn developer tools or the platform authenticator.
    - The console's mock mode (L0) runs on in-browser fixtures with a role and plan switcher; the production console build contains no fixture code (CI checks the bundle for a marker string).
    - **Layers:** L0 mock (UI build, visual and accessibility tests, the public demo) → L1 local stack (real server, gateway and simulators, the mock IdP, billing off or fake; the CI end-to-end test) → L2 local with the providers' sandboxes (opt-in, like M8's live GitHub test) → L3 hosted staging (M13) → L4 production (v1.0).
    - **Contract suites shared by fake and real adapters:** billing (checkout → event → ACTIVE; renewal; past due → grace; cancel → until period end; refund or chargeback → LAPSED) against the fake in CI and the provider's sandbox opt-in; OIDC sign-in against the mock server in CI and the hosted provider's staging opt-in.
    - **Order:** each flow is built on its fake and proven, then the real adapter swaps in behind the same port and the same contract suite.

*Onboarding (U2 core, commercial distribution screens; D15)*

17. **D15: steps** (resumable; progress computed from real records, never flags; HR-362..364): sign in → create an organization (name, slug, region shown, terms and data-processing agreement) → choose a plan and check out ("Activating…" until ACTIVE) → register a security key (required before deciding approvals) → invite teammates (roles; a separation-of-duties hint) → the first protected path (Claude Code, the Agent SDK, GitHub Actions or an MCP client; install `pclaw`, `pclaw login`, run the gateway with an enrollment token, `pclaw init` with the coding-to-production template; a live checklist: gateway, agent, first decision) → guided first tests (safe, permitted, out of scope; enforce one named path; the prohibited test stopped; approve one held action with the key; verify a receipt) → validation (an enforced deny, a working approval, suspend and restore the test agent) → "Protected" → Operations. A security-team path (F336, Team).
18. **D15: `OnboardingService.GetProgress(org)`** computes the steps from gateways, agents, decisions, approvals, receipts and suspension events, with evidence references from the caller's organization only; simulated records never complete a step (F630).
19. **D15: F335.** The 30-minute target is measured on the hosted flow at L2 and recorded at the exit.

*Console, website and demo (commercial distribution; D5–D7; recorded for the threat model)*

20. The console is a Vite single-page application built with no inline script or style and no `eval`, served by the server at `/app/` (D10); agent-written text is rendered only as text in a labelled box with bidirectional controls stripped, and lint rules fail the build on unsafe rendering; high-consequence actions call the step-up pages first; no optimistic updates on security actions; live lists never reorder items under review; WCAG 2.2 AA with no serious or critical automated findings; status is always icon, word and colour. The server confirmation pages stay canonical; the console links to them. Checkout is a redirect to the payment provider's hosted checkout page, so the console policy stays strict on every route; the fallback, a dedicated checkout route with its own wider policy, is used only if the hosted page is unavailable and is measured at L2 in report-only mode first (D13a).
21. The interactive demo is the console's demo build on its own origin with no cookies, `connect-src 'self'` and no API, on a simulated organization, with a permanent "Interactive demo · SIMULATED data" banner. The website is static, sets no cookies, loads no third-party scripts and uses cookieless analytics (R-54); the booking link points to an external page.
22. Only free component and animation libraries and original designs are used (F10); nothing from a paid component library, and no component recreated from paid previews.

**Dependencies to add:** none in the public repository. The extension point, the console mount, the cookie checks, accounts, plans and onboarding use the standard library and existing dependencies. The console, website and billing dependencies live in the commercial distribution under its own dependency policy, with named exceptions for the non-OSI licences (R-47).

**Tests to write first** (by stream; names are indicative, each HR id gets at least one `TestHR<id>_*`; final names are filled in at the exit):

| Stream | Tests |
|---|---|
| U1 core-web | `TestHR340_*` (the console policy on every `/app` response, the SPA fallback is no-store, hashed assets immutable, no console → no `/app` route), `TestHR341_*` (a route outside the prefixes, a shadowing route → start-up error), `TestHR342_*` (cross-site, missing header, GET, form content type, wrong `Origin` refused; same-origin accepted), `TestHR343_*`, `TestHR344_*` (the stream with and without the checks; no token in the URL), `TestHR345_*` (absolute, scheme-relative, backslash and encoded-slash return paths fall back), `TestHR346_*` (a production configuration with a development provider or without `deployment` refuses to start), `TestHR347_*`, `TestT160_*`, `TestT161_*`; RT-060, RT-061 |
| U2 core-tenancy | `TestHR348_*`..`TestHR364_*` (no linking by email; the lister is audited; account sessions refused outside the allow list; `CreateOrg` limits, rate limits, `SIGNUP_DISABLED`; invitation email mismatch, reuse and expiry; organization switch needs a sign-in; plan writes refused from the API; duplicate and older events ignored; the gate and its allow list; a lapsed organization still authorizes, enforces, contains and decides open approvals; complimentary plan limits; production refuses billing off; limits at creation; COMP and DEV refused through `ApplyPlan`; onboarding from records, other organizations' records and simulated records ignored), `TestT162_*`..`TestT166_*`, `TestTenancy_*` for 00160–00164, IDOR and permission-catalog tests for every new RPC; RT-062..RT-064 |
| Exit | the L1 journey end-to-end test (sign in through the mock IdP → create an organization → plan through the faked billing adapter → security key with a virtual authenticator → enroll a gateway and an agent → guided tests → validation), the demo end-to-end test, accessibility and policy sweeps on every console route, `TestUI_WiringComplete` |

**Exit criteria (UI done when the local checks and the end-to-end tests show):**
- the L1 journey passes end to end on the local stack, with the console served by the commercial binary at `/app/` under the console policy and no policy violation in any test;
- a lapsed organization keeps enforcing (HR-357) and a production configuration with a development seam refuses to start (HR-346, HR-359);
- the HR-340..HR-364 tests and `TestT160_*`..`TestT168_*` (or their mitigations' tests) are green; `task trace MILESTONE=UI`, `task check`, `task test:integration` and `task range` pass on the exit branch; RT-060..RT-064 run in `task range`;
- F335 is measured on the hosted flow at L2 and recorded.

**Residual risks** (added to THREAT_MODEL §8 by this brief):
- **R-47:** the free component library and the animation library are under licences that are not OSI-approved. Compensating controls: named exceptions in the commercial distribution's dependency policy; licence notices kept; nothing from a paid library.
- **R-48:** hosted sign-in depends on a hosted OIDC provider. Compensating controls: enforcement and existing sessions are unaffected; the provider is replaceable by configuration ([runbook](../runbooks/hosted-oidc-outage.md)).
- **R-49:** plan changes depend on the payment provider's webhooks. Compensating controls: idempotent, ordered events; a lapse never weakens enforcement; complimentary plans bridge an outage ([runbook](../runbooks/billing-webhooks.md)).
- **R-50:** the console's JavaScript supply chain. Compensating controls: the console policy with Trusted Types, a lockfile with a release-age cooldown, an install-script allow list, licence and secret scans; security re-checked on the server.
- **R-51:** no account linking across issuers. Compensating controls: one provider per hosted deployment; invitations bind by verified email.
- **R-52:** complimentary-plan misuse by an operator. Compensating controls: operator command line only, reason, at most one year, audited and visible.
- **R-53:** the commercial distribution's repository has no required checks. Compensating controls: CI on every pull request; the founder merges only after it is green.
- **R-54:** cookieless analytics on the website. Compensating controls: no cookies, no personal data beyond the early-access form; no analytics in the console or the demo.
- **R-55:** a single developer reviews AI-written UI code. Compensating controls: two AI reviewers, accessibility and policy checks in end-to-end tests, lint bans on unsafe rendering, every decision enforced on the server (EX-001).
- **Recent sign-in with the hosted provider** (D31, part of R-48): recent sign-in (HR-155) depends on the hosted OIDC provider reporting `auth_time`; it fails closed until that is verified at L2.

**Follow-ups (not UI):**
- re-implementing the server confirmation pages inside the console;
- automated issuance of self-hosted Enterprise licences;
- per-organization enterprise SSO and directory sync through the hosted provider (on the first Enterprise customer);
- account consolidation across issuers, by a person, with both sign-ins;
- the docs site and hosted staging and production infrastructure (M13);
- usage-based billing;
- verifying at L2 that the hosted OIDC provider reports `auth_time` and honours `max_age` or `prompt=login` for recent sign-in (HR-155); if it does not, a founder decision (D31).

**Founder decisions (F0–F14, 2026-10-20; recorded, not re-asked):**

- **F0: plan change.** The UI phase moves to right after M14, before M13: `… → M14 → UI → M13 → v1.0`.
- **F1: hosting.** PantherClaw hosts the control plane and the console (hybrid; PN-010.3 moves up from post-1.0); customers run the gateway and `pclaw`. Paid sign-ups open at v1.0 after M13's hardening.
- **F2: code location.** A new private repository for the website, the console, billing and cloud operations (ADR-0007); the console is part of the paid offering; free self-hosted Community keeps the CLI and the API, without the console.
- **F3: payments.** A merchant-of-record payment provider behind one replaceable billing port; plans and prices are defined later.
- **F4: demo.** An interactive demo of the real console on simulated data in the browser (no sign-up, no server), plus "book a demo" through an external booking page.
- **F5: sign-in.** A hosted OIDC provider for the hosted deployment; self-hosted customers keep their own IdP; PantherClaw security keys still guard approvals and high-risk actions.
- **F6: go-live.** The website, the demo and the booking link go live early on free static hosting; paid sign-up at v1.0.
- **F7: private CI.** The private repository stays on the free plan with no required checks; the founder merges each pull request by hand after CI is green.
- **F8: brand.** No logo yet: a placeholder mark and wordmark, with every brand value in one token file.
- **F9: test access.** A way for the founder to use the app without payments and without a real sign-in, for testing, placed so that each piece is proven before everything is joined (D12).
- **F10: components.** No paid component library and nothing recreated from its previews; free component libraries, a free animation library and original designs only.
- **F11, F12: start and execution** (superseded by F14). Start after M14 merged, one stream at a time with a review pass after each.
- **F13: plan confirmed as written.**
- **F14: parallel execution.** Start now and work in parallel in worktrees with pull requests; nothing merges until all of it is done.

**Design decisions in this brief:** the contracts D10, D11, D20, D21, D31, D32, D36, D37, D38 and D40 (D37 replaces D33) and the items D8, D9, D12, D13a, D15 and D35 above (public parts), with D1–D7, D13, D14, D16–D19, D22–D30, D34 and D39 in the coordinator's tracker (plan change, repositories, the web stack, design system, website, demo, console, the payment and sign-in adapters, threats and rules, private governance, execution, and the rule texts). They follow the founder's decisions and were made by the coordinator; their rule and threat statements became the HR-340..HR-364 and T-160..T-168 rows; approval of the brief approves them.

**Decision:** APPROVED — founder approval 2026-10-20. Decisions F0–F14 were made by Joshua Kato on 2026-10-20, and the plan was confirmed as written (F13) and started in parallel (F14) the same day.
