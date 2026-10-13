# PantherClaw — Mandatory Hardening Rules

**Status:** binding design constraints (G0, 2026-10-08). Source: adversarial design review + engineering review of the architecture. A rule may only be relaxed through an ADR plus a recorded exception in [GATES_AND_REVIEW.md](GATES_AND_REVIEW.md).

**Traceability convention:** every rule `HR-###` is verified by at least one test whose name contains the ID (e.g. `TestHR001_BeginDispatchRejectsStaleEpoch`). CI's traceability check fails if an `MVP` rule scheduled for a completed milestone has no test. Threat IDs (`T-###`) refer to [THREAT_MODEL.md](THREAT_MODEL.md).

## Dispatch, permits and idempotency

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-001 | Gateway MUST call `BeginDispatch(permit_id, epoch)` before sending any byte to a target; transition `ISSUED→DISPATCHING` is a single conditional UPDATE using the **database clock** and the org's current **containment epoch**. | T-010, T-031 | M1.5/M6 |
| HR-002 | Every containment change (suspend, revoke, quarantine, kill switch) increments the org containment epoch in the same transaction. | T-031 | M6 |
| HR-003 | Sweepers release reservations only for expired `ISSUED` permits. Stale `DISPATCHING` becomes `UNKNOWN` → reconciliation; never auto-released. | T-024 | M1.5 |
| HR-004 | All state transitions are conditional `UPDATE … WHERE state=<expected>`; a 0-row result is a lost race handled explicitly (no double release, no double consume). | T-024 | M1 |
| HR-005 | A finalized `(org, run_id, action_id)` never yields a second permit; repeated calls return the stored decision. | T-012 | M4 |
| HR-006 | Same `(org, run_id, action_id)` with a different action hash ⇒ `DENY` (`ACTION_TAMPERED`) + security alert. `DENY`/expired are terminal; `CANNOT_AUTHORIZE` is retryable. | T-005, T-012 | M4 |
| HR-007 | Irreversible operations declare a semantic dedupe key; an open `UNKNOWN` or recent success on the key parks new requests in `RECONCILIATION`. | T-012 | M4/M7 |
| HR-008 | Target idempotency keys derive from the server-minted transaction id, never agent-supplied ids. | T-012 | M6 |
| HR-009 | Permits are single-use, TTL ≈ 5 s, carry the containment epoch, and are verified by the gateway before `BeginDispatch`. | T-010 | M1.5 |
| HR-010 | Gateway refuses to dispatch when its revocation/containment stream heartbeat is older than 2 s; on start it loads a full containment snapshot before serving. | T-031 | M6 |
| HR-011 | Consumed approvals are restored only when the gateway proves nothing was sent; otherwise the action is `UNKNOWN`. | T-005 | M6 |

## Never trust the gateway or the agent

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-020 | The Authority derives org from the gateway's mTLS certificate binding and rejects ActionIR whose org differs. | T-009 | M6 |
| HR-021 | The gateway forwards the workload token, proof and raw-body hash; the Authority re-verifies them itself. | T-009 | M6 |
| HR-022 | `run_id` is minted by the Authority and bound to instance, launcher, principal and grant; mismatches ⇒ `DENY`. | T-001 | M3 |
| HR-023 | Agent-supplied task text, reasons and summaries never change scope; they are stored and displayed as **untrusted**. | T-001, T-017 | M4 |
| HR-024 | Cooperative modes (SDK authorize, hooks) are labeled `PARTIAL`/`OBSERVE_ONLY` unless the target verifies PAP action tokens (shared replay store + body-hash check). | T-014 | M8/M9 |

## Approvals and human decisions

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-030 | Approval binding = hash of action hash, decision-basis digest, digest of the bound fact members, grant revision, definition digest, run, agent instance, workload jkt, approver requirements, expiry, rendered-display hash (PAP/1 §8). An approval binds only the fact members a prerequisite declares in `binds` (for a merge, the head SHA); every other fact, and when or by whom any fact was observed, is not bound but read again and decided on at finalization (pipeline steps 6 and 7), and only a change to a bound member supersedes a request. Amended with the founder's approval on 2026-10-13. | T-005, T-006 | M5 |
| HR-031 | Finalization re-runs the full pipeline and requires the same requirement class to be satisfied. | T-006 | M5 |
| HR-032 | Approvals are accepted only from authenticated human sessions; API keys and service accounts can never approve. | T-002 | M5 |
| HR-033 | High-consequence approvals require WebAuthn (UV) with `challenge = binding`; Slack/email only deep-link to the authenticated approval page. | T-006, T-026 | M5 |
| HR-034 | Approval text is rendered only from the tool package's per-operation template using canonical fields and system-of-record facts; agent text shown in a quarantined UNTRUSTED block; bidi controls stripped; mixed-script identifiers flagged. A fact appears with the value of the members the approval binds (HR-030); a fact it binds nothing of is shown as checked again when the approval is used (founder approval 2026-10-13). | T-026 | M5 |
| HR-035 | Two-person rules require two distinct users **and** distinct WebAuthn credentials, account-age and role-change cooldowns, and notification to org admins. | T-027 | M5 |
| HR-036 | Initiator/launcher/represented principal cannot satisfy an independent-approval requirement for their own action. | T-002 | M5 |
| HR-037 | Pending HOLDs per grant are capped; approvers see the variant history of the action; variant-shopping is a detection. | T-007 | M5/M10 |
| HR-038 | For high-consequence actions the permit carries the approver's WebAuthn assertion; customer-hosted gateways verify it against customer-pinned approver keys. | T-030 | M6 |
| HR-039 | Approval delivery failure never counts as approval; expiry is enforced at use time. | T-006 | M5 |

## Policy engine (CEL) and delegation

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-040 | Any CEL evaluation error in a FORBID rule ⇒ `DENY`; in REQUIRE/CONSTRAIN rules ⇒ `CANNOT_AUTHORIZE`. Never "no match". | T-018 | M4 |
| HR-041 | Material amounts use custom `decimal`/`money` CEL types; ordering operators on string-typed material fields are rejected at type-check. | T-018 | M4 |
| HR-042 | Optional fields require `has()` guards (enforced by the policy linter). | T-018 | M4 |
| HR-043 | Per-tenant CEL cost budget; exceeding it ⇒ `CANNOT_AUTHORIZE`. Comprehension sizes bounded. | T-023 | M4 |
| HR-044 | Policy rules are mutation-tested before publication (flipping each comparison must fail at least one test). | T-018 | M11 |
| HR-045 | Grant constraints are a lattice (allowlists, numeric ranges, prefixes, time windows) so child ⊆ parent is decidable at issuance. | T-008 | M4 |
| HR-046 | Every ancestor grant is evaluated at decision time; effective authority is the intersection even if issuance checks were wrong. | T-008 | M4 |
| HR-047 | Delegation depth and fan-out are capped; children cannot outlive parents; revocation cascades within one transaction. | T-008 | M4 |
| HR-048 | Shared budgets debit the child and all ancestors, locking rows in a fixed ancestor-first id order. | T-011 | M4 |
| HR-049 | Count-based limits use counter rows updated in the finalization transaction (no check-then-act in CEL). | T-011 | M4 |

## Tenancy and database

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-050 | Composite `(org_id, id)` primary and foreign keys; every unique constraint includes `org_id`. | T-003 | M1 |
| HR-051 | Tenant context set only by `set_config('app.org_id', $1, true)` at transaction start; plain `SET`/string-built SQL is lint-banned. | T-003 | M1 |
| HR-052 | Pool `AfterRelease` runs `RESET ALL`; RLS policies use `NULLIF(current_setting('app.org_id', true), '')::uuid` inside `(SELECT …)` so a missing setting matches nothing. | T-003 | M1 |
| HR-053 | RLS ENABLEd and FORCEd on every tenant table; views use `security_invoker = true`; no SECURITY DEFINER except one audited cross-org lister. | T-003 | M1 |
| HR-054 | Cross-org sweepers list `(org_id, id)` via the audited lister, then process each org in its own transaction with tenant context set. | T-003 | M1 |
| HR-055 | `pc_app` has no TRUNCATE, COPY, DDL or BYPASSRLS; UPDATE/DELETE revoked on evidence tables. Tests run as `pc_app`. | T-003, T-029 | M1 |
| HR-056 | Job args, LISTEN/NOTIFY payloads and logs carry IDs only — never secrets or payloads. | T-015 | M1 |
| HR-057 | Every app connection sets `statement_timeout`, `lock_timeout`, `idle_in_transaction_session_timeout`. | T-023 | M1 |

## Credentials and keys

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-060 | Target credentials are HPKE-sealed (X-Wing) to a broker key per tenant or per gateway deployment (KMS-wrapped); `info`/AAD binds `(org_id, connection_id, cred_version, allowed_hosts)`. | T-015, T-016 | M6 |
| HR-061 | Credentials are opened only in gateway memory at dispatch; never returned by any API, logged, or placed in job args. | T-015 | M6 |
| HR-062 | Envelope encryption AAD binds org, table, column and row id (ciphertext cannot be moved between rows). | T-016 | M1 |
| HR-063 | Licence-signing and package-signing root keys are generated and kept offline; CI never holds them. | T-034, T-036 | M1 |

## Gateway egress (confused deputy / SSRF)

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-070 | Never follow redirects (`CheckRedirect` returns `http.ErrUseLastResponse`). | T-021 | M1.5 |
| HR-071 | Check the **connected** IP in `net.Dialer.Control`: deny loopback, link-local, RFC1918, CGNAT (100.64/10), ULA, IPv4-mapped IPv6, 0.0.0.0/::, cloud metadata; decimal/octal/hex encodings covered by tests. | T-021 | M1.5 |
| HR-072 | Ignore `HTTP(S)_PROXY`/`NO_PROXY` env vars on egress transports. | T-021 | M1.5 |
| HR-073 | Host and SNI come only from the registered connection; path templates are percent-encoded; reject `..`, `%2f`, `@`, `#`, `?`, CR/LF in substitutions; re-parse the final URL and assert it matches the reviewed route. | T-021 | M6 |
| HR-074 | Egress uses a separate `http.Transport` with no client certificate (the gateway's mTLS identity never leaves on egress). | T-022 | M1.5 |
| HR-075 | Outbound requests are re-serialized from ActionIR + definition template; raw agent bytes are never forwarded. | T-020 | M1.5 |
| HR-076 | Responses are size- and decompression-ratio-capped and scanned for echoed injected secrets (redacted). | T-015 | M6 |
| HR-077 | Egress deny list enforced at connection registration and at dial; connections to PantherClaw's own hosts are forbidden; private targets only via customer-hosted gateways. | T-002, T-021 | M6 |
| HR-078 | Per-connection circuit breaker on `UNKNOWN` rate → connection quarantine + alert. | T-013 | M6 |
| HR-079 | Destinations are classified public or internal. A gateway action's class is its connection's: the Authority resolves it from the connection the ActionIR names (never from the gateway or the agent), gives it to policy as `action.destination_class` and records it on the decision receipt (founder decision 2026-10-10). Disclosure-capable params carry size/entropy obligations (M10). | T-017 | M6/M10 |

## MCP and connector runtime

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-080 | `Mcp-Method`/`Mcp-Name` headers must match the JSON-RPC body; JSON-RPC batches are rejected. | T-019 | M6 |
| HR-081 | Agents receive tool descriptions from the reviewed tool package, never live upstream text; drift between live and reviewed definitions quarantines the package. | T-025 | M6 |
| HR-082 | Server→client `elicitation`/`sampling` are blocked by default and policy-gated when enabled. | T-028 | M6 |
| HR-083 | Stateful MCP sessions (2025-11-25) are bound to the workload jkt and re-verified per POST; JSON-RPC ids are remapped per session. MCP list caches are forced private. | T-009 | M6 |
| HR-084 | Third-party MCP servers run only in customer-hosted gateways (never multi-tenant SaaS gateways in MVP). | T-015 | M9 |
| HR-085 | Each connector runs in its own container and namespaces (PID, mount, network, IPC, UTS) as a distinct non-root uid, with a read-only root filesystem, all capabilities dropped, `no-new-privileges`, Docker's default seccomp profile and no host environment; gVisor (`runsc`) is used when available, detected and recorded, but is not required for `ENFORCED`. Its only network path is the edge on its internal network, to the gateway egress PEP, which injects credentials (G0 M9 decision 4, 2026-10-11). | T-015, T-088 | M9 |
| HR-086 | Routes through opaque MCP servers are capped at `PARTIAL` unless their egress is mediated. | T-014 | M9 |

## Identity protocol

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-090 | Verify token, `cnf`, and proof signature **before** inserting `jti`; replay store unique `(jkt, jti)`, time-partitioned. | T-032 | M3 |
| HR-091 | Server-issued DPoP nonces (≤ 5 min) remove reliance on client clocks; raw body hashed before parsing. | T-032 | M3 |
| HR-092 | Desktop workloads (`pclaw mcp proxy`) capped at L1, stdio only (never a localhost HTTP listener); same jkt from a new network ⇒ alert. | T-033 | M3/M6 |
| HR-093 | GitHub OIDC attestation matches `repository_id`, `repository_owner_id` and the workflow (`workflow_ref` for ordinary jobs, `job_workflow_ref` for reusable workflows, on a protected branch or tag), requires `ref_protected`, checks `aud = pantherclaw:<org>`, and rejects `pull_request` runs (from forks or the same repository) and `pull_request_target`. | T-035 | M3 |
| HR-094 | Owner confirms the key fingerprint in ADMISSION unless an L2 auto-admission policy matches pinned claims. | T-004 | M3 |
| HR-095 | Algorithms are pinned per key; `none`, HMAC on asymmetric keys and unlisted algorithms are rejected (go-jose allowlists). | T-032 | M2 |

## Canonicalization and input

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-100 | Strict JSON (`encoding/json/v2`): duplicate keys, invalid UTF-8 and unknown fields rejected; depth/size limits enforced. | T-020 | M4 |
| HR-101 | No JSON numbers in material params (decimal strings only). | T-020 | M4 |
| HR-102 | Mixed-script/confusable identifiers and bidi controls are rejected, not normalized; target-meaningful bytes are never normalized. | T-020, T-026 | M4 |
| HR-103 | Ambiguous targets, missing material fields, unsupported units ⇒ `CANNOT_AUTHORIZE` (no defaults). | T-020 | M4 |
| HR-104 | protovalidate at every API edge plus domain validation; explicit request DTOs (no mass assignment). | T-037 | M1 |

## Evidence and kill switch

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-110 | Receipts are written unchained inside their business transaction; a single per-org chainer (a per-org lock on the ledger head) links rows older than `pg_snapshot_xmin`. | T-029 | M1.5 |
| HR-111 | Signed Merkle checkpoints per window; `pclaw verify` checks consistency proofs; a global root (all orgs) is anchored to Rekor v2 with an RFC 3161 timestamp. | T-029 | M7 |
| HR-112 | Receipts reconcile against target-side logs where available to detect effects without receipts. | T-029 | M7 |
| HR-113 | Kill switch engage: one eligible responder + step-up; restore: two people + step-up; engage also pauses automations and revokes target creds where supported. | T-031 | M6 |

## Sandbox, red team and packages

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-120 | Red-team runs are server-enforced to simulator-only environments; receipts carry `simulated: true`. | T-038 | M12 |
| HR-121 | Sandbox closure probes run from a trusted sidecar plus an external canary, require positive and negative controls, and ENFORCED promotion expires. | T-039 | M9 |
| HR-122 | Sandbox networks are internal Docker networks in isolated gateway mode (`gateway_mode_ipv4=isolated`) with IPv6 off: no route to the host and no IPv6, ICMP, DNS or other egress except to the edge. Docker ≥ 28 required (isolated gateway mode; CVE-2024-29018 is fixed from 26) (G0 M9 decision 1, 2026-10-11). | T-039, T-086 | M9 |
| HR-123 | Tool packages are signed by the offline package root, or, for an org's own packages, by a package-signing key that org registered (HR-162, ADR-0020), with TUF-style expiring metadata; per-org version pins only move forward (anti-rollback). | T-036, T-056 | M4 |
| HR-124 | Package mappings are reviewed as code (a wrong mapping is a total bypass) and covered by golden tests. | T-036 | M4 |

## Supply chain and CI

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-130 | No `pull_request_target`; `persist-credentials: false`; `permissions: {}` default with per-job grants; all actions pinned by full SHA (repo policy enforced). | T-040 | M0 |
| HR-131 | Release job runs harden-runner in block mode, publishes via OIDC trusted publishing only, and attests every artifact. | T-040 | M0 |
| HR-132 | Dependencies pass govulncheck/OSV/dependency-review gates and a 7-day release cooldown; Trivy is not used (March 2026 compromise). | T-040 | M0 |

## Federated identity, runs and discovery (ADR-0018, G0 M3)

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-140 | Trusted-issuer entries pin the issuer, the key source, the audience `pantherclaw:<org>`, the allowed algorithms and at least one immutable claim binding a token to one agent (never a name alone); an entry without one is rejected. Only preset kinds can be configured, and rules built into a preset run in code that configuration cannot disable. | T-044 | M3 |
| HR-141 | Adding or widening an issuer entry (including turning on auto-admission) is a protected change: a new revision that takes effect only when a human holding `identity.issuer.activate` activates it, shown with what it widens and audited. Narrowing or disabling takes effect at once. | T-044 | M3 |
| HR-142 | Issuer keys are fetched, and Kubernetes TokenReview is called, only over TLS through the egress-guarded client; key documents are size-capped and cached at most 15 minutes, and an unknown `kid` triggers at most one refetch per minute per issuer. Private destinations are allowed only by operator configuration, never by tenant input. | T-045 | M3 |
| HR-143 | Attestation tokens are single use (keyed on `jti`, or on the token's SHA-256 when it has none), must carry exactly `aud = pantherclaw:<org>`, must expire at most 1 hour after issue, and confer L2 only until they expire; a workload token never outlives the attestation behind its level. | T-046 | M3 |
| HR-144 | Kubernetes attestation: TokenReview with audience `pantherclaw:<org>` must authenticate the token as the pinned namespace, service-account name and service-account UID and return the bound pod's name and UID, and that pod must still exist; the image digest comes only from trusted cluster state for that pod UID (or signed evidence bound to it), never from the workload. | T-047 | M3 |
| HR-145 | A subject token at `StartRun` is accepted only from an OIDC provider configured for subject tokens, as a signed JWT with an allowed algorithm (opaque tokens rejected), with `aud` naming PantherClaw, unexpired, `iat` at most 5 minutes old, never seen before (`jti` or token SHA-256), and `(iss, sub)` linked to an active user of the org. | T-048 | M3 |
| HR-146 | A run's represented principal is the launcher itself, a user proven by a subject token (HR-145), or for a child run its parent's principal; a principal named by the launcher is refused. A subject token never creates, widens or substitutes for a grant. | T-048, T-001 | M3 |
| HR-147 | Authority never moves between instances: runs (and, from M4, grants) bind to instance and agent ids, never names; a new enrollment, attestation, ownership transfer or reused name starts with no runs; a re-attestation whose binding claims differ from the instance's is refused. | T-004, T-049 | M3 |
| HR-148 | Unknown workloads hold no authority: requests from keys that are not admitted instances are refused (`CANNOT_AUTHORIZE`) and become discoveries deduplicated by key thumbprint, rate-limited per gateway and capped per org; observed attributes are stored and shown as untrusted. | T-050 | M3 |

## Browser sessions, WebAuthn and notifications (G0 M5 part 1)

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-150 | A browser session is issued only by a verified sign-in, as a 256-bit secret in the `__Host-pc_session` cookie (`Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`) stored only as its SHA-256. Each request checks org, user and session state, 30 minutes idle and 12 hours absolute by the database clock. The secret rotates at sign-in, at step-up and after a role change; a rotated secret presented after a 60-second grace ends the session. A user has at most 10 sessions. | T-051, T-037 | M5 |
| HR-151 | A state-changing request authenticated by a session cookie requires `Sec-Fetch-Site: same-origin` (or, without Fetch Metadata, an `Origin` equal to the public origin), the `PC-CSRF: 1` header and a JSON content type; `GET` never changes state. Pages use `html/template`, no inline script or style, a CSP with `script-src 'self'`, `frame-ancestors 'none'` and required Trusted Types, and `Cache-Control: no-store`; no CORS headers are sent. | T-051, T-037 | M5 |
| HR-152 | Browser sign-in uses a single-use `state`, PKCE S256, `nonce`, the RFC 9207 `iss` check and a binding cookie that must come back from the same browser; when `max_age` is requested, `auth_time` must be present and recent. The return path is chosen from a fixed list and stored server-side, never read from the callback. Only active members of the org get a session. | T-051, T-037 | M5 |
| HR-153 | WebAuthn ceremonies accept only the configured RP ID and exactly the public origin, require user verification (UV flag checked), allow ES256, EdDSA and RS256 with keys of at least 2,048 bits, and use a challenge that is bound to one browser session and user, valid 5 minutes and consumed by a conditional update. A credential id exists at most once per org. | T-052 | M5 |
| HR-154 | A signature counter that does not increase (other than 0 stored and 0 received) refuses the assertion and suspends the credential, with an audit event and a notice; a credential's backup-eligible flag cannot change after registration. | T-052 | M5 |
| HR-155 | Adding or removing a WebAuthn credential needs a provider sign-in at most 5 minutes old or a step-up with another active credential at most 5 minutes old; every change is audited and emailed to the user. Administrators can remove another user's credential but never register one. | T-052 | M5 |
| HR-156 | Step-up is recorded on one browser session and expires after 5 minutes; it never carries over to another session, a CLI token, an API key or a service account. Only users can hold browser sessions or WebAuthn credentials. | T-052, T-002 | M5 |
| HR-157 | Notification destinations: webhook URLs are `https` without credentials, never PantherClaw's own host, and are called only through the egress client (connected address checked, no redirects, no proxy variables); private ranges only by operator configuration. Slack URLs must be on `hooks.slack.com`. Email goes only to org users' provider addresses. Webhook secrets and Slack URLs are encrypted per row (HR-062), shown once, and never returned or logged. | T-053, T-021 | M5 |
| HR-158 | Notification content is rendered only from a fixed per-type template over ids, canonical names and counts: no agent text, no free text, no secrets. Channel messages contain no approve or deny action, only a deep link to the authenticated page, and dynamic text is escaped for each channel (Slack link syntax, mail headers). | T-054, T-026 | M5 |
| HR-159 | Deliveries are River jobs carrying ids only, retried at most 8 times (about 27 hours), stopped at notification expiry, capped at 1,000 pending per channel, and signed per Standard Webhooks for webhook channels. A delivery's outcome changes only delivery and channel health; no other module reads delivery state, and a channel never receives an approval. | T-054, T-006 | M5 |

## Grants and facts (G0 M4 part 2)

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-160 | Facts are accepted only from the provider registered for that fact name, authenticated as that provider; values a workload sends are never facts. A fact's observation time may be neither later than the database clock nor earlier than the provider's maximum lag allows, and an older observation never replaces a newer one. A required fact that is missing or older than its maximum age ⇒ `CANNOT_AUTHORIZE`. | T-055 | M4 |
| HR-161 | Workload credentials never issue, widen or change grants or guardrails. Guardrail changes need a person holding `guardrails.manage`. Root grants are issued only by a person holding `grant.issue` for the agent's team, unless G0 M4 decision 7 extends issuance to audited service accounts. A workload can only delegate a subset of its own run's grant to a child run, and only when that grant allows delegation and depth remains. | T-001, T-008 | M4 |
| HR-162 | Org package-signing keys (ADR-0020, Team edition and above): targets signed with an `org-packages-` key verify only against that org's registered, unrevoked Ed25519 keys, with anti-rollback per key. Only a person holding `package.key.manage` registers a key, at most 5 are active, and a revoked kid is never registered again; every change is audited. An org key never signs a `pc.` name, and within an org an operation is defined by packages of one kind of signer only (package root or org keys; retired versions do not count). Importing never activates. Revoking a key as `COMPROMISED` raises the containment epoch, quarantines its `ACTIVE` and `STALE` versions and retires its others in the same transaction, and no version it signed is activated again. | T-056, T-036 | M4 |
| HR-163 | The development package key (kid `packages-dev-`, made by `dev seed`; [G0 follow-up](../g0/M4-dev-package-key.md)) is trusted only by a server whose API and gateway listeners, gateway hostnames and public URL are all on loopback, with no declared proxy and without `live` API keys; a configuration that names it otherwise refuses to start. It is never a package root. | T-036 | M4 |

## Approvals, waitlist and wait handles (G0 M5 part 2)

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-170 | An approver or step-up subject is eligible only while they are an enabled user holding `approval.respond` through the requirement's role (G0 M5 part 2 decision 2) on the agent's scope path. Eligibility is checked when they respond and again inside the finalization that consumes the approval. Removing their role, disabling them, or removing or suspending their credential voids their unconsumed responses. The run's launcher and represented principal, and those of every ancestor run, never count toward an approval; an `independent` requirement also excludes the agent's owners and the grant's issuer (decision 3). A step-up is satisfied only by the person the requirement names. One response counts toward one requirement. | T-002, T-027, T-061 | M5 |
| HR-171 | An approval request is created only by the finalization that records a hold, and its binding is fixed then. A request whose binding no longer matches the current evaluation is superseded, never updated. An approved request is consumed by a conditional update inside the finalization that issues the permit: at most once, before its deadline and its consume-by time, by the database clock. A decline, an expiry or a narrower proposal ends the transaction as `DENY`. No hold is recorded while containment refuses the action. | T-005, T-006 | M5 |
| HR-172 | Declining, requesting evidence and proposing a narrower action grant nothing and need a human session. A narrower proposal keeps the operation, target, account and destinations, and moves only material parameters toward narrower values; the agent must submit it as a new action, with its own decision and approval. Evidence and notes from workloads or requesters are untrusted and size-capped. They are shown only in the untrusted block, never sent in notifications, and never change a binding; only facts from registered providers do. | T-063, T-026 | M5 |
| HR-173 | Approval requests and waitlist entries are routed only to currently eligible deciders, recomputed at every notification. Reminders and escalation steps notify more eligible deciders at wider scopes but never make anyone eligible, and all of them happen before the deadline. Having no eligible decider, or failing deliveries, is recorded as routing health and reported to the org's admins; the hold still resolves to `DENY` at its deadline. | T-061, T-006, T-054 | M5 |
| HR-174 | A wait handle names a transaction and is served only to a workload authenticated by PAP/1 as that transaction's run and instance. Waiting is read-only: it returns states, codes and times, never approver identities, notes or rendered content. A long-poll lasts at most 30 seconds and a stream at most 5 minutes, and concurrent waits are capped per instance and per server. Waiting never extends a deadline or dispatches anything; the agent resubmits the identical action. | T-060, T-023, T-005 | M5 |
| HR-175 | A batch approval covers only `ACTION_HOLD` entries that share an operation and definition digest, whose definition is reversible, whose requirement is one approver without step-up or `independent`, and whose value is at or below the org's batch ceiling. A batch has at most 25 entries and one WebAuthn assertion, whose challenge is the hash of exactly those entries' sorted bindings. Each entry keeps its own response, audit event and consumption. | T-062, T-007 | M5 |
| HR-176 | Access requests and restorations never change authority by themselves. An access request is resolved only by dismissal, or by a grant revision made through the grant API by a person allowed to issue that grant, with its issuance checks and audit. A restoration takes effect only when an eligible person other than the requester approves it with a WebAuthn assertion bound to the restoration. No approval widens a grant, a guardrail or a policy, and nothing approves "all similar" actions. | T-001, T-002, T-063 | M5 |
| HR-177 | A waitlist entry's kind, subject, priority and deadline come only from PantherClaw's own records, never from agent input. At most one entry per subject is open. Every transition is a conditional update. Deadlines are enforced at use by the database clock, and an entry past its deadline resolves to "not done" (denied, not admitted, not restored, not activated, unchanged). The exception is a `RECONCILIATION` entry, which stays open and escalates until it is resolved. | T-007, T-061 | M5 |

## Gateway identity, custody, modes and cooperative channels (G0 M6)

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-180 | A gateway is enrolled only with a single-use `pcg_` token (256-bit, at most 15 minutes, stored as SHA-256, bound to one gateway record) and a certificate request signed by a key the gateway generated; the gateway accepts the internal CA only if its SHA-256 equals the pin given with the token. Gateway certificates are Ed25519, valid at most 24 hours, and bind exactly one gateway and org in a URI SAN; renewal needs the current certificate and a new key. | T-065 | M6 |
| HR-181 | `AuthorityService` and gateway RPCs other than `Enroll` are served only on the server's gateway listener: TLS 1.3, a client certificate required and verified against the internal CA. Every call loads the certificate's row (cached at most 1 second) and requires the gateway to be `ACTIVE` and the certificate unexpired by the database clock and `ACTIVE` (or `SUPERSEDED` by a renewal less than 10 minutes ago); the org comes only from that row, so revocation applies on the next call. The public API refuses these RPCs whatever credential is presented. | T-065, T-009 | M6 |
| HR-182 | A broker key is registered only by its gateway, over that gateway's own mTLS identity, and is shown by fingerprint. `pclaw seal` seals only to the active broker key of the gateway that serves the connection, and the seal's `info` binds org, connection, credential version, allowed hosts, broker key and placement. Sealed bytes are returned only to that gateway, never to a user-facing API. | T-066, T-015 | M6 |
| HR-183 | Changes that weaken enforcement (a route from `enforce` to `monitor`; a connection's base URL, allowed hosts, gateway, package or access mode; restoring a quarantined connection; replacing a credential) need a person holding `connection.manage`, are audited with old and new values, and are notified to org admins. Changes that strengthen it (to `enforce`, quarantine, retire, revoke a credential) take effect at once and increment the containment epoch in the same transaction. | T-067 | M6 |
| HR-184 | Monitor mode never blocks on policy, reserves nothing and never claims prevention: its receipts say `monitor: true` with the hypothetical decision. It still needs a verified, admitted workload, and its permits are issued only when identity and containment pass and still go through `BeginDispatch`, so containment and the kill switch stop monitor-mode traffic too. | T-067, T-031 | M6 |
| HR-185 | A held MCP call or MCP task is bound to the org, connection, run, instance and action that created it; a poll, result or cancel from any other binding gets "not found". A resubmission reuses the held action id only for an identical tool call (same tool and canonical arguments); any changed argument is a new action. MCP tools are exactly the connection's reviewed package tools, and tool lists are served `private`. | T-068 | M6 |
| HR-186 | Cooperative channels (the hook endpoint and, from M8, SDK authorize) never make the gateway dispatch: an `ALLOW` passes `BeginDispatch` and is recorded with outcome `delegated`, access mode `agent_held`, and `PARTIAL` assurance. The Claude Code hook allows only `ALLOW` (and obligations it can honour), denies every other decision including holds (never asking the local user), and denies on any error or after its own deadline, which is shorter than the hook timeout. | T-069, T-014 | M6 |
| HR-187 | Paths in hook requests are normalized lexically before policy sees them (drive letter, separators, `.` and `..`); `\?\` and `\.\` device paths, alternate data streams and segments ending in a dot or space are refused (`CANNOT_AUTHORIZE`). The command text is never normalized. | T-069 | M6 |
| HR-188 | Action tokens (`pap-action+jwt`) are minted only by the Authority at `BeginDispatch`, over the hash of the exact outbound body the gateway will send; they are single use, expire within 60 seconds, carry the connection as audience and bind the transaction, action hash, operation and target. | T-065, T-014 | M6 |

## Effects, reconciliation and proof (G0 M7)

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-190 | Verification reads are made only by the gateway serving the connection, only on a single-use lease from the server (at most 30 s, bound to that gateway and connection), and only through the `access: read` definition, with method `GET` or `HEAD`, that the write's verifier names in the connection's pinned package. The request is built from that definition's dispatch template with values the server computed from the stored action and the target's reference, through the M6 egress path. Reads never write, stop under the kill switch, a quarantined or retired connection and a stale containment stream, and report only the fields the verifier declares plus a response digest. | T-070 | M7 |
| HR-191 | An effect state comes only from verifier observations or a recorded person's resolution, never from the executor's or the agent's assertion; an `accepted` outcome alone reaches only the acceptance level. Every effect receipt states the level required and achieved, the basis, the verifier and the definition's limits. Conflicting observations are all kept, and effect receipts are appended, never rewritten. When the required verification level cannot be reached for an action, it is `CANNOT_AUTHORIZE` (`VERIFIER_UNSUPPORTED`). | T-071 | M7 |
| HR-192 | Every `UNKNOWN` outcome, reported by the gateway or set by the sweeper, writes its execution attempt, a signed execution receipt and an open reconciliation task in the same transaction, and keeps its reservations and dedupe claim held. Evidence that the effect happened (a confirming observation, a late `accepted` report) resolves it automatically by committing. Only a person holding `transaction.reconcile` who is not the run's launcher, its represented principal, or the agent's owner or backup owner releases it, with a written basis and a WebAuthn assertion bound to the reconciliation, the resolution and that basis. | T-072, T-013, T-024 | M7 |
| HR-193 | Compensation and recovery are new, separately authorized transactions linked to the original. A link changes none of the original's records, receipts or budgets; the original becomes `COMPENSATED` only when the compensating effect is confirmed, and is never described as reversed. | T-072 | M7 |
| HR-194 | Each org's ledger is an RFC 9162 Merkle tree over its chained entry hashes, with a signed checkpoint per window. A checkpoint is signed only after the chain links of its new entries were recomputed from the entries and the new tree was proven consistent with the previous checkpoint; any mismatch stops checkpointing for that org and raises a security event. Every org's chain is re-verified against its latest checkpoint daily. Evidence keys are published with their validity and revocation. | T-029, T-073 | M7 |
| HR-195 | The anchored global root has one leaf per org per anchor, blinded with a fresh random nonce, so it reveals neither which org a leaf belongs to nor whether the org was active. It is signed by the separate `anchors` key and entered in the configured transparency log, with a timestamp from the configured authority; both responses are verified before the anchor counts. Anchoring runs outside authorization, never blocks it, and its failures are visible in every integrity report. | T-073 | M7 |
| HR-196 | `pclaw verify` works offline and trusts only keys the user pinned. It checks every signature, chain link, inclusion and consistency proof, anchor and timestamp in the bundle, and reports each as passed, failed or not available, with the limits of what passed: integrity, not completeness or effect. Evidence packs are signed manifests that list every item's digest, every effect state in scope (including unknown and conflicting), the versions that applied and every gap, and contain only what their creator could read. | T-073, T-077 | M7 |
| HR-197 | Decision replay evaluates the stored inputs of an evaluation without the finalization: it writes no transaction, receipt, reservation or permit and calls no gateway. Missing, removed or truncated inputs make a replay incomplete, never guessed. Input values are shown only to holders of `evidence.read_restricted`. | T-074 | M7 |
| HR-198 | Retention removes only bodies (receipt and ledger bodies, observed values, replay inputs, payload captures), through the `pc_retention` role used only by the retention job, leaving hashes, chain links, Merkle leaves and a tombstone. Items in an active legal hold are never removed. Shortening a retention period needs a person, is audited and notified, and takes effect after 7 days; `pc_app` keeps no UPDATE or DELETE on evidence (HR-055). | T-075 | M7 |
| HR-199 | Payload capture happens only under an active capture profile that a person holding `evidence.capture.manage` created with a purpose, scope, byte cap (≤ 64 KiB), retention (≤ 30 days) and expiry (≤ 90 days). Captures are taken at the gateway after secret-echo redaction, never include headers or credentials, are sealed per row (HR-062), and are read only by a person holding `evidence.read_restricted`, with a reason, through a read that is audited before the content is returned. | T-076, T-043 | M7 |

## Coding-agent integrations, GitHub and consequences (G0 M8)

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-200 | SDK and Agent SDK integrations fail closed: when PantherClaw cannot decide (unreachable, timed out, an error or an answer it cannot parse), a mapped tool call does not run. The Agent SDK integration enforces from its `PreToolUse` hook, which runs in every permission mode including bypass. `Bash` and `PowerShell` are decided through the local connection's `/hook` mapping; without one the integration refuses to start unless the application explicitly opts into observing the shell. Other tools go through `/sdk`. Every error in the hook or callback is caught and denies, and the hook's own deadline is shorter than its timeout. A `HOLD` never runs without a later `ALLOW`: the hook answers `ask` only in the permission modes where the SDK documents, and tests prove, that `canUseTool` is then called and no allow rule names the tool (otherwise it denies), and `canUseTool` allows only after a resubmission returns `ALLOW` within its own deadline, and denies at that deadline. Unmapped built-in tools run under the application's own permissions and are recorded `OBSERVE_ONLY`; other unmapped tools are denied unless the application opts into observing them. Agent SDK decisions are labelled `PARTIAL` (HR-024, HR-186). | T-080, T-069 | M8 |
| HR-201 | The gateway's `/sdk/{connection}` face decides only on ActionIR it maps itself, through the connection's signed package, from the raw tool call whose exact bytes the PAP/1 proof covers. An ActionIR, action hash or canonical form supplied by the SDK is never trusted; the SDK canonicaliser only checks returned hashes and resubmits an identical call. For a `target_enforced` connection the face re-serializes the outbound method, URL and exact body from its own ActionIR (HR-075), reports that body's hash at `BeginDispatch` so the action token binds it (HR-188), and returns those bytes with the token; the SDK sends them unchanged. | T-080, T-081 | M8 |
| HR-202 | Target verifier middleware refuses a request before its handler runs unless the action token's signature verifies against an `action_tokens` key from the configured JWKS (pinned algorithms, HR-095), its issuer is the configured one, its audience is this target's connection, it is unexpired, its `bh` equals the SHA-256 of the exact received body, its operation and target match the route, and its (`aud`, `jti`) is inserted for the first time into a replay store shared by every replica of the target. The store keeps each entry at least until `exp` plus the allowed clock skew, and the middleware refuses whenever the store cannot record (unreachable, full, evicting or restarted without its entries). | T-081 | M8 |
| HR-203 | Every GitHub installation token the gateway mints (for a dispatch, a verification or fact read, a connection test or a scan) is minted for that one task, scoped to the narrowest repositories and permissions the task needs (a dispatch: exactly the action's repository and its operation's declared minimum permissions; every read: read-only), never reused for another task, never returned to the agent, logged or stored, and revoked after use whatever the outcome. | T-082 | M8 |
| HR-204 | A GitHub App private key exists only as a sealed credential bound to the gateway that serves the connection (HR-060, HR-182), opened only in that gateway's memory to sign App JWTs that live at most 10 minutes; no API, log, job or receipt carries the key or a JWT. | T-082 | M8 |
| HR-205 | A merge is bound to the pull request's head SHA: every mapping requires it as a material parameter (the MCP tool's head-SHA argument and the REST body's `sha`), the approval binding includes it, and the dispatch passes it to GitHub so that any other head fails (409). A new commit on the pull request invalidates every unconsumed approval for it. | T-083 | M8 |
| HR-206 | Stored consequence rules (F405) are evaluated in the decision pipeline. When a fact a rule needs is missing, stale or unreadable, the result is at least `HOLD` with reason "Consequence unknown", carrying the requirements of every consequence the rule could produce as if it were predicted; a `DENY` still wins, and the result is never `ALLOW`. **Monitor mode (approved by the founder on 2026-10-13):** monitor mode stays observe-only (HR-184), so on a monitor-mode route such an action is still dispatched; its decision and receipt record "would HOLD: consequence unknown" (`would`) with the same reasons as enforce mode, and a security notification goes out, one per transaction. | T-083 | M8 |
| HR-207 | The independent reviewer of a merge (`code_reviewer`) and the release approver of a deployment consequence (`release_approver`) are each a person other than the run's launcher, its represented principal and the agent's owners, and, by GitHub user id when linked to a user, the pull request's author and every one of its commits' authors, committers and authenticated pushers. When these cannot all be read, the requirement cannot be met. The reviewer and the release approver of one action are two different people. A release approval counts only when it is consumed inside an active change window. | T-083 | M8 |
| HR-208 | `pclaw init` backs up every file before it changes it and writes atomically; it never writes a secret into configuration and never removes or weakens an existing deny rule, hook or server entry; it shows the diff before writing; and it reports failure when managed settings would disable its hooks or servers. | T-084 | M8 |
| HR-209 | The GitHub organisation scan reads metadata only: no secret values, and no file contents beyond the files it names (workflow and MCP configuration files). From those files it keeps names (servers, environment variables, headers, the command's base name) and drops every value and argument in memory before a finding is built. Its findings are candidates and never grant authority. | T-084 | M8 |

## Coverage, containment sandbox and connector runtime (G0 M9)

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-210 | Coverage states come only from evidence. `ENFORCED` needs current closure evidence for every material route in scope; a setting alone never yields a state (F460); monitor-mode routes are `OBSERVE_ONLY`; a scope whose routes are not known is `UNKNOWN`; cooperative routes are capped at `PARTIAL` (HR-024) unless current evidence (a passing target-verifier test, no older than the `ENFORCED` lifetime) shows the target refusing a request without a token, with a replayed token and with a mismatched body hash (HR-202). A declared replay store is a setting and never lifts the cap. | T-085 | M9 |
| HR-211 | `ENFORCED` expires (24 hours by default, configurable). Every invalidation event downgrades it at once: a change to a connection, package version, route mode, gateway, sandbox image or configuration, or credential. After expiry or invalidation, the state is recomputed from current evidence and capped at `PARTIAL` (it may be lower), and the last valid record is shown with the reason it lapsed. | T-085 | M9 |
| HR-212 | Coverage exclusions are weakening changes: only a person creates one, with a written reason and an expiry; every exclusion is audited and shown with the coverage it changes. | T-085 | M9 |
| HR-213 | In `pclaw sandbox run` the edge sidecar is the agent's only route: the agent is attached only to an internal network in isolated gateway mode, shared with the edge. The edge's only outbound connection is the gateway; it never dials a destination itself. Only the edge holds the run's workload key and the per-session CA key; the agent container holds no credential or key, only the CA certificate, mounted read-only. | T-086 | M9 |
| HR-214 | The edge refuses every destination without a mapped connection and intercepts TLS only for mapped hosts; it refuses and records every other `CONNECT` and plain request. | T-086 | M9 |
| HR-215 | Probe results are signed with a per-session key that `pclaw` creates outside the agent container and are bound to a server nonce; unsigned, replayed or stale results are rejected. Positive controls (a deliberately open path is seen as open) and negative controls (every catalogue route from the sandbox is closed) are required: a run with a missing or failed control promotes nothing, and a failed negative control also drops the scopes' current `ENFORCED`. | T-087 | M9 |
| HR-216 | Connector containers never receive the Docker socket, the host environment or the host network, and only customer-hosted gateways start them (HR-084), through the Docker CLI with fixed arguments. | T-088 | M9 |
| HR-217 | A decision receipt's optional coverage claim names the coverage snapshot (state and id) that was current for the action's scope at decision time. It is carried inside the signed payload and is absent, never null, when there is none, so receipts without a claim stay valid and unchanged. `pclaw verify` and evidence packs check it against the snapshot ledger. | T-089 | M9 |
| HR-218 | Sandbox and connector runs refuse to start on a Docker engine older than 28 or when the isolation self-check fails, and record the engine version, API version and runtime (`runc` or `runsc`) in their evidence. | T-086 | M9 |
| HR-219 | Reserved for M9 (G0 M9); not assigned. Kept so the number is not reused; it has no milestone, so the traceability check skips it. | — | — |
