# PantherClaw — Security Baselines (SG03–SG07, SG13)

**Status:** approved baseline (G0, 2026-10-08). Every implementation MUST meet these; deviations require an ADR and a recorded exception. Concrete, testable rules live in [HARDENING_RULES.md](HARDENING_RULES.md).

## SB-1 Secure patterns (SG03)

**Layered architecture.** `domain` (pure) ← `app` (use cases, authz, tx) ← `adapters` (DB, RPC, clients) ← `cmd`. Enforced by depguard + architecture test ([ARCHITECTURE.md §4](../ARCHITECTURE.md)).

**Least privilege.**
- DB roles: `pc_migrator` (DDL only, used by migration job), `pc_app` (DML, no TRUNCATE/COPY/BYPASSRLS, no UPDATE/DELETE on evidence), `pc_audit_ro` (read-only evidence).
- Processes: gateway has **no DB access**; server never holds plaintext target credentials; `pclaw-admin` offline only.
- Keys: separate keys per purpose (receipts, permits, workload tokens, internal CA, envelope DEKs, broker); a compromise of one does not grant the others.
- CI: `permissions: {}` default; jobs request the minimum; release publishing via OIDC only.
- Containers: distroless, non-root UID, read-only rootfs, all capabilities dropped, `no-new-privileges`.

**Zero trust.** No trust from network location. Every hop authenticates: humans (OIDC + session), services (`private_key_jwt`), workloads (PAP/1), gateways (mTLS with org binding). The Authority re-verifies identity forwarded by gateways. Authorization is checked at every API call against the caller, tenant and resource.

**Validation boundaries.**
1. Edge: protovalidate rules in protos (types, lengths, enums, patterns), request size limits.
2. Domain: constructors validate invariants; no exported struct can be created invalid.
3. Agent input: strict JSON v2, canonicalization rules (PAP/1 §6), tool-package mapping; ambiguity ⇒ `CANNOT_AUTHORIZE`.
4. Output: JSON responses with correct content types; no HTML rendering of untrusted text except the server-rendered approval page (contextual escaping, strict CSP, Trusted Types).
5. Outbound: re-serialization + egress guards (HR-070..077).
6. Untrusted by default: model output, tool descriptions, MCP server responses, webhook payloads, repository content, agent-supplied text.

**Safe APIs.** SQL only via sqlc (parameterized); no string-built SQL; `os/exec` only in the connector runtime and CLI with argument vectors (never shells); templates with contextual auto-escaping.

## SB-2 Authentication & sessions (SG04)

| Principal | Method | Validation | Lifetime | Revocation |
|---|---|---|---|---|
| Human (browser) | OIDC Authorization Code + PKCE (S256), `state`, `nonce`, RFC 9207 `iss` check | ID token: signature (RS256/ES256/EdDSA only), `iss`, `aud`, `azp`, `exp`, `iat`, `nonce`; JWKS cached with rotation | Session idle 30 min, absolute 12 h | Server-side session delete; logout; role change rotates session |
| Human (CLI) | OIDC device authorization grant | Same ID-token checks | Access 15 min, refresh 8 h, bound to device key | Revoke refresh token server-side |
| Human step-up | WebAuthn (passkey/security key), user verification required | Origin, RP ID, challenge, signature counter, credential owner | 5 min, bound to session; transaction-bound for approvals | Credential removal |
| Service account | OAuth2 client credentials with `private_key_jwt` (RFC 7523) | Assertion signature, `aud`, `exp` ≤ 5 min, `jti` replay | Access token 15 min, audience-bound | Disable account / rotate key |
| Integration API key | `pck_<env>_<256-bit random>` bearer | SHA-256 lookup, scope, expiry, optional IP allowlist | ≤ 1 year, default 90 days | Immediate revoke; GitHub secret-scanning pattern |
| Workload (agent) | PAP/1 workload token + DPoP proof | [PAP-1.md §3–4](../protocol/PAP-1.md) | 10 min | Instance suspension; key rotation |
| Gateway | mTLS client cert from internal CA, org binding in SAN URI | Chain, expiry, revocation list, org binding | 24 h auto-renew | Gateway disable + CA revocation |
| Inbound webhook | HMAC-SHA256 over `timestamp.body` | ±5 min tolerance, replay cache | per secret | Secret rotation |

Session cookie: `__Host-pc_session`, `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, 256-bit random, stored as SHA-256. CSRF: SameSite + `Sec-Fetch-Site` check + required custom header for state-changing requests. Brute force: per-identity and per-IP rate limits. Authentication is separated from authorization: authn yields a principal; every use case performs its own authz check (RBAC + scope + SoD).

**Roles (default):** Org Admin, Security Admin, Agent Owner, Policy Author, Policy Publisher, Approver, Responder, Auditor, Developer, Viewer, and (M3) Run Launcher, which may start runs for users who present a subject token (HR-146), Agent Admitter, which confirms instance fingerprints for agents its holder owns (HR-094, human only), and Identity Publisher, which activates trusted-issuer entries (HR-141, human only); (M4) Grant Issuer, which issues grants (HR-161, human only), and Fact Provider, for the service account a fact provider reports with (HR-160). From M4, Policy Publisher also changes guardrails, activates imported packages and registers fact providers (human only); Org Admin imports packages but cannot activate them. Platform administration never implies business approval or restricted-evidence access (F583). Author ≠ publisher for sensitive production changes; initiator ≠ approver.

## SB-3 Cryptography & key management (SG05)

| Purpose | Standard | Library |
|---|---|---|
| External transport | TLS 1.3 only; hybrid post-quantum key exchange (X25519MLKEM768) preferred; HSTS | `crypto/tls` |
| Internal transport | mTLS TLS 1.3, Ed25519/ECDSA P-256 certs, 24 h | `crypto/tls`, `crypto/x509` |
| Data at rest (fields) | AES-256-GCM, random 96-bit nonce (`cipher.NewGCMWithRandomNonce`), per-org per-purpose DEK, AAD = `org|table|column|row_id` | stdlib |
| Key wrapping | KEK via `KeyProvider`: file (dev, 0600, never in repo) → OpenBao Transit → cloud KMS/HSM | adapter |
| Sealed credentials | HPKE (RFC 9180) MLKEM768-X25519, HKDF-SHA256, AES-256-GCM; AAD binds org/connection/version/hosts | `crypto/hpke` |
| Signatures | Ed25519 (JWS EdDSA); optional ML-DSA-65 co-signature on receipts | `crypto/ed25519`, `crypto/mldsa`, go-jose v4 |
| Hashing | SHA-256; HMAC-SHA256 for webhooks | stdlib |
| Randomness | `crypto/rand` only (`math/rand` banned) | stdlib |
| Database & backups | Volume/disk encryption by host/provider; backups encrypted (age/KMS) | ops |
| FIPS variant | `GOFIPS140=certified`, tested with `GODEBUG=fips140=only`; X25519 replaced by P-256 / ML-KEM where required | stdlib |

**Rotation:** signing keys 90 days (≥ 7-day overlap, JWKS publishes both); DEKs yearly or on suspicion (lazy re-encryption job); KEKs per provider policy; internal CA intermediates yearly; broker keys on gateway re-enrollment. Runbook: [runbooks/key-rotation.md](../runbooks/key-rotation.md).
**Never:** custom primitives, ECB/CBC without MAC, static nonces, keys in env vars of agents, keys in source/CI. Signature ≠ proof of effect; encryption ≠ integrity of business facts.

## SB-4 Security logging (SG06)

**Streams**

| Stream | Content | Store | Retention (default) | Access |
|---|---|---|---|---|
| Platform audit | Privileged changes, authn events, role changes, evidence access, exports, kill switch | Ledger (hash-chained) | 1 year (edition-dependent) | Auditor, Security Admin |
| Product evidence | Decision / execution / effect receipts, approvals | Ledger | Per retention policy (7 d → custom) | Scoped by permissions |
| Operational logs | Service logs (no payloads) | stdout → Loki | 30 days | Operators |
| Traces/metrics | OTel spans, metrics | LGTM / OTLP | 14 days | Operators |

**Mandatory fields:** `ts` (UTC RFC 3339 nanos), `level`, `event` (dotted name e.g. `authz.decision`), `org_id`, `actor{type,id}`, `request_id`, `trace_id`, `txn_id` (when applicable), `outcome`, `reason_code`, `version` (build), relevant object versions.

**Redaction:** `Secret[T]` and `Sensitive[T]` wrapper types implement `slog.LogValuer` returning `[REDACTED]`; a `ReplaceAttr` denylist (`authorization`, `cookie`, `set-cookie`, `password`, `token`, `secret`, `api_key`, `proof`, `private_key`) as defense in depth; raw request/response payloads never logged; restricted payload capture only under an explicit, audited profile (F513). Values are JSON-encoded (control characters escaped) and capped at 2 KiB per attribute (log-injection defense).

**Failure behavior:** failure to write a platform-audit entry for a privileged change fails that change (fail closed). Operational log failures never block request handling. Missing telemetry is surfaced as a gap, not silence (F220).

## SB-5 Dependencies & build (SG07)

See [DEPENDENCY_POLICY.md](DEPENDENCY_POLICY.md). Summary: allowlisted direct dependencies with written justification; lockfiles (`go.sum`, `uv.lock`, `pnpm-lock.yaml`) committed; Go module proxy + checksum DB verification, `-mod=readonly`; 7-day release cooldown; govulncheck (reachability) blocking; OSV-Scanner for SDK ecosystems and images; dependency-review with licence allowlist; actions pinned by full SHA; distroless images pinned by digest; SBOM + provenance attestation per release; vulnerability SLAs: critical 7 d, high 30 d, medium 90 d; exceptions ≤ 30 d with owner and compensating controls.

## SB-6 Automated security checks (SG09)

| Check | Tool | When | Blocking |
|---|---|---|---|
| Static analysis | golangci-lint v2 (gosec, staticcheck, errcheck, bodyclose, sqlclosecheck, forbidigo, depguard…) | PR, pre-push | Yes |
| Pattern rules | Opengrep/Semgrep CE with project rules in `tools/semgrep/` | PR | Yes (high) |
| Go vulnerabilities | govulncheck | PR, nightly, released versions weekly | Yes (reachable) |
| Ecosystem vulnerabilities | OSV-Scanner (go.mod, uv.lock, pnpm-lock, images) | PR, nightly | Yes (high+) |
| New dependency review | dependency-review-action (vulns + licences) | PR | Yes |
| Secrets | GitHub push protection; gitleaks (pinned binary) | push, PR, pre-commit | Yes |
| Workflow security | zizmor | PR | Yes |
| Licence headers | header check tool | PR, pre-commit | Yes |
| Product invariants | invariant, race, tenancy, adversarial suites | PR | Yes |
| API fuzzing | Schemathesis against generated OpenAPI | nightly | Findings → register |
| Go fuzzing | `go test -fuzz` (canonicalizer, parsers, CEL inputs) | nightly | Findings → register |
| Load & latency | k6 + benchmarks | nightly | Regression > 10% alerts |
| Supply chain posture | OpenSSF Scorecard | weekly | Tracked |

CodeQL is intentionally not used: its free licence covers OSI-licensed codebases and PantherClaw's core is BSL ([ADR-0008](../adr/0008-security-scanning-toolchain.md)). A green scanner result proves only that tool's scope.

## SB-7 Secrets handling

Secrets never in source, env files committed, CI logs, job args, receipts or exports. Local dev secrets in `.env.local` (git-ignored) or OS keychain. Server secrets via file mounts or KMS. Target credentials only as HPKE-sealed blobs. Secret-like values detected in agent params are classified and redacted in evidence.

## SB-8 HTTP & RPC server hardening

TLS config from `platform/httpx` only; `ReadHeaderTimeout` 5 s, `ReadTimeout` 30 s, `WriteTimeout` 60 s (streaming endpoints exempt with heartbeats), `IdleTimeout` 120 s, `MaxHeaderBytes` 32 KiB, body limit 1 MiB default; security headers (HSTS, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Content-Security-Policy: default-src 'none'` for APIs, `frame-ancestors 'none'`; the sign-in form pages (`/device`) send `Referrer-Policy: same-origin` instead, because a browser form POST under `no-referrer` carries `Origin: null`, which the same-origin check refuses); panic recovery returns generic errors (no stack traces to clients); errors carry stable codes, never internal details; per-identity/per-IP rate limiting; health endpoints unauthenticated but non-sensitive; pprof only on admin listener bound to localhost.

## SB-9 Privacy & retention

Separate retention per category (F512); raw payloads not captured by default (F513); no secrets in ordinary evidence (F514); source permissions propagate to search, graphs, counts and exports (F515); restricted-evidence access audited (F516); deletion workflows preserve "payload unavailable" vs "never existed" (F521); data residency claims only as actually supported (F523).

## SB-10 Review baseline (SG13)

OWASP ASVS **5.0.0** Level 2 (Level 3 for authentication, session, authorization and cryptography modules) · OWASP API Security Top 10 **2023** · OWASP Top 10 **2025** · CWE Top 25 **2025** · OWASP Top 10 for **Agentic Applications (2026)** and OWASP Top 10 for LLM Applications 2025 for product-threat coverage · MITRE ATLAS for detection mapping. Mapping and status: [OWASP_CWE_MAPPING.md](OWASP_CWE_MAPPING.md).
