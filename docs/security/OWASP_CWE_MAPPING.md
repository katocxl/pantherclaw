# PantherClaw — OWASP / CWE Baseline Mapping (SG13)

**Selected:** 2026-10-08 (G0). **Editions:** OWASP Top 10:2025 · OWASP API Security Top 10 2023 · OWASP ASVS 5.0.0 (L2; L3 for V6–V11) · OWASP Top 10 for Agentic Applications 2026 · CWE Top 25 2025 · MITRE ATLAS (detections). Category names were taken from the published editions; re-verify wording at each milestone G0.

**Status vocabulary (SG14):** `Planned` · `In progress` · `Implemented (pending verification)` · `Verified` (test evidence for the stated revision) · `Exception` · `N/A (justified)`. Nothing starts as Verified.

## 1. OWASP Top 10:2025

| Category | Applicability | Primary controls | Evidence (tests) | Status |
|---|---|---|---|---|
| A01 Broken Access Control | Critical (product core) | Per-call authz, RLS, composite keys, SoD, grants/policy engine | HR-050..055, T-003, T-037, T-042 | Planned |
| A02 Security Misconfiguration | High | Hardened defaults (SB-8), distroless, config validation at start, no debug in prod | config tests, image policy | Planned |
| A03 Software Supply Chain Failures | High | DEPENDENCY_POLICY, pinned actions, cooldown, SBOM, attestations | HR-130..132 | Planned |
| A04 Cryptographic Failures | High | SB-3 stdlib crypto, AAD binding, rotation | HR-060..063, crypto vectors | Planned |
| A05 Injection | High | sqlc, no shells, strict JSON, CEL type-check, templated output | Semgrep rules, fuzzing | Planned |
| A06 Insecure Design | Critical | Threat model, invariants, hardening rules, state machines | Invariant suite | Planned |
| A07 Authentication Failures | Critical | SB-2, PAP/1, WebAuthn | HR-090..095, T-032, T-037 | Planned |
| A08 Software or Data Integrity Failures | Critical | Signed packages/receipts/permits, ledger, release attestations | HR-110..112, HR-123 | Planned |
| A09 Security Logging & Alerting Failures | High | SB-4, audit ledger, detections | redaction tests, detection fixtures | Planned |
| A10 Mishandling of Exceptional Conditions | Critical | Fail-closed CEL, CANNOT_AUTHORIZE, UNKNOWN outcomes, heartbeat fail-closed | HR-040, HR-003, HR-010 | Planned |

## 2. OWASP API Security Top 10 2023

| Risk | Controls | Status |
|---|---|---|
| API1 Broken Object Level Authorization | Typed OrgID, RLS, resource authz in every use case | Planned |
| API2 Broken Authentication | SB-2, PAP/1, rate limits | Planned |
| API3 Broken Object Property Level Authorization | Explicit request/response DTOs per role; field-level redaction | Planned |
| API4 Unrestricted Resource Consumption | Body/depth limits, CEL cost, rate limits, long-poll caps, quotas per edition | Planned |
| API5 Broken Function Level Authorization | Permission catalog checked in app layer; deny by default | Planned |
| API6 Unrestricted Access to Sensitive Business Flows | Approvals, budgets, counters, HOLD caps, detections | Planned |
| API7 Server Side Request Forgery | HR-070..077 | Planned |
| API8 Security Misconfiguration | SB-8 | Planned |
| API9 Improper Inventory Management | Single protobuf contract, buf breaking checks, versioned API | Planned |
| API10 Unsafe Consumption of APIs | Target responses untrusted; independent verifiers; size caps; circuit breaker | Planned |

## 3. OWASP Top 10 for Agentic Applications (2026) — product coverage

PantherClaw is itself a mitigation product for these risks; this table maps what the product enforces for customers.

| Risk | PantherClaw mitigation | Pillar |
|---|---|---|
| ASI01 Agent Goal Hijack | Goals cannot expand authority: task grants, sequence rules, holds, detections | 5, 8, 12 |
| ASI02 Tool Misuse & Exploitation | Reviewed action meaning, parameter constraints, budgets, approvals | 5, 6, 8 |
| ASI03 Identity & Privilege Abuse | PAP/1 workload identity, launcher ≠ principal, no name-based inheritance, delegation lattice | 4, 5 |
| ASI04 Agentic Supply Chain Vulnerabilities | Signed tool packages, reviewed descriptions, drift quarantine | 6, 16 |
| ASI05 Unexpected Code Execution | Shell/host routes governed, sandbox, coverage states | 16, 17 |
| ASI06 Memory & Context Poisoning | Agent memory is never evidence of history/authority (F126); trusted facts only | 5, 8 |
| ASI07 Insecure Inter-Agent Communication | Child agents get own identities and narrowed grants; delegation lineage. Peer agent-to-agent calls over A2A are mediated by the gateway (M14, [ADR-0029](../adr/0029-peer-agent-calls-a2a.md)): pinned agent cards with drift quarantine, requests rebuilt from ActionIR with text parts only, decided under the requester's grant; an enrolled peer acts in a child run under the intersection of the requester's grant and the route's peer scope (HR-322..327, T-148, T-149). External peers are governed outbound only and labelled `PARTIAL` (R-41) | 4, 5, 6 |
| ASI08 Cascading Failures | Fail-closed, circuit breakers, kill switch, dependency previews | 6, 10, 14 |
| ASI09 Human-Agent Trust Exploitation | Template-only approval rendering, untrusted text quarantine, WebAuthn binding | 7 |
| ASI10 Rogue Agents | Discovery, admission, containment, detections | 2, 10, 12 |

## 4. OWASP ASVS 5.0.0 chapters

| Chapter | Level | Owner modules | Status |
|---|---|---|---|
| V1 Encoding & Sanitization | L2 | gateway, approval page | Planned |
| V2 Validation & Business Logic | L2 | authority, budgets, approvals | Planned |
| V3 Web Frontend Security | L2 (console and approval page) | authn, server (console mount, cookie sessions on Connect) | Planned (milestone UI; HR-340..347) |
| V4 API & Web Service | L2 | all Connect services | Planned |
| V5 File Handling | L2 | evidence packs, package import | Planned |
| V6 Authentication | **L3** | authn, identity | Planned |
| V7 Session Management | **L3** | authn | Planned |
| V8 Authorization | **L3** | tenancy, authority | Planned |
| V9 Self-contained Tokens | **L3** | PAP/1 tokens, permits | Planned |
| V10 OAuth & OIDC | **L3** | authn | Planned |
| V11 Cryptography | **L3** | platform/crypto, keys, broker | Planned |
| V12 Secure Communication | L2 | httpx, mTLS | Planned |
| V13 Configuration | L2 | platform/config, deploy | Planned |
| V14 Data Protection | L2 | evidence, retention | Planned |
| V15 Secure Coding & Architecture | L2 | all | Planned |
| V16 Security Logging & Error Handling | L2 | platform/log, audit | Planned |
| V17 WebRTC | N/A — no WebRTC | — | N/A |

## 5. CWE focus set (from CWE Top 25 2025 and product threats)

| CWE | Weakness | Where it could arise | Control |
|---|---|---|---|
| CWE-862 / 863 | Missing / incorrect authorization | Any API, graph/search | App-layer authz, RLS, tests per endpoint |
| CWE-639 | Authorization bypass via user-controlled key (IDOR) | Object lookups | Typed OrgID + resource checks |
| CWE-287 / 306 | Improper / missing authentication | APIs, gateway | SB-2, PAP/1 |
| CWE-352 | CSRF | Approval page, session APIs | SameSite Strict + Fetch Metadata + custom header |
| CWE-918 | SSRF | Gateway egress, webhooks out | HR-070..077 |
| CWE-89 / 78 / 77 / 94 | SQL / OS / command / code injection | DB, connector runtime, CLI | sqlc, argv exec, no eval |
| CWE-20 | Improper input validation | Agent input, APIs | protovalidate + strict JSON + domain validation |
| CWE-22 | Path traversal | Package import, evidence export, URL templates | Path cleaning, HR-073 |
| CWE-200 / 532 | Information exposure / sensitive info in logs | Logs, errors, exports | SB-4 redaction, stable error codes |
| CWE-269 | Improper privilege management | Roles, delegation | SoD, delegation lattice |
| CWE-284 | Improper access control (tenancy) | DB | RLS, composite keys |
| CWE-347 | Improper verification of cryptographic signature | Tokens, packages, licences | go-jose allowlists, tests |
| CWE-362 / 367 | Race condition / TOCTOU | Budgets, approvals, permits | Conditional updates, finalization tx |
| CWE-400 / 770 | Uncontrolled resource consumption | Gateway, CEL, long polls | Limits, cost budgets |
| CWE-502 | Deserialization of untrusted data | JSON, protobuf | No polymorphic decoding; strict schemas |
| CWE-798 | Hard-coded credentials | Source, images | Secret scanning, KeyProvider |
| CWE-807 | Reliance on untrusted inputs in a security decision | Agent claims | HR-022, HR-023 |
| CWE-1021 | Improper restriction of rendered UI layers (clickjacking) | Approval page | `frame-ancestors 'none'` |

## 6. MITRE ATLAS (detection mapping)

Detections (pillar 12) carry ATLAS technique references where applicable (e.g. LLM prompt injection — direct/indirect, LLM plugin compromise, exfiltration via ML inference API, erode ML model integrity). The mapping table lives with each detection rule in `internal/detections/rules/` and is exported in OCSF findings.
