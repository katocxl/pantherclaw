# ADR-0007 — BSL 1.1 core, Apache-2.0 SDKs, private enterprise repo

**Status:** Accepted (2026-10-08). Legal review recommended when funds allow.

**Context.** The founder wants a public repository while preventing code theft and unpaid production use, and wants SDKs to be easy to adopt.

**Decision.** Root licence: Business Source License 1.1 with an Additional Use Grant (free production use ≤ 5 governed Agents in one Organization; no hosted, embedded or competing offering), Change Date four years per version, Change License Apache-2.0. Apache-2.0 for `sdk/*`, `integrations/claude-code` and `docs/protocol`. Enterprise features, SaaS operations and curated content live in a private repository and plug in through extension interfaces. Every source file carries SPDX + copyright headers (CI-enforced). Signed licence keys gate editions; signing roots stay offline. A CLA is required before outside contributions.

**Note (2026-11-01, founder decision H7).** There is no separate enterprise repository. SCIM and SAML code goes in a clean package in a private repository, with `cmd/pantherclaw-server-ee`. Its tables and ports stay in public core. Compliance reports stay in public core under the BSL, gated by edition.

**Consequences.** Not OSI open source: the CodeQL free licence and pkg.go.dev documentation are unavailable for the core (see ADR-0008). Clear legal basis for takedowns and commercial licences. SDK adoption is unaffected.

**Alternatives.** FSL-1.1-ALv2 (blocks only competitors; internal production use unlimited); PolyForm Noncommercial (blocks all commercial use; hurts adoption); Apache-2.0 everywhere (no moat).
