# PantherClaw — Protecting the Code While the Repository Is Public

**Honest premise:** anything in a public repository can be read, cloned, forked (forking cannot be disabled for public repositories on personal accounts), scraped and used to train models. Technical secrecy is impossible for public code. Protection therefore comes from four layers, all active from the first commit.

## 1. Legal layer

| Control | Status | Where |
|---|---|---|
| Business Source License 1.1 with usage cap (≤ 5 Agents, 1 Organization, no hosted/embedded/competing offering) | Active | [LICENSE](../LICENSE) |
| Apache-2.0 only for SDKs, protocol spec, Claude Code integration | Active | [NOTICE](../NOTICE) |
| SPDX identifier + copyright line in **every** source file, CI-enforced | Active (`task license:check`) | all source |
| Trademark policy (PantherClaw™) — forks must rebrand | Active | [TRADEMARKS.md](../TRADEMARKS.md) |
| Commercial licence path | Active | [COMMERCIAL_LICENSE.md](../COMMERCIAL_LICENSE.md) |
| CLA before any outside contribution (keeps relicensing/commercial rights) | Template ready; app install pending | [CLA.md](../CLA.md) |
| Trademark registration, company formation, legal review | Upgrade | [UPGRADES.md](UPGRADES.md) |

**Header format (Go):**
```go
// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
```
SDK files use `Apache-2.0` and `Copyright 2026 Joshua Kato`.

## 2. Architectural layer — keep the crown jewels private

| Public (this repo) | A private repository |
|---|---|
| Core server, gateway, CLI, simulators, multi-org fleet management, high availability | SCIM and SAML in a clean package, with `cmd/pantherclaw-server-ee` |
| PAP/1 spec and SDKs, SIEM content packs (Apache-2.0) | Web console |
| Extension interfaces (`internal/extension`; G0 UI, ADR-0030) | Advanced detection content and threat intelligence |
| Basic tool packages for simulators | Curated, reviewed tool-package catalog for real providers |
| Community red-team scenarios, compliance reports (edition-gated) | Full adversarial scenario library |
| | SaaS operations, billing, tenant provisioning, infrastructure as code |

Rule: no private code, credentials, customer data or unfixed-vulnerability details ever enter the public repository. Open security findings live only in private GitHub Security Advisories.

## 3. Cryptographic layer — things a copy cannot reproduce

- **Licence keys:** Ed25519-signed licence documents (org, edition, agent limit, expiry, features) verified by the binary against an embedded public key. The private licence root is generated offline by `pclaw-admin keygen` and never enters CI or the repository. Removing the check is a licence violation and does not create entitlement.
- **Signed content:** official tool packages and detection content are signed by an offline package root with expiring TUF-style metadata. Copies of the code receive no updates and no trust in our content.
- **Signed builds:** releases carry GitHub artifact attestations (and Sigstore signatures for images). "Only attested builds are supported" is stated in NOTICE; customers can verify authenticity in one command.

## 4. Detection layer

- **Canary fingerprint** `pcfp-37609359f35b52c36816` appears in NOTICE and source; additional unique identifiers exist in code.
- **Weekly copy watch:** `.github/workflows/canary-watch.yml` searches GitHub code search for the fingerprints and opens an issue when they appear outside this repository (needs a fine-grained read-only token secret `CANARY_SEARCH_TOKEN`; skipped gracefully when absent).
- **Takedown playbook:** [runbooks/dmca-takedown.md](runbooks/dmca-takedown.md) — collect evidence (URLs, commit SHAs, matching fingerprints, licence terms violated), file a GitHub DMCA notice (free), follow with a licence-violation notice for production use beyond the grant.

## 5. Operational hygiene

- No secrets in the repository (push protection + gitleaks + pre-commit).
- No customer names, pricing internals or private roadmap in public docs.
- Release notes avoid detailing unfixed weaknesses.
- AI-training opt-out cannot be enforced technically; the licence governs use of the code, and the trademark policy governs the name.
