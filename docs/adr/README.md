# Architecture Decision Records

Format: Context → Decision → Consequences → Alternatives considered. Status: Proposed | Accepted | Superseded by ADR-XXXX. New ADRs are numbered sequentially and reviewed at G0/G1. ADR-0001 to ADR-0014 were accepted at G0 on 2026-10-08 after an adversarial security review and a toolchain-currency review; later ADRs state their own status and date.

| ADR | Title |
|---|---|
| [0001](0001-go-backend.md) | Go for all backend binaries |
| [0002](0002-control-plane-and-gateway-split.md) | Modular-monolith control plane + separate gateway PEP |
| [0003](0003-postgres-rls-single-store.md) | PostgreSQL as the single authoritative store, RLS FORCEd |
| [0004](0004-cel-policy-engine.md) | CEL rules with fixed Go composition; OPA restrict-only adapter |
| [0005](0005-protobuf-connect-contracts.md) | Protobuf + buf + connect-go v2 as the single contract |
| [0006](0006-river-jobs-no-temporal.md) | River jobs and Postgres state machines; no Temporal in MVP |
| [0007](0007-licensing-bsl-apache-split.md) | BSL 1.1 core, Apache-2.0 SDKs, private enterprise repo |
| [0008](0008-security-scanning-toolchain.md) | Scanning toolchain without CodeQL or Trivy |
| [0009](0009-evidence-ledger.md) | Evidence ledger: unchained writes, per-org chainer, Merkle checkpoints, Rekor |
| [0010](0010-mcp-support.md) | MCP support for spec 2026-07-28 and 2025-11-25 |
| [0011](0011-strict-json-canonicalization.md) | encoding/json/v2 + RFC 8785 for ActionIR |
| [0012](0012-crypto-and-keys.md) | Standard-library cryptography and KeyProvider |
| [0013](0013-pap1-workload-identity.md) | PAP/1 workload identity with DPoP-style proofs |
| [0014](0014-permits-and-dispatch-commit.md) | Dispatch permits with a server-side commit point |
| [0015](0015-budget-settlement-off-the-hot-row.md) | Keep budget settlement off the hot row (accepted 2026-10-10: asynchronous settlement and a fail-fast lock timeout; escrow slots deferred) |
| [0016](0016-human-and-service-authentication.md) | Human and service authentication for the control plane (M2) |
| [0017](0017-coding-agents-first-and-proven-coverage.md) | Coding and DevOps agents first; v0.1.0 built around proven coverage (2026-10-09) |
| [0018](0018-federated-workload-identity-and-represented-principals.md) | Federated workload identity and represented principals from the customer's IdP (M3) |
| [0019](0019-standards-at-the-edges.md) | Standards at the edges: AuthZEN endpoint (M14) and Shared Signals receiver (M10) |
| [0020](0020-org-package-signing-keys.md) | Org package-signing keys for customer-written packages (M4 follow-up, Team edition) |
