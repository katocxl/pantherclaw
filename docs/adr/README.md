# Architecture Decision Records

Format: Context → Decision → Consequences → Alternatives considered. Status: Proposed | Accepted | Superseded by ADR-XXXX. New ADRs are numbered sequentially and reviewed at G0/G1. ADR-0001 to ADR-0014 were accepted at G0 on 2026-10-08 after an adversarial security review and a toolchain-currency review; later ADRs state their own status and date.

| ADR | Title |
|---|---|
| [0001](0001-go-backend.md) | Go for all backend binaries |
| [0002](0002-control-plane-and-gateway-split.md) | Modular-monolith control plane + separate gateway PEP; M14 note on target databases |
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
| [0019](0019-standards-at-the-edges.md) | Standards at the edges: AuthZEN endpoint (M14) and Shared Signals receiver (M10); M14 implementation note 2026-10-17 |
| [0020](0020-org-package-signing-keys.md) | Org package-signing keys for customer-written packages (M4 follow-up, Team edition) |
| [0021](0021-github-app-custody-and-per-action-tokens.md) | GitHub App custody and per-action installation tokens (M8, proposed 2026-10-11) |
| [0022](0022-containment-sandbox-edge.md) | Containment sandbox edge, per-session TLS interception and probe trust (M9, proposed 2026-10-11) |
| [0023](0023-adversarial-range.md) | The adversarial range: range agents, simulated connections and a local gate (M12, proposed 2026-10-14) |
| [0025](0025-policy-lifecycle-staged-enforcement.md) | Policy lifecycle: staged enforcement and change approval (M11.1, proposed 2026-10-15; ADR-0024 is reserved by the v0.1.0 preview) |
| [0026](0026-reflex-detection-containment-and-signals.md) | Reflex: detection over the evidence ledger, containment controls in the decision path, Shared Signals receiver trust (M10, proposed 2026-10-15) |
| [0027](0027-governed-automations.md) | Governed automations: execution identity, ceiling-bounded issuance, closed step catalogue, signed inbound events (M11 part 2, proposed 2026-10-15; amends G0 M4 decision 7) |
| [0028](0028-business-connectors-and-data-scoping.md) | Business connectors and data scoping: Stripe test mode, structured Postgres, scope obligations, Slack bot cards (M14, accepted 2026-10-17) |
| [0029](0029-peer-agent-calls-a2a.md) | Peer agent calls: A2A mediation and peer delegation (M14, accepted 2026-10-17; OWASP ASI07) |
| [0030](0030-web-console-hosted-split-and-extension-point.md) | Web console, hosted split and extension point: `internal/extension`, the console at `/app/` under a strict policy, browser sessions on Connect (milestone UI, accepted 2026-10-20) |
| [0031](0031-hosted-accounts-per-org-plans-and-test-seams.md) | Hosted accounts, per-organization plans and test seams: global accounts, self-serve organizations, the plan gate that keeps protection on, configuration-chosen test adapters (milestone UI, accepted 2026-10-20) |
| [0032](0032-hosted-deployment-kek-custody-and-backups.md) | Hosted deployment, KEK custody, backups and recovery: free staging VM now, paid host later; RPO and RTO targets (M13, accepted for staging 2026-10-21) |
| [0033](0033-observability-exporter.md) | Observability exporter: our own OTLP/HTTP-protobuf exporter without gRPC; Grafana Cloud free (M13, accepted 2026-10-21) |
| [0034](0034-customer-approved-support-access.md) | Customer-approved support access and break-glass: per-request approval by an org admin, read-only sessions of at most 72 hours, no standing access; pre-designated, 60-minute break-glass (M13, accepted 2026-10-21) |
| [0035](0035-export-deletion-and-lapse-retention.md) | Export, deletion and retention after a lapsed plan: signed exports, deletion after a 7-day window with a signed record, 90 days after a lapse, account deletion (M13, accepted 2026-10-21) |
| [0036](0036-server-backed-mcp-state-discovery-and-reviewed-surface.md) | Server-backed MCP state, discovery and the reviewed MCP surface: holds, tasks and sessions on the server with sealed task bodies, discovered tools and resources drafted for review, reviewed resources as reads, policy-gated form-mode elicitation (M15, accepted 2026-10-29) |
| [0037](0037-data-flow-holds-external-policy-checks-and-suggestions.md) | Data-flow holds, external policy checks and evidence-backed suggestions: read classes across the run tree, grant flow allowances, restrict-only classification facts, OPA checks and identity-risk facts that fail closed, suggestions that only draft (M16, accepted 2026-10-29) |
| [0038](0038-consequence-chains-customer-rules-and-verifier-kinds.md) | Consequence chains, customer consequence rules and new verifier kinds: verified downstream consequences, add-only two-person customer rules, bounded chains, GitLab CI, SPIFFE, GCP, AWS, Azure and Entra attestation (M17, accepted 2026-10-29) |
| [0039](0039-delegated-administration-org-identity-providers-and-key-service.md) | Delegated administration, organization identity providers and the key service: scoped admins bind only roles they hold inside their scope, org identity providers as two-person protected changes (a customer IdP admin can still defeat SoD, R-08), OpenBao Transit with in-place re-wrap, pclaw secrets in the OS keychain (M18, accepted 2026-10-29) |
| [0040](0040-high-availability-semantics.md) | High-availability semantics: shared state in Postgres only, leased limits and stream leases across replicas, a stated staleness bound for every decision-path cache, fail-closed failover with multi-host connections and the primary-timeline rule, two or more workers, A2A ownership on shared gateway state (M19, accepted 2026-10-29) |
| [0041](0041-hosted-per-org-gateway-pool.md) | The hosted gateway pool: one gateway process per organization on shared hosts, provisioned from records by a worker job and a host agent with no organization authority, isolated per organization, routed by SNI passthrough with one-name server certificates; host RPCs only under the declarable-only `hosting.agent` (M19, accepted 2026-10-29) |
| [0042](0042-integrations-breadth.md) | Integrations breadth: per-org Ed25519 webhook keys next to HMAC, push export destinations with receipts, target-confirmed GitHub App key rotation through the gateway, GitLab, Jira, Teams and AWS connectors, Jira ticket sync that never restores authority, link-only Slack DMs and Teams cards (M20, accepted 2026-10-29) |
| [0043](0043-branching-automations-and-the-model-provider-boundary.md) | Branching automations and the model-provider boundary: a v2 format with branch, switch and join nodes validated per path, v1 unchanged; an optional, customer-keyed model provider as an external processor that only drafts, with strict output parsing (M21, accepted 2026-10-29) |
