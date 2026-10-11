# PantherClaw — Dependency & Build Policy (SG07)

## 1. Principles

1. **Fewer dependencies is a security feature.** Prefer the Go standard library. Every direct dependency needs a written justification below before its first import.
2. **Pinned and verified.** Lockfiles are committed; installs are reproducible and verified against checksums.
3. **Cooldown.** New upstream releases are not adopted for 7 days (malicious releases are usually caught within that window). Security fixes for actively exploited vulnerabilities may skip the cooldown with a recorded reason.
4. **Reachability-aware.** Go vulnerabilities are judged by `govulncheck` call-graph reachability; unreachable findings are tracked, not ignored.
5. **No copyleft in shipped artifacts.** Allowed licences for code linked into released binaries/SDKs: Apache-2.0, MIT, BSD-2/3-Clause, ISC, MPL-2.0 (file-level, unmodified), Unicode-DFS, CC0, 0BSD, and the Go project's additional patent grant (`PATENTS` file in `golang.org/x/*`, reported by scanners as `LicenseRef-scancode-google-patent-license-golang`). Disallowed: GPL/AGPL/LGPL (except standalone dev tools never shipped, e.g. golangci-lint, k6), SSPL, BSL/FSL from others, unknown.

## 2. Sources

| Ecosystem | Source | Verification | Lockfile |
|---|---|---|---|
| Go | `proxy.golang.org` (default `GOPROXY`), `sum.golang.org` | `go mod verify`, `GOFLAGS=-mod=readonly`, `GONOSUMDB` unset | `go.sum` |
| Go dev tools | `tool` directives in `tools/go.mod` (run with `go tool -modfile=tools/go.mod`) | same | `tools/go.sum` |
| Python SDK | PyPI via `uv` | `uv lock` with hashes, `uv sync --locked`, `exclude-newer = "7 days"` | `uv.lock` |
| TypeScript SDK | npm registry via pnpm (pinned through `packageManager` + Corepack) | `pnpm install --frozen-lockfile`, `minimumReleaseAge: 10080`, lifecycle scripts blocked except allowlist | `pnpm-lock.yaml` |
| GitHub Actions | GitHub Marketplace | **full commit SHA pins** (repository policy enforces), version comment | workflow files |
| Containers | Distroless / official images | **digest pins** | Dockerfiles, compose |
| Binaries in CI (gitleaks, buf, etc.) | Official GitHub releases | SHA-256 checksum verified in workflow | workflow files |

Excluded: **Trivy and `aquasecurity/trivy-action`** (supply-chain compromise, March 2026, CVE-2026-33634) — replaced by OSV-Scanner and Scorecard. `tj-actions/changed-files` (2025 compromise) — use `dorny/paths-filter`.

## 3. Approved direct dependencies (Go core)

| Module | Purpose | Licence | Justification |
|---|---|---|---|
| `github.com/jackc/pgx/v5` | PostgreSQL driver + pool | MIT | De-facto standard; needed for COPY-free, typed, context-aware access |
| `github.com/pressly/goose/v3` | Migrations | MIT | Embedded SQL migrations, simple, no DSL |
| `github.com/riverqueue/river` (+ `riverpgxv5`) | Postgres job queue / outbox | MPL-2.0 | Transactional enqueue (InsertTx) |
| `connectrpc.com/connect/v2` (+ `otelconnect`, `grpchealth`, `validate`) | RPC framework | Apache-2.0 | One handler for gRPC/Connect JSON. Pinned to `v2.0.0-rc.1` until `v2.0.0` (2026-10-07) clears the 7-day cooldown (founder decision 2026-10-08). `otelconnect`, `grpchealth` and `validate` are not used yet: the OTel and protovalidate interceptors are in `platform/rpc` and health uses plain HTTP endpoints |
| `buf.build/go/protovalidate` | Contract validation (CEL) | Apache-2.0 | Declarative input validation |
| `google.golang.org/protobuf` | Protobuf runtime | BSD-3 | Required by Connect |
| `cel.dev/cel-go` (formerly `github.com/google/cel-go`) | Policy/detection expressions | Apache-2.0 | Safe, typed, cost-bounded expressions. Now published under `cel.dev`; first pulled in by protovalidate v1.4.0 |
| `github.com/go-jose/go-jose/v4` (≥ 4.1.5) | JWS/JWT/JWK, thumbprints | Apache-2.0 | Algorithm allowlists; RFC 7638 |
| `github.com/coreos/go-oidc/v3` | OIDC relying party | Apache-2.0 | ID token verification, discovery |
| `golang.org/x/oauth2` | OAuth2 flows | BSD-3 | Auth code, device flow |
| `github.com/go-webauthn/webauthn` | WebAuthn step-up (`internal/authn/app`) | BSD-3 | Maintained server-side WebAuthn: all attestation formats, the browser and authenticator edge cases, and a caller-supplied challenge (needed for transaction-bound approvals, HR-033). v0.18.2 is from 2026-09-19 (outside the cooldown; founder decision 1, G0 M5). Used with attestation `none` and user verification required. Adds 11 modules, all under allowed licences: `fxamacker/cbor/v2` and `x448/float16` (MIT, CBOR), `go-webauthn/x` (BSD-3), `golang-jwt/jwt/v5` (MIT, metadata service), `google/go-tpm` (Apache-2.0, TPM attestation), `google/uuid` (BSD-3), `go-viper/mapstructure/v2` (MIT), `tinylib/msgp` and `philhofer/fwd` (MIT), `golang.org/x/crypto` and `golang.org/x/sys` (BSD-3). Alternative considered: a verifier written here for attestation `none` only (fewer modules, but security-critical parsing maintained by one person) |
| `github.com/modelcontextprotocol/go-sdk` | MCP server/client | MIT/Apache | Official SDK |
| `go.opentelemetry.io/otel` (+ SDK, OTLP exporters) | Telemetry | Apache-2.0 | Standard |
| `github.com/google/uuid` | UUIDv7 | BSD-3 | Small, stable |
| `golang.org/x/text` | Unicode (confusables/NFC helpers) | BSD-3 | Canonicalization |
| `golang.org/x/sync` | errgroup/singleflight | BSD-3 | Concurrency helpers |
| `go.yaml.in/yaml/v3` | YAML tool package files (`internal/definitions/manifest`) | MIT AND Apache-2.0 | Maintained by the YAML organisation (successor of `gopkg.in/yaml.v3`). Already in the module graph through protovalidate → cel-go, so it adds no module; v3.0.5 is from 2026-07-26 (outside the cooldown). Used only to build a node tree: anchors, aliases, merge keys, tags, floats, nulls, duplicate keys and multiple documents are rejected before the JSON is decoded with `encoding/json/v2` (HR-100). Alternatives: JSON-only packages (harder to review by hand); `github.com/goccy/go-yaml` (a new module for no gain) |
| `github.com/BurntSushi/toml` | Reads OpenAI Codex CLI's `config.toml` in `pclaw scan` (`internal/scan`, PN-001.1) | MIT | The long-standing Go TOML decoder (5,000 stars, commits in August 2026), kept in step with the `toml-test` conformance suite by the same maintainers. It has no dependencies of its own, so it adds one module. v1.6.0 is from 2025-12-18 (outside the cooldown). Only `toml.Decode` into a `map[string]any` is used, for files of at most 1 MiB that the user owns; no struct reflection and no encoding. Alternatives: a minimal reader for the subset Codex writes (people also edit the file by hand: literal and multi-line strings, dotted and quoted keys, inline tables, mixed arrays; a parser that misreads a value as a key could put a credential into a submitted finding, HR-056); `github.com/pelletier/go-toml/v2` (also MIT with no dependencies; either would do, BurntSushi is the older and smaller API) |

Test-only: `github.com/testcontainers/testcontainers-go` (MIT), `github.com/peterldowns/pgtestdb` (MIT), `pgregory.net/rapid` (MPL-2.0, property tests).
Dev tools (not shipped): golangci-lint (GPL-3.0, tool only), gofumpt, sqlc, buf, goose CLI, task, actionlint, govulncheck, osv-scanner, gitleaks, zizmor, Semgrep CE, goreleaser, syft, cosign, k6 (AGPL, tool only), schemathesis.
Dev-tool pin exceptions in dependency review (`allow-dependencies-licenses`; these modules are dependencies of the buf and sqlc pins only, never linked into shipped artifacts): `github.com/opencontainers/go-digest` (Apache-2.0 AND CC-BY-SA-4.0 for docs), `github.com/opencontainers/image-spec` (Apache-2.0 AND MIT AND DCO-1.1), `github.com/segmentio/asm` (MIT-0), `github.com/fatih/structtag` (BSD-3-Clause AND CC-BY-3.0), `github.com/pganalyze/pg_query_go/v6` (BSD-3-Clause AND PostgreSQL).

Adding a dependency: PR adds a row here (purpose, licence, maintenance status, alternatives considered, transitive count), passes dependency-review, and is called out in the G1 review.

### SDK dependencies (G0 M8 decision 8)

The SDKs (`sdk/`, `integrations/`) are Apache-2.0 and embedded in customers' agents and services, so they keep runtime dependencies to these. The Go SDK uses only the standard library and the TypeScript SDK has none at runtime.

| Package | Where | Purpose | Licence | Justification |
|---|---|---|---|---|
| `cryptography` (≥ 42) | `sdk/python`, runtime | Ed25519 signing (PAP/1 proofs) and verification (proof checks, action tokens) | Apache-2.0 OR BSD-3-Clause | The Python Cryptographic Authority's library: the standard library has no Ed25519, and this is the maintained, widely deployed choice with wheels for every major platform. It adds `cffi` (MIT) and `pycparser` (BSD-3) on CPython. Alternatives: PyNaCl (libsodium through cffi; maintained, but less widely deployed), a pure-Python Ed25519 (unreviewed and slow). `uv.lock` with hashes is generated with `uv lock` once `uv` is installed (Day-0 item 5) |
| `@anthropic-ai/claude-agent-sdk` (≥ 0.3.286, < 0.4) | `integrations/claude-agent-sdk/typescript`, optional peer | The Agent SDK the integration plugs into; the application installs it | Anthropic's terms for the SDK | Never installed or redistributed by PantherClaw: an optional `peerDependencies` entry that states the supported range (0.3.286 is the first where `permissionMode` must be passed explicitly). The integration uses only its hook and `canUseTool` types, re-declared locally |

## 4. Updates

- Dependabot: `gomod` (root, `tools/`, `sdk/go`), `uv`, `npm`, `github-actions`, `docker`; weekly; grouped minor/patch; `cooldown: default-days: 7`; security updates immediate.
- Major upgrades get their own PR with changelog review and full test run.
- Upstream releases with breaking module paths (e.g. connect-go v2) are adopted deliberately with an ADR note.

## 5. Vulnerability handling

| Severity (reachable) | Fix deadline | Exception max |
|---|---|---|
| Critical | 7 days | 7 days |
| High | 30 days | 30 days |
| Medium | 90 days | 30 days |
| Low | next routine update | — |

Unreachable vulnerabilities: tracked, fixed at next routine update. Released versions are re-scanned weekly (`nightly.yml`); new findings against a release create a private advisory and a patch release.

## 6. Build integrity

- Builds are reproducible from a tag: `-trimpath`, `-buildvcs=true`, pinned toolchain (`toolchain go1.27.2`), `CGO_ENABLED=0` for release binaries.
- Release artifacts: SBOM (SPDX + CycloneDX via syft), GitHub artifact attestations (build provenance) for binaries, checksums, SBOMs and images; container images also signed with cosign (keyless, Sigstore bundle).
- Publishing uses OIDC trusted publishing (PyPI, npm) bound to the protected `release` environment; no long-lived registry tokens exist.
- Users verify with `gh attestation verify` / `cosign verify`; `pclaw` self-update verifies attestations before replacing itself.
