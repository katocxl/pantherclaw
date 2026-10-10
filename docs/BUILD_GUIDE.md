# PantherClaw — Build Guide

**The authoritative guide for building PantherClaw from an empty repository to a production-ready v1.0 backend.**
Version 1.1 · 2026-10-09 · Owner: Joshua Kato · Approved at G0 (M0); delivery order and first market revised by ADR-0017, M3 identity scope by ADR-0018.

> PantherClaw is an AI Agent Identity & Runtime Authorization Firewall — an *agent transaction firewall*. It gives agents useful authority, makes every consequential action explainable, and stops that authority when it is no longer appropriate.

---

## 0. How to use this guide

**Who reads it:** the founder and the AI coding assistant (Claude) that implements milestones. Every coding session starts by reading §0–§4 and the current milestone in §8.

**Document map and precedence** (higher wins on conflict):

1. [security/HARDENING_RULES.md](security/HARDENING_RULES.md) — binding rules `HR-###`, each with tests.
2. [protocol/PAP-1.md](protocol/PAP-1.md) — identity & authority protocol, wire formats.
3. [ARCHITECTURE.md](ARCHITECTURE.md) — components, flows, layering, data architecture.
4. [security/SECURITY_BASELINES.md](security/SECURITY_BASELINES.md) — auth, crypto, logging, dependencies, checks.
5. **This guide** — process, conventions, milestones, tests, definition of done.
6. [FEATURES.md](FEATURES.md) — what to build (pillars, phases, editions, F-/PN- IDs).
7. [PRODUCT.md](PRODUCT.md) — positioning, the seven product components, first market and packaging (how features are grouped and sold; never changes behavior).
8. [reference/](reference/) — original product specification (F001–F802) for detailed behavior.

Also: [THREAT_MODEL.md](security/THREAT_MODEL.md) (`T-###`), [GATES_AND_REVIEW.md](security/GATES_AND_REVIEW.md) (gates, exceptions, briefs), [OWASP_CWE_MAPPING.md](security/OWASP_CWE_MAPPING.md), [DEPENDENCY_POLICY.md](security/DEPENDENCY_POLICY.md), [adr/](adr/), [UPGRADES.md](UPGRADES.md), [IP_PROTECTION.md](IP_PROTECTION.md), [runbooks/](runbooks/).

**Working loop per milestone** (SG01, SG08–SG12):

```
G0 brief (GATES_AND_REVIEW §5) → protos/migrations/contracts first → tests named by ID first
→ implement (domain → app → adapters → cmd) → commit on a branch → task check (+ task test:integration, task trace where they apply) → pull request; the founder merges
→ update traceability (FEATURES status, HR/T test links) → next slice
```

While EX-004 is active there is no CI: GitHub runs no checks on a pull request, so the local checks are the only gate. Run them before you open the pull request and report the result in it. Several sessions may work at once: each works on its own branch and worktree and opens its own pull request, and only the founder merges ([PARALLEL_WORK.md](PARALLEL_WORK.md)).

Rules for the AI implementer:
- Implement only what the current G0 brief covers; surface missing security decisions instead of guessing.
- Never weaken an `HR-###` rule, an invariant, or a test to make something pass. If a rule seems wrong, stop and propose an ADR.
- Never add a dependency that is not in DEPENDENCY_POLICY §3 without adding the justification row in the same PR.
- Keep commits small (≤ ~600 lines of non-generated diff) and single-purpose.

---

## 1. Day-0 checklist (founder actions the AI cannot perform)

| # | Action | Why | Status |
|---|---|---|---|
| 1 | Install the **CodeRabbit** GitHub App on `katocxl/pantherclaw` (free for public repos) | Second, independent AI reviewer (SG11) | ☐ |
| 2 | Add `~/.ssh/id_ed25519.pub` to GitHub as a **Signing key**; start the Windows OpenSSH agent and `ssh-add` the key; then `git config commit.gpgsign true` and `gpg.ssh.program "C:/Windows/System32/OpenSSH/ssh-keygen.exe"` | Verified local commits (EX-002) | ☐ |
| 3 | Run `claude setup-token` and save it as repository secret `CLAUDE_CODE_OAUTH_TOKEN` | Claude AI security review in CI | ☐ |
| 4 | Reserve package names: PyPI pending trusted publisher `pantherclaw` (workflow `release.yml`, environment `release`); npm organization `@pantherclaw` | Prevent name squatting; OIDC publishing | ☐ |
| 5 | Optional: install Task (`winget install Task.Task`) for shorter commands; install `uv` (`winget install astral-sh.uv`) before SDK work (M8). All other tools are pinned under `tools/pins/` and run via `go tool` | Local tooling | ☐ |
| 6 | (M1) On an offline-capable machine: `go build -o pclaw-admin ./cmd/pclaw-admin`, then `pclaw-admin keygen --purpose licence --out-dir <offline media> --passphrase-file <file>` (and the same with `--purpose packages`). Copy each `*-root.key` to a second offline medium. Commit only the public keys: paste the key from `licence-root.pub.json` into `internal/billing/licence/roots.json`, and (M4) the key from `packages-root.pub.json` into `internal/definitions/trust/roots.json`. Until then every licence is rejected and servers run with Community limits, and no tool package verifies. (M4) Then sign the reviewed packages, still offline: `pclaw-admin packages sign --key <offline media>/packages-root.key --passphrase-file <file> --version 1 --expires-days <days> --out targets.jws packages/mock-payments/package.yaml` (180 days, G0 M4 decision 1), and check it with `pclaw-admin packages verify --roots internal/definitions/trust/roots.json --targets targets.jws packages/mock-payments/package.yaml` | Licence and package trust roots (HR-063) | ☐ |
| 7 | Optional: create `%UserProfile%\.wslconfig` with `memory=8GB` | Docker stability with Keycloak + LGTM | ☐ |
| 8 | Before accepting outside PRs: install CLA Assistant (cla-assistant.io) linked to `CLA.md` | Keep relicensing rights | ☐ |
| 9 | Optional: create fine-grained PAT (public repos, read-only) as secret `CANARY_SEARCH_TOKEN` | Copy detection workflow | ☐ |

---

## 2. Product in one page

**Unit of security:** an agent action performed under a specific grant of authority. **Durable record:** the *transaction* (exact logical request, authority, decision, human requirements, attempts, effects).

**Six primary objects:** Agent · Run · Resource · Grant · Policy · Action. Supporting: people/services, tools, connections, approvals, incidents, automations, teams/environments, action definitions, consequence rules, coverage records, receipts.

**Twelve invariants:** see [ARCHITECTURE §1](ARCHITECTURE.md#1-product-invariants-non-negotiable). Tests in `test/invariants/` are named `TestINV01_…` … `TestINV12_…`.

**Twenty commercial pillars** ([FEATURES.md](FEATURES.md)): Inventory · Discovery · Lifecycle · Identity & Authority Protocol · Authorization · Non-bypassable Transaction Boundary · Agent Waitlist · Agent Controls · Sessions · Containment · Monitoring · Threat Detection · Investigation · Breach Radius · Proof · Coverage & Bypass Resistance · Adversarial Sandbox · Deployments · Performance · Management.

**Seven product components** ([PRODUCT.md](PRODUCT.md)), the way buyers see the pillars: **Badge** (know every agent) · **Pass** (grant temporary access) · **Guardrails** (set the boundaries) · **Checkpoint** (control every action) · **Stash** (keep credentials safe) · **Reflex** (stop threats) · **Trail** (prove what happened), on **Root**, the platform (manage it all).

**First market** ([ADR-0017](adr/0017-coding-agents-first-and-proven-coverage.md)): coding and DevOps agents. The v0.1.0 preview proves enforced coverage for a coding agent ("three routes, three stops"); refunds stay the engine's test harness and become the second market.

**Editions:** Community (BSL free grant: ≤ 5 agents, 1 org) · Team · Business · Enterprise (private repo + licence keys).

---

## 3. Engineering rules

### 3.1 Go conventions
- Go toolchain pinned in `go.mod` (`toolchain go1.27.2`); `GOFLAGS=-mod=readonly`.
- Formatting: gofumpt (via golangci-lint formatters). Imports grouped std / third-party / local.
- Packages are nouns (`grants`, `budgets`), no `util`/`common`/`helpers`.
- **Context first** for anything doing I/O; never store contexts in structs.
- **Errors:** wrap with `%w`; domain errors are typed (`errors.Is/As`); API errors map to stable codes in `internal/platform/errors` (never leak internal messages); security failures return the precise decision (`DENY`, `CANNOT_AUTHORIZE`) not generic 500s.
- **No panics** across package boundaries; recover only at server edges.
- **Time:** inject `clock.Clock`; deadlines that guard security use the DB clock inside transactions.
- **IDs:** typed IDs (`type OrgID uuid.UUID` etc.) — never raw strings/UUIDs across layers; UUIDv7.
- **Money/amounts:** `decimal` type in `internal/platform/money` (string-backed, fixed scale, no floats).
- **JSON:** `encoding/json/v2` + `jsontext` only in core.
- **Concurrency:** `errgroup` for fan-out; every goroutine has an owner and a stop path; no unbounded channels/queues.
- **Config:** typed struct loaded once at start (env + file), validated; secrets loaded through `KeyProvider`/file mounts, wrapped in `Secret[T]`.
- **Logging:** `slog` via `internal/platform/log`; event names dotted (`authz.decision`); never `fmt.Print*`.
- **Headers:** every source file starts with SPDX + copyright (see [IP_PROTECTION.md](IP_PROTECTION.md)); `task license:fix` adds them.

### 3.2 API & contract rules
- Change protos first; run `task gen`; commit generated code in the same PR.
- Every request message has protovalidate rules (lengths, patterns, enums, required).
- Every RPC declares its required permission in a comment `// permission: <name>` checked by a test that walks the service registry.
- List endpoints are paginated (cursor), filtered by tenant first, with maximum page size 200.
- Idempotent mutations accept an `idempotency_key`.
- No breaking changes without a new package version (`v2`).

### 3.3 Database rules
- Migrations: `migrations/NNNN_name.sql` (goose, up + down), reviewed by squawk; never edit a merged migration.
- Every tenant table: `org_id uuid NOT NULL`, composite PK `(org_id, id)`, composite FKs, RLS ENABLE + FORCE, policy using `(SELECT NULLIF(current_setting('app.org_id', true), '')::uuid)`.
- Immutable revision tables for anything versioned; append-only evidence (UPDATE/DELETE revoked).
- Queries live in `queries/*.sql` (sqlc); repositories take `OrgID` explicitly and run inside `db.InTenantTx(ctx, orgID, fn)`.
- State changes are conditional updates (`WHERE state = $expected`).
- Avoid reserved words as column names (`limit_amount`, not `limit`).
- Every new table gets a cross-tenant negative test (generated table list check).

### 3.4 Security rules quick list (full list: HARDENING_RULES)
Fail closed · never trust agent claims · never trust the gateway's org/identity assertions · no secrets in logs/job args/receipts · re-serialize outbound requests · egress guards on every outbound client · CEL fail-closed · conditional state transitions · approvals humans-only · cooperative modes labeled PARTIAL · tenancy twice (typed OrgID + RLS).

### 3.5 Testing rules
| Kind | Location | Tooling | Naming |
|---|---|---|---|
| Unit | next to code | `testing`, table-driven | `TestXxx` |
| Property | next to code / `test/invariants` | `pgregory.net/rapid` | `TestINV##_…`, `TestPropXxx` |
| Hardening rule | anywhere | — | `TestHR###_…` |
| Threat negative test | `test/…` | — | `TestT###_…` |
| Integration (DB) | `*_integration_test.go`, build tag `integration` | pgtestdb template DBs, connect as `pc_app` | `TestIntXxx` |
| Tenancy | `test/tenancy` | generated per-table checks | `TestTenancy_<table>` |
| Race | `test/race` (+ `-race` everywhere on Linux) | goroutine storms | `TestRace_…` |
| Fuzz | `test/fuzz` + package-level | `go test -fuzz` | `FuzzXxx` |
| E2E scenarios | `test/e2e` | compose stack + simulators | `TestE2E_S##_…` |
| SDK conformance | `test/conformance` (JSON fixtures shared by Go/Python/TS) | each SDK's runner | fixture ids |
| Load | `test/load` | k6 | script names |
| Adversarial | `redteam/scenarios` | scenario engine | `RT-###` |

Rules: tests first for security behavior; no sleeps (use clocks/conditions); no network except to test containers/simulators bound to 127.0.0.1; golden files are LF and marked `-text`; deterministic randomness via `testing/cryptotest.SetGlobalRandom` where needed.

### 3.6 Definition of done (every PR)
- [ ] Linked G0 brief and requirement IDs (F/PN/HR/T) in the PR description.
- [ ] Tests for new behavior incl. negative/abuse cases; `task check` green; `ci-ok` green.
- [ ] Both AI reviews addressed (fixed, or disagreement recorded with reason).
- [ ] Threat model / hardening rules / ADR updated if boundaries, identity, data flow or dependencies changed.
- [ ] Docs updated (API docs from protos, FEATURES status).
- [ ] No secrets, no TODOs without an issue link, no disabled tests/linters without an exception record.
- [ ] Founder G1 approval comment after cooling-off.

---

## 4. Development environment

**Prerequisites:** Go 1.27 (toolchain auto-downloads 1.27.2), Docker Desktop (WSL2), optional Task (otherwise `go tool -modfile=tools/pins/task/go.mod task`), uv (M8), Node 24 + Corepack (pnpm pinned per package), Git with `core.autocrlf=false` for this repo.

**Windows specifics:** LF line endings (`.gitattributes`); servers in tests bind `127.0.0.1`; race/integration/signal tests run in Linux via `task test:linux` (container) — CI is canonical; Postgres uses named volumes; file-permission checks are skipped on NTFS; Claude Code integration must cover both Bash and PowerShell tools.

**Tasks** (`Taskfile.yml`):

| Task | Does |
|---|---|
| `task setup` | set `core.hooksPath=.githooks` (pre-commit, pre-push), build pinned tools |
| `task check` | fmt check, licence headers, lint (all Go modules), workflow lint (actionlint), unit tests, secret scan |
| `task lint:workflows` | actionlint over `.github/workflows` |
| `task fmt` / `task lint` / `task test` | individual steps |
| `task test:linux` | race + integration tests inside a Linux container |
| `task test:integration` | database integration tests (`-tags integration`) against the throwaway cluster started by `task up PROFILE=test` (127.0.0.1:5433, tmpfs); tests connect as `pc_app` |
| `task gen` | buf generate + sqlc generate (M1+) |
| `task license:check` / `task license:fix` | SPDX/copyright headers |
| `task build` | build all binaries into `bin/` |
| `task up` / `task down` | compose stack (profile via `PROFILE=core`) |
| `task vuln` | govulncheck |

**Run the server locally (M1):** secrets live in the git-ignored `deploy/dev/secrets/`.

```bash
task up                                                   # PostgreSQL 17 on 127.0.0.1:5432
mkdir -p deploy/dev/secrets
for r in pc_app pc_migrator pc_audit_ro; do openssl rand -hex 24 > deploy/dev/secrets/$r.pw; done
set -a; . deploy/compose/.env; set +a                       # PC_PG_PASSWORD of the compose database
printf 'postgres://pc_owner:%s@127.0.0.1:5432/pantherclaw?sslmode=disable' "$PC_PG_PASSWORD" > deploy/dev/secrets/admin.url
go run ./cmd/pantherclaw-server db bootstrap --admin-url-file deploy/dev/secrets/admin.url \
  --app-password-file deploy/dev/secrets/pc_app.pw --migrator-password-file deploy/dev/secrets/pc_migrator.pw \
  --audit-password-file deploy/dev/secrets/pc_audit_ro.pw
go run ./cmd/pantherclaw-server keys gen-kek --out deploy/dev/secrets/kek
go run ./cmd/pantherclaw-server migrate up --config deploy/dev/server.example.json
go run ./cmd/pantherclaw-server serve --config deploy/dev/server.example.json
```

Then `curl http://127.0.0.1:8080/readyz`, `curl http://127.0.0.1:8080/.well-known/pantherclaw/jwks.json`, or call `pantherclaw.v1.SystemService/GetBuildInfo` with `buf curl`. The server refuses to run the application pool as a superuser or BYPASSRLS role, and plaintext HTTP only on loopback.

**Gateway (M6):** gateways reach `AuthorityService` only on the server's mTLS gateway listener (`gateway_api`), with a 24-hour certificate from PantherClaw's internal CA. A gateway gets its first certificate with a single-use enrollment token and pins the CA by its SHA-256. The public API refuses every gateway call. For development, `dev seed --gateway-out` (or `dev gateway --org ID --out FILE` for an existing org) writes an enrollment file holding the API URL, the token (valid 15 minutes) and the CA pin. The gateway enrolls from it on first start, keeps its identity in `control.identity_dir`, and renews the certificate itself.

```bash
go run ./cmd/pantherclaw-server dev seed --config deploy/dev/server.example.json \
  --org-name acme --budget-limit 1000.00 --gateway-out deploy/dev/secrets/gateway-enroll.json \
  --target-url http://127.0.0.1:9090 --workload-out deploy/dev/secrets/workload.json \
  --facts-key-out deploy/dev/secrets/facts.key   # a gateway to enroll, its payments connection, a workload with a grant and a run, a fact provider's API key
go run ./cmd/pantherclaw-server serve --config deploy/dev/server.example.json   # API on :8080, gateway listener on :8443
go run ./cmd/pantherclaw-sim payments --addr 127.0.0.1:9090   # simulated payments API (SIMULATED)
# within 15 minutes of dev seed (or run dev gateway again):
go run ./cmd/pantherclaw-gateway serve --config deploy/dev/gateway.example.json --enroll-file deploy/dev/secrets/gateway-enroll.json
# since M4 every refund needs a fresh payments.charge.refundable fact about its charge, and identical
# refunds are parked: --unique varies charge and amount, --facts-key-file reports the facts first
go run ./cmd/pantherclaw-sim load --workload-file deploy/dev/secrets/workload.json --facts-key-file deploy/dev/secrets/facts.key \
  --unique --rate 1 --duration 2s --warmup 0s
```

Since M4 (slice 214) `dev seed` imports and activates the reference package (signed with the development package key, see M4 below), registers a development fact provider, issues the workload a grant (refunds up to `authority.grant_max_per_action` each, a task budget of `--budget-limit`, at most `--max-count` refunds) and binds its run to it. Identical irreversible refunds are parked for the repeat window (HR-007), so without `--unique` the load driver gets one acceptance and then `RECONCILIATION_REQUIRED`. To report a fact by hand, use `pclaw fact put` with the provider's API key in `PANTHERCLAW_API_KEY`. The M4 measurements are in [docs/perf/M4.md](perf/M4.md).

Since M6 the gateway serves the routes of its connections at `/{connection}/…`: `--target-url` creates the connection `payments` to the simulator, in enforce mode, so a refund is `POST /payments/v1/refunds` (`dev connection --org ID --target-url URL` adds one to an existing org). The gateway maps the request through the connection's reviewed package to ActionIR, asks the Authority, verifies the permit, builds the request from the package's dispatch template, commits it with `BeginDispatch`, sends that **re-serialized** request to the target with `Idempotency-Key: pc-<transaction id>`, and records the outcome. The agent gets the target's answer with `PC-Transaction-Id`, `PC-Outcome` and `PC-Receipt` headers, or a JSON refusal with an `error_class`. Its `Server-Timing` header breaks down where the time went. Since M3 every request is PAP/1-signed: the workload sends its workload token (`Authorization: PAP …`), a `PAP-Proof` over the method, the gateway's `public_url`, the body hash and a server nonce, its run in `PAP-Run-Id` and its action in `PC-Action-Id`; the gateway forwards them and the Authority verifies them. `curl` cannot sign, so the example uses `pantherclaw-sim load`, which reads the key file, gets a workload token from the server and signs every request.

**Credential custody and action tokens (M6):** `--access-mode` sets how the target holds agents to the gateway. The default `none` leaves the target open to direct calls.
- `pantherclaw_held`: the gateway places a sealed credential as `Authorization: Bearer`.
  1. Give the gateway a broker key (`pantherclaw-gateway broker-key generate`, then `broker.key_file` and `broker.kek_files`) and start it, so that it registers the key.
  2. Seal the credential with `pclaw seal --connection ID --from-file FILE`.
  3. Run the simulator with `--token-file FILE`, so it refuses calls without the credential.
- `target_enforced`: every dispatch carries a PAP-Action token. Run the simulator with `--require-action-tokens --jwks-url http://127.0.0.1:8080/.well-known/pantherclaw/jwks.json --audience <connection id>`.

**MCP and the Claude Code hook (M6):** the same gateway serves MCP at `/mcp/{connection}` (2026-07-28, and 2025-11-25 with sessions) and cooperative hooks at `/hook/{connection}`.

- **An MCP client** reaches a connection through `pclaw mcp proxy --gateway URL --connection NAME --key-file FILE`, a stdio shim that signs every request. The [workload-identity runbook](runbooks/workload-identity.md) shows a client configuration.
- **A remote MCP server** sits behind a `kind: mcp` connection. `go run ./cmd/pantherclaw-sim mcp --addr 127.0.0.1:9091` serves the simulated refunds over MCP. Its fault flags (`--legacy`, `--stream`, `--ask`, `--input-required`, `--tool-error`, `--description`) exercise upstream behaviour and drift.
- **Dogfooding the Claude Code hook** is opt-in per developer and never goes in this repository's shared configuration:
  1. `dev seed … --gateway-out … --shell --workload-out …` also activates `pc.shell`, creates the `kind: local` connection `shell` in enforce mode, and lets the seeded grant run shell commands;
  2. set `PANTHERCLAW_GATEWAY`, `PANTHERCLAW_HOOK_CONNECTION=shell`, `PANTHERCLAW_WORKLOAD_KEY_FILE` and `PANTHERCLAW_RUN` in your own environment;
  3. start Claude Code with `--plugin-dir integrations/claude-code`.

  With the plugin loaded and the stack down, every Bash and PowerShell command is blocked, by design ([integrations/claude-code](../integrations/claude-code/README.md)).

Operator procedures are in the runbooks: [gateways](runbooks/gateway.md), [the kill switch](runbooks/kill-switch.md) and [broker keys and credentials](runbooks/key-rotation.md).

**Sign in and administer (M2):** people sign in through an OpenID provider; locally that is the Keycloak development realm in `deploy/keycloak` (users `alice` / `alice-dev-only` and `bob` / `bob-dev-only`, development only). The server is the relying party; `pclaw` never talks to the provider.

```bash
task up PROFILE=identity                                   # Keycloak on 127.0.0.1:8180 (set KC_ADMIN_PASSWORD in deploy/compose/.env)
printf 'pantherclaw-dev-only-client-secret' > deploy/dev/secrets/keycloak.secret
# in your server config, add to "auth": "oidc_providers": [{"name": "keycloak",
#   "issuer": "http://127.0.0.1:8180/realms/pantherclaw", "client_id": "pantherclaw",
#   "client_secret_file": "deploy/dev/secrets/keycloak.secret", "allow_insecure_loopback": true}]
go run ./cmd/pantherclaw-server org create --config deploy/dev/server.local.json --name acme   # prints the org id and a one-time admin token
go run ./cmd/pantherclaw-server serve --config deploy/dev/server.local.json
go run ./cmd/pclaw login --server http://127.0.0.1:8080 --org <org id> --invitation <pci_ token>   # sign in as alice in the browser
go run ./cmd/pclaw whoami
go run ./cmd/pclaw team create --slug payments --name Payments
go run ./cmd/pclaw invite create --email bob@example.test --role viewer      # bob runs pclaw login with this token
go run ./cmd/pclaw sa create --name ci && go run ./cmd/pclaw sa key-generate <sa id> --out ci-key.json
go run ./cmd/pclaw sa token --key-file ci-key.json                          # private_key_jwt client credentials
```

**Agents and workloads (M3):** an owner registers an agent, and its workload proves who it is with its own key (PAP/1). The workload commands run inside the workload and use only its key file.

```bash
go run ./cmd/pclaw agent create --name coder --team <team id> --env <env id> --owner <user id> --context ci
go run ./cmd/pclaw agent enroll-token <agent id> --out enroll.token   # single use, 15 minutes
# inside the workload:
go run ./cmd/pclaw workload init --key-file workload.json
go run ./cmd/pclaw workload enroll --key-file workload.json --server http://127.0.0.1:8080 --enrollment-token-file enroll.token
# the owner compares the printed fingerprint, then:
go run ./cmd/pclaw instance admit <instance id> --fingerprint <fingerprint>
go run ./cmd/pclaw run start <agent id> --instance <instance id> --task "nightly refunds"
go run ./cmd/pclaw workload token --key-file workload.json             # a workload token, valid 10 minutes
go run ./cmd/pclaw workload renew --key-file workload.json --out workload.token   # a long-running service: always a valid token in the file
```

`workload renew` runs until it is stopped. It replaces the file atomically, halfway through each token's lifetime, and exits with code 3 when the server refuses renewal (instance revoked, agent suspended or retired); the [workload-identity runbook](runbooks/workload-identity.md) shows a systemd unit and a Kubernetes sidecar.

CI jobs and pods can attest instead of using an enrollment token: an admin proposes a trusted-issuer entry (`pclaw issuer propose-github …` or `pclaw issuer propose-kubernetes …`), a person with the Identity Publisher role activates it (`pclaw issuer activate ENTRY REVISION`), and the workload enrolls with `--github` (an Actions job with `id-token: write`) or `--kubernetes-token FILE` (a projected service-account token with audience `pantherclaw:<org id>`). Unknown keys that reach the gateway show up as discovered agents: `pclaw agent list --state discovered`, then `pclaw agent claim` or `pclaw agent retire`. `pclaw scan` looks for shadow agents on a machine: the MCP servers configured for Claude Desktop, Claude Code, Cursor, VS Code, Windsurf (now Devin Desktop), Zed, JetBrains Junie, JetBrains AI Assistant (`options/llm.mcpServers.xml` of every JetBrains IDE and version, `~/.ai/mcp/mcp.json`, and `.idea/workspace.xml` and `.ai/mcp/mcp.json` in a project), OpenAI Codex CLI (`~/.codex/config.toml` or `$CODEX_HOME`, and `.codex/config.toml` in a project) and Google Gemini CLI (`~/.gemini/settings.json` or `$GEMINI_CLI_HOME`, and `.gemini/settings.json` in a project), agent-framework projects under `--path`, and credentials in the environment and in those servers' environment values, HTTP headers and OAuth client secrets (shown redacted). Results stay local; `--submit` adds the MCP servers and agent projects to the discovered agents (credentials are never sent).

The bootstrap admin token is single use and valid 24 hours; `pantherclaw-server org admin-invite --org <id>` issues a new one. Automation can skip `pclaw login`: set `PANTHERCLAW_SERVER` and `PANTHERCLAW_API_KEY` (a `pck_` key from `pclaw apikey create`). Integration tests use an in-process OpenID provider; the CI also runs the end-to-end scenario against `navikt/mock-oauth2-server` (`docker compose --profile test` starts it on 127.0.0.1:8181; set `PC_TEST_MOCK_OIDC_URL=http://127.0.0.1:8181`), and `PC_TEST_KEYCLOAK_URL=http://127.0.0.1:8180` runs the Keycloak realm test.

**Authority: packages, facts, guardrails, grants and policies (M4):** a run's actions use only the grant its run is bound to, so an org needs an active tool package, the facts its definitions require, a grant, and optionally guardrails and a published policy. Each document is a JSON (or YAML package) file; the server decodes it strictly. Importing a package needs a targets document signed by a trusted package root (`pclaw-admin packages sign`); activating packages, changing guardrails, issuing grants, registering fact providers and publishing policies are human only.

```bash
go run ./cmd/pclaw package import --name pc.mock-payments --version 1.0.0 --targets-file targets.jws --file packages/mock-payments/package.yaml
go run ./cmd/pclaw package transition pc.mock-payments 1.0.0 --to active
go run ./cmd/pclaw fact-provider register --name billing --sa <sa id> --fact payments.charge.refundable:boolean:payments.charge:5m
go run ./cmd/pclaw fact put --name payments.charge.refundable --subject-type payments.charge --subject-id ch_1 --value-file true.json   # as the provider's service account
go run ./cmd/pclaw guardrail create --scope team:<team id> --name payments --bounds-file team-bounds.json --max-root-lifetime 72h
go run ./cmd/pclaw grant issue <agent id> --principal user:<user id> --expires 48h --bounds-file bounds.json --limits-file limits.json
go run ./cmd/pclaw run start <agent id> --instance <instance id> --grant <grant id> --task "refund ch_1"
go run ./cmd/pclaw grant get <grant id>      # lineage, guardrails and effective bounds
go run ./cmd/pclaw grant budget <grant id>   # reserved, spent and available per budget account
go run ./cmd/pclaw policy create --file bundle.json && go run ./cmd/pclaw policy publish <version id>
```

Locally, packages are signed with the development package key instead of the offline root (decision 3, [follow-up brief](g0/M4-dev-package-key.md)). `dev seed` creates it on its first run as `deploy/dev/secrets/package-dev.key` and `package-dev.pub.json`, reuses it afterwards and signs the reference packages with it. `deploy/dev/server.example.json` names the public half in `dev.package_key_file`, so that server trusts the key for imports. A server whose configuration names it refuses to start unless its API and gateway listeners, gateway hostnames and public URL are all on loopback, no proxy is declared and `auth.api_key_env` is not `live` (HR-163); production configurations never name it. Each seeded org's reference packages use targets version 1, so sign from version 2. Import as an Org Admin of the seeded org (`pantherclaw-server org admin-invite --org <org id>`, then `pclaw login`, as in M2):

```bash
go run ./cmd/pclaw-admin packages sign --key deploy/dev/secrets/package-dev.key --version 2 --expires-days 30 \
  --out deploy/dev/secrets/targets.jws packages/pc-shell/package.yaml
go run ./cmd/pclaw package import --name pc.shell --version 1.0.0 --targets-file deploy/dev/secrets/targets.jws --file packages/pc-shell/package.yaml
```

To let a service start runs on behalf of a signed-in user (M3), add `"subject_token_audience": "<audience>"` to that provider: its tokens whose `aud` contains that value are accepted as subject tokens at `StartRun`. The service needs the Run Launcher role (`run.represent`) and passes the user's fresh token (at most 5 minutes old, single use; an access token must be typed `at+jwt`). The user must already exist and be active in the org, and the token grants the run nothing.

**Browser sign-in, security keys and notifications (M5 part 1):** WebAuthn needs a domain name, so locally use `http://localhost:8080` as `auth.public_url` (the Keycloak development realm accepts both callback URLs). Security keys are off, with a start-up warning, while the public URL is an IP address.

```bash
# in your server config: "auth": {"public_url": "http://localhost:8080", ...}
# optional email through a local relay: "notifications": {"smtp": {"host": "127.0.0.1", "port": 1025, "tls": "none", "from": "pantherclaw@localhost"}}
go run ./cmd/pantherclaw-server serve --config deploy/dev/server.local.json
# open http://localhost:8080/account?org=<org id>, sign in, then "Add a security key or passkey"
go run ./cmd/pclaw login --server http://localhost:8080 --org <org id>
go run ./cmd/pclaw session list && go run ./cmd/pclaw key list
go run ./cmd/pclaw channel create --name ops --kind log --event 'security.*'
go run ./cmd/pclaw channel create --name siem --kind webhook --event 'security.*' --url https://hooks.example.com/pantherclaw   # prints the signing secret once
go run ./cmd/pclaw channel create --name chat --kind slack --event 'security.*' --url-file slack-url.txt                      # the Slack URL is a secret
go run ./cmd/pclaw channel test <channel id> && go run ./cmd/pclaw delivery list --channel <channel id>
go run ./cmd/pclaw user revoke-sessions <user id>                                                                             # sign a person out everywhere
```

Browser sessions last 30 idle minutes and 12 hours at most. Adding or removing a key needs a sign-in at most 5 minutes old (the page sends you back to your identity provider) or a step-up with a key you already have, and the user is emailed about it. Webhooks are signed per Standard Webhooks: any `standardwebhooks` library verifies them with the `whsec_` secret. Slack and email messages only link back to PantherClaw; nothing in a channel can approve anything. Community allows 3 channels. Without `notifications.smtp.host`, email deliveries are skipped and shown as such in `pclaw delivery list`.

**Approvals and the Agent Waitlist (M5 part 2):** `dev seed` publishes the policy `dev-holds`, so a refund over `--hold-over` (default 50.00) is held for one Approver. The gateway answers a held call with its transaction id, which is the wait handle. A person approves only on the approval page, with a security key bound to that exact action (decision 1); `pclaw` declines, asks for evidence or proposes a narrower action, and opens the page to approve.

```bash
go run ./cmd/pantherclaw-server org admin-invite --config deploy/dev/server.local.json --org <org id>   # alice signs in with this token
go run ./cmd/pclaw invite create --email bob@example.test --role approver                              # as alice; bob signs in with that token
# bob: open http://localhost:8080/account?org=<org id>, sign in, add a security key
go run ./cmd/pclaw workload wait <transaction id> --key-file deploy/dev/secrets/workload.json --follow   # the agent's side: READY or how it ended
go run ./cmd/pclaw approval list --waiting-for-me                                                      # as bob
go run ./cmd/pclaw approval approve <request id>                                                       # opens /approvals/<id> to approve with the key
go run ./cmd/pclaw approval decline <request id> --reason too_risky --alternative person_performs
go run ./cmd/pclaw waitlist list --overdue && go run ./cmd/pclaw escalation get
```

Approvals count only from people whose account is 7 days old and whose role and key are 1 day old (decision 5), so a freshly invited approver waits that long; the tests backdate their fixtures. Batch review and `pclaw waitlist metrics` need the Team edition. Each org sets its hold deadline, consume window and batch ceilings with `pclaw waitlist update-settings`; a server sets its wait limits with `waitlist.max_waits_per_instance`, `waitlist.max_waits` and `waitlist.long_poll_max`.

**Measure latency (M1.5):** seed a budget large enough for the run (for example `--budget-limit 100000000.00`), start the three processes as above, then drive an open-loop constant rate. Authorize and gateway overhead come from `Server-Timing`, so the target's own latency is excluded:

```bash
go run ./cmd/pantherclaw-sim load --workload-file deploy/dev/secrets/workload.json --facts-key-file deploy/dev/secrets/facts.key \
  --unique --rate 1000 --duration 30s --warmup 5s --out perf.json
```

Results and the machines they were measured on are recorded in `docs/perf/M1.5.md`.

---

## 5. Repository layout

```
cmd/                     pantherclaw-server, pantherclaw-gateway, pclaw, pantherclaw-sim, pclaw-admin
proto/pantherclaw/v1/    API contracts (buf)
internal/gen/            generated Go (committed)
internal/platform/       config, log, db, crypto, keys, ids, clock, errors, httpx, rpc (also the OpenTelemetry spans), money, extension, edition, version
internal/<module>/       {domain, app, adapters} — see §6
internal/gateway/        mcp, httpproxy, sdk, dispatch, egress, broker, runtime
migrations/  queries/    goose SQL, sqlc queries
policies/templates/      built-in task templates (support, refund, diagnostics, release, analysis)
packages/                signed tool packages (mock-payments, mock-crm, mock-git, github, stripe, slack, postgres)
sdk/go | sdk/python | sdk/typescript   Apache-2.0 SDKs (separate modules/packages)
integrations/claude-code Apache-2.0 plugin + hooks
deploy/                  compose (profiles), helm, keycloak realm, cloudflared
redteam/scenarios/       adversarial scenarios (YAML)
test/                    invariants, race, tenancy, e2e, fuzz, load, conformance
tools/                   go.mod with tool directives + Go helper programs (licence check, traceability check)
docs/                    this guide and companions
```

---

## 6. Module map

| Module | Responsibility | Key types | First milestone |
|---|---|---|---|
| `platform/*` | Cross-cutting infrastructure | `Clock`, `OrgID`, `Secret[T]`, `KeyProvider`, `Signer`, `AEAD`, `TenantTx` | M1 |
| `tenancy` | Orgs, BUs, teams, environments, users, memberships, roles, SoD | `Org`, `Membership`, `Permission`, `RoleBinding` | M2 |
| `authn` | OIDC RP, device flow, sessions, WebAuthn, service accounts, API keys | `Principal`, `Session`, `StepUp` | M2/M5 |
| `agents` | Inventory, ownership, lifecycle, change history | `Agent`, `LifecycleState` | M3 |
| `identity` | PAP/1: enrollment, instances, workload tokens, proofs, nonces, attestation | `Instance`, `WorkloadToken`, `Proof`, `AttLevel` | M3 |
| `runs` | Runs, launcher vs principal, child runs | `Run` | M3 |
| `definitions` | Tool packages, action definitions, consequence rules, ActionIR mapping | `Package`, `ActionDefinition`, `ActionIR` | M4 |
| `grants` | Envelopes, grants, revisions, lattice constraints, delegation, revocation | `Grant`, `Constraint`, `Lineage` | M4 |
| `budgets` | Budgets, counters, ledger, reservations | `Budget`, `Reservation` | M4 |
| `facts` | Trusted fact providers, freshness | `Fact`, `Provider` | M4 |
| `policy` | Structured rules, CEL compile/eval, templates, tests, simulation, rollout | `Rule`, `Bundle`, `Evaluation` | M4/M11 |
| `authority` | Decision pipeline, finalization, permits, BeginDispatch, RecordExecution | `Decision`, `Checklist`, `Permit` | M1.5/M4/M6 |
| `approvals` | Approval requests/responses, binding, eligibility, two-person | `ApprovalRequest`, `Binding` | M5 |
| `waitlist` | Unified decision queue, wait handles, escalation | `Entry`, `Handle` | M3/M5 |
| `transactions` | Execution attempts, effects, verifiers, reconciliation | `Attempt`, `Effect`, `Reconciliation` | M6/M7 |
| `credentials` | Sealed credentials, broker key registry, access modes | `SealedCredential`, `AccessMode` | M6 |
| `connections` | Connections, routes, capability manifests, health | `Connection`, `Route` | M6 |
| `coverage` | Coverage snapshots, states, invalidation, probes | `Snapshot`, `CoverageState` | M9 |
| `evidence` | Receipts, ledger, chainer, checkpoints, anchoring, packs, replay, retention, platform audit | `Receipt`, `LedgerEntry`, `Checkpoint` | M1/M7 |
| `detections` | CEL detection rules, windows, mappings | `DetectionRule`, `Hit` | M10 |
| `incidents` | Alerts, incidents, cases, findings, suppressions | `Case`, `Finding` | M10 |
| `response` | Containment actions, epochs, kill switch, restoration | `ContainmentAction`, `Epoch` | M6/M10 |
| `reach` | Effective reach, blast radius, exposure graphs | `ReachGraph` | M10 |
| `search` | Structured + FTS search, saved queries (permission-safe) | `Query` | M10 |
| `automations` | Definitions, schedules, triggers, executor | `Automation`, `Schedule` | M11 |
| `notifications` / `exports` | Channels (log, SMTP, Slack, webhook), OCSF export, Standard Webhooks | `Notification`, `Delivery` | M5/M10 |
| `discovery` | Shadow agent discovery (gateway-observed, `pclaw scan`, GitHub org scan) | `Discovery` | M3/M8 |
| `billing` | Editions, licence verification, entitlements, metering | `Licence`, `Entitlement` | M1/M13 |
| `redteam` | Scenario engine, assurance reports | `Scenario`, `Report` | M12 |

---

## 7. Data model by milestone

| MS | Tables (all `org_id` + RLS unless noted) |
|---|---|
| M1 | `orgs` (root, RLS on id), `cross_org_list_audit` (global), `ledger_entries`, `ledger_chain` (insert-only links), `ledger_heads`, `keys` (public material + wrapped private refs), `deks`, `licence_state` (global), River tables (no RLS; River's migrations run as goose Go migrations) |
| M1.5 | `transactions`, `decision_receipts`, `permits`, `execution_attempts`, `budgets`, `budget_ledger`, `org_containment` |
| M2 | `business_units`, `teams`, `environments`, `users`, `memberships`, `role_bindings`, `service_accounts`, `service_account_keys`, `api_keys`, `invitations`, `device_codes`, `cli_sessions` (CLI refresh tokens), `auth_replay` (client-assertion `jti`s) |
| M3 | `agents` (owner and backup owner columns), `agent_changes`, `agent_instances`, `enrollment_tokens`, `trusted_issuers`, `attestations`, `dpop_nonces`, `dpop_jti` (partitioned), `runs`, `discoveries`, `waitlist_entries`; subject-token `jti`s in `auth_replay` (M2) |
| M4 | `package_trust`, `tool_packages`, `package_versions`, `package_pins`, `package_signing_keys` (follow-up, 00026), `action_definitions`, `consequence_rules`, `policies`, `policy_versions`, `envelopes`, `envelope_revisions`, `grants`, `grant_revisions`, `grant_lineage`, `budget_accounts` (00023: one row per rule, hashed grouping key and period; the M1.5 `budgets` table is left as it was), `counters`, `reservations`, `fact_providers`, `fact_declarations` (00024), `facts`, `dedupe_claims`; idempotency lives in columns on `transactions` (M1.5) |
| M5 | `sessions` (browser), `login_requests` (browser sign-ins in progress), `webauthn_credentials`, `webauthn_ceremonies` (pending registrations and assertions; `BINDING` in part 2), `notifications`, `notification_channels`, `deliveries`; part 2: `approval_requests`, `approval_responses`, `approval_evidence`, `hold_slots`, `escalation_chains`, `waitlist_routes`, `waitlist_settings`, `approval_batches`; `waitlist_entries` (M3) gains the other five kinds |
| M6 | `gateways`, `gateway_enrollment_tokens`, `gateway_certs`, `broker_keys`, `connections`, `connection_routes`, `credentials` (sealed), `circuit_states`, `kill_switch_requests`; `org_containment` gains who engaged the kill switch; `transactions` and `permits` gain mode and connection |
| M7 | `execution_receipts`, `effect_receipts`, `verifications`, `observations`, `reconciliation_tasks`, `transaction_links`, `target_log_runs`, `unreceipted_effects`, `ledger_tiles`, `checkpoints`, `anchors` (global, blinded leaves only), `anchor_leaves`, `evaluation_inputs`, `retention_policies`, `legal_holds`, `capture_profiles`, `payload_captures`, `evidence_packs`; `transactions` gains effect state and levels; evidence tables gain body-removal columns (G0 M7 decision 4) |
| M9 | `coverage_snapshots`, `coverage_routes`, `probes`, `probe_results`, `sandbox_sessions` |
| M10 | `detection_rules`, `detection_state`, `alerts`, `incidents`, `cases`, `case_notes`, `findings`, `suppressions`, `containment_actions`, `export_destinations`, `saved_queries` |
| M11 | `policy_tests`, `policy_simulations`, `policy_rollouts`, `exceptions`, `automations`, `automation_versions`, `schedules`, `triggers`, `executions`, `step_executions` |
| M12 | `redteam_runs`, `redteam_results` |
| M13 | `entitlements`, `usage_meters`, `support_access_grants`, `data_requests` |

---

## 8. Milestones

Each milestone starts with a G0 brief in [GATES_AND_REVIEW.md](security/GATES_AND_REVIEW.md) §7 and ends when its exit criteria pass in CI.

**Delivery order** ([ADR-0017](adr/0017-coding-agents-first-and-proven-coverage.md)); milestone numbers are identifiers, not order, and `tools/traceability` holds this order:

```
M0 → M1 → M1.5 → M2 → M3 → M4 → M5 → M6 → M7 → M8 → M9 → M12 → v0.1.0 preview
   → M10 → M11 → M14 → M13 → v1.0 → UI phase
```

Releases: `v0.0.x` pre-releases from M1; **v0.1.0 preview after M12** (coding-agent wedge, exit below); **v1.0 after M13**.

### M0 — Bootstrap (done when CI is green)
- Docs set (this guide and companions), IP/legal files, repo security settings, rulesets, `release` environment.
- Skeleton: Go module, `cmd/*` stubs, `internal/platform/version` with tests, Taskfile, `.githooks`, pinned tools (`tools/pins/*`: golangci-lint, govulncheck, gitleaks, osv-scanner, actionlint, task), licence-header checker (`tools/licensecheck`), golangci config, Semgrep rules, `.gitattributes`, devcontainer, compose (Postgres), workflows (ci, scorecard, nightly, release, ai-review, pr-hygiene, canary-watch), Dependabot, GoReleaser config.
- **Exit:** `ci-ok` green on `main`; Scorecard runs; settings verified via API; G0(M1) recorded.

### M1 — Platform foundation
**Threat slice:** T-003, T-016, T-034, T-041 · **HR:** HR-004, HR-050..057, HR-062, HR-063, HR-104.
- `platform/config` (typed, validated), `platform/log` (slog JSON, `Secret[T]`, `Sensitive[T]`, ReplaceAttr denylist, field caps), `platform/clock`, `platform/ids` (typed UUIDv7), `platform/errors` (codes), `platform/money` (decimal).
- `platform/db`: pgx pool (AfterConnect timeouts, AfterRelease `RESET ALL`), `InTenantTx`, `InGlobalTx` (restricted), goose runner, role bootstrap migration (`pc_migrator`, `pc_app`, `pc_audit_ro`), audited cross-org lister function.
- `platform/crypto`: AEAD envelope (AES-256-GCM, AAD builder), Ed25519 signer/verifier (go-jose JWS with allowlist), HPKE seal/open (X-Wing), hashing helpers; `platform/keys`: `KeyProvider` (file implementation), key registry, JWKS document.
- `platform/httpx`: hardened server (timeouts, limits, headers, recovery), hardened outbound client factory (`egress` defaults: no redirects, dial-time IP check, no proxy env) — shared with the gateway.
- `platform/rpc`: connect v2 server setup, interceptors (request id, logging, protovalidate, panic recovery, auth placeholder), health (plain `/livez` and `/readyz`; `grpchealth` is not connect-v2-ready). OpenTelemetry is API-only: `observeInterceptor` starts one server span per call, no SDK or exporter is wired and nothing is exported; there is no `platform/otel` package. The exporter is decided in M13 (G0 M1 deviation 4, answered 2026-10-10).
- River setup (migrations imported into goose), job registry, `InsertTx` helper.
- `evidence` (part 1): `ledger_entries` (unchained insert), per-org chainer job, platform audit API (`audit.Record(ctx, tx, event)`).
- `billing` (part 1): licence document format, Ed25519 verification against embedded public key, edition limits (Community: 5 agents, 1 org), `cmd/pclaw-admin keygen|licence sign`.
- `cmd/pantherclaw-server`: config, migrations (`migrate up` subcommand), API + worker roles, health endpoints.
- **Tests:** RLS suite as `pc_app` (missing setting matches nothing; cross-tenant read/write/FK oracle fail); crypto known-answer and tamper tests (AAD swap fails — HR-062); redaction tests (no secret in any log output); licence tamper/expiry tests; chainer correctness (gaps, concurrent inserts, rollback); `TestHR004_*` state transition helper.
- **Exit:** suites green; `v0.0.1` pre-release exercises the release pipeline.

### M1.5 — Walking skeleton (thin end-to-end slice)
**Purpose:** validate latency, chaining and budget designs before building on them. **HR:** HR-001, HR-003, HR-009, HR-070..075, HR-110.
- `pantherclaw-sim payments` (refund endpoint, fault injection flags).
- Gateway minimal: HTTP proxy for one hard-coded connection/route, static workload identity (dev only, clearly flagged), ActionIR for `payments.refund.create`, Authorize → permit → `BeginDispatch` → re-serialized dispatch → `RecordExecution`.
- Authority minimal: hard-coded grant (max $100, one refund), budget reservation, decision receipt, permit lifecycle with epoch, sweeper.
- k6 script: 1k rps allow path; budget race script. The k6 script (`test/load/refund.js`) is historical: it records how the M1.5 baseline was measured. Since M3 the gateway accepts only PAP/1-signed requests, which k6 cannot sign, so `pantherclaw-sim load --unique --facts-key-file …` is the load driver (§4, [docs/perf/M4.md](perf/M4.md)).
- **Exit:** measured p99 vs SLOs recorded in `docs/perf/M1.5.md`; zero overspend under 1,000 concurrent reservations; crash-mid-dispatch test yields UNKNOWN (no release); ADR updated if the design must change.

### M2 — Tenancy & service authentication
**Threat slice:** T-003, T-032, T-037, T-043 · **HR:** HR-095.
- Org → BU → team → environment hierarchy; users (from OIDC), memberships, invitations (single-use, expiring random tokens stored as hashes; ADR-0016), roles and permission catalog; SoD primitives.
- OIDC RP for CLI device flow (browser sessions arrive in M5); `pclaw login`.
- Service accounts with `private_key_jwt`; API keys (`pck_`), scopes, expiry; auth interceptor; bootstrap admin token (printed once, single use).
- Keycloak dev realm (`deploy/keycloak`) + mock-oauth2-server for CI.
- **Tests:** alg `none`/HS256 rejected, wrong `aud`/`iss`, expired/revoked/substituted tokens, mix-up, replayed client assertion; permission catalog test (every RPC declares a permission); IDOR tests.
- **Exit:** authenticated, authorized CRUD for tenancy via Connect + CLI.

### M3 — Agents & PAP/1 identity
**Threat slice:** T-001, T-004, T-032, T-033, T-035, T-044..T-050 · **HR:** HR-022, HR-090..094, HR-140..148 · **F:** F015–F037, F224–F236 · **PN:** PN-001 (part), PN-002 (incl. PN-002.8), PN-004 (ADMISSION) · **ADR:** 0018 · **G0:** [g0/M3.md](g0/M3.md).
- Agents inventory, owners/backup, purpose, environment, lifecycle state machine, change history.
- Enrollment tokens, instance key registration, ADMISSION waitlist entries, fingerprint confirmation.
- Workload tokens, proofs, server nonces, replay store (partitioned), attestation L1 + L2.
- **L2 through configured trusted issuers** (ADR-0018): each entry pins issuer, key source, audience, algorithms and immutable binding claims; presets carry rules configuration cannot disable. Ships the GitHub Actions OIDC and Kubernetes TokenReview presets; further presets are PN-002.3 (Next). Issuer changes are protected changes (F582).
- Runs (server-minted, launcher vs represented principal, child runs). **`StartRun` accepts an RFC 8693 subject token** from a configured OIDC provider to prove the represented user, with the launcher as actor (PN-002.8); it grants nothing by itself.
- Discovery: gateway-observed unknown workloads → unclaimed queue.
- The G0 brief turns the ADR-0018 constraints into HR-140..148 and T-044..T-050 (issuer without pinned claims, protected issuer changes, key fetch through egress guards, single-use attestation tokens, Kubernetes binding, subject-token audience and freshness, represented principal, no authority moving between instances, discovery limits).
- **Tests:** replay, stolen token without key, wrong `htu`/`bh`, stale nonce, GitHub `pull_request` (fork and same-repository) and `pull_request_target` rejection, an unprotected triggering ref (`ref_protected` false) or workflow ref rejected, ordinary-job (`workflow_ref`) and reusable-workflow (`job_workflow_ref`) bindings, name-collision instances not inheriting authority, issuer entry without binding claims rejected, token from an unconfigured issuer or for another org's audience rejected, subject token from an unconfigured IdP, for another audience, stale or replayed rejected, subject token never widening a grant.

### M4 — Authority core
**Threat slice:** T-001, T-008, T-011, T-012, T-018, T-020, T-023, T-036, T-055 · **HR:** HR-005..007, HR-023, HR-040..049, HR-100..103, HR-123, HR-124, HR-160, HR-161 · **F:** F038–F130 · **G0:** [g0/M4.md](g0/M4.md) (parts 1 and 2).
- Tool packages: format (YAML), signature verification (package root), TUF-style metadata, per-org pins (monotonic), action definitions (operation, target identity, material params with types/units, effects, reversibility, constraints, prerequisites, retry semantics, verifier, approval template, dedupe key).
- ActionIR mapping from MCP tool calls and HTTP routes (CEL extraction), strict canonicalization, hashing.
- Grants: envelopes (org guardrails), lattice constraints, revisions, delegation (depth/fan-out caps, expiry ceiling), revocation cascade, budgets per grouping with ancestor debiting, counters.
- Facts providers (trusted sources, freshness), CEL environment (decimal/money types, cost limits), structured rules (FORBID, REQUIRE_APPROVAL, REQUIRE_STEP_UP, CONSTRAIN, ANNOTATE), fail-closed evaluation.
- Decision pipeline (10 steps), checklist/explanations, decision receipts, idempotency semantics.
- **Tests:** 12 invariant property tests; 1,000-goroutine budget race; delegation lattice properties; CEL fail-closed + mutation tests; canonicalizer fuzzing; golden tests for packages; the six policy scenario tests from F193.

### M5 — Human approvals, step-up & Agent Waitlist
**Threat slice:** T-002, T-005, T-006, T-007, T-026, T-027, T-051..T-054, T-060..T-063 · **HR:** HR-030..039, HR-150..159, HR-170..177 · **F:** F139–F171 · **PN:** PN-004, PN-020 · **G0:** [g0/M5.md](g0/M5.md): part 1 (browser sessions, CSRF, WebAuthn, notifications) and part 2 (approvals, transaction-bound step-up, approval page, Agent Waitlist), which builds on M3 and M4 part 2.
- Browser sessions (OIDC auth code + PKCE), CSRF defenses, WebAuthn registration/assertion, transaction-bound step-up.
- Approval requests with binding hash, eligibility (role/scope/independence), two-person rule, expiry, invalidation (material change, role removal, revocation), decline with reason, request evidence, propose narrower action.
- Minimal server-rendered approval page (template-only rendering, untrusted box, strict CSP) — the only HTML before the UI phase.
- Agent Waitlist: all entry types, priority, deadlines, escalation chains, wait handles (long-poll + SSE), batch review for homogeneous low-risk entries, SLA metrics.
- Notifications: log, SMTP, Slack (deep-link only), webhook (Standard Webhooks signatures).
- **Tests:** replay/theft by sibling run, self-approval, API-key approval refused, sock-puppet (same WebAuthn cred), TOCTOU after approval, variant-shopping cap, delivery failure ≠ approval.

### M6 — Gateway & non-bypassable boundary
**Threat slice:** T-009, T-010, T-013, T-015, T-019, T-021, T-022, T-025, T-028, T-030, T-031, T-065..T-069 · **HR:** HR-001..011, HR-020, HR-021, HR-038, HR-060, HR-061, HR-070..083, HR-113, HR-180..188 (HR-084 and HR-085 moved to M9) · **PN:** PN-002.6, PN-003, PN-005, PN-013, PN-014, PN-015 · **G0:** [g0/M6.md](g0/M6.md).
- Gateway enrollment + mTLS (internal CA), org binding; Authorize/BeginDispatch/RecordExecution clients; revocation/containment stream with heartbeat and cold-start snapshot.
- MCP proxy (2026-07-28 stateless + 2025-11-25 stateful), tasks extension for HOLD, reviewed descriptions, elicitation/sampling gating; `pclaw mcp proxy` stdio shim.
- HTTP proxy (route matching from packages), outbound re-serialization, egress transport; credential broker (sealed creds, per-tenant keys, AAD binding), `pclaw seal`.
- Circuit breaker; monitor vs enforce mode per route. The connector runtime for third-party MCP servers (customer-hosted only, with isolation) moves to M9 (G0 M6 decision 3).
- Kill switch (asymmetric) and containment epoch bumps.
- Claude Code plugin (PreToolUse for Bash + PowerShell, path normalization) — dogfooded on PantherClaw development.
- **Exit — refund scenario table (`test/e2e`):**

| ID | Scenario | Expected |
|---|---|---|
| S01 | $30 refund within grant | ALLOW → dispatched → accepted |
| S02 | $85 refund (policy: approval > $50) | HOLD → approve (WebAuthn) → resubmit → dispatched |
| S03 | $125 refund (grant max $100) | DENY even if a manager tries to approve |
| S04 | Revoke grant while held | Pending approval invalidated; resubmit → DENY |
| S05 | Change amount after approval | Material change → new decision; old approval unusable |
| S06 | Two concurrent refunds against one-refund budget | Exactly one succeeds |
| S07 | Target timeout | UNKNOWN; reservation held; no auto-retry; reconciliation entry |
| S08 | Gateway killed between BeginDispatch and Record | UNKNOWN, not released |
| S09 | Authority unavailable | CANNOT_AUTHORIZE; nothing dispatched |
| S10 | Child agent with narrowed grant | Child cannot exceed parent; parent revocation cascades |
| S11 | Direct call to simulator bypassing gateway | Route labeled uncontrolled; coverage PARTIAL |
| S12 | SSRF/rebinding/redirect payloads | Blocked by egress guards |
| S13 | Kill switch engaged mid-run | All subsequent dispatches refused < 1 s |

### M7 — Effects, reconciliation & proof
**Threat slice:** T-013, T-024, T-029, T-043, T-070..T-077 · **HR:** HR-003 and HR-007 (resolution), HR-110..112, HR-190..199 · **F:** F461–F532 (F500 and F533 in M11) · **PN:** PN-007 · **G0:** [g0/M7.md](g0/M7.md), built in two parallel tracks (A: effects and reconciliation; B: proof).
- Verifiers (follow-up reads by the gateway on leased tasks), effect state machine, verification levels (required vs achieved), deadlines, conflicting evidence, reconciliation queue with owners (a person releases an unknown outcome; evidence resolves it only towards "occurred"), target-log reconciliation, compensation linking.
- Execution/effect receipts, Merkle tiles, signed checkpoints, Rekor v2 anchoring (blinded global root, RFC 3161; configured endpoints), `pclaw verify` (offline), decision replay (non-executing; proposed-policy replay; difference explanation), evidence packs (signed), retention categories (bodies removed, hashes kept), restricted payload capture profile, optional ML-DSA co-signing of checkpoints and pack manifests.
- **Tests:** tampering detected (row edit, deletion, re-signing without witness), replay never dispatches, pack completeness incl. uncertain states.

### M8 — Coding-agent integrations
**PN:** PN-001.2, PN-014, PN-016.1, PN-016.2, PN-017.1 · **F:** F158, F346, F351 · **ADR:** 0017.
- `sdk/go` (client + target verifier middleware); core `sdk/python` and `sdk/typescript` clients (PAP/1, DPoP, ActionIR canonicalizer, wait handles), which the Agent SDK callback needs; cross-language conformance fixtures. Framework wrappers wait for M14.
- Claude Agent SDK `canUseTool` integration; `pclaw init` (detect Claude Code, MCP and framework config, enroll, rewrite config with backup, apply the "coding to production" template).
- GitHub App connector (per-action installation tokens, PR/merge, branch protection facts) and GitHub organisation scan.
- §43 coding-agent scenario on a sandbox GitHub repo: merge requires independent reviewer; deployment consequence requires release approver.

### M9 — Coverage & containment sandbox
**HR:** HR-024, HR-084..086, HR-121, HR-122 · **F:** F433–F460 · **PN:** PN-008.
- Routes inventory, coverage snapshots (UNKNOWN/OBSERVE_ONLY/PARTIAL/ENFORCED), invalidation events, freshness contract, closure evidence, access-mode disclosure, credential-overreach findings.
- `pclaw sandbox run`: egress-locked Docker network (gateway only; IPv6/ICMP/DNS blocked), no creds, read-only FS, non-root, optional gVisor; trusted sidecar probes + external canary; expiring ENFORCED promotion.
- Connector runtime for third-party MCP servers run as local processes (moved from M6, G0 M6 decision 3): each in its own locked-down container on the same sandbox machinery, customer-hosted gateways only, egress only through the gateway, which injects credentials (HR-084, HR-085).

### M10 — Detect, investigate, respond
**F:** F211–F271, F534–F572, F607–F623 · **PN:** PN-006, PN-018, PN-024 · **ADR:** 0019.
- Detection engine (CEL rules over outbox events, windowed counters with cardinality caps, ATLAS/OWASP mapping), attention levels, grouping, suppression with scope/expiry.
- Alerts → incidents → cases (facts, hypotheses, open questions, lenses, closure requirements), posture findings and lifecycle.
- Breach radius: observed vs effective vs credential/bypass reach, dependency previews, exposure matrix.
- Containment actions with per-path verification, restoration workflow; OCSF 1.9 export, Standard Webhooks, delivery health; permission-safe search & saved queries; live operations stream (SSE).
- Shared Signals (CAEP/RISC) receiver for the customer IdP (PN-024, ADR-0019): signed events from configured transmitters only; identity events suspend grants only through preauthorized playbooks, otherwise open a case. The M10 brief threat-models the new inbound endpoint.

### M11 — Policy lifecycle & governed automations (MVP subset)
**F:** F172–F210, F652–F754 (subset).
- Templates (support, refund, diagnostics, release, analysis), policy tests with expected reasons, historical simulation (newly denied/held/constrained/allowed/unevaluable), shadow evaluation, pilot cohorts, per-target rollout states, rollback, exceptions, behavioral diffs.
- Automations: definitions (When/If/Under authority/Do/Wait/If fails/Finish), schedules (timezone, DST, missed-run policy), event/manual triggers, linear steps with waits and approvals, bounded retries, loop detection via ancestry, shadow mode, execution inspector data. Full branching engine = Next.

### M12 — Adversarial range (delivered after M9, before the preview)
**HR:** HR-120 · **PN:** PN-009.
- Scenario engine (YAML), ≥ 30 attacks (see FEATURES pillar 17), simulator-only enforcement, assurance reports (signed), CI regression gate on every PR touching authority/gateway.
- Coding-agent scenarios first: direct-API bypass of an MCP merge, found PAT/SSH key, sub-agent escalation, approval reuse after a new commit, injection → exfiltration over an allowed channel, stolen workload token, sandbox DNS/IPv6 escape.

### v0.1.0 preview exit — coding-agent wedge (ADR-0017)
- **Three routes, three stops**, in CI against the git simulator and live against a sandbox GitHub repository: a merge through the GitHub MCP server without a reviewer is held; the same merge by direct `curl` to the GitHub API is mapped to the same action and decision (F099); a push with a found PAT or SSH key fails because the sandbox holds no reusable credentials and its egress is closed. Each attempt has a signed receipt that `pclaw verify` checks offline.
- The §43 scenario passes end to end with effect verification on the target branch.
- The coverage card shows the repository routes `ENFORCED` from sandbox probe evidence, with expiry.
- The 30-minute onboarding path for Claude Code (F335) is measured and recorded.
- The coding-agent scenarios of M12 are green and gate CI.

### M13 — Commercial & production hardening → v1.0
**PN:** PN-010, PN-011, PN-012, PN-019.
- Entitlements & metering per edition, rate limits/quotas, support access (task-bound, customer-approved, audited), data export/deletion, Helm chart, backup/restore + DR drill, FIPS build variant, SLOs met under load (`pantherclaw-sim load`; k6 cannot sign PAP/1), Schemathesis clean, threat-model refresh (G4), docs site.
- The OpenTelemetry exporter (founder decision 2026-10-10, G0 M1 deviation 4): until then spans are API-only and nothing is exported. Choose between the OTLP/HTTP exporter (it pulls in gRPC and grpc-gateway), a small OTLP/HTTP-protobuf exporter of our own, or export through logs; then wire the SDK, and decide on a pgx tracer and metrics (ARCHITECTURE §14).

### M14 — Framework SDKs & business connectors (delivered after M11, before M13)
**PN:** PN-016.3, PN-017.2, PN-017.3, PN-017.4, PN-023 · **F:** F101 · **ADR:** 0017, 0019.
- Framework wrappers on the core clients: Python (LangChain/LangGraph, OpenAI Agents SDK, CrewAI on py3.13), TypeScript (Vercel AI SDK, MCP TS), all on the conformance suite.
- Connectors: Stripe test mode (refunds, idempotency keys), Slack (approval deep links, notifications), Postgres query (read-only, row limits, field filtering); data-scoping constraints where connectors support them.
- AuthZEN decision endpoint for third-party enforcement points (PN-023, ADR-0019); routes decided this way are `PARTIAL`, and budget-consuming allows are recorded as dispatched with an unreported outcome.
- Refund scenario as the second-market demo on real Stripe test mode.

### UI phase (after backend)
Next.js console over generated Connect clients: seven surfaces (Operations, Agents, Policies, Approvals, Investigations, Connections, Automations) + universal search; accessibility and comprehension tests (F001–F014, F643–F651).

---

## 9. CI/CD summary

| Workflow | Trigger | Purpose |
|---|---|---|
| `ci.yml` | PR, push `main` | Path-filtered Go/proto/SQL/Python/TS/security/product suites; single required check `ci-ok` |
| `scorecard.yml` | weekly, push `main` | OpenSSF Scorecard |
| `nightly.yml` | schedule | E2E compose scenarios, fuzzing, Schemathesis, k6, OSV image scan, re-scan of released versions |
| `release.yml` | push of a `v*` tag (founder) | Verify tagged commit → `release` environment approval (G2/G3) → GoReleaser draft (binaries, SBOMs, checksums, changelog) → build-provenance attestations → publish (immutable) |
| `ai-review.yml` | PR (same-repo) | Claude security review (advisory) using the review brief |
| `pr-hygiene.yml` | PR | Semantic title, size labels |
| `canary-watch.yml` | weekly | Copy detection |

Hardening: SHA-pinned actions (repo policy), `permissions: {}` default, `persist-credentials: false`, no `pull_request_target`, harden-runner (audit; block on release), concurrency cancel-in-progress, Dependabot with 7-day cooldown.

---

## 10. Demo scenarios (investor / design partner)

Ordered for the coding-agent first market (ADR-0017); scripts and talk tracks follow [PRODUCT.md](PRODUCT.md) §6.

1. **Three routes, three stops** (v0.1.0): MCP merge held, direct API call gets the same decision, found credential useless in the sandbox; every attempt has a verifiable receipt.
2. **Coding agent to production** (M8): merge vs deployment consequence; independent reviewer + release approver; effect verification on the target branch; partial deployment.
3. **Shadow agent discovery** (M3/M8): `pclaw scan` on a laptop finds MCP configs and keys; claims → ADMISSION waitlist.
4. **Kill switch** (M6): engage → gateways refuse within 1 s → restore with two people.
5. **Prove it** (M12): red-team range report against the demo tenant; sandbox closure evidence promotes coverage to ENFORCED.
6. **Refund firewall** (M6, second market): S01–S09 live, with evidence explorer showing decision/execution/effect receipts.

All demo data is synthetic and labeled `SIMULATED` (F630).

---

## 11. Glossary

| Term | Meaning |
|---|---|
| Task grant | Bounded authority for a run/task (AuthorizationEnvelope / DelegationGrant) |
| Envelope | Org/BU/team guardrail ceiling within which grants are issued |
| Action definition | Reviewed meaning of an operation (ActionIR schema, effects, constraints) |
| Tool package | Signed, versioned bundle of action definitions and mappings (SemanticPackage) |
| ActionIR | Canonical representation of one requested action |
| Permit | Single-use, short-lived authorization to dispatch one finalized action |
| BeginDispatch | Server-side commit point immediately before dispatch |
| Containment epoch | Per-org counter incremented by every containment change |
| Coverage | Scoped evidence that equivalent routes are mediated or blocked |
| Receipts | Decision, execution and effect evidence records |
| Waitlist | Unified queue of agents/actions awaiting a security decision |
| PAP/1 | PantherClaw Authority Protocol, version 1 |
| Component | One of the seven buyer-facing groupings of pillars ([PRODUCT.md](PRODUCT.md)) |
| Trusted issuer | A configured source of workload tokens accepted as L2 attestation (ADR-0018) |
