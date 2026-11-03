# PantherClaw — Free Stack Now, Upgrades Later

Everything in the MVP runs at **$0 recurring cost** on the founder's machine plus free tiers. Each upgrade below lists the trigger, the exact change, and the expected cost. Ports/adapters were designed so upgrades are configuration or adapter swaps, not rewrites.

| Area | Free now | Upgrade | Trigger | Exact change | Est. cost |
|---|---|---|---|---|---|
| Demo hosting | Local Docker Compose + authenticated Cloudflare Tunnel (Access ≤ 50 users) | Oracle Cloud Always Free ARM VM (4 vCPU/24 GB) | Need 24/7 demo or design partner pilot | Add `deploy/oracle/` cloud-init; G3 environment `staging` | $0 (card verification) |
| Production hosting | — | Managed containers (Cloud Run/ECS/Fly) or Kubernetes (Helm chart) | First paying customer | Helm values / IaC; no code change | $50–500/mo |
| Database | Postgres 17 container, named volume | Managed Postgres with HA + PITR (RDS, Cloud SQL, Crunchy, Neon) | Pilot customers | DSN + role bootstrap migration; RLS unchanged | $30–400/mo |
| Key management | File KEK (`0600`, dev only) | OpenBao Transit (self-hosted) → cloud KMS/HSM | Any non-local deployment (OpenBao) / enterprise (KMS) | New `KeyProvider` adapter selected in config; DEK re-wrap job | $0 → $1–5/key/mo |
| Blob storage (evidence packs, restricted payloads) | Postgres `bytea` / filesystem | S3 / R2 / GCS | Packs > 100 MB or retention scale | `BlobStore` adapter config | cents/GB |
| Human identity (dev) | Keycloak 26.7 in compose (`--profile identity`); mock-oauth2-server 6.0 in CI | Customer IdP (Okta, Entra ID, Google Workspace) | Every customer | Today: `auth.oidc_providers` in the server config (per deployment); later: per-org provider records for multi-org SaaS | $0 |
| CLI credential storage | `credentials.json` (0600) in the user profile, device key in the same file (ADR-0016, R-14) | OS keychain (Windows Credential Manager, macOS Keychain, Secret Service) or TPM-bound device key | Enterprise rollouts or security questionnaires | `pclaw` credential-store adapter; needs a new dependency row | $0 |
| API key network limits | Scopes and expiry only | Per-key IP allowlists (SB-2 option) | A customer asks for them | Trusted-proxy configuration first, then an `allowed_cidrs` column | $0 |
| Enterprise identity | — | SCIM 2.0 provisioning, SAML bridge | Enterprise deals | Clean package in a private repository; tables and ports in public core | — |
| Email | Log mailer / SMTP | Resend / SES / Postmark | Real notifications | `Mailer` adapter config | $0–20/mo |
| Telemetry | `grafana/otel-lgtm` container | Grafana Cloud free tier → paid / Datadog | Hosted environments | OTLP endpoint config | $0 → usage |
| Replay & rate-limit store | Postgres (partitioned `dpop_jti`) | Valkey | > ~5k rps per org | Adapter swap | $15+/mo |
| Event fan-out | River + LISTEN/NOTIFY | NATS JetStream | Many gateways / high fan-out | Adapter for revocation stream | $0 self-hosted |
| Search | Postgres FTS + trigram | OpenSearch | Large evidence volumes | Search facade adapter | $$ |
| Workflows | River + Postgres state machines | River Pro or Temporal | Complex branching automations at scale | ADR + executor adapter | $$ |
| CI | GitHub Actions (public repo: unlimited standard runners, free ARM runners) | Larger runners / self-hosted runners | Build times > 15 min | `runs-on` labels | usage |
| Code scanning | gosec, Opengrep/Semgrep CE, govulncheck, OSV, dependency-review | Semgrep Pro; GitHub Advanced Security (CodeQL) | Enterprise security questionnaires | Workflow addition + licence | $$ |
| AI code review | Claude (founder subscription) + CodeRabbit (free for public repos) | Paid tiers / additional reviewer vendor | PR volume | App/plan upgrade | $15–30/mo/seat |
| Repository home | Personal account `katocxl/pantherclaw` | GitHub organization (merge queue, teams, `@pantherclaw` namespace) | Second contributor | Transfer repo; **Go module path changes** (`github.com/<org>/pantherclaw`) — do before v1.0 | $0 |
| Domain | GitHub Pages / Releases | `pantherclaw.dev` (or similar) | Public launch | DNS + docs config; install URLs | ~$10–15/yr |
| Trademark | Common-law ™ | Registered trademark (per class/jurisdiction) | Before marketing spend | Filing | ~$350/class (US) |
| Company | Individual licensor | LLC/C-corp; copyright assignment from founder (CLA allows) | First contract / funding | Update LICENSE licensor, NOTICE | $100–500 + fees |
| Legal review | Templates (BSL grant, CLA, ToS) | Lawyer review | Before first commercial licence | Document updates | $$ |
| Security assurance | Self-review, AI reviewers, red-team range | External penetration test; SOC 2 Type I/II | Enterprise sales | Engagement | $$$ |
| Billing | Entitlements + metering only | Stripe Billing / Paddle | First invoice | Billing adapter in private repo | % of revenue |
| Signing | Sigstore keyless + GitHub attestations | Additional KMS-backed release keys | Enterprise/FIPS requirements | Release workflow step | $1/key/mo |
| FIPS | `GOFIPS140=certified` build | Validated deployment guidance, FIPS-only images | Government customers | Build matrix entry | — |
