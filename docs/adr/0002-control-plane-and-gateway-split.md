# ADR-0002 — Modular-monolith control plane + separate gateway PEP

**Status:** Accepted (2026-10-08)

**Context.** Authorization decisions need authoritative state (grants, budgets, approvals, containment). Enforcement must run close to agents and, for hybrid customers, inside their network with their credentials.

**Decision.** `pantherclaw-server` is a modular monolith (roles `api`, `worker`, `all`) containing the Transaction Authority. `pantherclaw-gateway` is a separate binary and trust boundary: it has **no database access**, talks to the server only via mTLS Connect RPC, holds sealed target credentials, and enforces decisions. The Authority never trusts gateway assertions (re-verifies identity; derives org from the gateway certificate).

**Consequences.** One extra network hop on the transactional path (SLO: Authorize p99 ≤ 25 ms); hybrid deployments keep credentials in the customer network; gateway compromise is contained to its routes (the gateway is in the TCB for those routes — documented residual risk R-01).

**Alternatives.** Decision engine inside the gateway with replicated state (complex consistency for budgets/approvals); microservices per domain (operational cost without benefit at MVP scale).

**Note (M14, 2026-10-17; [G0 M14](../g0/M14.md) D58).** "No database access" means PantherClaw's own database. A customer database reached through a `postgres` connection is a target, like an HTTP API. Only the package `internal/gateway/pgtarget` (the pgx pool, dial and read-only transaction runner) may import `github.com/jackc/pgx/v5` (with `pgxpool` and `pgconn`); everything else under `internal/gateway/**` keeps the ban, and `pgtarget` itself may not import `database/sql`, `internal/platform/db` or `internal/gen/**`. The `.golangci.yml` rule `gateway-has-no-database` carries this one exception, and a separate rule keeps `pgtarget` away from PantherClaw's own database code.
