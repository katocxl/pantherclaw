# ADR-0040 — High-availability semantics: shared limits, stated staleness, fail-closed failover

**Status:** Accepted (2026-10-29). Founder decisions G10 (shared state in Postgres only) and G11 (no monitor fast path, no offline read continuation) were answered with the recommended option. The [G0 M19 brief](../g0/M19.md) records them with the coordinator's design decisions D201, D202 and D204. Builds on [ADR-0002](0002-control-plane-and-gateway-split.md) (the gateway has no database), [ADR-0015](0015-budget-settlement-off-the-hot-row.md) (settlement off the hot row) and [ADR-0036](0036-server-backed-mcp-state-discovery-and-reviewed-surface.md) (server-backed MCP state).

**Context.** PantherClaw can run several API replicas, but several parts are still per replica or single:
- The authenticated API's limits per organization and per credential are counted in memory per replica, so N replicas admit N times the limit (R-58).
- Operations streams, containment streams per certificate and wait handles per instance are capped per process.
- The gateway certificate cache forgets a revoked certificate only on the replica that revoked it.
- A2A task ownership lives in each gateway replica's memory.
- The server connects to one database host.
- The worker runs as one replica.
- Some caches on the decision path have no written staleness bound.

High availability (PN-010.7) must not weaken any decision-path guarantee: no decision without the Authority's database, revocation within the 2 s fail-closed bound (HR-010), and the decision and reservation order (HR-001, HR-048).

**Decision.**
1. **Shared state lives in Postgres only** (G10). No new store (no Valkey, no in-memory consensus).
2. **Limits hold across replicas** (HR-490..494).
   - The API limits are spent from leased chunks of `pc.rate_counters`: k = max(1, limit/16) per lease, a chunk expiring at its window's end. Across N replicas a window admits at most limit + (N−1)·k, at one write per k calls.
   - A store error refuses authenticated calls except the safety and allow classes. HR-376 is unchanged.
   - Stream and wait caps hold through `pc.stream_leases`: inserted on open and counted in the same transaction, heartbeated every 10 s, expiring after 30 s.
   - Per-IP pre-authentication limiters stay per replica (R-66); counting floods in the database would amplify them.
   - Tenant-keyed limits (signal transmitters, evidence replays) move to the shared store.
3. **Every decision-path cache has a stated staleness bound** (HR-493): ≤ 2 s, or invalidated through LISTEN. The table below is the reference, and each row has a test.
4. **Failover is fail closed** (HR-495..497; G11).
   - The server connects with several hosts and `target_session_attrs=read-write`, verifying TLS for each host. A stable endpoint is the documented alternative.
   - While no read-write primary answers, Authorize and BeginDispatch answer CANNOT_AUTHORIZE, other calls 503, and `/readyz` is false.
   - LISTEN reconnects and re-polls. Nothing is served from a standby or from a cache as a decision.
   - Production HA recommends `synchronous_commit=remote_apply` with one synchronous standby.
   - After an asynchronous promotion, the server starts in the maintenance hold (HR-379) and leaves it only with an epoch bump (HR-373, HR-496), as after a restore (T-171).
5. **Workers scale out** (HR-498). Every River job is audited, and those not safe with two workers are fixed. The chart then defaults to two workers with a PodDisruptionBudget.
6. **Gateway replicas share A2A ownership** on M15's `pc.gateway_mcp_state` (kinds `A2A_TASK`, `A2A_CONTEXT`), with its binding and caps (HR-411, HR-412). Per-replica circuit breakers and A2A client and drift state stay local and documented.
7. **Decision speed.**
   - Only Prepare is merged into the snapshot transaction, for the first refund of a period (HR-504).
   - A busy budget row keeps the 100 ms lock timeout and `BUDGET_BUSY`, with at most one jittered gateway retry (HR-505).
   - Finalize + BeginDispatch is not merged: it would move the HR-001 timing set by ADR-0002 and needs its own decision.
   - The snapshot is never run inside Finalize, which would hold the hot row during evaluation (ADR-0015).

**Cache staleness** (the HR-493 reference; "decision path" means a value that can change an Authorize, BeginDispatch or gateway serving answer).

| Cache | Where | Decision path | Bound | Invalidation |
|---|---|---|---|---|
| Gateway certificate checks (`authCache`) | `internal/gateways/app/enroll.go` | yes | 1 s | forgotten locally on revoke or disable, and on every replica through `LISTEN pc_containment` (HR-492) |
| Containment view per org (server hub) | `internal/gateways/app/watch.go` | yes | 250 ms poll | woken at once by `LISTEN pc_containment` |
| Gateway containment view | `internal/gateway/control/containment.go` | yes | 2 s (`MaxStaleness`); stale → fail closed | the WatchContainment stream and its heartbeats |
| Wait handles | `internal/approvals/app/wait.go` | yes (approval outcome) | the long-poll period; state is read from the database | woken by `LISTEN pc_wait` |
| Permit verification keys (JWKS) | `internal/gateway/dispatch/permits.go` | yes | an unknown key id triggers a refetch, at most once a second | refetch on an unknown kid |
| Approver keys (`Pinned`) | `internal/approvals/proof/keys.go` | yes | re-read whenever the file's size or modification time changes; fail closed while it does not load | file change |
| Compiled policy conditions | `internal/policy/app/engine.go` | yes | none needed: keyed by policy bundle and definition digest (content-addressed) | a new digest is a new entry |
| Current data-encryption key | `internal/keystore/current.go` | no (sealing only; older keys stay readable) | its TTL | rotation takes effect within the TTL |
| Gateway listener certificate | `internal/server/wiring_m6.go` | no | reissued after 24 h, valid 7 days | — |
| MCP holds, tasks, sessions | server, `pc.gateway_mcp_state` | yes | none: read from the server per call (ADR-0036) | — |
| A2A clients, drift, failure counters | `internal/gateway/dispatch/a2a*.go` | serving health only | per replica | documented, not shared |
| Circuit breakers | `internal/gateway/dispatch/breaker.go` | serving health only | per replica | documented, not shared |

S19a's tests confirm each bound and record any correction in this table at the exit.

**Consequences.**
- Rate limits and caps are true across replicas, and R-58 closes. A lease costs one database write per k calls, so a window can admit up to (N−1)·k beyond the limit.
- Revocation reaches every replica within the existing bounds. No cache on the decision path is unbounded.
- A database failover is an outage of decisions, not a loss of safety. Its length is the promotion time plus reconnection.
- With an asynchronous standby, the last committed writes can be lost (R-67). The maintenance hold and epoch bump stop old authority from acting again, at the cost of operator work after a promotion.
- Two workers need every job to stay safe under concurrency (HR-498). New jobs inherit this requirement.
- The failover test runs locally with two Postgres containers. It is not a CI gate, and its result is recorded in the exit pull request.

**Alternatives.**
- Valkey or another shared store: rejected by G10, as a new dependency and operational burden at $0.
- Dividing each limit by a live replica count: approximate, and wrong during scale events.
- Counting every API call in the database: the latency R-58 avoided.
- Serving reads from a standby during failover: G11 keeps decisions on the primary only.
- Requiring synchronous replication: recommended, not required, because single-host deployments stay supported.
- Merging Finalize with BeginDispatch: a follow-up founder decision.
