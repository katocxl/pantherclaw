# ADR-0040 — High-availability semantics: shared limits, stated staleness, fail-closed failover

**Status:** Accepted (2026-10-29). Founder decisions G10 (shared state in Postgres only) and G11 (no monitor fast path, no offline read continuation) were answered with the recommended option. The [G0 M19 brief](../g0/M19.md) records them with the coordinator's design decisions D201, D202, D204, D207, D208, D211, D213–D218, D220 and D221. Builds on [ADR-0002](0002-control-plane-and-gateway-split.md) (the gateway has no database), [ADR-0015](0015-budget-settlement-off-the-hot-row.md) (settlement off the hot row) and [ADR-0036](0036-server-backed-mcp-state-discovery-and-reviewed-surface.md) (server-backed MCP state).

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
   - **The timeline rule** (HR-496; D207, D213). A promotion shows up as a new primary timeline.
     - **Record.** The acknowledged timeline and its `sync_verified` flag are kept in the single-row operator table `pc.db_primary_timeline`.
     - **When sync counts.** Replication counts as synchronous only when the configuration declares it AND the primary verifies `synchronous_commit = remote_apply` with a non-empty `synchronous_standby_names`. Otherwise it counts as asynchronous, with a warning.
     - **At start-up.** The server compares the primary's timeline with the acknowledged one. A moved timeline counts as sync only if the old acknowledged row has `sync_verified = true` AND the new primary verifies; otherwise the server starts in the maintenance hold (HR-379). On the first start, with no row yet, it records the timeline and does not hold.
     - **At run time.** Every new connection reads its timeline (`pg_walfile_name(pg_current_wal_lsn())`) in the pool's after-connect hook.
       - A connection on a different timeline is accepted only when the acknowledged row has `sync_verified = true`, never on this process's own start-up result alone, AND the new primary verifies sync on that connection; the new timeline is then recorded. A process in the hold carries no sync.
       - Otherwise the process gets `ErrTimelineChanged`: it refuses every connection, makes no decision, and fails readiness and liveness, so the orchestrator restarts it into the start-up hold. Pooled connections serve nothing after that: a pool hook refuses them, idle ones are closed, and beginning a transaction refuses.
     - **Leaving the hold.** `bump-epochs` (HR-373) records the new timeline. This is the same path as after a restore (T-171).
5. **Workers scale out** (HR-498). Every River job is audited, and those not safe with two workers are fixed. The chart then defaults to two workers with a PodDisruptionBudget.
6. **Gateway replicas share A2A ownership** on M15's `pc.gateway_mcp_state` (kinds `A2A_TASK`, `A2A_CONTEXT`), with its binding and caps (HR-411, HR-412).
   - Both kinds use the TASK caps and the 1-hour lifetime.
   - An `A2A_TASK` body is the sealed context id; an `A2A_CONTEXT` entry has none.
   - A new task's entry is reserved under a per-request id before the call goes to the target, so a cap refusal comes before the target creates anything. The cap is keyed by the calling principal. A message that names an existing task reserves nothing.
   - Per-replica circuit breakers and A2A client and drift state stay local and documented.
7. **Decision speed** (D208).
   - Decision snapshots stay `REPEATABLE READ, READ ONLY`, and no write moves into them (HR-504). Merging Prepare into the snapshot would open every evaluation read-write to save one round trip per budget period, so it is not done.
   - A busy budget row keeps the 100 ms lock timeout. The Authority retries once, after a jittered 5–25 ms, from a fresh snapshot through Finalize, then answers `BUDGET_BUSY` (HR-505). The retry never reuses the first evaluation, and the proof is consumed once.
   - Finalize + BeginDispatch is not merged: it would move the HR-001 timing set by ADR-0002 and needs its own decision.
   - The snapshot is never run inside Finalize, which would hold the hot row during evaluation (ADR-0015).

**Cache staleness** (the HR-493 reference; "decision path" means a value that can change an Authorize, BeginDispatch or gateway serving answer).

| Cache | Where | Decision path | Bound | Invalidation |
|---|---|---|---|---|
| Gateway certificate checks (`authCache`) | `internal/gateways/app/enroll.go` | yes | 1 s | forgotten locally on revoke or disable, and on every replica through `LISTEN pc_containment` (HR-492); a per-org generation drops a result read before the forget |
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
- With an asynchronous standby, the last committed writes can be lost (R-67). The maintenance hold and epoch bump stop old authority from acting again, at the cost of operator work after a promotion. Because the timeline is checked on every new connection, a promotion behind a stable endpoint is caught too, not only at restart. A declared but unverified synchronous setup is treated as asynchronous.
- Two workers need every job to stay safe under concurrency (HR-498). New jobs inherit this requirement.
- The failover test runs locally with two Postgres containers, under the build tag `integration && failover`. It is not a CI gate, and its result is recorded in the exit pull request.

**Alternatives.**
- Valkey or another shared store: rejected by G10, as a new dependency and operational burden at $0.
- Dividing each limit by a live replica count: approximate, and wrong during scale events.
- Counting every API call in the database: the latency R-58 avoided.
- Serving reads from a standby during failover: G11 keeps decisions on the primary only.
- Requiring synchronous replication: recommended, not required, because single-host deployments stay supported.
- Merging Finalize with BeginDispatch: a follow-up founder decision.
- Merging Prepare into the decision snapshot: rejected (D208), because it gives up the read-only snapshot on every decision. Pre-creating period rows outside the decision path is the follow-up if the measurement shows the first-of-period cost matters.
- Trusting the configuration's replication mode without checking the primary, or checking the timeline only at start-up: rejected (D207, D213), because a misconfigured standby or a promotion while running would go unnoticed.
