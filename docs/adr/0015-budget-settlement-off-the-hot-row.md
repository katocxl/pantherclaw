# ADR-0015 — Keep budget settlement off the hot row

**Status:** Accepted, parts 1 and 2 (founder, 2026-10-10); part 3 stays deferred. Proposed 2026-10-08 from the M1.5 measurements. See [as implemented](#as-implemented) below.

**Context.** The M1.5 walking skeleton reserves and settles budgets on one row per budget (ARCHITECTURE §6.3). A conditional `UPDATE` locks that row until `COMMIT`, and `COMMIT` waits for the WAL flush. Every refund therefore puts **two** flushes behind the same row lock: the reservation in `Authorize` and the commit or release in `RecordExecution`. One budget's throughput is bounded by about `1 / (2 × flush latency)` whatever the CPU count. On the development laptop, where Docker Desktop's virtual disk flushes take about 0.9 ms (`pg_test_fsync`), that is 350–500 refunds per second at best. Flush-latency spikes then made calls queue past the gateway's 2 s timeout and collapse into `503`s at loads as low as 100 rps (`docs/perf/M1.5.md`).

The safety argument for moving work off the row is that settlement never makes the budget look *less* consumed:
- A commit moves an amount from `reserved` to `spent`, so `spent + reserved` is unchanged.
- A release lowers `reserved`.

Delaying either can only make the budget look **more** consumed than it is, which fails safe (no overspend). Only the reservation must be synchronous.

**Decision.**
1. **Asynchronous settlement.**
   - `RecordExecution` writes the outcome, the budget-ledger entry and a pending settlement row, and does not touch the budget row.
   - A River job settles pending rows per budget with one aggregated `UPDATE` (as the sweeper now does) and deletes them in the same transaction.
   - Hot-row flushes drop from two per refund to one, plus one per settlement batch.
   - Read paths that show "spent" use the budget row plus pending settlements.
2. **Fail fast on the hot row.** The finalization transaction sets `SET LOCAL lock_timeout` to about 100 ms. A budget lock that cannot be taken quickly yields `CANNOT_AUTHORIZE` (fail closed) instead of queueing towards the caller's timeout. This turns overload into fast, safe refusals rather than a cascade.
3. **Escrow slots, only when measured necessary.** A budget that must exceed one row's flush-bound rate is split into N slot rows that each hold a share of the limit. A reservation takes a random slot with headroom, and a rebalance job moves headroom between slots. This adds complexity, so it waits until a real workload needs it.

**Consequences.**
- One budget's peak rate roughly doubles with (1).
- (2) bounds Authorize latency under contention and removes the timeout cascade, at the cost of refusals during spikes.
- Settlement lag (seconds) appears in budget views.
- (3) is deferred.
- Hardware matters: NVMe flushes of about 0.1 ms move the single-row bound to about 5,000 refunds per second before any of this.

**Alternatives considered.**
- `synchronous_commit = off`: rejected. A crash could lose a committed reservation after its permit was dispatched, which means overspend.
- Advisory locks or an in-memory counter in front of the row: rejected. They are not crash-safe and not shared across replicas.
- Removing `FOR SHARE` on the containment row: it is not the bottleneck (the samples show no waits on it). `BeginDispatch` re-checks the epoch anyway.

## As implemented

Accepted on 2026-10-10 for parts 1 and 2, on the M4 decision pipeline (its budget accounts and counters, which replaced the M1.5 budget row). Migration `00070_budget_settlement`, numbered after M7's range (founder, 2026-10-10). It reached `main` after M7's `00060`–`00066`, and M7 migrations still to come take `00071` and later. Its guard refuses to replace the lister if the lister has purposes it does not carry.

**Part 1, asynchronous settlement.**
- **The pending settlement is the reservation itself.** `RecordExecution` (accepted, delegated or failed) and the sweep (an expired permit) record each held reservation `COMMITTED` or `RELEASED` and **`pending`**, in one statement per permit. They never update an account or counter row. An `UNKNOWN` outcome still keeps its reservations `HELD` (HR-003).
  - This replaces the separate pending-settlement table the proposal described.
  - Each row's state is the account or counter row plus its pending reservations.
- **Applying them.** The sweep job (`authority.sweep_org`) applies pending reservations in batches of up to 1,000. Each batch runs in its own transaction:
  - lock the batch `FOR UPDATE SKIP LOCKED` and clear `pending`;
  - update each account or counter row once, in the fixed (rank, id) order (HR-048), last.
  - So a batch is applied exactly once, and two settlements never apply the same reservation.
- **Finding the orgs.** The sweep dispatcher finds orgs with pending reservations through a new purpose of the audited lister, `budget_settle` (HR-053, HR-054), besides `permits_sweep`. It runs every second, so the lag is about a second.
- **Decisions use the row alone.** The pipeline's usage check and `Finalize`'s conditional update see the row alone. This is conservative and both agree: a pending commit leaves `spent + reserved` unchanged, and a pending release frees its amount only once applied.
- **Views add the pending ones.** The decision receipt's budget state and the grants budget view (`GetBudgetState`) show `reserved` minus pending, and `spent` plus pending commits. Their `available` can therefore be ahead of the row by a release not yet applied, for about a second.

**Part 2, fail fast on the hot row.**
- **The timeout is set just before the reservation.** `Finalize` sets `lock_timeout` to `authority.budget_lock_timeout` (default 100 ms, allowed 10 ms to 1 s) right before its conditional updates, so it bounds only the wait for budget and counter rows. Other waits (the dedupe claim, which serializes identical actions, HR-007) keep the pool's timeout.
- **A timeout is a decision.** It rolls the finalization back, and the Authority records `CANNOT_AUTHORIZE` with reason **`BUDGET_BUSY`**: no permit, no reservation, and an `OPEN` transaction the agent may resubmit.
- **The HR-048 exit race is unchanged.** `TestHR048_NoOverspendUnder1000ConcurrentAuthorizations` runs without the timeout and still requires exactly 500 permits. `TestHR048_NoOverspendWithFailFastLocksAndAsyncSettlement` runs the same race with a 50 ms timeout and concurrent settlement. There, busy refusals may leave budget unused, but nothing is overspent and every answer is a decision.

Measurements: [docs/perf/M4.md](../perf/M4.md#2026-10-10-budget-settlement-off-the-hot-row-adr-0015).
