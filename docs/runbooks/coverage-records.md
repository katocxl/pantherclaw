# Runbook — Coverage records

**Milestone:** M9 (track A) · **Owner:** the org's Security Admin (exclusions, findings, reassessment); the platform operator (the freshness contract) · **Status:** tested procedure (the M9 coverage integration tests and the rapid properties of the state calculus).

A coverage record answers one question for one **agent × connection × operation**: can this agent produce the operation's effect through another usable route without PantherClaw's authorization? Background: [g0/M9.md](../g0/M9.md), HR-210, HR-211, HR-212, HR-217, HR-024, HR-086, F433–F460, F021, F048.

## States

| State | When |
|---|---|
| `UNKNOWN` | No route of the scope is known (observed or declared), or the scope was never assessed. A connection setting alone never yields a state. |
| `OBSERVE_ONLY` | Routes are known, but none is a gateway channel in enforce mode on an active connection: nothing is prevented. |
| `PARTIAL` | A gateway channel is in enforce mode, but something short of `ENFORCED` remains: no current closure, an equivalent route not proven closed, agent-held access, an instance outside the sandbox, or lapsed evidence. Cooperative SDK or hook channels stay here unless a target-verifier test of the scope's own operation, no older than the `ENFORCED` lifetime, shows the target refusing calls without an action token (HR-024, HR-210). In M9 that test lifts only the read it tested: write operations stay here whatever the test (`write_not_liftable_m9`). Routes through a remote MCP server stay here, and so do connector containers without mediated egress (HR-086). |
| `ENFORCED` | Every channel is mediated in enforce mode on PantherClaw-held access, or on target-enforced access verified for this read. A passed sandbox closure for this agent and connection proves every containment route closed (direct API, host, Git/SSH, credentials, browser, delegated, intermediaries); an exclusion never stands in for that. Every active instance of the agent runs in that closure's sandbox session. The closure must still be bound to the connection's revision, gateway, package version and credential, with no invalidating change since its session started. `ENFORCED` expires with the closure, or earlier with the target-verifier test it uses. |

Every equivalent route kind is listed in a record. A kind that no source showed is *not observed*, never *absent* (F450).

## Freshness

`pclaw coverage freshness` prints the contract:

- **Expiry.** `ENFORCED` holds for `coverage.enforced_ttl` (24 h by default, 1 h to 168 h) from its closure evidence.
- **Invalidating changes.** Any of these makes the closure evidence stale at once:
  - a connection change or a move to another gateway;
  - a route mode change;
  - a credential sealed, superseded or revoked;
  - a change to the GitHub App installation behind the connection (its permissions, account or repository selection);
  - a new package pin;
  - a gateway's state;
  - an agent instance admitted outside a sandbox;
  - a new sandbox image or configuration;
  - a failed closure.

  A new route, an exclusion or an expiry does not make the closure stale, but like every change it makes the next read recompute the scope.
- **Lapse.** A record holds while its snapshot is unexpired and no change to the scope is pending. Once it lapses, the next read recomputes the scope from current evidence and reads it at most `PARTIAL`, lower when the evidence is. It keeps the last valid `ENFORCED` snapshot and says why it lapsed (F442).
- **Reassessment.** The reassess job runs every `coverage.reassess_every` (1 min by default). It reads new traffic, records a new snapshot for every scope that changed or that a change touched, enters each change in the ledger (`coverage.invalidation`), and derives each agent's protection. A scope whose evidence cannot be read is skipped and logged; its changes stay pending.

Each snapshot is also a `coverage.snapshot` ledger entry. A decision receipt names the snapshot that was current for its scope (HR-217), and `pclaw verify` checks that claim against the snapshot ledger (`receipt.coverage` in [evidence-verification.md](evidence-verification.md)).

## Commands

| Command | Who | What |
|---|---|---|
| `pclaw coverage list [--agent ID] [--connection ID]` | `coverage.read` | the current record of every scope |
| `pclaw coverage show AGENT CONNECTION OPERATION` | `coverage.read` | one record, as JSON |
| `pclaw coverage explain AGENT CONNECTION OPERATION` | `coverage.read` | one record in words: why it has its state, each route, the last valid record, the freshness contract |
| `pclaw coverage history AGENT CONNECTION OPERATION` | `coverage.read` | the scope's snapshots, newest first |
| `pclaw coverage routes`, `pclaw coverage closure ID` | `coverage.read` | the route inventory; one closure's probes, configuration checks and what they closed |
| `pclaw coverage access CONNECTION [--agent ID]` | `coverage.read` | the access detail (§39.2–39.3): custodian, modes, scope, audience, expiry, issuance, affected agents, verification basis, the routes still open |
| `pclaw coverage reassess CONNECTION [--agent ID]` | `coverage.reassess` | recompute now |
| `pclaw coverage exclude CONNECTION --reason TEXT --expires-in-days N [--agent] [--operation] [--route KIND]` | `coverage.manage`, person | exclude a scope or a route kind |
| `pclaw coverage unexclude ID`, `pclaw coverage exclusions` | `coverage.manage`, person / `coverage.read` | end an exclusion; list them |
| `pclaw coverage findings`, `pclaw coverage acknowledge ID --reason TEXT` | `coverage.read` / `coverage.manage`, person | credential-overreach findings (F048) |

## Exclusions

An exclusion records that a person accepts a gap, so only a person holding `coverage.manage` (Security Admin) creates one. It needs a written reason (10 to 1,000 characters) and an expiry (at most 90 days). Every creation and revocation is audited (`audit.coverage.exclusion_*`), and every creation is notified (`security.coverage_excluded`, without the reason). Every record and every receipt claim lists the exclusions that applied:

- Exclusions never raise a state (design decision 1, as the founder decided). An excluded route kind reads *excluded* but still counts as open: a scope whose closure did not close it stays `PARTIAL` at most, with the kind named and the reason `excluded`.
- A scope excluded as a whole keeps its state. Any scope with an exclusion, of a route kind or of the whole scope, counts as not protected for the agent: an agent with one is `PARTIALLY_PROTECTED` at most (F021).

Review exclusions before they expire, and revoke any whose reason no longer holds.

## Credential-overreach findings

For each connection, the permissions its credentials actually hold are compared with what the package declares for the operations the org's grants allow. For GitHub, the held permissions come from the App installation behind the connection, as last read, and from every other installation the gateway's org scan found for it (a person's `pclaw scan` cannot report GitHub installations). The finding also lists what the operations executed in the last 30 days used. Reach beyond the need is an exposure finding, never extra permission:

| Severity | Excess |
|---|---|
| critical | any admin permission |
| high | write access to administration, members, secrets, workflows or environments |
| medium | other write access |
| low | read access |

The fix is to reduce the installation's permissions; the finding resolves on the next reassessment. Acknowledging a finding dismisses it. It needs a written reason, is audited, and stays dismissed until the excess changes, which makes a new finding.
