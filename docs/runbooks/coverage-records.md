# Runbook — Coverage records

**Milestone:** M9 (track A) · **Owner:** the org's Security Admin (reassessment, exclusions, findings); the platform operator (the freshness contract) · **Status:** tested procedure (the M9 coverage integration tests and the rapid properties of the state calculus).

A coverage record answers one question for one **agent × connection × operation**: can this agent produce the operation's effect through another usable route without PantherClaw's authorization? Background: [g0/M9.md](../g0/M9.md), HR-210, HR-211, HR-212, HR-217, HR-024, HR-086, F433–F460, F021, F048.

## States

| State | When |
|---|---|
| `UNKNOWN` | Nothing proves which routes are usable: no traffic was observed, the connection is retired, or the scope was never assessed. A connection setting alone never yields a state. |
| `OBSERVE_ONLY` | The traffic was observed in monitor mode, or the route is in monitor mode now: nothing is prevented. |
| `PARTIAL` | A route is mediated in enforce mode, but an equivalent route is possible, unverified or excluded. Cooperative SDK or hook channels stay here unless the target verifies action tokens (HR-024), and so do routes through an MCP server whose own egress is not mediated (HR-086). |
| `ENFORCED` | Every observed channel is mediated in enforce mode, and a passed sandbox closure for this agent and connection proves every containment route closed: direct API, host, Git/SSH, credentials, browser, delegated and intermediaries. The closure must still be bound to the connection's revision, gateway and package version, with no change since its session started. ENFORCED expires with the closure. |

Every equivalent route kind is listed in a record. A kind that no source showed is *not observed*, never *absent* (F450).

## Freshness

`pclaw coverage freshness` prints the contract:

- **Expiry.** ENFORCED holds for `coverage.enforced_ttl` (24 h by default, 1 h to 168 h) from its closure evidence.
- **Invalidating changes.** Any of these drops a record to `PARTIAL` at once, on the next read and before any reassessment:
  - a connection change or a move to another gateway;
  - a route mode change;
  - a credential sealed, superseded or revoked;
  - a new package pin;
  - a gateway's state;
  - a new sandbox image or configuration;
  - a failed closure.
- **Last valid record.** The record keeps the last valid ENFORCED snapshot and says why it lapsed (F442).
- **Reassessment.** The reassess job runs every `coverage.reassess_interval` (1 min by default). It reads new traffic and records a new snapshot for every scope that changed.

Each snapshot is also a `coverage.snapshot` ledger entry. A decision receipt names the snapshot that was current for its scope (HR-217), and `pclaw verify` checks that claim against the entry (`receipt.coverage` in [evidence-verification.md](evidence-verification.md)).

## Commands

| Command | Who | What |
|---|---|---|
| `pclaw coverage list [--agent ID] [--connection ID]` | `coverage.read` | the current record of every scope |
| `pclaw coverage show AGENT CONNECTION OPERATION` | `coverage.read` | one record, as JSON |
| `pclaw coverage explain AGENT CONNECTION OPERATION` | `coverage.read` | one record in words: why it has its state, each route, the last valid record, the freshness contract |
| `pclaw coverage routes`, `pclaw coverage closure ID` | `coverage.read` | the route inventory; one closure's probes and what they closed |
| `pclaw coverage access CONNECTION [--agent ID]` | `coverage.read` | the access modes that apply (§39.2), who holds the credential, the routes still open |
| `pclaw coverage reassess CONNECTION` | `coverage.manage`, person | recompute now |
| `pclaw coverage exclude CONNECTION --reason TEXT --expires-in-days N [--agent] [--operation] [--route KIND]` | `coverage.exclude`, person | exclude a scope or a route kind |
| `pclaw coverage unexclude ID`, `pclaw coverage exclusions` | `coverage.exclude` / `coverage.read` | end an exclusion; list them |
| `pclaw coverage findings`, `pclaw coverage dismiss ID --reason TEXT` | `coverage.read` / `coverage.manage`, person | credential-overreach findings (F048) |

## Exclusions

An exclusion weakens the claim, so only a person holding `coverage.exclude` creates one. It needs a written reason (10 to 1,000 characters) and an expiry (at most 90 days). Every creation and revocation is audited (`audit.coverage.exclusion_*`). An exclusion never raises a state:

- An excluded route reads *excluded*.
- A scope excluded as a whole stops counting toward the agent's protection, so an agent can be `PROTECTED` while that scope is not `ENFORCED` (F021).

Review exclusions before they expire, and revoke any whose reason no longer holds.

## Credential-overreach findings

For each connection, the permissions its credentials actually hold are compared with what its operations declare they need. For GitHub, the held permissions come from the App installation the org scan found. Reach beyond the need is an exposure finding, never extra permission:

| Severity | Excess |
|---|---|
| critical | any admin permission |
| high | write access to administration, members, secrets, workflows or environments |
| medium | other write access |
| low | read access |

The fix is to reduce the installation's permissions; the finding resolves on the next reassessment. A dismissal needs a written reason, is audited, and stays dismissed.
