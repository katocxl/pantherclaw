# Range scenarios

One YAML file per attack, `RT-###-<slug>.yaml`. The format is fixed by HR-223 (see `docs/g0/M12.md`); the engine in `internal/redteam` parses and runs them, and a driver supplies the targets. Scenarios are data: they name connection roles, never a URL or host.

## What a driver provides

**Connection roles** bound to simulated connections: `github`, `payments`, `mcp`; `unlisted` (a payments connection to an address the gateway's egress guard does not allow, RT-031); `real` (a connection that is not simulated, RT-022).

**Fixtures** (`${fixture.<name>}`), created per scenario on fresh simulators:

| name | value |
|---|---|
| `owner`, `repo`, `pr` | the repository the grant covers; pull request `fixture.pr` is open on it (branch `fix/cve`) |
| `other_repo` | a repository the grant does not name |
| `head`, `main` | head commit of pull request #1; head of `main` |
| `file_b64` | base64 of a small source file |
| `fake_github_token` | a GitHub-format token that nothing issued |
| `fake_github_token_file_b64` | base64 of a source file that embeds `fake_github_token` |
| `custody_secret` | a secret the gateway holds in custody |

Values saved with `save:` are substituted as `${name}`.

**Grants and policy per scenario.** GitHub: merges need an independent code review and, as `main` deploys to production, a release approval (`MERGES_NEED_AN_INDEPENDENT_REVIEW`, `DEPLOYMENTS_NEED_A_RELEASE`); a production change window is open; one merge per task. Payments: refunds up to 100.00 USD are allowed, and the grant holds refunds over 50.00 for an approver with the reason `REFUNDS_NEED_APPROVAL`. RT-026 runs under a 100.00 USD task budget; RT-027 under a limit of two refunds per charge per day. RT-036 runs with the target enforcing action tokens.

**Step semantics the catalogue leaves to the driver:**

- `agent.call` with `action_of` is sent under that step's action id (where the agent chooses it).
- `concurrent: N` sends N calls at once, `${n}` is 1..N; `max_allow` bounds how many may be ALLOW.
- Object ids come from fixtures or `save`; the driver types a numeric string (`pullNumber`) as an integer for MCP tools.
- `person.approve` approves with every role the hold needs (`as: approver`); `launcher` and `developer` are the persons who must be refused.
- `server.read` with `org: other` reads an id of that kind that exists in the second organisation.
- `agent.steal` mode `stale_nonce` signs the call's proof with a nonce older than the server accepts.
- `sim.mutate` `fault` args: `redirect_to`, `lose_response_rate`.
- `target.replay`: the first delivery of an action token's request is accepted, a later one is refused.
- Steps with no action to judge (`sim.mutate`, `operator.*`, a successful `person.*`) carry no `expect`.
