# Range scenarios

One YAML file per attack, `RT-###-<slug>.yaml`. The format is fixed by HR-223 (see `docs/g0/M12.md`); the engine in `internal/redteam` parses and runs them, and a driver supplies the targets. Scenarios are data: they name connection roles, never a URL or host.

## What a driver provides

**Connection roles** bound to simulated connections: `github`, `payments`, `mcp`; `jira` and `gitlab` (G0 M20, capabilities `jira.comment`, `gitlab.merge` and `gitlab.deploy`); `aws-ecs` (capability `aws.ecs.deploy`, harness only); `unlisted` (a payments connection to an address the gateway's egress guard does not allow, RT-031); `real` (a connection that is not simulated, RT-022).

**Fixtures** (`${fixture.<name>}`). The operator supplies read-only context about the simulators; the driver generates the rest for every range run (D38, D39). A scenario creates every object it acts on (branch, file, pull request, charge ids), because a transaction backs the steps of one scenario per range.

| name | value |
|---|---|
| `owner`, `repo` | the repository the range grant covers (operator) |
| `other_repo` | a repository the grant does not name (operator) |
| `main` | head commit of `main` when the range starts (operator) |
| `file_b64` | base64 of a small source file (operator) |
| `nonce` | 12 hex characters, fresh for every range run; object names are `rt-NNN-${fixture.nonce}` |
| `planted_github_token`, `planted_github_token_file_b64` | a GitHub-format token nothing issued, and base64 of a source file that embeds it |
| `planted_private_key`, `planted_private_key_file_b64` | a fresh throwaway private key (PEM), and base64 of a file that holds it |
| `jira_internal_issue`, `jira_customer_issue` | with `jira.comment`: an issue in an internal project and a ticket in a service desk (customer-visible) project |
| `gitlab_project`, `gitlab_merge_request`, `gitlab_head`, `gitlab_unverified_merge_request`, `gitlab_unverified_head` | with `gitlab.merge`: the project (with one environment), a merge request whose pipeline passed at its head, and one whose pipeline is still running, both approved; `gitlab.deploy` also makes a release approver decide deployments |
| `aws_account`, `aws_other_account`, `aws_cluster`, `aws_service`, `aws_classic_service`, `aws_codedeploy_service`, `aws_task_definition` | with `aws.ecs.deploy`: the role's account, an account that isn't, the cluster, a service with rollout states, one with none, one under another deployment controller, and a revision to deploy |

Charges a scenario refunds are `ch_${fixture.nonce}rtNNN`, with a letter (`b`…) or `n${n}` after them for more than one; the driver reports them refundable.

Values saved with `save:` (for example `pr` and `head` from the pull request a scenario opens) are substituted as `${name}`.

**Grants and policy per scenario.** GitHub: merges need an independent code review and, as `main` deploys to production, a release approval (`MERGES_NEED_AN_INDEPENDENT_REVIEW`, `DEPLOYMENTS_NEED_A_RELEASE`); a production change window is open; one merge per task. Payments: refunds up to 100.00 USD are allowed, and the grant holds refunds over 50.00 for an approver. RT-026 runs under a 100.00 USD task budget; RT-027 under a limit of two refunds per charge per day. RT-036 runs with the target enforcing action tokens.

**Step semantics the catalog leaves to the driver:**

- `agent.call` with `action_of` is sent under that step's action id (where the agent chooses it).
- `concurrent: N` sends N calls at once, `${n}` is 1..N; `max_allow` bounds how many may be ALLOW.
- Object ids come from `save` or generated fixtures, never literals; the driver types a numeric string (`pullNumber`) as an integer for MCP tools.
- `person.approve` approves with every role the hold needs (`as: approver`); `launcher` and `developer` are the persons who must be refused.
- `server.read` with `org: other` reads an id of that kind that exists in the second organisation.
- `agent.steal` mode `stale_nonce` signs the call's proof with a nonce older than the server accepts.
- `sim.mutate` `fault` args: `redirect_to`, `lose_response_rate`.
- `target.replay`: the first delivery of an action token's request is accepted, a later one is refused.
- `wait` `for: downstream_read` passes only after the gateway has read the step's consequence: it observes `CONFIRMED` if that read confirmed it and `UNKNOWN` if not. No read in time is an error, never `UNKNOWN`. The live driver doesn't support it.
- Steps with no action to judge (`sim.mutate`, `operator.*`, a successful `person.*`) carry no `expect`.
