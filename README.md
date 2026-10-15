# PantherClaw

**The agent transaction firewall.**

PantherClaw verifies which AI agent is acting and for whom, gives it only the access its current task needs, and puts its actions behind a firewall that proves, route by route, where it cannot be bypassed, with evidence your auditors can check. It answers one question for every consequential action: can this agent run do this, for this task, through this route, right now, and can we prove the boundary held?

> **Status: pre-alpha.** Under active development; not ready for production use. Everything below is planned.

## What's inside

| Component | Tagline | What it does |
|---|---|---|
| **Badge** | Know every agent | Finds every agent, gives it an owner, and verifies which workload is acting and for whom, using the identities you already have (your IdP, GitHub Actions, Kubernetes) |
| **Pass** | Grant temporary access | Just enough access for one task, for a limited time, with exact human approvals |
| **Guardrails** | Set the boundaries | Org rules, budgets and sequence limits that hold across parallel agents and sub-agents |
| **Checkpoint** | Control every action | An agent firewall: a gateway for MCP and API calls plus a containment sandbox, with per-route evidence of which routes cannot be bypassed |
| **Stash** | Keep credentials safe | Credentials PantherClaw holds never reach the agent and are used only for authorized actions; keys an agent still holds are reported as gaps |
| **Reflex** | Stop threats instantly | Spot misuse, see the blast radius, and stop a run, an agent or the whole org; the target is containment reaching every gateway in under 1 second at p99 |
| **Trail** | Prove what happened | Signed decision, execution and effect receipts you can verify offline, plus a red-team range for your own policies |
| **Root** | Manage it all | The platform: self-hosted or hybrid deployment, administration, automations and licensing |

Details: [docs/PRODUCT.md](docs/PRODUCT.md).

## Integrations

Planned (not yet released), coding agents first: Claude Code and the Claude Agent SDK, MCP clients, GitHub, and Go, Python and TypeScript SDKs. See the milestones in [docs/BUILD_GUIDE.md](docs/BUILD_GUIDE.md).

## Try it

On one machine, with nothing real connected: `task demo:up` starts a local server, gateway and GitHub simulator, and [docs/quickstart.md](docs/quickstart.md) walks through the first 30 minutes of a coding agent behind PantherClaw (one action allowed, one held for approval, one blocked). Needs Go, Docker and Git Bash on Windows. The time it takes is measured in [docs/perf/onboarding.md](docs/perf/onboarding.md).

## Development

```bash
task setup    # git hooks + pinned tools
task check    # format, headers, lint, tests, workflow lint, secret scan
```

You need Go and Docker. Task is optional: every tool, Task included, is pinned under `tools/pins/`, so without a global Task run `go tool -modfile=tools/pins/task/go.mod task <name>`. See [CONTRIBUTING.md](CONTRIBUTING.md).

> **No CI.** Continuous integration is switched off during development ([EX-004](docs/security/GATES_AND_REVIEW.md#4-exceptions)). Every change arrives as a pull request that the founder merges, and is checked locally (`task check`, plus `task test:integration` and `task trace` where they apply) before the pull request is opened; see [CLAUDE.md](CLAUDE.md).

## Security

Report vulnerabilities privately: [Security advisories](https://github.com/katocxl/pantherclaw/security/advisories/new). See [SECURITY.md](SECURITY.md).

## License

- Core (server, gateway, CLI, simulators): **Business Source License 1.1** — free for development, testing and evaluation, and for production use governing up to **5 agents in one organization**; not for hosted/competing offerings. Each version converts to Apache-2.0 four years after release. See [LICENSE](LICENSE) and [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md).
- SDKs, protocol specification and Claude Code integration: **Apache-2.0** (see [NOTICE](NOTICE)).
- PantherClaw™ is a trademark of Joshua Kato — see [TRADEMARKS.md](TRADEMARKS.md).
