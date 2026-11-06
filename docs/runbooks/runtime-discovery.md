# Runbook — Discovery of agents in cloud agent runtimes

**Milestone:** M34 ([G0 M34](../g0/M34.md) D997, D997a; HR-768, HR-769). **Audience:** security teams. **Edition:** Business and above (`SaaSDiscovery()`), as [SaaS discovery](saas-discovery.md).

Agents deployed in Amazon Bedrock AgentCore, Vertex AI Agent Engine and Azure AI Foundry are found by a scan through your PantherClaw gateway, with a read-only collector credential. A scan of these sources also runs daily, on its own (founder decision FQ34-3). A person can still start a scan at any time. Found agents are listed, not controlled: they stay `external` and observe-only, as SaaS agents do.

Scans read metadata only. The AgentCore and Foundry API shapes are unconfirmed until live checks (R-85): an unexpected answer reports not scanned, never an empty result.

## What each source reads

| Source | Package | Credential kind | Tenant | Read | Finding kind |
|---|---|---|---|---|---|
| `aws_agentcore` | `pc.aws-agentcore` | `aws_sigv4` | the 12-digit AWS account; it must be the sealed role's account, and the region is the credential's | `runtimes` (ListAgentRuntimes) | `agentcore_runtime` |
| `vertex_agent_engine` | `pc.vertex-agent-engine` | `google_service_account` | `<project>/<location>`; the location must be the one the connection's regional host serves | `reasoning_engines` | `vertex_reasoning_engine` |
| `azure_foundry` | `pc.azure-foundry` | `oauth_client` (Entra, scope `https://ai.azure.com/.default`) | the Foundry project name; it must be the connection base URL's `/api/projects/<project>` | `agents` | `foundry_agent` |

A tenant that is not the connection's fails the scan before anything is read. Each finding keeps a closed set of attributes (name, id, region or location, created and updated times, status); `status` is the material attribute, so a status change is recorded as a change.

The collector connections are `http` connections of the packages above. Give each one a credential that can only list: for AgentCore, an `aws_sigv4` credential sealed with `--aws-service bedrock-agentcore` for a role whose policy allows `bedrock-agentcore:ListAgentRuntimes` (each scan's session is narrowed to that one action); for Vertex, a service account with read on reasoning engines; for Foundry, an app with read on the project's agents. `pc.aws-agentcore` has reads only in M34; the deploy operations of `pc.vertex-agent-engine` and `pc.azure-foundry` belong on separate connections that agents use, so the collector credential stays read-only.

## Start a scan and its daily schedule

```bash
pclaw discover scan --source aws_agentcore --connection <id> --tenant 123456789012
pclaw discover scan --source vertex_agent_engine --connection <id> --tenant my-project/us-central1
pclaw discover scan --source azure_foundry --connection <id> --tenant my-project
```

- Needs `agent.manage` at the org, and a person: each daily scan is started as the person who set it.
- For the three runtime sources, `--daily` defaults to true, so the scan also sets a daily schedule for that connection and tenant. `--daily=false` scans once. If the scan starts but the schedule is refused, the CLI says so.

Set or stop a schedule without scanning:

```bash
pclaw discover schedule set --source <source> --connection <id> --tenant <tenant>
pclaw discover schedule clear --source <source> --connection <id> --tenant <tenant>
```

`SaasDiscoveryService.SetSaaSScanSchedule` is the API. Only a person sets or clears a schedule (`HUMAN_ONLY` otherwise); each change is audited as `saas.scan_schedule_set` or `saas.scan_schedule_cleared`. A schedule is unique per org, source, connection and tenant. Clearing one that does not exist changes nothing.

## What the daily job does

An hourly dispatcher enqueues one job per active org (`saas.daily_scans_org`). For each schedule whose last start is 20 hours old or more, the job starts one scan with origin `schedule`, `started_by` the schedule's person, through the gateway as any scan. The audit actor is System (`saas_schedule`) with `schedule_person` in the details.

Before each start it checks again. A schedule is skipped, with a warn log `saas.schedule_skipped`, the metric `pc_saas_schedule_skipped_total` (by `reason` and `source`), and its last start unchanged, when:

| Reason | Meaning | What to do |
|---|---|---|
| `person` | The person who set it is no longer an ACTIVE member holding `agent.manage` | Another person sets the schedule again, or clears it |
| `connection` | The connection can no longer scan the source (not ACTIVE, another package or credential kind) | Fix or replace the connection |
| `running` | A scan of the connection is already running | Nothing; the next hourly run tries again |
| `edition` | The edition has no SaaS discovery | — |

A skipped schedule is tried again every hour. Watch the metric: a schedule skipped for days is reads nobody is getting (T-349).

## Stale or wider credentials (T-349)

A schedule keeps scanning with whatever the connection's credential allows, after the person who set it stops looking at it. Keep it narrow:

- Seal a read-only collector credential, and rotate it like any other connection credential. A credential the provider refuses leaves the read not scanned, never an empty result; the queue source `saas` shows it as `SAAS_NOT_SCANNED`.
- A schedule stops when its person leaves or loses `agent.manage` (`person` skips).
- Review the schedules with the audit trail (`saas.scan_schedule_set`) and the skip metric.

## The deployed-agent alert

The built-in detection `pc.runtime.agent_deployed` (LOW, atlas AML.T0103, Business) alerts when discovery records a new external agent from `aws_agentcore`, `vertex_agent_engine` or `azure_foundry`, and again when a dismissed one is found again. It is alert only: nothing is held or contained (HR-769). Someone checks whether the deploy was intended and names the agent's owner with `SetSaasAgentOwner`.

AgentCore deploys are not decided by PantherClaw in M34 (D993a, founder decision FQ34-5): this scan and alert are how they are seen. Vertex and Foundry deploys through `pc.vertex-agent-engine` and `pc.azure-foundry` are decided operations (`agent.deploy`); deploys made outside PantherClaw are seen here.

## Simulators

```
pantherclaw-sim agentcore --secret-file FILE [--addr 127.0.0.1:9113]
pantherclaw-sim vertex-agent-engine [--addr 127.0.0.1:9114] [--service-account-file FILE]
pantherclaw-sim azure [--addr 127.0.0.1:9115] [--client-file FILE]
```

The dev seed's `--agentcore-url`, `--vertex-agent-engine-url` and `--azure-url` (with `--gateway-out`) seed the packages and their connections against the simulators. DEVELOPMENT ONLY.

## Migration

`00382_runtime_discovery.sql` adds the three sources to `pc.discoveries` and `pc.saas_scan_runs`, the run origin `schedule`, and `pc.saas_scan_schedules` (row-level security, forced, with the org write guard).
