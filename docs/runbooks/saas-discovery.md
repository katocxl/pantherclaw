# Runbook — SaaS agent discovery

**Milestone:** M26 ([G0 M26](../g0/M26.md) D407, D534, D535). **Audience:** security teams. **Edition:** Business and above (`SaaSDiscovery()`); below it the API, the CLI import and the queue source answer EDITION_REQUIRED.

SaaS discovery lists agents built in Copilot Studio and ChatGPT Enterprise. It keeps metadata only: prompts, instructions and knowledge content are never kept, logged or sent to the server, and conversations are never asked for. Found agents are listed, not controlled.

**Both sources are built from synthetic fixtures.** No real capture exists yet, and OpenAI's Compliance API reference needs an enterprise sign-in, so its paths and fields are unconfirmed until a real tenant check (F801). An unexpected answer reports not scanned, never none found.

## Import a recording

```
pclaw discover import --source copilot_studio --file recording.json
pclaw discover import --source chatgpt_enterprise --file recording.json
```

- Needs `agent.manage` at the org. The file is parsed on your machine; only metadata goes to the server.
- Limits: 32 MiB a recording, 5000 records a list, 200 findings an import. A larger recording is sent as several imports, each noting it was sent in parts, so none counts misses. If one fails, the CLI says which were recorded.
- A file of the wrong shape is refused, never read as "none found".
- The expected shapes are in `internal/saasdiscovery/parse/testdata/*.synthetic.json`.

## Scan through a gateway

- `SaasDiscoveryService.StartSaasScan`: a person only, with `agent.manage`. One scan of a connection at a time.
- It runs as a `saas_scan` lease on the connection's gateway, reading for at most 20 s of the 30 s lease. What is left is reported not scanned, so a large tenant needs an export import for now.
- **Copilot Studio:** package `pc.copilot-studio`, credential kind `oauth_client` (an Entra app with read on the bot and botcomponent tables, scope `https://<org>.crm.dynamics.com/.default`), base URL the Dataverse org URL. It reads WhoAmI, then bots and botcomponents with a fixed `$select`. The tenant must equal WhoAmI's OrganizationId.
- **ChatGPT Enterprise:** package `pc.chatgpt-enterprise`, credential kind `static` (a compliance key). The scan reads `GET /v1/compliance/workspaces/{id}/gpts`. No field filter is known, so a page may carry a GPT's instructions; the gateway's first decode drops them and clears the page. PantherClaw does not bind the workspace to the connection: it relies on the Compliance API refusing a workspace the key does not reach. A refused or unreachable workspace fails the run with `tenant` not scanned.
- Neither package exposes a tool to agents.

## Reading results

- `GetSaasScan` and `ListSaasScans` show state (PENDING, RUNNING, DONE, FAILED), counts, `scanned` and `not_scanned`. Empty findings with `not_scanned` set means unread, never none found.
- Counts are `agents` and `records_unread` only. `records_unread` is how many records kept their recorded tools because a side read did not finish; every other record's change is still recorded, and the run can still count misses.
- A lease that expires, is cancelled, or ends without a report fails the run.
- Queue source `saas`: `EXTERNAL_AGENT_UNOWNED` (name an owner) and `SAAS_NOT_SCANNED` (the latest run of a tenant left something unread or failed).
- Changes and vanished agents use the existing `discovery` queue source. Only a complete run counts a miss, and an agent is noticed as vanished once. Neither changes state or authority.
- Text from a tenant is untrusted. It stays bounded, cleaned text and is never acted on.

## Owners

- `SetSaasAgentOwner` sets the owner and backup, closes the admission entry, and moves the discovery to CLAIMED.
- The agent stays DISCOVERED, `external` and observe-only. It can hold no instance, token or grant: an enrollment token answers `AGENT_STATE`, a grant `AGENT_NOT_ELIGIBLE`, and `ClaimAgent` answers `AGENT_EXTERNAL`.
- The API words it as "owner set, external agent" (or "no owner, external agent", "dismissed, external agent").
- To change the owner, call `SetSaasAgentOwner` again: `TransferOwnership` needs a claimed agent.

## Simulators

```
pantherclaw-sim copilot-studio [--addr 127.0.0.1:9100] [--deny-components]
pantherclaw-sim chatgpt-enterprise [--addr 127.0.0.1:9101] [--key-file FILE] [--deny]
```

Rows are SYNTHETIC and include one hostile name. `GET /__sim/stats` counts content columns asked for and conversation reads; both must stay 0.

## Migration

`00294_saas_discovery.sql` adds `pc.agents.external`, discovery sources, `pc.saas_scan_runs` (row-level security, forced, with the org write guard) and the `saas_scan` lease purpose.
