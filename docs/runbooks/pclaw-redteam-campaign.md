# `pclaw redteam campaign run`

**Milestone:** M25 ([G0 M25](../g0/M25.md) D305–D310, D313, D523, D525, D541, D543; founder decisions H6 and H10). **Audience:** security engineering. **Edition:** Business.

A campaign runs library attack campaigns, RT-140 to RT-149, against a range twin of your agent. The twin is a range agent with its image pinned by digest, running in the containment sandbox against simulated connections. A campaign measures whether the boundary held. It does not measure whether the model behaved, and it is never a certification.

## What a result says

The server derives every outcome from its own transactions:
- **HELD**, **DENIED**, **ALLOWED**;
- **NOT_ROUTED_REPORTED**: the sandbox edge reported that the route was not taken. It is labelled reported and never shown as proven;
- **NOT_EXERCISED**: a gap, never a pass. `RUN_TOO_LARGE` is one reason for it.

A result names the image digest, says it tested a twin and not production, and says whether a scripted stand-in or a real model drove it. Campaigns never enter an assurance pack. A step held during the campaign stays HELD in the result even if someone approves it after the campaign finishes: the result describes what the boundary did while the campaign ran.

There is one open campaign per range agent. A campaign nobody finishes is abandoned after 24 hours.

## The model key

- It is read once from a file, after every other check, and kept only in the memory of a relay that `pclaw` runs beside the sandbox, outside the agent's container.
- It is never in the container's environment, arguments or mounts, never logged and never sent to the server.
- The key file must not be inside `--workspace`. A key file linked into the workspace, or hard-linked anywhere in it, is refused.
- The agent gets `ANTHROPIC_API_KEY` and `OPENAI_API_KEY` set to a placeholder. The edge drops the placeholder without reporting it. Any other key the agent sends is stripped and reported, as on every route.
- The relay sends only to the one model host named for the campaign, over verified HTTPS, and refuses redirects, other hosts and upgrades.

## The model route

The route is a written exception to HR-075:

agent → sandbox edge (dials only the gateway) → gateway model face `/model/{relay}/{host}/…` → relay → model host.

- Bytes cross unchanged and stream. There is no ActionIR, no Authority decision and no transaction.
- The secret scan (HR-225) does not cover this traffic. Planted bait, canaries included, can reach your own model provider. The real key never reaches the agent.
- The gateway asks the server about every request. The route is off unless the campaign is open. A real connection, a real agent, a quarantined relay, the kill switch, or a campaign older than 24 hours stops it.
- Limits: 8 MiB a request, 8 MiB an answer, 256 MiB a run with both ways together, 5 minutes a call. An answer past the cap breaks the connection rather than arriving cut.
- The server keeps the request count, bytes each way and model host for each run. It never keeps a body.

This route is for campaigns only. An agent outside a campaign reaches its model through a model connection, where each call is decided, scanned and metered ([model connections](model-connections.md), M29).

## Set up

1. Create a model relay connection: simulated `http`, package `model-relay`, access mode none, no agent hosts. Its base URL is a loopback or private IP literal where the relay will listen. A relay is known by its mark, not by its name.
2. Allow the relay's address in the gateway's egress allowed prefixes, as for any simulator.
3. Run the relay and the gateway on the same host or private network. A remote gateway is refused.
4. **Upgrade the server before the gateways.** A gateway of this release reports a relay's serving state as LOCAL_RELAY, which an older server does not know. That server refuses the gateway's whole status report, not just that connection. A gateway older than this release refuses a configuration that holds a model relay.

## Run a campaign

```
pclaw redteam campaign run --agent RANGE_AGENT_ID --connection SIM_CONN_ID... --relay-connection RELAY_CONN_ID \
  --grant GRANT_ID --gateway http://127.0.0.1:8443 --image REPO@sha256:... \
  --model-host api.anthropic.com --model-key-file ~/model.key [--model-key-header x-api-key] \
  [--campaigns redteam/campaigns] [--only RT-140,RT-144] [--fixture repo=acme/payments --fixture pr=7 ...] \
  [--scripted] [--workspace DIR] [-- AGENT COMMAND ARGS]
```

- `--fixture NAME=VALUE` fills `${NAME}` in the campaign files (`repo`, `pr`, `head`, `branch`, `other_repo`). A missing one stops the run. `${canary_*}` bait is generated fresh for each run and cannot be set.
- The relay listens at the relay connection's base URL. Pass `--gateway-peer IP` when the gateway reaches it from a private address; the default is this host's loopback.
- The agent also gets `PC_CAMPAIGN` (the id) and `PC_CAMPAIGN_TASK` (the task text).
- Each campaign runs in its own sandbox session with its own workspace: a copy of `--workspace`, then the campaign's plants. The copy skips symbolic links and says how many. With `--scripted` the agent is the scripted stand-in, the demo agent's `campaign` command.
- The campaign always finishes, even after a failure. Output is one line per attempt (outcome and basis), the counts and the statement. The relay's request and byte counts go to stderr.
- `--model-ca` and `--model-dial` are hidden. They exist only for a local test provider. Never use them against a real provider.

**Exit codes:** 0 when nothing was ALLOWED; 1 when an attempt was ALLOWED or `RUN_TOO_LARGE` (an agent under test can push its own step past the bounds); 2 for usage or infrastructure errors. NOT_EXERCISED for any other reason does not fail the run, and it is printed as a gap.

## During a campaign

**Do not start manual runs of the range twin, or delegated runs from them, while a campaign is running.** Steps run one at a time. The step opens before the sandbox session exists, so it cannot tell the campaign's runs from yours: every simulated run of the twin made while a step is open is bound to it, and so is every descendant of a bound run, under any agent. Your runs would be counted, and could push the step to `RUN_TOO_LARGE`.

Past a step's bounds (32 bound runs, 256 stored route reports) an attempt is NOT_EXERCISED with reason `RUN_TOO_LARGE`, unless an ALLOWED was already read, which then wins.

## What is tested, and what is not

- No real model provider has been called in tests: a local TLS fake provider stands in.
- `task test:sandbox` runs the campaign end to end (RT-140, scripted stand-in). `E2E_RUN=^TestE2E_M25_` narrows to it.
- The end-to-end test shows a sandbox cannot reach a relay on this host's loopback or on a private address of Docker's default bridge. A relay on a host LAN address is not tested: on Docker Desktop the host's firewall may drop the connection by itself, which would look like the sandbox's doing.
- `task range:library` regenerates `campaigns.json` with the scenario library.
- A relay connection shows serving state LOCAL_RELAY in gateway status.
