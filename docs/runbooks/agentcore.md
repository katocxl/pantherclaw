# Connect an Amazon Bedrock AgentCore gateway

An AgentCore gateway runs MCP tools for agents in AgentCore. With the PantherClaw request interceptor, the gateway asks your own PantherClaw gateway about each `tools/call` before the target runs it (G0 M34; HR-764..766). Raw tool arguments stay in your network: the interceptor never calls the PantherClaw server about a tool call.

Every decision is **PARTIAL**: AgentCore runs the tool, and a gateway without the interceptor is not asked about (R-82). Each AgentCore gateway is one PantherClaw agent, so its callers are not told apart (R-83). The AgentCore API shapes are unconfirmed until live checks (R-85).

## What you set up

- **One Lambda per AgentCore gateway**, running `pc-agentcore-interceptor`, set as that gateway's request interceptor.
- **A trusted issuer entry** for the Lambda's execution role, bound to the gateway's agent, with a run grant.
- **A connection per AgentCore target**, of kind `mcp` with custody `agent_held`, bound to the target with its runtime target.
- **A PantherClaw gateway** the Lambda can reach over HTTPS, serving those connections.

## 1. The agent and its issuer entry

Create one agent for the AgentCore gateway. Then propose an AWS issuer entry for the Lambda's execution role, bound to that agent, and give it a run grant: the Lambda starts its runs under it (HR-761). Without a run grant every run start is refused (`RUNTIME_NO_RUN_GRANT`) and every tool call is denied.

```bash
pclaw issuer propose-aws --agent <agent id> --account-id <12-digit account> --role-name <Lambda role name> \
  --run-grant <grant id> --auto-admit --reason "AgentCore interceptor for <gateway>"
```

The entry must admit automatically: the Lambda makes a new key at each cold start and enrols it with `aws_iam` attestation, signed with the role's own credentials. The key lives only in the Lambda's memory.

## 2. A connection per target

For each AgentCore target whose tools PantherClaw decides, create a kind `mcp` connection with custody `agent_held` and the package that maps the target's tools. Bind it to the target with `ConnectionService.SetConnectionRuntimeTarget`:

```
agentcore:<gateway ARN>/<target name>
```

The ARN is the AgentCore gateway's (for example `arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/my-gateway`), and the target name is the one AgentCore prefixes to its tools (`<target>___<tool>`). One connection per target per org. Setting or clearing a binding needs `connections.manage` and is audited (HR-762).

The account in the ARN must be the account the Lambda role is in: the Authority refuses a tool call whose target's account differs (`RUNTIME_ACCOUNT_MISMATCH`, HR-765).

## 3. The Lambda

Build `cmd/pc-agentcore-interceptor` for Linux (`GOOS=linux GOARCH=arm64` or `amd64`) as `bootstrap` and deploy it on a custom runtime (`provided.al2023`). It uses the Lambda Runtime API directly. Set:

| Variable | Value |
|---|---|
| `PC_SERVER_URL` | Your PantherClaw server's API URL, for enrolment, tokens and runs |
| `PC_GATEWAY_URL` | Your PantherClaw gateway's URL, for every tool call |
| `PC_ORG` | Your org's id |

Give the function a timeout of at least 10 seconds: each decision waits at most 8 seconds, and less when the invocation's own deadline is closer. Put it in a network that reaches both URLs. It needs no AWS permissions beyond its role; `sts:GetCallerIdentity` needs none.

Set the Lambda as the AgentCore gateway's request interceptor. `passRequestHeaders` is not needed: the interceptor reads the JSON-RPC body and the gateway ARN from the Lambda client context.

## What happens on a call

- **`tools/call`:** the tool name is split on its first `___`. The PantherClaw gateway finds the connection bound to that AgentCore target, maps the call through its package and decides it. On an allow the original request goes on to the target; PantherClaw records it as delegated and never forwards it itself (HR-760).
- **Deny or hold:** AgentCore gets a tool error and the target is not called. A hold says "held for a person's approval in PantherClaw; ask again after". Once a person approves it, the agent asks again.
- **`initialize`, `ping`, `tools/list`, `notifications/*`** pass without a decision. Any other method gets a JSON-RPC error (`RUNTIME_METHOD_NOT_DECIDED`).
- **HTTP and Runtime targets** are refused (`RUNTIME_HTTP_NOT_SUPPORTED`).
- **Anything that goes wrong** (no enrolment or run yet, the gateway unreachable, a slow answer) is a tool error: "PantherClaw cannot decide this tool call, so it does not run" (HR-766).

The Lambda logs enrolment, run starts and refusal reasons, never tool arguments.

## Try it locally

`pc-agentcore-interceptor --local 127.0.0.1:<port>` serves `POST /invoke` (the body is the interceptor event, the `PC-Runtime-Gateway` header names the gateway ARN) instead of the Runtime API. The AgentCore simulator (`pantherclaw-sim agentcore`, port 9113) builds an event and posts it there with `POST /sim/invoke-interceptor`. Set the same variables, plus `AWS_LAMBDA_FUNCTION_NAME`, `AWS_LAMBDA_LOG_STREAM_NAME` and the AWS credential variables the simulator accepts.

## Runs

Each Lambda execution environment starts one run named `agentcore:<function name>:<log stream>`. Characters outside `[A-Za-z0-9._:/-]` become `-`, so `[$LATEST]` reads `--LATEST-`. When the gateway reports that the run ended, the Lambda starts a new one.
