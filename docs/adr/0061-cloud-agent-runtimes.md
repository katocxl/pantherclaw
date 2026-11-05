# ADR-0061 — Cloud agent runtimes

**Status:** Proposed (2026-11-05; the [G0 M34](../g0/M34.md) brief records the coordinator decisions D990–D1001). A stub: it is completed when M34's code is tested.

**Context.** Agents now run inside cloud runtimes: Amazon Bedrock AgentCore, Google Vertex AI Agent Engine and Azure AI Foundry. The runtime runs the tools itself, so no call passes a PantherClaw route by itself. AgentCore offers a request interceptor before each target. Vertex has no gateway hook, only ADK's in-agent `before_tool_callback`. Foundry hands MCP approvals to the client app.

**Decision.**
1. **A `runtime` channel** (HR-760). A runtime's tool call is decided like any other action and recorded as delegated, never forwarded: the runtime runs it. Coverage is PARTIAL.
2. **AgentCore through the customer's own gateway** (HR-764..766; founder decisions FQ34-1, FQ34-2). An interceptor Lambda, one per AgentCore gateway, enrols with `aws_iam` attestation and asks the customer's PantherClaw gateway, so raw tool arguments stay in the customer's network. Each AgentCore gateway is one PantherClaw agent. A connection is bound to an AgentCore target by `runtime_target` (HR-762), and the Authority checks that the target's account is the attested one (HR-765).
3. **Runtime runs** (HR-761). An instance enrolled by cloud attestation starts its run under its issuer entry's run grant.
4. **ADK and Foundry helpers** (HR-767). A callback and an approvals helper in the customer's code, both failing closed.
5. **Deploy and admin-command operations** (HR-763). Vertex and Foundry agent deploys and Azure Run Command through PantherClaw are irreversible operations that no template grants. AgentCore is reads only for now, and SSM waits for a founder decision (D993a).
6. **Daily discovery** (HR-768, HR-769; FQ34-3). Agents deployed in the three runtimes are found daily through the gateway, and a new one raises an alert only.

**Consequences.**
- The interceptor is cooperative: a customer can remove it (R-82).
- Callers of one AgentCore gateway are not told apart (R-83).
- ADK and Foundry decisions happen in customer code (R-84).
- The Foundry and AgentCore API shapes are unconfirmed until live checks (R-85).
- AML.T0103 and T1651 leave Unaddressed on the threat map.

**Alternatives.**
- The interceptor calling the PantherClaw server directly (FQ34-1 chose the customer's gateway).
- Per-caller identity in AgentCore (FQ34-2 left it for later).
- Discovery only when a person starts a scan (FQ34-3 chose daily).
