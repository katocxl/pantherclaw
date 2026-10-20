# AuthZEN enforcement points

**Milestone:** M14 ([G0 M14](../g0/M14.md) D26–D29; [ADR-0019](../adr/0019-standards-at-the-edges.md) and its implementation note). **Audience:** an Org Admin or Security Admin connecting a gateway the organization already runs (Envoy `ext_authz`, an API or agent gateway). Command flags below follow the brief; the M14 exit status records any change.

An **enforcement point** is your own proxy that asks PantherClaw for a decision through the OpenID AuthZEN Authorization API 1.0 and then forwards or blocks the request itself. PantherClaw decides with the full pipeline (grants, budgets, holds, consequences) and records the decision, but it does not send the request, so these routes are labelled **`PARTIAL`** (HR-320, R-40) unless the target verifies the PAP/1 action token.

## 1. Before you start

- The connections the point will guard must be `agent_held` or `target_enforced`. A `pantherclaw_held` connection cannot be bound to a point: route it through the PantherClaw gateway instead.
- The agents must call through the point with their own PAP/1 credentials (`Authorization: PAP …`, `PAP-Proof`, `PAP-Run-Id`, and `PC-Action-Id` when resubmitting). PantherClaw refuses evaluations that name an agent without its proof (HR-318).

## 2. Create the service account and the point

1. Create a service account for the point and register its `private_key_jwt` key as for any service account ([workload-identity runbook](workload-identity.md) covers keys).
2. Bind it to the built-in role **Enforcement Point** (org scope only; only service accounts can hold `authzen.evaluate`).
3. As a person holding `enforcement_point.manage` (service accounts are refused), create the point:

```bash
pclaw authzen point create edge-proxy --service-account <service account id> --connection <connection id> [--connection <id> ...]
pclaw authzen point list
pclaw authzen point get <point id>
pclaw authzen point connections <point id> --add <connection id>     # a widening prints a confirm URL
pclaw authzen point disable <point id>
```

4. The new point is PENDING and `create` prints a confirm URL. Open it in the browser, check the service account and connections, and confirm with your security key; only then is the point ACTIVE and able to evaluate.

Narrowing a point's connections applies at once. A widening is stored as proposed and prints a confirm URL; the point keeps serving its current connections until someone confirms the widening on that page with a security key. Disabling (a person only) applies at once with no step-up, and the point's next evaluation fails with 401. Every change is audited.

## 3. Wire the proxy

Discovery: `GET https://<pantherclaw public url>/.well-known/authzen-configuration` lists the evaluation endpoints and the capability `urn:pantherclaw:authzen:pap1-subject`. There are no search endpoints.

The point gets an access token from the OAuth token endpoint with `private_key_jwt`, then calls `POST /access/v1/evaluation` (or `/access/v1/evaluations` for up to 10 at once):

```json
{
  "subject":  {"type": "pantherclaw_workload", "id": "<agent id, optional>",
               "properties": {"pap_token": "...", "pap_proof": "...", "pap_run_id": "...", "pc_action_id": "..."}},
  "resource": {"type": "pantherclaw:http_request", "id": "<connection name>",
               "properties": {"protocol": "http", "method": "POST", "url": "https://...", "content_type": "application/json", "body_b64": "..."}},
  "action":   {"name": "POST"}
}
```

For MCP traffic use `"protocol": "mcp"` and action `tools/call`; `initialize`, `tools/list` and `ping` answer true with no action recorded. The URL must sit under the connection's base URL. Bodies: requests at most 128 KiB, the forwarded body at most 64 KiB. Each point is rate limited (default 50 requests per second per server instance). Other MCP requests through a point (GET, DELETE) are refused. JSON-RPC bodies are parsed strictly (only `jsonrpc`, `method`, `params` and `id`). `properties.method` must match `^[A-Z]{3,7}$` and equal `action.name` (for MCP the action is `tools/call`). Each proof decides at most one evaluation: a batch item that would reuse a proof (for example through a shared top-level subject) answers `decision: false` with `PROOF_ALREADY_USED`.

The reference point `sdk/go/pep` (Apache-2.0) does all of this as an `http.Handler` reverse proxy. It forwards only allow-listed request headers (by default Content-Type, Accept, Accept-Language, User-Agent and X-Request-ID; configurable) and exactly the evaluated URL and content type; it refuses a Content-Encoding other than identity, `X-HTTP-Method-Override` and trailers, strips every `PAP`/`PC` header the agent sent (in any spelling) except the `PAP-Action` it adds itself, calls PantherClaw over HTTPS (loopback only in dev), ignores proxy environment variables, and drops its token after a 401; `sdk/go/pep/cmd/pep` wraps it in a small command (listen address, upstream, evaluation URL, key file). Use it or copy its behaviour.

## 4. Reading the answer

| PantherClaw outcome | `decision` | What the point does |
|---|---|---|
| ALLOW | true | Forward; for `target_enforced` connections add `PAP-Action` from `context.pantherclaw.action_token` |
| observe (monitor routes) | true | Forward |
| HOLD | false | Answer 403 with `reason_user`; the agent waits with its SDK (`context.pantherclaw.wait`) and resubmits the identical request with the same `pc_action_id` after approval |
| DENY, CANNOT_AUTHORIZE | false | Answer 403 with the reason |

Denials are HTTP 200 with `{"decision": false}`. A 401 means the token, the service account, its permission or the point is not valid or ACTIVE; a 403 means the connection is not bound to this point. `X-Request-ID` is echoed.

An ALLOW for a budget-consuming action is committed at once as a delegated execution: the budget is spent and never released early (HR-319). If the point then fails to forward, the money or count stays spent; reconcile from the transaction id in the context. Each transaction records `decided_via = authzen` and the enforcement point before anything is committed; if that record cannot be written, nothing is dispatched, the reservation is released when the permit expires, and the answer is `decision: false` (CANNOT_AUTHORIZE). Channel `authzen` is decided only through these endpoints, never through a PantherClaw gateway.

## 5. Troubleshooting

| Symptom | Cause | Action |
|---|---|---|
| 401 | Expired token, missing `authzen.evaluate`, or the point is disabled | Refresh the token; check the role binding and `pclaw authzen point get` |
| 403 | The connection is not bound to the point | `pclaw authzen point connections --add` (step-up) |
| `decision: false`, proof code | The proof does not match the URL, method or body, or was replayed | Make the point forward the exact request bytes the agent signed |
| `decision: false`, name-only subject | The subject has no PAP/1 token and proof | Forward the agent's PAP/1 headers |
| 429 | The per-point rate limit | Spread load or raise the limit in server config |
| `PROOF_ALREADY_USED` | A batch reused one proof for several evaluations | Send one proof per evaluation |
| The point cannot evaluate after create | It is still PENDING | Confirm it on the page whose URL `create` printed |
