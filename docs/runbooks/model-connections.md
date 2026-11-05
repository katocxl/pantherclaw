# Model connections

**Milestone:** M29 ([G0 M29](../g0/M29.md); [ADR-0056](../adr/0056-model-connections.md)). **Audience:** an Org Admin connecting a model provider, and agent owners who run agents that call one. **Edition:** model connections, token caps, the run cap and the fake model on every edition; estimates and the monthly token report on Team.

A model connection lets an agent call its model provider through the gateway. The gateway holds the provider key, decides each call like any other action, scans the prompt for secrets, streams the answer and counts tokens against your caps. The agent never holds the key.

Two packages back model connections, and they back nothing else:

| Package | Operations | Agent request |
|---|---|---|
| `pc.anthropic` | `anthropic.messages.create` | `POST …/messages` |
| | `anthropic.messages.count_tokens` | `POST …/messages/count_tokens` |
| | `anthropic.models.read` | `GET …/models`, `GET …/models/{id}` |
| `pc.openai` | `openai.chat.create` | `POST …/chat/completions` |
| | `openai.responses.create` | `POST …/responses` |
| | `openai.models.read` | `GET …/models`, `GET …/models/{id}` |

`pc.openai` also serves OpenAI-compatible servers and Azure OpenAI's v1 API. Azure's deployment-path API, Bedrock and Vertex are not served.

## 1. Create a model connection

The gateway that will hold the key must have registered its broker key ([gateway runbook](gateway.md)).

1. Create the connection with kind `model`, the package, access mode `pantherclaw_held` and the base URL. The base URL includes the API version path:

   | Provider | Base URL |
   |---|---|
   | Anthropic | `https://api.anthropic.com/v1` |
   | OpenAI | `https://api.openai.com/v1` |
   | Azure OpenAI (v1 API) | `https://<resource>.openai.azure.com/openai/v1` |
   | The fake model | `http://127.0.0.1:9103/v1` (simulated connections only) |

   ```bash
   pclaw connection create anthropic --kind model --gateway <gateway id> --package pc.anthropic \
     --base-url https://api.anthropic.com/v1 --access pantherclaw_held --default-mode enforce \
     --agent-host api.anthropic.com
   ```

   `--agent-host` is the host agents use, so the sandbox edge maps it to this connection (repeatable, at most 16). The key header defaults to `x-api-key` with no scheme on `pc.anthropic`, and `Authorization` with `Bearer` on `pc.openai`. For Azure, set the header to `api-key` with no scheme (`--header api-key`).
   A model connection has fixed limits (section 3): do not set `--timeout-ms` or `--max-response-bytes` on it.
2. Seal the key, then delete the key file:
   ```bash
   pclaw seal --connection <connection id> --from-file ~/.pantherclaw/anthropic.key --fingerprint <broker key fingerprint>
   ```
   The key is any printable ASCII without spaces, 8 to 512 characters. The gateway places it only on requests to the connection's own host.
3. `pclaw connection test <connection id>` should report the connection ready.

A model connection has three settings of its own, on `pclaw connection create` and `pclaw connection update`:
- **Max output tokens** (`--max-output-tokens N`, 1 to 1,000,000; default 64,000). The gateway adds it to a request that sets none (section 2).
- **Allowed provider-side tools** (`--allow-server-tool TYPE`, repeatable; default none; section 5). On update the list replaces the old one, and `--allow-server-tool ''` alone clears it.
- **Prices** (optional, Team; section 7): `--price-currency`, `--price-input`, `--price-output`, `--price-cache-read`, `--price-cache-write`; `--clear-price` on update.

## 2. What the gateway does with each call

- **The key.** The edge strips every credential the agent sends. The gateway places the sealed key on the request, and only to the connection's host. Any key the agent sends is stripped and reported.
- **A strict parse.** The body must be one JSON object, `Content-Type: application/json`, valid UTF-8, with no duplicate member names and nesting at most 256 deep. Anything else is refused.
- **The checked body is what is sent.** The gateway decides on the request's metadata (model, max tokens, choices, stream, input size, provider-side tools) and the sha256 of the body it re-encoded. It sends exactly that body. Its only edit is adding the max-tokens field when the request has none. The decision, any approval and the receipt bind that hash.
- **Max output tokens.** The field is `max_tokens` on Anthropic, `max_completion_tokens` on Chat Completions (the older `max_tokens` is accepted; both with different values is refused) and `max_output_tokens` on Responses. It must be 1 to 1,000,000. When it is missing, the gateway adds the connection's max output tokens.
- **Fixed paths.** The request path must be the base URL's path plus the operation's path. The only query parameters passed on are `beta=true` on `pc.anthropic` and `api-version` on `pc.openai`.
- **Listed headers only.** Toward the provider: `Content-Type`, `Accept`, `anthropic-version`, `anthropic-beta`, `OpenAI-Beta`, `User-Agent` and the key header. Back to the agent: `Content-Type`, `Cache-Control`, `Retry-After`, the request id headers, the rate-limit headers and PantherClaw's own `Pc-*` headers.
- **Retries.** Identical prompts are independent calls. An SDK's automatic retry after an overload or a server error is decided again, never parked as a duplicate.

## 3. Limits

| | Model connections | Every other connection |
|---|---|---|
| Request body | 16 MiB | 64 KiB |
| Answer | 16 MiB, streamed as it arrives | 64 KiB, buffered |
| Time per call, stream included | 10 minutes | 2 minutes |

The same limits hold on the sandbox edge. A stream that passes a limit, or breaks, is cut off, never passed on as whole. Its outcome is UNKNOWN, and its token reservation stays until it is reconciled (section 6).

## 4. Refusals

Refusals come in the provider's error shape, so the agent's SDK shows them. The message reads `PantherClaw: <reason> (<code>, transaction <id>)`. The `pantherclaw` member holds the agent-safe explanation, never budget values or content.

| Status | Error type | When |
|---|---|---|
| 403 | `permission_error` | a DENY, an approval or hold, a provider-side tool, a secret, containment, other refusals |
| 413 | `request_too_large` | the body is over 16 MiB (`body_too_large`) |
| 415 | `invalid_request_error` | the body is not `application/json` (`unsupported_media_type`) |
| 400 | `invalid_request_error` | invalid JSON (`invalid_json`), a query parameter that is not allowed (`query_not_allowed`), a bad field (`invalid_request`), a GET with a body |
| 404 | `not_found_error` | a path that is not an operation (`unknown_route`) |
| 401 | `authentication_error` | the request's PantherClaw identity (PAP) failed |
| 503 | `api_error`, with `Retry-After: 1` | a busy budget (`BUDGET_BUSY`), or the authority or a check it needs unavailable; retry |
| 502 | `api_error` | the gateway could not carry out the call |
| 504 | `api_error` | the outcome became uncertain before any answer arrived |

The codes you will see most:
- `TOKEN_BUDGET_EXHAUSTED`: the call would pass a token cap (section 6).
- `SECRET_IN_PAYLOAD`: the prompt carries a credential format. The call is held for an approver (section 8).
- `MODEL_SERVER_TOOL_NOT_ALLOWED`: the request asks for a provider-side tool the connection does not allow (section 5).

## 5. Provider-side tools

Some tools run on the provider's servers, not in the agent: web search and fetch, code execution, remote MCP servers, a code container, background mode. They are a route around PantherClaw, so they are refused unless you allow the tool's type on the connection.

- Anthropic: a `tools[]` entry with a `type` other than `custom` and the client-run types (`computer_…`, `text_editor_…`, `bash_…`, `memory_…`), `mcp_servers`, or `container`.
- Chat Completions: a `tools[]` type other than `function` or `custom`, or `web_search_options`.
- Responses: a `tools[]` type other than `function`, `custom`, `local_shell` or `computer_use_preview`, or `background: true`.

A type the gateway does not know counts as provider-side. The name to allow is the tool's `type` string exactly as the request sends it (at most 32 per connection). Policies see the request's provider-side tools as `server_tools`.

## 6. Token caps

A budget rule with `max_tokens` caps the tokens of model calls. Put it in a grant's limits (`--limits-file`, grouping `task`) or a guardrail envelope's limits (any other grouping), as for money and count rules:

```json
{
  "budgets": [
    {"id": "model_tokens", "grouping": "task", "operations": ["anthropic.*", "openai.*"], "max_tokens": "2000000", "period": "none"}
  ]
}
```

- A token rule has `max_tokens`, a whole number written as a string like `max_count` (1 to 1,000,000,000,000), and none of `currency`, `limit` or `max_count`. A narrowed grant or template may lower `max_tokens`, never raise or drop it.
- It covers only model operations that reserve tokens (the create operations), filtered by `operations`. Every other action skips it. Token counts and model reads reserve nothing.
- **Reserve by estimate.** Before a call the pipeline reserves the max tokens, times the choices (`n` on Chat Completions), plus a third of the request's bytes. A call that would pass a cap is refused with `TOKEN_BUDGET_EXHAUSTED`.
- **Settle by usage.** A completed call settles at the tokens the provider reported: input, output, cache reads and cache writes together. When the provider reported none, the whole reservation is spent. A call the provider rejected releases its reservation.
- **Chat Completions streams report usage only when asked.** An OpenAI Chat Completions stream sends its usage only when the request sets `"stream_options": {"include_usage": true}`. Without it no usage is reported, so the call's whole reservation is spent. The gateway does not add the option: the only edit it makes to a request is the max-tokens field (section 2). Set it in the agent's client to have streamed calls settle at what they used.
- **Unknown outcomes.** A cut stream, a timeout or an error event is UNKNOWN. The reservation stays held and goes to reconciliation, which commits or releases it whole.
- Spent may pass a cap by what one call's input estimate missed.
- A run can also have its own cap (`pclaw sandbox run --max-tokens`, [sandbox runbook](sandbox.md)). It only restricts.

To see a run's token lines (held, committed, released, remaining, and the cap):

```bash
pclaw run inspect <run> --section budget
```

There is no `pclaw run show`. `pclaw grant budget <grant>` shows a grant's accounts with their unit.

## 7. Prices and estimates (Team)

PantherClaw ships no price list. On Team you may set your own prices on a model connection: a currency, a price per million input tokens and per million output tokens, and optional prices for cache reads and cache writes (empty means the input price). Then:
- the run inspector shows an estimate for the run, with the number of priced and unpriced calls;
- each call's usage row carries an estimate;
- the monthly token report shows estimates per row.

Every estimate is labelled "estimate". It comes from your prices and the token counts the providers reported. It is not a bill: your provider's invoice is the record of what you owe. On Community, prices cannot be set and no estimate is shown. A price kept from a Team period stays stored, but no estimate is shown or written.

The monthly token report (Team, `budget.read`):

```bash
pclaw tokens report --month 2026-11 --by team      # or agent, connection, model
```

It shows calls, calls with no reported usage, unknown calls, each kind of token and the total, per team, agent, connection or model, for one UTC month. It ends with: "Token counts are what the model providers reported. Costs are estimates from prices your organization set, not a bill."

## 8. Secrets in prompts

The gateway scans every string of the request body, and the model id, for secrets.
- A secret PantherClaw holds is refused (`secret_in_payload`).
- A credential format (an Anthropic, OpenAI, GitHub or other known key) is held for an approver with `SECRET_IN_PAYLOAD`. The approval binds the body's hash, so only the identical request passes.
- A body the scan cannot finish within its limits is refused (`payload_not_scannable`).

**What happens to a held call.** A direct client that resends the same action id after the approval goes through. An agent in `pclaw sandbox run` cannot resume a held call: the edge gives each request a new action id. The agent gets a 403 naming `SECRET_IN_PAYLOAD` and the transaction, and you see the hold. Remove the secret from the workspace and from the agent's conversation, then run again. Resuming through the sandbox is planned for a later milestone.

## 9. No capture

PantherClaw never captures, stores or logs a prompt or a reply on a model connection.
- A capture profile that names a model connection is refused. One that covers every connection skips model connections.
- Gateway and edge logs carry the connection, operation, model, sizes, status and token counts, never a body.
- The transaction keeps the request's metadata and a usage row with token counts.

The gateway and the edge still see prompts in plaintext while they pass (R-73).

## 10. Rehearse with the fake model (no tokens)

`pantherclaw-sim model` answers both APIs, streamed, with usage numbers. It never calls a real provider and costs no tokens. Every answer is marked simulated, and its text starts with `SIMULATED`.

```bash
pantherclaw-sim model [--addr 127.0.0.1:9103] [--key KEY] [--stream-delay 0s] [--status 0]     # default key: sim-model-key
```

`--stream-delay` waits before each stream event; `--status` answers every model call with that HTTP status, in the API's error shape.

Create a simulated model connection with base URL `http://127.0.0.1:9103/v1` and seal the sim's key. `dev seed … --gateway-out … --model-url` creates two (BUILD_GUIDE §4), `anthropic` and `openai`, and they are simulated too.

Only a range agent's runs can use a simulated connection (HR-220, [range.md](range.md)). An ordinary agent's run that reaches one is denied `SIMULATION_MISMATCH`. To try the fake model, use a range agent (`range_agent = true`; `pclaw redteam setup` creates one, see range.md).

The model id picks a behaviour:

| Model id | Behaviour |
|---|---|
| any other | "SIMULATED reply.", a few output tokens |
| `sim-max` | output tokens equal the request's max tokens (reaches a cap fast) |
| `sim-cut` | the stream is cut after the first delta (an UNKNOWN outcome) |
| `sim-error` | Anthropic 529 `overloaded_error`, OpenAI 503 |
| `sim-no-usage` | a Chat Completions stream with no usage chunk |
| `sim-tool` | one tool call named `sim_tool` |

The range scenarios RT-190..RT-197 and every M29 test use it. Never point a test or a range run at a real provider (HR-699).

## 11. Troubleshooting

| Symptom | Cause | Action |
|---|---|---|
| 403 `TOKEN_BUDGET_EXHAUSTED` | A grant, envelope or run token cap would be passed | `pclaw run inspect <run> --section budget`; raise the cap or wait for the period |
| 403 `SECRET_IN_PAYLOAD` | The prompt carries a credential format | Approve or deny the hold; from a sandbox, remove the secret and rerun (section 8) |
| 403 `MODEL_SERVER_TOOL_NOT_ALLOWED` | A provider-side tool not allowed on the connection | Allow its type on the connection, or drop the tool from the request |
| 400 `invalid_json` | Duplicate members, invalid UTF-8, too deep, or not one object | Fix the client; the gateway never guesses |
| 404 `unknown_route` | The path is not the base URL's path plus an operation's path | Check the base URL's version path (section 1) |
| 413 `body_too_large` | Request over 16 MiB | Shorten the conversation |
| Outcome UNKNOWN, reservation held | The stream was cut, timed out or passed 16 MiB | Reconcile it; the reservation is committed or released whole |
