# `pclaw mcp inspect`

**Milestone:** M24 ([G0 M24](../g0/M24.md) D210, D214). **Audience:** people deciding whether to review an MCP server. This page follows the brief and was written before the command landed; the M24 exit status records any change.

`pclaw mcp inspect <spec>` runs an MCP server in the containment sandbox on your own machine, with no credentials and egress denied. It lists the server's tools and resources, records its egress attempts and runs the supply-chain checks. It never runs on the server or hosted.

With `--submit`, it adds an operator-reported note to the inventory row. The note is labelled as reported by an operator.

## Checks

| Check | Looks for |
|---|---|
| `hidden_instruction` | Zero-width, tag or bidirectional characters, HTML comments |
| `injection_pattern` | Known injection patterns |
| `tool_shadowing` | The same name as a built-in or an approved tool |
| `overbroad_schema` | Free-form command, SQL or URL strings; unbounded additional properties |
| `rug_pull` | A description or schema changed with no version change after approval |
| `provenance_unknown` | No known provenance |

Each flag has a severity and the offsets of what it found. Flagged text is untrusted: read it as data.

## Reading the result

A result with no flags means **no known flags**. It does not mean the server is safe. These checks read what the server shows; they cannot show what it would do with credentials, on another day or on the network. A flag approves nothing and blocks nothing by itself. Tool review stays the decision.
