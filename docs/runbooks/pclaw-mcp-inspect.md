# `pclaw mcp inspect`

**Milestone:** M24 ([G0 M24](../g0/M24.md) D210, D214, D243, D245, D274). **Audience:** people deciding whether to review an MCP server. This page follows the brief and was written before the command landed; the M24 exit status records any change.

`pclaw mcp inspect <spec>` runs an MCP server in the containment sandbox on your own machine, with no credentials and egress denied. It lists the server's tools and resources, records its egress attempts and runs the supply-chain checks. It never runs on the server or hosted.

In M24 it reads images pinned by digest only: `<spec>` is an image pinned by digest, not a package or a URL.

With `--submit`, it adds an operator-reported note to the inventory row. The note is labelled as reported by an operator.

## Checks

| Check | Looks for |
|---|---|
| `hidden_instruction` | Zero-width, tag, variation-selector, filler or bidirectional characters, HTML comments |
| `injection_pattern` | Known injection patterns |
| `tool_shadowing` | The same name as a built-in or an approved tool. Without an upstream digest it is MEDIUM, with reason `digest_unknown` |
| `overbroad_schema` | Free-form command, SQL or URL strings; unbounded additional properties |
| `rug_pull` | A description or schema changed with no version change after approval. If the text compare finds nothing, it reads "definition changed" |
| `provenance_unknown` | No known provenance |
| `schema_unavailable` | A schema or other field was cut or left out, so it could not be fully read |

The checks cover names and values, title, annotations and outputSchema as well as descriptions, and a schema that will not parse still gets the hidden and injection checks on its raw text.

Not flagged, because normal text uses them: a variation selector after an emoji, a joiner inside an emoji sequence, joiners inside joining scripts, direction marks beside right-to-left text, and a byte-order mark at the start.

Each flag has a severity and the offsets of what it found. Flagged text is untrusted: read it as data.

## Reading the result

A result with no flags means **no known flags**. It does not mean the server is safe. These checks read what the server shows; they cannot show what it would do with credentials, on another day or on the network. A flag approves nothing and blocks nothing by itself. Tool review stays the decision.
