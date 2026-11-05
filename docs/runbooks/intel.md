# Use and share threat indicators

Every org can use and share indicators of known-bad MCP servers, tool descriptions and injection text (G0 M38; [ADR-0065](../adr/0065-partners-and-shared-indicators.md); HR-817..822). Indicators are hashes only: nothing readable enters or leaves the feed. A match holds the call for a person, or only alerts; it never refuses (founder decision FQ38-2). Consuming and sharing are both off until an org turns them on.

Consuming needs the Business edition; contributing works on every edition.

## 1. Indicators

| Kind | What is hashed |
|---|---|
| `mcp_server` | SHA-256 of `lower(name)@version` from the server's MCP `serverInfo`, of `package_ref@version`, or of an image digest |
| `tool_description` | SHA-256 of the normalized description: NFC, trimmed, whitespace collapsed, lowercased |
| `injection_text` | Up to 64 SHA-256 of normalized 8-word shingles; a match needs at least min(3, n) of them |

Each indicator also has an id, a severity, techniques, a first-seen date and a summary of at most 280 characters.

## 2. Load the feed (operator)

The feed is a compact JWS (`pc-intel-feed+jwt`) signed with an offline root key of purpose `intel` (`intel-dev` on loopback only); the roots are in `internal/intel/roots.json`. Load it either way:

- `pclaw-admin` with the feed file (ImportIntelFeed), or
- set `intel.feed_url` and the server fetches it once a day through the egress client. Empty means no fetch.

A feed is refused when its signature does not verify, its version is not above the loaded one (no rollback), or it has expired (at most 30 days after issue). An accepted feed replaces the whole set at once.

## 3. Turn on matching (org)

With `intel.manage` (Security Admin), set consume to:

- `OFF` (the default): nothing is matched.
- `HOLD`: a matching call waits for a person's approval with reason `INTEL_MATCH_HOLD`, and an alert is raised.
- `ALERT_ONLY`: a matching call goes on, and an alert is raised.

Servers and tool descriptions are matched at discovery, on drift and on the decision path; injection text is matched in the content-signal scan. Every match is recorded, audited `intel.matched`, and raises the built-in detection `pc.intel.match` (HIGH, alert only). `intel.read` (Security Admin, Auditor) lists matches and the feed's state.

The server's `serverInfo` is recorded on the connection's inventory for matching only; it never identifies or admits a server on its own (HR-822).

## 4. Contribute

With the org's share switch on (`intel.manage`), a person with `intel.contribute` turns a confirmed finding into an indicator with `ContributeIndicator`. The hash or shingles are computed in your org; the text never leaves. The operator collects contributions with `ExportIntelContributions`, which carries no org, account or time finer than a day.

## 5. STIX

`ExportIntelSTIX` returns a STIX 2.1 bundle of `indicator` objects, one pattern `[x-pantherclaw-indicator:sha256 = '<hex>']` per hash (per shingle for injection text), with the kind as a label and the techniques as kill chain phases. TAXII is a follow-up.

## 6. Limits

A hash-only feed misses changed text: a renamed server or a reworded description no longer matches, and shingles match only the text they share (R-92). Indicators add to content signals and the reviewed MCP surface; they don't replace them.
