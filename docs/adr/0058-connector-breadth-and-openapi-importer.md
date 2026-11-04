# ADR-0058 — Connector breadth and the OpenAPI importer

**Status:** Proposed (2026-11-04; the [G0 M31](../g0/M31.md) brief records the coordinator decisions D950–D963). A stub: it is completed when M31's code is tested.

**Context.** Teams want PantherClaw in front of the services their agents already reach: Google Workspace, Microsoft 365, Salesforce, Notion, Linear, Anthropic models on Bedrock and Vertex, and Snowflake. Writing each package by hand from a provider's docs is slow, and several of these services need request shapes the HTTP dispatch could not build: a list of objects, array items, GraphQL, a raw mail message, a Google service account's token.

**Decision.**
1. **Shared dispatch contracts** (HR-723, HR-724). JSON body keys gain array indices and `[*]` (one object per identifier-list item, at most 64); a `graphql` dispatch sends a fixed document with the mapping as its variables; `rfc5322-raw` builds a plain-text message whose header values can never carry a line break. Everything the agent sends still reaches the target only through the reviewed template (HR-075).
2. **Token endpoints from a closed list** (HR-722). An `oauth_client` credential names Microsoft's or Salesforce's token endpoint, or a loopback simulator's.
3. **Google service accounts minted per dispatch** (HR-721). The key never leaves the gateway; only a token minted for one dispatch is placed.
4. **An importer that drafts, never imports** (HR-720). `pclaw package draft openapi` writes a draft whose `review_required` key the decoder refuses; a person reviews it, removes the key and signs it with an org key.
5. **Packages on these contracts** (HR-725..727): `pc.gmail`, `pc.google_workspace`, `pc.m365`, `pc.salesforce`, `pc.notion`, `pc.linear`, `pc.bedrock`, `pc.vertex`, `pc.snowflake`, each with a simulator.

**Consequences.**
- An `oauth_client` credential sealed earlier with an endpoint outside the list no longer opens; only Microsoft Teams used the kind, with Microsoft's endpoint.
- A drafted package is a starting point, not a reviewed one: its targets, units and extraction expressions are placeholders marked `# review:`.
- F-ids reach four digits (F1005 on).

**Alternatives.** A general OpenAPI-driven proxy without packages (no reviewed meaning per operation); importing drafts directly as DRAFT packages (a draft would sit one transition from use); Google user OAuth (needs a person's sign-in per connection).
