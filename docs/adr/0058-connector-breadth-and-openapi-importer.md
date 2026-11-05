# ADR-0058 — Connector breadth and the OpenAPI importer

**Status:** Proposed (2026-11-04; the [G0 M31](../g0/M31.md) brief records the coordinator decisions D950–D963). Body completed 2026-11-05, when M31's code was tested (HR-720..727, T-330..T-334, RT-210..RT-214).

**Context.** Teams want PantherClaw in front of the services their agents already reach: Google Workspace, Microsoft 365, Salesforce, Notion, Linear, Anthropic models on Bedrock and Vertex, and Snowflake. Writing each package by hand from a provider's docs is slow, and several of these services need request shapes the HTTP dispatch could not build: a list of objects, array items, GraphQL, a raw mail message, a Google service account's token.

**Decision.**
1. **Shared dispatch contracts** (HR-723, HR-724). JSON body keys gain array indices and `[*]` (one object per identifier-list item, at most 64); a `graphql` dispatch sends a fixed document with the mapping as its variables; `rfc5322-raw` builds a plain-text message whose header values can never carry a line break. Everything the agent sends still reaches the target only through the reviewed template (HR-075).
2. **Token endpoints from a closed list** (HR-722). An `oauth_client` credential names Microsoft's or Salesforce's token endpoint, or a loopback simulator's.
3. **Google service accounts minted per dispatch** (HR-721). The key never leaves the gateway; only a token minted for one dispatch is placed.
4. **An importer that drafts, never imports** (HR-720). `pclaw package draft openapi` writes a draft whose `review_required` key the decoder refuses; a person reviews it, removes the key and signs it with an org key.
5. **Packages on these contracts** (HR-725..727): `pc.gmail`, `pc.google-workspace`, `pc.m365`, `pc.salesforce`, `pc.notion`, `pc.linear`, `pc.bedrock`, `pc.vertex`, `pc.snowflake`, each with a simulator.

**How it works.**
- *Body shapes.* A body key is a dotted path of names, `[n]` indices and at most one `[*]`, at most 8 levels deep. `[*]` takes only an identifier list and builds one object per item, so a list value can never add structure the package did not review. The decoder and the egress builder check the key grammar twice (HR-526, HR-723).
- *GraphQL.* The package carries the document (at most 4 KiB, no subscriptions); the dispatch sends it with the mapped fields as `variables`. An agent's own `query` is not a field of any tool, so it never reaches Linear or Notion (T-333).
- *Mail.* `rfc5322-raw` builds `To`, `Cc`, `Bcc`, `Subject` and a plain-text body from mapped fields only. A CR, LF or other separator in a header value is refused when the request is read and again when the message is built (HR-724).
- *Provider token URLs.* The endpoint is derived from the URL: Microsoft's `login.microsoftonline.com/{tenant}/oauth2/v2.0/token` (tenant a GUID, either case, or a domain), Salesforce's My Domain `*.my.salesforce.com/services/oauth2/token`, or a loopback host. Any other endpoint is refused when sealed and when opened (HR-722).
- *Google service accounts.* A per-dispatch RS256 assertion (300 s, `sub` the sealed subject) is exchanged at the bound Google token host for one access token; nothing is cached, and the key is never placed on a request (HR-721). A call that names a mailbox other than the credential's subject is refused before anything is minted (`TARGET_NOT_CREDENTIAL_SUBJECT`, D956a).
- *Shares.* Drive permissions and Microsoft 365 invites and links name their destinations to the M30 share step: anyone or an anonymous link is `SHARE_PUBLIC`; a user, group or domain outside the organization's owned accounts is `SHARE_ACCOUNT_NOT_OWNED`; a share the extractor cannot read counts as public (HR-725). Gmail send, Drive permission create and the Microsoft 365 send, invite and link operations are irreversible, never retried, and reconcile an unknown outcome (D1002).
- *Snowflake.* Reads are built from the package's allow-list with typed binds in the Snowflake dialect, signed with a key-pair JWT per dispatch (HR-726). *Model clouds:* Bedrock Converse and Vertex Messages calls are read like M29's model calls, provider-side tools named and refused unless allowed (HR-727).

**Consequences.**
- An `oauth_client` credential sealed earlier with an endpoint outside the list no longer opens; only Microsoft Teams used the kind, with Microsoft's endpoint.
- A drafted package is a starting point, not a reviewed one: its targets, units and extraction expressions are placeholders marked `# review:`. The importer refuses what it cannot read safely (external `$ref`s, `$ref` chains deeper than 16, a `pc.` name, Swagger 2).
- F-ids reach four digits (F1005 on).
- Residual risk: a reviewer who removes `review_required` without reading the draft loads what it says; the org signature records who did.

**Alternatives.** A general OpenAPI-driven proxy without packages (no reviewed meaning per operation); importing drafts directly as DRAFT packages (a draft would sit one transition from use); Google user OAuth (needs a person's sign-in per connection).
