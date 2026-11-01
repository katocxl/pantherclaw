# ADR-0048 — IdP assertions and MCP client authorization

**Status:** Accepted (2026-11-01; G0 M26 design decisions D400–D407, founder decisions H4, H7 and H8; the [G0 M26](../g0/M26.md) brief records them). Amends [ADR-0039](0039-delegated-administration-org-identity-providers-and-key-service.md) point 2.

**Context.** Enterprises want agent access granted in their identity provider and enforced per task by PantherClaw. Okta Cross App Access uses ID-JAG assertions, and ID-JAG is still an IETF draft. Standard MCP clients expect the MCP 2026-07-28 authorization flow, and they hold bearer tokens, not PAP/1 proofs. Two rules stand in the way of the easy answer. HR-146 says a token proving who is represented never creates or widens a grant. ADR-0039 point 2 covers organization identity providers for sign-in only, and an assertion issuer is a new way for an organization to bring trust in from outside.

**Decision.**
1. **An assertion uses or narrows an existing grant, and never creates one** (D400, H8, HR-620). The port is `AssertionVerifier`, and the adapter `adapters/idjag` names the draft revision. It enters through `oauthhttp.HandleGrant` jwt-bearer. `iss+sub` maps to `pc.users`, and `client_id` maps to an enrolled agent by a pinned binding (HR-140, HR-621). The run's principal source is `id_jag`. The assertion's scope intersects the grant. With no existing grant it is refused with `NO_GRANT`.
2. **Assertion issuers need two people** (D401, H8, HR-622). `pc.org_assertion_issuers` holds them, as a two-person protected change under HR-481..484, with HTTPS discovery through the egress guard and a pinned audience. **This amends ADR-0039 point 2:** that point dealt with identity providers people sign in through, and it now also covers organization entries that vouch for agent access. They are separate records with the same protection. Sign-in providers are otherwise unchanged.
3. **Standard MCP clients get an opt-in route with a weaker proof** (D402, H8). `internal/gateway/mcpauth` is off by default per organization, with RFC 9728 metadata, the issuer check, RFC 8707 audience and CIMD. A client URL is allow-listed by the organization to one enrolled agent (HR-623). The token is `pap-mcp+jwt`, valid for 5 minutes, with `aud` one gateway server, and every call gets a full policy check (HR-624). The gateway forwards it and the Authority re-verifies it (HR-021). Policy sees `workload.proof == "bearer"`, which never satisfies an attestation requirement, so policy can refuse it (HR-625). PAP/1 routes are unchanged.
4. **Provisioning code stays private, its data does not** (D405, D406, H7). Tables and ports are in public core; the code is in a clean private package with `cmd/pantherclaw-server-ee`, under the extension prefixes (HR-341). A group maps only to non-admin roles, and Org Admin and Security Admin bindings stay in PantherClaw (R-08). A mapping change is a protected change. Deprovision ends sessions and API keys and refuses the last admin.
5. **SaaS agents are listed, not controlled** (D407). Metadata only, never conversations. They land DISCOVERED and OBSERVE_ONLY, with an `external` mark and no key path, and claiming sets an owner only.

**This is not ADR-0018's token-exchange service.** ADR-0018 rejected a full token-exchange service that issues downstream tokens, because connectors already mint narrow provider-native tokens. M26 keeps that rejection:
- an assertion comes in from the customer's IdP and proves who is asking; it grants nothing, as with a subject token (HR-146);
- PantherClaw issues no token for any downstream provider, and connectors still mint those per action;
- `pap-mcp+jwt` is good only at one PantherClaw gateway server, for 5 minutes, and the Authority still decides each call.

**Consequences.**
- The IdP can only reach what a PantherClaw grant already allows, so an IdP-side grant with no matching PantherClaw grant fails with `NO_GRANT`. Customers must set up both.
- ID-JAG can change without touching the rest of the code, since the draft stays behind one adapter.
- Bearer tokens are weaker than PAP/1 proofs: a stolen token works from anywhere for up to 5 minutes at one server. Audience, lifetime, the policy check on each call and the attribute policy can refuse are what limit it.
- R-08 stays accepted: a customer's IdP admin can still act as the people they control. An assertion gives such an admin nothing a grant does not already allow.
- All of this is tested on a simulated IdP and synthetic fixtures. The real tenant check stays pending (F801).

**Alternatives.** Assertions that create grants (breaks HR-146, and hands authority to the IdP); a token-exchange service that issues downstream tokens (ADR-0018); treating a bearer client as attested (F801); organization issuers under the organization's protect category (the same reason ADR-0039 gave for sign-in providers); a new enterprise repository (H7); group mappings to admin roles (R-08 would get worse).
