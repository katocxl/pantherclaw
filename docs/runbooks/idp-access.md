# Runbook — IdP agent access and MCP authorization

**Milestone:** M26 ([G0 M26](../g0/M26.md) D400–D403, D408, D540, D542, D559, D560; [ADR-0048](../adr/0048-idp-assertions-and-mcp-client-authorization.md)). **Audience:** Org Admins and identity teams. **Edition:** Team and above (`IdpAccess()`), checked when a change is filed and when it applies, never on the token path.

PantherClaw is the per-task layer behind your identity provider. An IdP assertion or an MCP client's sign-in only uses or narrows a grant the person already holds in PantherClaw. It never creates one. Nothing here has been tested against a real Okta tenant yet: it runs on a simulated IdP (F801).

## What you turn on

All of these are two-person protected changes under CUSTODY in every protect mode, made by a person, and every org admin is told:
- **Add an assertion issuer:** issuer URL, audience, optional tenant, and algorithms from RS256, ES256 and EdDSA. The URL, audience and tenant are fixed once the issuer has been ACTIVE.
- **Bind a client id to an agent.** A binding is never re-pointed: remove it and add a new one.
- **Turn MCP authorization on** for the org. It is off by default and needs the gateway URL.
- **Allow-list each MCP client** by its Client ID Metadata Document URL (HTTPS with a path). Each allow-listed client gets its own `mcp_client` instance.

Disabling an issuer, removing a binding or client, and turning MCP authorization off take effect at once, with no second person. Removing a client also revokes its instance.

Permissions: `identity_provider.manage` for changes, `identity_provider.read` for lists.

## Names

- Org authorization server issuer, and the ID-JAG audience: `<public URL>/orgs/<org id>`.
- Metadata: `/.well-known/oauth-authorization-server/orgs/<org id>`. It answers 404 for an org with neither MCP authorization on nor an ACTIVE issuer.
- Consent page: `/orgs/<org id>/mcp/authorize`.
- Token endpoint: the shared `/oauth2/token`.
- Protected resource: `<gateway URL>/mcp-oauth/<connection>`. PAP/1 routes are unchanged. Resource identifiers compare as exact strings.

## What access it gives

- An assertion or sign-in only uses or narrows an existing active root grant of that agent, principal and environment. It writes no grant row. With no match it is refused `NO_GRANT`.
- Several matching grants are refused unless the scope names one with `pc.grant:<uuid>`.
- Scope values are operation names or prefixes, intersected with the grant and held on the run. An empty intersection, or a scope PantherClaw does not know, is refused; it never means the whole grant. An operation outside the run's scope is denied `OUTSIDE_RUN_SCOPE`.
- Revoking the grant stops the next call (`GRANT_REVOKED`) and the next task (`NO_GRANT`).

## ID-JAG assertions (Okta Cross App Access)

- Spec: draft-ietf-oauth-identity-assertion-authz-grant-06.
- JWS typ `oauth-id-jag+jwt`; `iat` at most 5 minutes old; a lifetime of at most 5 minutes; 60 seconds of clock skew; 16 KiB at most; `jti` single use.
- `cnf` and `authorization_details` are refused.
- The client authenticates with `private_key_jwt`, using the key of an admitted instance of the agent its `client_id` is bound to.
- A multi-tenant issuer entry requires its pinned tenant. An untenanted entry is never used while any entry of the same issuer pins a tenant, even a DISABLED or PENDING one.
- An ID-JAG exchange gets no refresh token.

## MCP clients

- `pap-mcp+jwt` lives 5 minutes, names one gateway server, and is re-verified by the Authority on every call. It is signed with the `mcp_tokens` key purpose and is never accepted as a workload token.
- The code flow needs PKCE S256, a signed-in person, and their consent on a page that names the client, the agent and the server. Codes last 60 seconds and are single use. The page warns when the redirect is a plain-HTTP loopback address.
- A `pap-mcp+jwt` is not sender-constrained: a stolen one works from anywhere for up to 5 minutes, at the one server it names (R-69).
- Refresh tokens exist only for the code flow. They rotate on every use and end with the run.
- **A reused code or refresh token ends its run.** A spent code presented again, or a rotated refresh token used again, revokes the run and its descendants (end reason `authorization_code_reused` or `refresh_token_reused`). A refresh reuse also kills the whole token family. Each raises an audited event, and the notice says the run was ended.

### When a client changes its metadata document

- The allow-list entry keeps the document a second person confirmed: its name, redirect URIs and digest. The consent page shows the stored name.
- A redirect is usable only if both the stored and the live document list it. A redirect only the changed document lists is refused `CLIENT_DOCUMENT_CHANGED` on the page.
- Every refused attempt is audited (`idaccess.client_document_changed`). The org admins are told once per changed document, not once per attempt; a further change notifies again.
- To accept the new document, call `RefreshMcpClientDocument` (permission `identity_provider.manage`). It files taking the new document as a new two-person change.

## Policy

`workload.proof == "bearer"` is a policy attribute, recorded so replay matches. Bearer proof is level 0: it never satisfies an attestation requirement, and your policy can refuse it.

## Rolling back migration 00291

The `00291` Down migration drops its tables and deletes the runs and `mcp_client` instances it created. **It refuses, deleting nothing, when any other row still refers to one of those runs or instances**: waitlist, approvals, grants, sandbox sessions, tool observations, automation launches, A2A peer runs, attestations or approval evidence. It never deletes evidence. Roll back only an organization that never used IdP access, or keep the migration.
