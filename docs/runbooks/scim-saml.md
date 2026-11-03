# Runbook — SCIM provisioning and SAML sign-in

**Milestone:** M26 ([G0 M26](../g0/M26.md) D405, D406, D409, D527, D528). **Audience:** identity teams and Org Admins. **Edition:** Enterprise to add or change; reads, removals, deprovisioning, disabling and sign-in on an ACTIVE connection work in every edition. **Build:** `pantherclaw-server-ee`, the core server with the enterprise package, with no billing and no console.

## SCIM

**Endpoint:** `https://<public-url>/v1/ext/scim/v2/`: Users, Groups, ServiceProviderConfig, ResourceTypes and Schemas. There is no Bulk, no sorting and no ETags. Bearer token only, also for the discovery endpoints, whose content is fixed.

### Tokens

- Create a token with `ProvisioningService.CreateScimToken`: a name, an issuer, a subject attribute (`userName` or `externalId`) and a lifetime of 1 to 366 days. The secret is shown once.
- **The token does nothing until a different person** holding `identity_provider.manage` confirms its activation on the change page. Revoking applies at once, even mid-request.
- A token's issuer must be one of the org's identity providers (OpenID or SAML, not disabled) or one of the deployment's, at creation and again at activation. It sees only that issuer's users and groups.
- The subject attribute is the SCIM attribute that holds what the user signs in with: for OpenID usually `userName` = the `sub` claim, or `externalId`; for SAML, the NameID.

### Requests

- Filters: only `attribute eq "value"`, on `userName` or `externalId` for Users and `displayName` or `externalId` for Groups. `userName` matches without case; the others match exactly. An empty value is refused (400 `invalidFilter`). At most 100 results a page.
- PATCH on Users: add or replace `active`, `userName`, `externalId`, `displayName`, `name.formatted` and `emails`.
- PATCH on Groups: add members, remove named members, `displayName` and `externalId`. Replacing or clearing every member by PATCH is refused (400): use PUT with the full list.
- A POST without `active` creates an active user; a PUT without `active` keeps the user's state.
- Concurrent creates of one group name: one succeeds, the others get 409.
- New users count against the plan's member limit.

### Editions

Creating and re-enabling users, changing their attributes, and adding groups and members need Enterprise (the org's own plan). Reading, deprovisioning, deleting and removing members work in every edition. Below Enterprise, a request that removes and also adds or changes applies only the removal, answers 200 with the stored resource, and records what it dropped as `audit.scim.parts_dropped`. A request with no removal is refused (403).

### Deprovisioning

- It ends the user's CLI and browser sessions at once.
- **API keys the user made before it stay active.** Each appears in the posture queue (source `provisioning`, kind `DEPROVISIONED_OWNER_KEY`) until someone rotates or revokes it, even if the user is enabled again.
- Deprovisioning the last Org Admin, or the last admin with a way to sign in, is refused (409) and recorded as `audit.scim.user_deprovision_refused`. A person must act in PantherClaw.
- SCIM re-enables only users SCIM disabled. A user a person disabled stays disabled until a person enables them.

### Groups and roles

- Groups sync freely. The roles a group carries are set in PantherClaw (`AddGroupRoleMapping`); adding and removing a mapping are held two-person changes.
- Org Admin, Security Admin, Scope Admin, Emergency Responder and any role that can bind roles can never be mapped.
- A group role and a role a person bound directly can both exist for one user. A group sync adds and removes only the group-given one.
- An identity-provider admin can still create identities that look like distinct people, and group changes take effect with no second person (R-08).

## SAML

- Sign-in is SP-initiated only. IdP-initiated responses are refused.
- **The IdP must sign the assertion itself.** A signed Response carrying an unsigned assertion is refused.
- Encrypted assertions are not supported: turn assertion encryption off in the IdP.
- One assertion per response. The audience must be our SP entity id, the response must answer our request within its time window, and each assertion id is accepted once.
- Keep the IdP's and the server's clocks in sync (NTP). There is no clock skew allowance; an AuthnInstant more than five minutes ahead of the server is refused.
- The sign-in must finish in the browser that started it: the cookie `__Host-pc_saml` rides the IdP's POST back. The public URL must be HTTPS.
- A connection signs in existing users only (created by SCIM or an invitation), whose issuer is `saml:<entity id>`. There is no just-in-time creation.

### Connections

- Name: 1 to 27 lowercase letters, digits or hyphens. The entity id never changes; make a new connection instead.
- Certificates: base64 DER (one line, no PEM header), 1 to 4 per connection, RSA 2048+ or ECDSA, unexpired. Add the new certificate before the IdP rotates, then remove the old one.
- Activating, changing and disabling a connection are held two-person changes. Disabling is refused when no admin would have a way left to sign in.
- URLs: login `https://<public-url>/app/ext/saml/<org>/<connection>/login`, ACS `.../acs` (HTTP-POST binding), metadata `.../metadata`. The SP entity id (the audience) is the metadata URL. Requests are sent unsigned over the redirect binding.

### Refused sign-ins

A refused response to a real sign-in is recorded as `audit.saml.sign_in_refused` with a reason: ENCRYPTED_ASSERTION, ASSERTION_SHAPE, ASSERTION_UNSIGNED, SIGNATURE_INVALID, AUDIENCE, TIME, IN_RESPONSE_TO, SUBJECT, MALFORMED or REPLAYED. A post with no sign-in started from that browser is refused and not recorded. The browser sees only a generic page.
