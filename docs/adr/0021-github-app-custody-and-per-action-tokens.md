# ADR-0021 — GitHub App custody and per-action installation tokens

**Status:** Proposed (2026-10-11; G0 M8 decision 3, answered by the founder with the recommended option; accepted with the [G0 M8 brief](../g0/M8.md))

**Context.** For coding agents, the strongest route around PantherClaw is a reusable GitHub credential: a personal access token, an SSH key, a `gh` login or an App's private key. Any of them lets an agent merge, push or change settings directly. The product promise (§39 of the product specification) is that inside an enforced boundary the agent holds no reusable target authority that can defeat a decision, and that people can see where access comes from without seeing a secret. GitHub Apps fit that promise:
- the App's RSA private key signs a short JWT (RS256, at most 10 minutes);
- the JWT buys an installation access token (valid for one hour), which can be narrowed at creation to chosen repositories and to a subset of the installation's permissions;
- a token can be revoked with `DELETE /installation/token`.

GitHub's newer stateless installation tokens (`ghs_`) are about 520 characters long and carry structure that GitHub may change. Founder decision 3 (2026-10-11): the App's private key is sealed to the gateway; for each authorized action the gateway mints a token scoped to one repository and the operation's minimum declared permissions and revokes it after dispatch; the agent never sees the token; tokens are opaque.

**Decision.**
1. **Custody.** A connection of kind HTTP with credential kind `github_app` holds the App id and the RSA private key (PEM) as one sealed credential. It is HPKE-sealed to the broker key of the gateway that serves the connection, with the M6 binding of org, connection, credential version, allowed hosts, broker key and placement (HR-060, HR-182). The installation id and the GitHub organisation are connection configuration, not secrets. The key is opened only in that gateway's memory, to sign App JWTs: `iss` is the App id, `iat` is 60 seconds in the past, and `exp` is at most 10 minutes after `iat`. A JWT may be reused for later mints until 1 minute before it expires. It is never written down, logged or returned (HR-204).
2. **One token per action.** After `BeginDispatch`, the broker asks GitHub for a token with exactly `repository_ids: [<the action's repository id>]` and `permissions` set to the operation's minimum declared in the pinned package (`github.permissions` per operation, for example `pull_requests: write` and `contents: write` for a merge). It uses the token for that dispatch only, then revokes it (HR-203). Verification reads (M7), fact reads and the org scan mint their own read-only tokens in the same way, one lease at a time.
3. **Fail closed on scope.** GitHub answers with the permissions and repositories it granted. If either is wider than requested, or the repository id differs, the gateway revokes the token and does not dispatch. The outcome is `failed` with `CREDENTIAL_SCOPE_MISMATCH`, and nothing has been sent to the target.
4. **Opaque tokens.** Tokens are never parsed, and no length or format is assumed. Header limits on egress allow at least 4 KiB per header, and secret-echo redaction (HR-076) covers the exact token bytes of the dispatch that used them, not only a `ghs_` prefix pattern.
5. **Never seen by the agent.** No token, JWT or key is in any API response, log, job argument, receipt or capture. The execution receipt records only access metadata: the installation, the repository id, the permissions requested and granted, the expiry GitHub stated, and the revocation result. That is the "access detail" of §39.3, without the secret.
6. **Revocation is best effort.** A failed `DELETE` is retried once and then recorded (`credential.revoke_failed`, an audit event and a metric). The token still expires within the hour GitHub set. The receipt says which happened.
7. **GitHub REST version.** Requests send `X-GitHub-Api-Version: 2022-11-28`, `Accept: application/vnd.github+json` and a fixed `User-Agent`. A move to a later version is a package and gateway change with golden tests.

**Consequences.**
- An agent behind the gateway can only do what an authorized action allows. Even a stolen token reaches one repository, with one operation's permissions, for at most an hour, and normally for the length of one dispatch.
- Every action costs two extra GitHub calls (mint and revoke): about 100–300 ms, and the App's rate limits. The circuit breaker (HR-078) and the reconciliation path apply when GitHub's token endpoint fails. A mint failure before dispatch is `failed`, never `UNKNOWN`.
- GitHub attributes the change to the App (`<app>[bot]`), not to a person. Attribution to the agent, the run and the approvers comes from PantherClaw's receipts, which name the transaction.
- Branch rulesets still apply to the App. Customers must not give the App a ruleset bypass; the org scan reports one (PN-001.2).
- The installation's real permissions are visible to PantherClaw, so M9 can compare them with what operations use (F048).

**Alternatives considered.**
- Caching one installation token per connection: rejected. It is reusable authority for an hour, broader than any single action, and a leak exposes every repository the installation reaches.
- Holding a personal access token: rejected. It is bound to a person, cannot be narrowed per call, and outlives any decision.
- Giving the agent a short-lived token: rejected. A token the agent holds is reusable for its whole life and defeats §39.1; the decision would no longer bound the effect.
- User-to-server (OAuth) tokens acting as the developer: deferred. They tie GitHub authority to a person's account, which is the opposite of custody; they may come back for "on behalf of" flows after v1.0.
