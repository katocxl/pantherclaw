# Hosted OIDC provider outage

**Milestone:** UI ([G0 UI](../g0/UI.md) D8, D11; [ADR-0031](../adr/0031-hosted-accounts-per-org-plans-and-test-seams.md); R-48). **Audience:** the operator of a hosted deployment. Self-hosted deployments sign in through the customer's own IdP and are not affected by the hosted provider.

The hosted control plane signs people in through a hosted OIDC provider, which the core treats as an ordinary OIDC provider (authorization code with PKCE, nonce and issuer checks, HR-152). When the provider is down or unreachable, **sign-in is down; enforcement is not**.

## What still works

- Gateways keep enforcing and the Authority keeps deciding: agents, the CLI with existing tokens, service accounts and API keys are unaffected, because none of them use the hosted provider at request time.
- People who are already signed in keep their browser sessions until the idle or absolute timeout; security-key step-ups and approvals on the approval page keep working for them (step-up uses the person's registered key, not the provider).
- The kill switch already engaged stays engaged; engaging it from the CLI with an existing credential works.

## What does not

- New sign-ins, sign-ins after a session expires, switching organization (a fresh sign-in, HR-353), accepting invitations and creating organizations.
- `pclaw login` for people whose CLI token has expired.

## Steps

1. **Confirm it is the provider.** The provider's status page; the server's sign-in errors (discovery or token endpoint failures, timeouts). A failure of only one sign-in method (for example one social login) is the provider's, not PantherClaw's.
2. **Tell users.** Post a status note: sign-in is unavailable, agents and enforcement are unaffected, stay signed in if you are.
3. **Keep incident response possible.** Responders who need to act and are signed out use the CLI with an existing token, or a service account for the actions that need no person (never weaken a rule to let them in). If an approval is urgent and no eligible approver is signed in, it waits or expires as designed; it is never decided another way.
4. **Do not switch providers in a hurry.** Accounts are keyed by issuer and subject and are never linked across issuers by email (HR-348), so a second provider would create new, empty accounts. A planned second provider is a configuration change made after review, not an outage step.
5. **After recovery,** check that sign-in works end to end (a test account signs in, picks an organization, passes a step-up), and record the incident and its duration.
