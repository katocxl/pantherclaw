# Runbook — Shared Signals (CAEP and RISC) from your IdP

**Milestone:** M10 · **Owner:** the org's Security Admin (`signals.manage`) · **Edition:** Business · **Status:** procedure written from the [G0 M10 brief](../g0/M10.md) (D37–D39); tested at the M10 exit.

Your identity provider can push security events (SETs) about your people: a revoked session, a disabled account, a compromised credential. PantherClaw opens a case for each event about a known person. With the identity playbook enabled, it also contains that person. Background: [g0/M10.md](../g0/M10.md), [ADR-0019](../adr/0019-standards-at-the-edges.md), [ADR-0026](../adr/0026-reflex-detection-containment-and-signals.md), HR-261, HR-262, R-30.

## 1. Configure a transmitter

1. Create a transmitter through the `shared_signals.proto` API (`signals.manage`, a person) with:
   - the issuer (the IdP's `iss`);
   - the `jwks_uri`, which must be on the issuer's host;
   - the audience, by default the endpoint URL.
2. The transmitter is created **PENDING**. A person opens its confirmation page and confirms with a security key; it becomes **ACTIVE**.
3. In the IdP, set the push endpoint to `https://<your PantherClaw>/v1/ssf/{org}/{transmitter}` (RFC 8935 push delivery) and the audience you configured.
4. Send a verification event from the IdP. PantherClaw acknowledges SSF `verification` events.

## 2. What PantherClaw accepts

A SET is accepted (202) only when all of these hold:
- the transmitter is ACTIVE and the path names it;
- `Content-Type: application/secevent+jwt`, body at most 64 KiB, within the per-transmitter rate limit;
- signed with RS256 or ES256 by a key from the pinned JWKS (cached 15 minutes; an unknown `kid` refetches at most once a minute). Headers `jku`, `x5u` and `jwk` are refused: keys never come from the token;
- `iss` is the issuer; `aud` contains the audience; `iat` is within ±5 minutes; the `jti` was not seen from this transmitter in the last 7 days; exactly one event.

Otherwise the answer is 400 with an RFC 8935 error code: `invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience` or `authentication_failed`. Errors never say whether a subject matched a person.

Events handled: CAEP `session-revoked`, `credential-change`; RISC `account-disabled`, `account-purged`, `credential-compromise`, `account-credential-change-required`. Other event types are recorded and ignored.

Subjects (`sub_id`) in the formats `email`, `iss_sub` and `opaque` are matched to a person: `iss_sub` against the person's linked OIDC identity first, and only when its issuer is the transmitter's configured issuer (otherwise it counts as an email-grade match or none); an email only for an ACTIVE person whose email is unique. The match basis is recorded. An email match only opens a case; the identity playbook acts on `iss_sub` matches only. An event with no match is recorded and opens nothing.

## 3. What happens on an event

Without the playbook (the default): a case opens with the event, listing the grants the person issued, approved or is represented in, and their waiting approvals. A responder decides what to do ([incident-response.md](incident-response.md)). Nothing is contained automatically.

With the identity playbook enabled, for the event types it lists and a subject matched by `iss_sub`:
- a principal DENY_ALL containment control is added for the person, and controls for the grants they issued (nothing wider; the server computes and stores the preview);
- the waiting approvals they requested or must decide are voided;
- the case links all of it.

The controls are ordinary containment controls: they show per-path status and are lifted only through restoration, with an independent reviewer.

## 4. Enable, change or disable the playbook

1. Request the change (ENABLE or CHANGE, with the event types) through the `shared_signals.proto` API (`signals.manage`).
2. **Two different people, each with their own security key**, confirm it on `/integrations/playbook/{id}/confirm`. Each confirmation is a BINDING ceremony over the request; the same person or the same key twice is refused.
3. Disabling needs one person's confirmation.
4. Every change sends `signals.playbook_changed` and is audited.

Enable the playbook only when you trust the IdP to report compromise faster than people can react. A compromised IdP could send events that contain people (R-30); that containment is reversible, and every SET is kept with its issuer and `jti` for the investigation.

## 5. Troubleshooting

- **400 `invalid_key`:** the key is not in the pinned JWKS, the algorithm is not RS256 or ES256, or the token carries key headers. Check the IdP's signing key and that `jwks_uri` serves it.
- **400 `invalid_issuer` or `invalid_audience`:** compare the token's `iss` and `aud` with the transmitter's configuration.
- **400 `invalid_request`:** wrong content type, more than one event, a body over 64 KiB, `iat` outside ±5 minutes, or a reused `jti`. Check the IdP's clock.
- **No case opened:** the subject did not match a person, or the event type is not handled. The received events list shows each SET and its outcome (`signals.read`).
- **Rotating the IdP's key:** publish the new key in the JWKS before signing with it. An unknown `kid` triggers a refetch, at most once a minute.
