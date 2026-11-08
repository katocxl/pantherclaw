# Federate with a peer organization

Federation lets your agents message a trusted peer organization's listed agents, and the peer's agents message yours, through each side's PantherClaw gateway (G0 M35; [ADR-0062](../adr/0062-federation-and-infrastructure-attestation.md); HR-770..776). Each side decides every call under its own grants and policy. A peer's agent may only send A2A messages to the agents you list and name in a cross-org grant; it gets no tool or data access (founder decision FQ35-1). Enterprise edition.

What a peer sees of your decisions is a minimal signed receipt: the decision, ids, time and the request digest, never your checks, reasons or policy (FQ35-2, R-87). A peer's claimed attestation level is trusted as the peer states it (R-86): require a level in the cross-org grant only for peers whose attestation you accept.

## What you set up

- **A federation endpoint:** your gateway's public HTTPS URL, which peers call at `/fed/a2a/{listing}`.
- **A trust per peer org**, proposed from the peer's federation document and confirmed by an admin on each side with a security key.
- **Listings:** the agents a peer may message, each with the a2a connection that reaches it and the skills offered.
- **Cross-org grants:** which peer agent may use which listing, for which operations, until when.
- **Outbound connections:** an a2a connection whose federation peer names a trust and the peer's listing.

Commands need a person with `federation.manage` (`org_admin` or `security_admin`); reads need `federation.read`. Issuing a cross-org grant also needs the grant-issuing permission.

## 1. Your endpoint and document

```bash
pclaw federation endpoint https://gateway.example.com
pclaw federation doc
```

Your federation document is public at `<server URL>/.well-known/pantherclaw/orgs/<org id>/federation.json`. It is a JWS signed by your org's federation key and names your org, your server and endpoint URLs, your keys and your listed agents. It never names your trusted peers, and it expires within 7 days, so the server reissues it.

Rotate the key with `pclaw federation rotate` (your security key is needed). The old key stays RETIRING for 7 days and signs the document beside the new one, so peers pin the new key without a new confirmation.

## 2. The trust

Both admins run the same steps, each against the other's document:

```bash
pclaw federation trust propose https://pantherclaw.peer.example/.well-known/pantherclaw/orgs/<peer org id>/federation.json
pclaw federation trust show <trust id>      # shows the safety code: 5 groups of 4 characters
```

Compare the safety code with the peer's admin out of band (a call, or a meeting): both sides compute the same code from both orgs' keys. If it differs, do not confirm: revoke and start again. When it matches:

```bash
pclaw federation trust confirm <trust id>   # needs your security key
```

The trust becomes ACTIVE only when both sides confirmed. Until then calls are refused (`FEDERATION_NOT_TRUSTED`). `pclaw federation trust list` shows each trust's state: PROPOSED, CONFIRMED_LOCAL, ACTIVE, STALE or REVOKED.

The server refreshes each trust daily. A peer key change is pinned only when a key you already pinned also signed the new document; otherwise the old keys stay and the audit records `federation.peer_rotation_unverified`. A document that expired or cannot be fetched makes the trust STALE, and a stale trust refuses every call until a refresh succeeds.

## 3. Listings and cross-org grants (inbound)

List an agent the peer may message, with the a2a connection whose peer is that agent and the skills offered:

```bash
pclaw federation listing create support-desk --agent <agent id> --connection <a2a connection id> --skill answer-ticket
```

The listing's signed card is public at `https://gateway.example.com/fed/a2a/support-desk/.well-known/agent-card.json`. Then let one of the peer's agents use it:

```bash
pclaw federation grant issue <trust id> --peer-agent pc:org/<peer org>/agent/<peer agent> --listing support-desk \
  --op federation.message.receive --op federation.task.read --expires-at 720h
```

A grant lasts at most 90 days. Your policy decides every call, and holds wait for your people: the peer's agent is told the message is held for your approval and asks again later. Revoke with `pclaw federation grant revoke <grant id> --reason "..."`, or revoke the whole trust, which takes effect at once:

```bash
pclaw federation trust revoke <trust id>
```

## 4. Messaging a peer's agents (outbound)

```bash
pclaw federation peers <trust id>
```

lists the peer's listed agents. One is verified only when the trust is ACTIVE and the peer document, the card's digest and the card's signature all check under the pinned keys. Create an a2a connection whose federation peer names the trust and the listing; its URL and card come from the peer's document, so no person pins the card. Your agents then send to it like any other a2a connection, under your grants. The gateway sends each message with a short-lived token bound to that exact request.

If the peer holds or refuses a message, the dispatch fails with `PEER_HELD` or `PEER_DENIED`, and your agent is told the receiving organization held or refused it.

## 5. Receipts

```bash
pclaw federation receipts --trust <trust id>
```

lists the receipts both sides keep: OUT receipts are the peer's answers to your messages, IN receipts are the peer's tokens your decisions were made on. A missing or invalid peer receipt leaves the dispatch outcome as sent and counts in `pc_federation_receipt_problems_total`.

## 6. When something goes wrong

| Code | Meaning | What to do |
|---|---|---|
| `FEDERATION_NOT_TRUSTED` | No ACTIVE trust for that org, or it was revoked | Check `pclaw federation trust list`; confirm on both sides |
| `FEDERATION_PEER_STALE` | The peer's document expired or could not be fetched | Ask the peer to check its server; refresh after |
| `FEDERATION_TOKEN_INVALID` | The token is unsigned by a pinned key, expired, or not for this exact request | Check both gateways' public URLs and clocks |
| `FEDERATION_REPLAY` | The token was used before | The sender retries with a new token |
| `FEDERATION_SAFETY_CODE` | The peer's confirmation names another safety code | Revoke and propose again; compare codes out of band |
| `FEDERATION_KEY_UNVERIFIED` | A peer key change was not signed by a pinned key | Confirm with the peer's admin out of band; propose a new trust if the key change is theirs |
| `FEDERATION_LISTING_UNKNOWN` | No ACTIVE listing of that name | Check `pclaw federation doc` |
| `FEDERATION_METHOD_NOT_DECIDED` | A method other than SendMessage, GetTask or CancelTask | Only those three are taken |
| `FEDERATION_EDITION` | Federation needs the Enterprise edition | Check the licence |

The dev seed can make a second org on one dev server: `pantherclaw-server dev seed --gateway-out A.json --federation-peer-gateway-out B.json` prints the steps above for both orgs. The server and both gateways must be reachable over HTTPS.
