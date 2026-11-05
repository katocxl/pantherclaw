# Agent payments in a sandbox

**Milestone:** M39 ([G0 M39](../g0/M39.md) D1120–D1126; [ADR-0066](../adr/0066-agent-payments-verify-only.md)). **Audience:** a Security Admin setting up agent payments, and a developer trying them with the simulator. RPC and flag names below follow the brief; the M39 exit status records any change. **Edition:** Business.

PantherClaw verifies the AP2 mandates an agent presents and decides each payment; it never signs a mandate and holds no card, network token or payment credential (HR-830). **Sandbox only:** every trust anchor must be a sandbox anchor on an allow-listed host, and there is no live switch (HR-831).

## 1. How a payment is decided

1. The agent calls `agentpay.checkout.submit` (HTTP `POST /ap2/checkout` or the MCP tool `submit_checkout`) with `merchant`, `amount` (minor units), `currency`, `checkout_jwt` and `payment_mandate`, the AP2 envelope as JSON text:
   - v0.2: `{"checkout_mandate": <SD-JWT or [open, closed]>, "payment_mandate": <SD-JWT or [open, closed]>}`;
   - v0.1: `{"ap2.mandates.CartMandate": {...}, "ap2.mandates.PaymentMandate": {...}}`.
2. The gateway verifies the mandate against the org's ACTIVE trust anchors and reports the fact `payments.mandate {mandate_valid, amount_minor, currency, merchant, payee, mandate_digest}`. Policies never see the mandate itself.
3. The Authority's payment step refuses:

| Reason | When |
|---|---|
| `MANDATE_REQUIRED` | No mandate was sent |
| `MANDATE_INVALID` | The chain did not verify: a bad signature, an issuer or merchant that is not an ACTIVE anchor, a KB-JWT that is missing, stale or for another audience, an unknown constraint, a changed closed value, or an expired mandate |
| `MANDATE_MISMATCH` | The verified amount, currency or merchant is not exactly the action's (also audited `payments.mandate_refused` and raised as the alert `pc.payments.mandate_mismatch`) |
| `MANDATE_REPLAYED` | The same mandate (by digest) was already dispatched in the org; a mandate pays once, approved or not |
| `PAYMENTS_LIVE_REFUSED` | An anchor is not a sandbox anchor, or an anchor's or the connection's merchant endpoint host is not allow-listed; the connection's breaker trips and `security.payments_live_refused` is recorded |

4. Otherwise the payment waits for a person (HR-835). The approval shows the amount, currency, merchant, mandate digest and "mandate (N bytes)", and binds the digest: a different mandate needs a new approval (HR-837).
5. If an ACTIVE merchant cap allows it (section 4), the payment goes on without a person and counts toward the cap's day total.
6. After a successful submit the receipt carries `payments.effect` evidence: mandate digest, merchant, amount, currency, transaction id and outcome, never the mandate (HR-840).

An unknown outcome (a lost answer) is reconciled by a person; the merchant honours the `Idempotency-Key`, so a reconciled retry is not a second payment.

## 2. Add the trust anchors

A Security Admin (`payments.manage`) adds each anchor with `PaymentsService.CreatePaymentTrustAnchor`:
- `MANDATE_ISSUER`: the credentials provider that signs payment mandates;
- `MERCHANT`: each merchant whose `checkout_jwt` is accepted, named by its merchant id;
- `AGENT_DIRECTORY`: a Web Bot Auth directory or Visa key service, for agent request signatures.

Each anchor is a static JWKS or an https URL, must be marked sandbox, and starts PENDING. Activate it on `/integrations/payment-anchors/{id}/confirm` with a security key; the RPC Activate always answers `STEP_UP_REQUIRED` (HR-832). Revoke an anchor with `RevokePaymentTrustAnchor`; mandates from it then fail as `MANDATE_INVALID`.

## 3. Try it with the simulator

```
pantherclaw-sim agentpay                       # 127.0.0.1:9118
pantherclaw dev --gateway-out ... --agentpay-url https://127.0.0.1:9118
```

The dev seed adds `pc.agentpay` and the connection `agentpay` and prints the two anchors to add: `MANDATE_ISSUER` with the JWKS at `/cp/.well-known/jwks.json`, and `MERCHANT` `sim-merchant.example` with the JWKS at `/merchant/.well-known/jwks.json`. Activate both with a security key.

The simulator's credentials provider (`POST /cp/mandates`) returns a mandate envelope for a checkout from `POST /ap2/checkouts`; pass it as `payment_mandate`. Faults:
- `--mismatch`: mandates for one minor unit more than the checkout (expect `MANDATE_MISMATCH`);
- `--expired`: mandates that expired a minute ago (expect `MANDATE_INVALID`);
- `--decline`: every checkout answered as declined.

The simulator serves https on loopback with a development certificate that only the dev gateway trusts. The connection carries `merchant_audience`, the audience the mandate's KB-JWT must name. The simulator's keys are fixed development keys; everything it signs is SIMULATED.

## 4. Merchant caps

A cap lets payments to one merchant in one currency go on without a person, up to `max_per_payment_minor` each and `max_per_day_minor` per day.

1. A person with `payments.manage` calls `PaymentCapService.ProposePaymentCap {merchant, currency, max_per_payment_minor, max_per_day_minor}`. The cap is DRAFT and a policy change request of kind `PAYMENT_CAP` is opened.
2. Two distinct people confirm the change request with security keys (HR-836). If the org cannot supply two, the request is voided with `TWO_PEOPLE_REQUIRED` and the cap stays DRAFT.
3. On confirmation the cap becomes ACTIVE and replaces any earlier ACTIVE cap for that merchant and currency (audited `payments.cap_activated`, `payments.cap_retired`).
4. `ListPaymentCaps` (`payments.read`) lists caps; `RetirePaymentCap` retires one at once. Retiring is a tightening and needs no second person.

Only cap-allowed payments count toward the day total (a budget owned by the cap, grouping `merchant`). A payment over either limit waits for a person; it is never refused for being over a cap.

## 5. Agent request signatures (merchant customers)

A merchant backend calls `PaymentsService.VerifyAgentSignature` with the request's method, authority, path, headers and body (at most 64 KiB). The answer gives valid, anchor, keyid, tag and agent claims; each check is audited `payments.agent_signature_checked`. Signatures need `@authority` and `@path`, a window of at most 480 s and a fresh nonce; keys come only from ACTIVE `AGENT_DIRECTORY` anchors (HR-838). Mastercard agentic tokens are not verified by PantherClaw (R-93).

## 6. Troubleshooting

| Seen | Check |
|---|---|
| Every payment `MANDATE_INVALID` | Both anchors ACTIVE; the mandate not expired; the KB-JWT's audience is one PantherClaw accepts; the clock |
| `MANDATE_MISMATCH` | The agent's amount (minor units), currency and merchant against the mandate's; an alert is raised for each |
| `PAYMENTS_LIVE_REFUSED` and a quarantined connection | An anchor that is not a sandbox anchor or a host outside the allow-list; fix the anchor, then restore the connection |
| Payments still wait for a person with a cap | The cap ACTIVE (not DRAFT); the same merchant id and currency; the amount and the day's total within the limits |
| A cap request voided `TWO_PEOPLE_REQUIRED` | The org needs at least two people who can confirm policy changes |
