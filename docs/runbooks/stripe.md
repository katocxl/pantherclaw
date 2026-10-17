# Stripe in test mode

**Milestone:** M14 ([G0 M14](../g0/M14.md) D12–D14, D48–D52; [ADR-0028](../adr/0028-business-connectors-and-data-scoping.md)). **Audience:** an Org Admin connecting Stripe, and the founder running the live test. Command flags below follow the brief; the M14 exit status records any change.

`pc.stripe` 1.0.0 lets agents create and read refunds, payment intents and transfers in **Stripe test mode only**. Live mode is not supported in M14 (R-43): every write is refused before sending unless the sealed key is a test key, a refund on a live-mode payment is refused, and any Stripe answer that reports live mode quarantines the connection (HR-301, HR-303).

## 1. What the package does

| Operation | Stripe call | Kind | Effect check |
|---|---|---|---|
| `stripe.refund.create` | `POST /v1/refunds` | irreversible | `GET /v1/refunds/{id}`: `pending`, `requires_action` → pending; `succeeded` → CONFIRMED; `failed`, `canceled` → NONE_CONFIRMED; within 600 s |
| `stripe.payment_intent.create` | `POST /v1/payment_intents` (confirmed, off-session, card) | irreversible | `processing` → pending; `succeeded` → CONFIRMED; `requires_payment_method`, `requires_action`, `canceled` → NONE_CONFIRMED |
| `stripe.payment_intent.cancel` | `POST /v1/payment_intents/{id}/cancel` | write | `canceled` → CONFIRMED |
| `stripe.transfer.create` | `POST /v1/transfers` | irreversible | `GET /v1/transfers/{id}`: not reversed and the same amount → CONFIRMED |
| `stripe.refund.read`, `stripe.payment_intent.read`, `stripe.transfer.read`, `stripe.balance.read` | `GET` | read | — (billing details, receipt email and shipping are `pii`) |

What the gateway does on every call:
- **Test key only.** Each definition carries the credential pattern `^(sk|rk)_test_[A-Za-z0-9]{16,}$`, checked on the opened credential before any byte is sent; a mismatch is `CREDENTIAL_PATTERN` and Stripe receives nothing.
- **Live-mode answers.** If any Stripe answer or verifier read reports `livemode: true`, the gateway records the security audit event `security.stripe_livemode`, the admins are notified, and the connection's circuit opens until an admin closes it.
- **Form bodies rebuilt from the decision.** Stripe takes `application/x-www-form-urlencoded`; the gateway rebuilds the body from ActionIR (sorted keys, strict bracket syntax) and sends amounts in minor units (`usd` 2 decimals, `jpy` 0; other currencies outside the fixed table are refused).
- **Pinned API version** `Stripe-Version: 2026-09-30.endive`.
- **Idempotency.** `Idempotency-Key: pc-<transaction>` and `metadata[pantherclaw_key]` with the same value on every write (HR-304). A retry of the same transaction replays; a lost answer becomes UNKNOWN, is never retried, and is correlated through that metadata key (HR-305).
- **Refundable amount.** A refund needs the fact `stripe.payment.refundable`, read by the gateway at most 60 s earlier. The refund amount must be at most the remaining refundable amount in the same currency (`CURRENCY_MISMATCH` otherwise), and a payment with `livemode: true` is refused.
- **Recently changed payees.** A transfer needs the fact `stripe.account.payout_details_changed`, read through the Events API (`account.external_account.*` events on the connected account within 7 days). If the payee changed recently, the `payee_changed_recently` consequence applies; if the events cannot be read, the fact is UNAVAILABLE and the treasury template holds the transfer for a second approver (HR-306).

## 2. Create a restricted test key

In the Stripe Dashboard, in **test mode**:
1. Developers → API keys → **Create restricted key**.
2. Permissions: **write** on Refunds, PaymentIntents and Transfers; **read** on Charges, Balance, Connected accounts and Events. Nothing else.
3. Copy the `rk_test_…` value into a file outside the repository (for example `~/.pantherclaw/stripe-test.key`). Never paste it into chat or a ticket.

For transfers you also need a connected account (Connect, test mode) to act as the destination.

## 3. Connect it

The gateway that will hold the key must have registered its broker key ([gateway runbook](gateway.md)).

```bash
pclaw connection create stripe --kind http --gateway <gateway id> --package pc.stripe --base-url https://api.stripe.com \
  --access pantherclaw_held --header Authorization --scheme Bearer --default-mode enforce
pclaw seal --connection <connection id> --from-file ~/.pantherclaw/stripe-test.key --fingerprint <broker key fingerprint>
```

Then delete the key file. `pclaw connection test <connection id>` should report the connection ready. To rotate, create a new restricted key, seal it (the new version supersedes the old) and roll the old key in Stripe.

Grant refunds with a money bound and, for transfers, a destination set of `acct_…` payees. The customer-support and treasury-payments templates ([G0 M14](../g0/M14.md) D40) are the starting points.

## 4. Development and CI

The simulator `pantherclaw-sim stripe` is Stripe-shaped: form bodies, Bearer test keys only, `livemode: false` on every object, Stripe's error envelope and idempotency rules. It also has faults for latency, declines, lost answers, settle-after, fail-after-pending and a recent bank change.

```bash
pantherclaw-server dev seed --stripe http://127.0.0.1:<sim port>
```

This creates the connection, seals a test key, pins the package and issues a demo grant: refunds of at most USD 100.00, held above USD 50.00, with a one-refund budget. `TestE2E_M14_StripeRefunds` and range scenarios RT-039..RT-041 run against the simulator.

## 5. The live test (founder, opt-in)

`task test:stripe-live` runs one refund, one payment intent and one transfer against real Stripe test mode through a local gateway, and prints the transaction ids. Nothing runs it automatically, and it skips without its variables.

```bash
export PC_TEST_STRIPE_KEY="$(cat ~/.pantherclaw/stripe-test.key)"
export PC_TEST_STRIPE_CONNECTED_ACCOUNT=acct_...
go tool -modfile=tools/pins/task/go.mod task test:stripe-live
```

Check the printed transactions in the Stripe Dashboard (test mode) and with `pclaw verify` on their receipts.

## 6. Troubleshooting

| Symptom | Cause | Action |
|---|---|---|
| `CANNOT_AUTHORIZE` `CREDENTIAL_PATTERN` | The sealed key is not a test key | Seal an `rk_test_…` key; live keys are never accepted |
| Connection circuit open after `security.stripe_livemode` | Stripe answered with a live-mode object | Treat it as a security event: check which key is sealed and what Stripe account it belongs to, seal a test key, then close the circuit |
| Refund `CANNOT_AUTHORIZE`, fact stale or missing | The refundable read failed or is older than 60 s | Check the key's Charges read permission and the gateway's reach to Stripe |
| `CURRENCY_MISMATCH` | The refund currency differs from the payment's | Refund in the payment's currency |
| Transfer held with `payee_changed_recently` or an UNAVAILABLE fact | The payee changed bank details within 7 days, or Events cannot be read | Confirm the payee out of band before a second approver approves; grant Events read |
| Effect UNKNOWN | The answer was lost | Do not retry by hand; resolve the reconciliation entry after checking `metadata[pantherclaw_key]` in Stripe |
