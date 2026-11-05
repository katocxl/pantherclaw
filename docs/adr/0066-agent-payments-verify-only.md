# ADR-0066 — Agent payments, verify only

**Status:** Proposed (2026-11-05; the [G0 M39](../g0/M39.md) brief records the coordinator decisions D1120–D1126). A stub: it is completed when M39's code is tested.

**Context.** Agents are starting to pay merchants with mandates their person signed: AP2 carries a merchant-signed checkout and a payment mandate issued by the person's credentials provider, and the card networks add agent request signatures (Visa TAP, Mastercard Web Bot Auth). PantherClaw already decides every agent action, but it had no payment-class action, no way to check that a mandate says what the agent asks to pay, no merchant grouping for budgets, and only Stripe test mode for money movement.

**Decision.**
1. **Verify, never sign** (HR-830, HR-839; FQ39-1). PantherClaw verifies mandates and agent signatures against the org's trust anchors. It never signs a mandate for a person and stores no card, network token or payment credential; instrument fields are digests only. Agentic network tokens are never proof.
2. **Sandbox only** (HR-831, HR-832). Every trust anchor is a sandbox anchor on an allow-listed host, activated with a security key. Anything else is `PAYMENTS_LIVE_REFUSED` and trips the breaker. There is no live switch.
3. **The full chain before a decision** (HR-833, HR-838). SD-JWT with KB-JWT holder binding, AP2 v0.2 open → closed chains (unknown constraints fail) and v0.1 cart and payment mandates; RFC 9421 signatures with a short window, nonces and anchor-only key discovery.
4. **The mandate must match exactly** (HR-834). The verified amount, currency and merchant must equal the action's params, else `MANDATE_MISMATCH`; a missing or invalid mandate is refused before any approval.
5. **Held for a person by default** (HR-835, HR-837; FQ39-2). Every payment needs an approval that binds the mandate digest, unless an ACTIVE merchant cap allows it.
6. **Caps are a loosening** (HR-836). A cap becomes ACTIVE only through a two-person `PAYMENT_CAP` change request with security keys; cap-allowed payments count toward a daily `merchant` budget, and over the cap holds for a person.
7. **Digests in receipts** (HR-840). Evidence and audits carry the mandate digest and verified facts, never the mandate.

**Consequences.**
- AP2 is pre-1.0; formats may change and need a documented update (R-94).
- Agentic network tokens stay unverified by PantherClaw (R-93).
- Live payments need a later decision, a new ADR and new tests; nothing in M39 can be switched to live.
- A payment is slower by default: a person approves it unless the org sets a cap.

**Alternatives.**
- Signing mandates for a person or holding payment credentials (FQ39-1 chose verify only).
- Letting payments under a policy amount through with no person by default (FQ39-2 chose holding by default with per-merchant caps).
- Accepting a mandate whose amount is at most the params' (rejected: an exact match only).
- Discovering keys at hosts a request names (rejected: anchors only).
- A live mode behind a setting (rejected: sandbox only in M39).
