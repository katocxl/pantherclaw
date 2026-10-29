# ADR-0038 — Consequence chains, customer consequence rules and new verifier kinds

**Status:** Accepted (2026-10-29). It rests on the G0 M17 founder decisions G1 and G2, each answered with the recommended option. The [G0 M17 brief](../g0/M17.md) records them together with the coordinator's design decisions. It builds on M8's stored consequence rules (HR-206) and on M3's pinned-claims trusted issuers ([ADR-0018](0018-federated-workload-identity-and-represented-principals.md), HR-140..143). Azure managed identity and Entra Agent ID are not decided here (D122, an open founder decision).

**Context.**
- *Consequences.* Since M8, a package's consequence rules predict one hop: a merge to `main` triggers a production deploy. That prediction raises requirements at decision time. Nothing verifies it afterwards:
  - a predicted consequence without a definition, verifier, environment or captured value is skipped without a trace;
  - a parent transaction has no downstream state;
  - follow-on work cannot wait for one.

  Customers cannot add rules for their own systems. A chain (merge → deploy → migration) cannot be expressed at all.
- *Identity.* L2 attestation accepts only GitHub Actions and Kubernetes. The verifier is shaped around GitHub's claims, and an attestation's kind is dispatched with a default case.

**Decision.**
1. **Consequences are verified as their own transactions** (D102–D104; HR-450..452).
   - A confirmed parent opens a transaction for each depth-1 PREDICTED consequence it can verify. Each PREDICTED consequence it cannot verify is audited as not verifiable.
   - The parent gets a downstream state: PENDING, CONFIRMED, UNCONFIRMED or NOT_VERIFIABLE.
   - Downstream CONFIRMED comes only from the consequences' own evidence, over the whole chain below the parent. It appends a `downstream` effect receipt with basis `consequence`. No earlier receipt is rewritten.
   - Automations wait on it (`wait_effect` with `consequences: true`). Policy reads `run.consequences_pending` and `run.consequences_unconfirmed`.
2. **Customers can add consequence rules, only to add requirements** (G1; D106–D108; HR-453, HR-454).
   - Rules have ids `cx.*` and live in `pc.customer_consequence_rules`, one ACTIVE version per id.
   - Every change goes through `protect` as a two-person change, in every protect mode, OFF included.
   - Customer rules are evaluated after the package rules, and their results are added to them. They cannot reference, replace or suppress a package rule, turn an UNKNOWN into NOT_TRIGGERED, or be waived by an exception.
   - Team edition. Package rules stay in every edition.
3. **Consequences chain within bounds** (D109–D111; HR-455..457).
   - A PREDICTED consequence becomes the next hop's (operation, target). Every hop is a named rule over verified facts about that target.
   - Depth is at most 4 (per-rule `max_depth`, default 1). There are at most 16 consequences per action; past that, the result is UNKNOWN `CONSEQUENCE_FANOUT`.
   - A visited set stops cycles. An UNKNOWN hop is not expanded and stays at least a HOLD. An expired rule yields UNKNOWN.
   - Each consequence carries a derived label (MAY_CAUSE, AUTHORIZED, UNKNOWN, NOT_TRIGGERED, ACCEPTED, CONFIRMED) and an explanation that names facts but never their values. Recordings pin every rule id of a chain.
4. **One verifier per attestation kind** (G2; D118–D121; HR-461..465).
   - The verifier is refactored into one implementation per kind. An unknown kind is refused.
   - Issuer keys support RSA-PSS and EC algorithms from per-preset lists, and come from one of three key sources: discovery, a pinned JWKS URL, or a static JWKS from operator configuration.
   - Four Enterprise kinds are added, each with built-in rules that configuration cannot disable:
     - `gitlab_ci`: operator-configured issuers, protected refs only, no merge-request pipelines, numeric ids;
     - `spiffe_jwt`: operator-configured trust-domain bundles, an exact SPIFFE ID, a matching trust domain;
     - `gcp_workload`: a pinned Google key URL, the numeric service-account id;
     - `aws_iam`: a presigned `GetCallerIdentity` to allow-listed STS hosts, with a signed `x-pantherclaw-audience` header, at most 15 minutes old, single use, replayed through the egress client.
   - HR-140 and HR-143 are unchanged for all four.

**Consequences.**
- A merge whose deploy was never verified can now hold follow-on work, instead of passing on the merge's acceptance alone. Packages without a read for the consequence object still report NOT_VERIFIABLE, now visibly.
- Decisions with chains do more reads. The depth and fan-out caps bound them, and replay stays deterministic because rule ids and definition digests are pinned.
- Customers can encode their own downstream systems without loosening anything. Two people are needed for every rule change, even with protection OFF.
- Old recordings (v1, v3) still replay, and old receipts still verify. The new receipt fields are optional.
- New workload platforms attest without code paths shared with GitHub's. Azure and Entra stay out until the founder decides whether their audiences and 24-hour tokens may relax HR-140 and HR-143 for those presets. L3 (X.509 SVIDs, instance identity) waits for a PAP-1 revision.

**Alternatives.**
- Customer rules that may also loosen (rejected by G1).
- Customer rules behind the ordinary protect category mode, where OFF would let one person change them.
- Unbounded chains, or chains derived from observed causality instead of named rules (the model never invents causality, F405).
- Downstream state inferred from the parent's acceptance.
- Generic OIDC issuers configured entirely by the customer, without built-in preset rules (T-044).
- AWS attestation through an IAM-signed JWT broker instead of a presigned STS request (another service to run and trust).
