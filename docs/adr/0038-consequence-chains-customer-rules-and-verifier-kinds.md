# ADR-0038 — Consequence chains, customer consequence rules and new verifier kinds

**Status:** Accepted (2026-10-29). It rests on the G0 M17 founder decisions G1 and G2, each answered with the recommended option, and G18, answered against the recommendation. The [G0 M17 brief](../g0/M17.md) records them together with the coordinator's design decisions. It builds on M8's stored consequence rules (HR-206) and on M3's pinned-claims trusted issuers ([ADR-0018](0018-federated-workload-identity-and-represented-principals.md), HR-140..143).

**Context.**
- *Consequences.* Since M8, a package's consequence rules predict one hop: a merge to `main` triggers a production deploy. That prediction raises requirements at decision time. Nothing verifies it afterwards:
  - a predicted consequence without a definition, verifier, environment or captured value is skipped without a trace;
  - a parent transaction has no downstream state;
  - follow-on work cannot wait for one.

  Customers cannot add rules for their own systems. A chain (merge → deploy → migration) cannot be expressed at all.
- *Identity.* L2 attestation accepts only GitHub Actions and Kubernetes. The verifier is shaped around GitHub's claims, and an attestation's kind is dispatched with a default case. Azure managed identity and Entra Agent ID tokens cannot meet HR-140 and HR-143 as written: their audience is an Entra application, never `pantherclaw:<org>`, and they live about 24 hours, not at most 1.

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
5. **Azure and Entra attest under a narrow relaxation** (G18; D129; HR-469).
   - Two more Enterprise kinds: `azure_mi` (pins `tid` and the managed identity's `oid`, optionally `xms_mirid`; `idtyp` must be `app` when present) and `entra_agent_id` (pins `tid`, the agent identity's `oid`, and the claim that marks an agent identity).
   - For these two kinds only, HR-140 and HR-143 carry an exception clause that points to HR-469. Their meaning for every other kind is unchanged.
     - *Audience.* The audience is the operator-pinned app id, or `api://<app_id>`. The operator's `entra_apps` table maps each app id to exactly one organization; duplicates are refused at start-up. The organization is found through that table, never from a `pantherclaw:` prefix. An organization may configure only a pair pinned to it.
     - *Lifetime.* The token may live up to 24 hours. The assurance, and any credential issued from the attestation, still ends at most 1 hour after the attestation. The token stays single use until its `exp`.
   - `iss` must name the pinned tenant, and keys come only from that tenant's pinned key URL.
   - **Why (G18).** The founder chose to support these platforms in M17, overriding the recommendation to defer them. The audience rule exists so that a token minted for another relying party cannot attest for an organization. An operator-pinned, one-organization app id keeps that property, because the app id is then PantherClaw's audience for exactly one organization. The 1-hour rule exists to bound how long a stolen token confers assurance. Capping assurance at 1 hour from the attestation, and keeping the token single use until `exp`, keeps that bound, even though the token itself lives longer.

**Consequences.**
- A merge whose deploy was never verified can now hold follow-on work, instead of passing on the merge's acceptance alone. Packages without a read for the consequence object still report NOT_VERIFIABLE, now visibly.
- Decisions with chains do more reads. The depth and fan-out caps bound them, and replay stays deterministic because rule ids and definition digests are pinned.
- Customers can encode their own downstream systems without loosening anything. Two people are needed for every rule change, even with protection OFF.
- Old recordings (v1, v3) still replay, and old receipts still verify. The new receipt fields are optional.
- New workload platforms attest without code paths shared with GitHub's. L3 (X.509 SVIDs, instance identity) waits for a PAP-1 revision.
- Azure and Entra tokens remain valid at the issuer for longer than the assurance they confer. A stolen token can be presented once, until its `exp`, and its assurance lasts at most 1 hour (T-205). The operator, not the tenant, carries the responsibility for the `entra_apps` mapping.

**Alternatives.**
- Customer rules that may also loosen (rejected by G1).
- Customer rules behind the ordinary protect category mode, where OFF would let one person change them.
- Unbounded chains, or chains derived from observed causality instead of named rules (the model never invents causality, F405).
- Downstream state inferred from the parent's acceptance.
- Generic OIDC issuers configured entirely by the customer, without built-in preset rules (T-044).
- AWS attestation through an IAM-signed JWT broker instead of a presigned STS request (another service to run and trust).
- Leaving Azure managed identity and Entra Agent ID out of M17 (the coordinator's recommendation in D122, overridden by G18).
- Relaxing HR-140 and HR-143 for every kind, or letting the tenant choose the app id without an operator pin.
