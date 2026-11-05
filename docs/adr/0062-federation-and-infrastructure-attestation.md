# ADR-0062 — Federation and infrastructure attestation

**Status:** Proposed (2026-11-05; the [G0 M35](../g0/M35.md) brief records the coordinator decisions D1020–D1046). A stub: it is completed when M35's code is tested.

**Context.** Agents of one organization increasingly need to ask agents of another: a supplier's agent asks a customer's, a partner's agent hands work to ours. Until M35 an external A2A peer was governed only outbound, and an inbound message had to come from one of our own PAP/1 workloads. At the same time, the strongest attestation level was L2 (a cloud or CI token for the workload), which does not prove the workload's PAP key, and evidence verifiers pinned Sigstore trust by hand and had no independent witness of the deployment's log.

**Decision.**
1. **Pairwise trust between orgs** (HR-770..772; FD10). Each org has its own Ed25519 federation key and a signed public federation document. A trust is proposed from the peer's document, both admins compare a safety code derived from both orgs' keys and confirm with a security key, and it is ACTIVE only when both sides confirmed. Rotation is accepted only when a pinned key signed it. Orgs on one deployment use the same protocol over HTTPS: there is no shortcut.
2. **Listed agents and federated A2A messages** (HR-773..775; FQ35-1). An org lists the agents a peer may message. Our agent messages a peer's listed agent through an a2a connection whose card and URL come from the peer's verified document, with a `pap-fed+jwt` bound to the exact request. A peer's agent messages ours through the gateway's federation face; the server admits the call (`StartFederatedCall`), maps it on channel `federation` through the built-in `pc.federation` package, and decides it under a cross-org grant like any other action. After an allow the body is forwarded unchanged to the listed agent. The peer gets no tool or data access.
3. **Minimal receipts both ways** (HR-776; FQ35-2). Every answer carries our `pap-fed-receipt+jwt`: the decision, ids, time and request digest, nothing of our checks, reasons or policy. Each side stores the other's token or receipt.
4. **L3 "Infrastructure-attested"** (HR-777..779). An infrastructure attestation bound to the PAP key thumbprint and a fresh server nonce: SPIFFE X.509-SVIDs from the operator-configured trust domain and GCE identity tokens. PAP/1 stays v1 (an additive `att_lvl` 3).
5. **TUF for Sigstore trust** (HR-780, HR-781; FQ35-4). go-tuf v2 fetches and checks Sigstore's `trusted_root.json`, for `pclaw verify` and for anchoring; offline verification stays possible.
6. **Witnesses on the global log only** (HR-782, HR-783; FQ35-3). C2SP witnesses cosign the deployment-wide global log; per-org logs are never sent.
7. **ML-DSA-65 on receipts** (HR-784). With the existing Enterprise gate, receipts carry a post-quantum co-signature in `sigs[]`; the compact JWS is unchanged and federated receipts stay Ed25519 only.

**Consequences.**
- A peer's claimed attestation level is trusted as the peer states it (R-86).
- A peer's people can see the minimal receipts we return (R-87).
- Azure and AWS workloads have no L3 yet (R-88).
- T1199 (Trusted Relationship) stays outside PantherClaw on the threat map; cross-org grants bound what a trusted peer may do through PantherClaw.

**Alternatives.**
- Transitive or hub-based trust instead of pairwise trust (FD10 chose pairwise).
- Giving peers direct tool access under our grants (FQ35-1 limited them to A2A messages to listed agents).
- Full receipts to peers with checks and reasons (FQ35-2 chose minimal receipts).
- Witnessing per-org logs (FQ35-3 chose the global log only).
- sigstore-go instead of go-tuf (FQ35-4; M7 decision 3(a) kept Sigstore verification in-house).
