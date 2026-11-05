# ADR-0064 — Publishers and bundles

**Status:** Proposed (2026-11-05; the [G0 M37](../g0/M37.md) brief records the coordinator decisions D1080–D1087). A stub: it is completed when M37's code is tested.

**Context.** The Hub carries only content the PantherClaw project writes and signs (`pc.` names). Vendors and communities want to ship tool packages, detection rules and playbooks for their own products, and orgs want to use them without trusting a party they did not choose, without running anyone's code on the server or gateway, and with a way to stop at once when a publisher's key leaks or a bundle turns out harmful.

**Decision.**
1. **Publisher namespaces** (HR-796; D1080). A publisher id owns `ext.<publisher>.…`; `pc.`, `org.` and other publishers' names are refused.
2. **Signed bundles of data only** (HR-797, HR-803; FQ37-2). A `.pcbundle` zip holds a manifest, its EdDSA signature and item files of a closed list of data kinds, under strict decoding and fixed limits. The only simulator is the existing data-driven OpenAPI one. Nothing in a bundle is executed by pclaw, the server or the gateway.
3. **Pins confirmed with a security key** (HR-795; FQ37-1). An org admin pins a publisher's key; the pin is trusted only after a person confirms it with a WebAuthn step-up on the core page.
4. **Install as drafts** (HR-796, HR-798; FD8). An install is verified against an ACTIVE pin, its allowed kinds and the digests, refuses rollback and equivocation, and turns each item into a draft through the kind's existing path. The org still reviews and signs every tool package, and publishing a rule keeps its two-person confirm.
5. **Revocation stops use at once** (HR-799, HR-800; FQ37-3). An admin, or a statement signed by a key of that publisher the org pinned, revokes a key or a bundle. In one transaction installs and items are revoked, packages quarantined, rules disabled and automations paused, and admins are alerted.
6. **Templates without secrets** (HR-801). A channel template carries only non-secret fields; an admin creates the channel and its secrets through the existing flow.
7. **A listing-only marketplace** (HR-802). Static pages list publishers, key fingerprints, digests and commands to copy; no endorsement, payment or install action.

**Consequences.**
- An org must check a publisher's fingerprint through a channel it trusts; the marketplace cannot do that for it (T-364).
- A publisher's `revocations_url` may go silent; revocation then relies on the org's own action (R-91).
- Content that needs code (other simulators, fact readers, channel kinds) still ships only with PantherClaw.
- Hosting the marketplace is a Phase C founder step.

**Alternatives.**
- The marketplace vouching for publishers or signing their bundles (FQ37-1 chose org-pinned keys; the marketplace vouches for nobody).
- Bundles that carry code such as WASM simulators or fact readers (FQ37-2 chose data only).
- Installing bundle items active (rejected: FD8 keeps the org signing step).
- Revocation that waits for the next refresh (FQ37-3 chose to stop at once).
