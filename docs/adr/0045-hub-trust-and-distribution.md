# ADR-0045 — Hub trust and distribution

**Status:** Accepted (2026-10-31; G0 M23 design decisions D100–D107, founder decisions H1 and H3; the [G0 M23](../g0/M23.md) brief records them).

**Context.** Customers write the same policies, detection rules and scenarios from scratch. Open content is how comparable products draw people in, but content that changes security behaviour needs signing, and a marketplace needs quality rules from the first day. PantherClaw already signs tool packages, yet Hub cannot reuse that path: `TargetOf` needs a package, and a Hub document signed under the packages root would also pass `ImportPackage`. Detections, automation templates, packs and range digests compile in, so nothing installs them at run time. The package and licence roots are still empty until the offline root ceremony.

**Decision.**
1. **Hub is a Root part.** The seven components stay (H3). Hub lives in `hub/` in the public repository, Apache-2.0 (H1), and publishes PantherClaw content only, with no third-party code.
2. **A static signed directory** (D100, D100a, HR-563). `index.jws` plus `items/<sha256>.json`, no archives. The index is a compact JWS with its own type, a rising version and an expiry of at most 180 days. Kinds are closed: `policy_template`, `detection_rule`, `range_scenario`, `tool_package`, `automation`. Items hold no code and no scripts. Index and item travel in one RPC under the 1 MiB request limit, so an item is at most 384 KiB and a compact index at most 640 KiB with at most 1,000 items, enforced from one constant and refused rather than truncated (D100a). Names match the `pc.` pattern.
3. **Its own signature domain** (D101, HR-560). A new key purpose and root file, with `internal/definitions/trust` unchanged. A Hub document never verifies as a package document, and the reverse. The dev key works on loopback only, and empty roots off loopback give `HUB_NO_ROOT`.
4. **The server verifies; the CLI is transport** (D104, D107). The server re-verifies everything it is handed and never fetches an index, so Hub adds no outbound call. Rollback is refused per organization and in the CLI (HR-562).
5. **Install is inert** (HR-561). Each kind lands as a draft or passes through `ImportPackage` unchanged; nothing is activated, published or enabled, and no agent's tool-version pins change. A `tool_package` install advances package anti-rollback as any import does, and the version stays REVIEWED (D104a). `range_scenario` is written locally by the CLI and refused on the server. The normal gates then apply, so a detection rule keeps its Business gate.

**Consequences.**
- Until the root ceremony only the dev key signs, so Hub works on loopback and nowhere else. Real distribution waits for that founder step.
- "Update available" lives in the CLI; the server cannot tell an organization that a newer index exists.
- A person installs each item, and each draft still goes through its gate. That is slower than a one-click pack, and intended.
- Every new kind needs its own install route and a change to this closed list.
- Hub content keeps its Apache-2.0 licence apart from the BSL core, so `tools/licensecheck` must know `hub/`.

**Alternatives.** Reusing the packages root (a Hub document would also pass package import); signed archives (a directory is simpler and lets each item be fetched and checked alone); a hosted index service (an outbound call and a service to run, at no benefit before partners); server-side fetch and update (a new egress path); install that activates content (bypasses publication gates, F793); outside publishing now (quality rules and the CLA come first); BSL or CC-BY for content (Apache-2.0 matches open content practice, founder decision H1).
