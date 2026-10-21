# ADR-0035 — Export, deletion and retention after a lapsed plan

**Status:** Proposed (2026-10-21; G0 M13 founder decision F2; the [G0 M13 brief](../g0/M13.md) records it). The high-level model below is decided; the design (tables, jobs, procedures, rules and threats) is added with wave 2, migrations `00176`–`00179`, rules HR-390..394. Answers the follow-up "retention after a plan lapses" left by milestone UI ([ADR-0031](0031-hosted-accounts-per-org-plans-and-test-seams.md), D85).

**Context.** PN-012.5 requires a tenant-wide export of records and evidence and a verified tenant deletion that keeps a deletion record. Milestone UI decided that a lapsed plan never turns protection off and that evidence stays readable and exportable for at least 30 days, leaving the end of that period to M13; until then lapsed and paused organizations keep read access with no cutoff.

**Decision (high-level model, F2).**
1. **90 days after a lapse:** enforcement, reads and export keep working; changes stay blocked (HR-357 is unchanged).
2. **Reminders** to the organization's admins on days 0, 30, 60 and 83.
3. **Paying again before day 90** restores the organization fully.
4. **On day 90: verified deletion** of the organization's data, with a **signed deletion record** that is kept.
5. **Tenant-wide export** of records and evidence is available throughout, so a customer can leave with its evidence.

**Consequences.**
- PRODUCT §7 states 90 days followed by verified deletion instead of "at least 30 days".
- Deletion interacts with retention, legal holds and the evidence ledger; how a deletion record proves what was removed without keeping it, and how legal holds apply, is part of the wave 2 design.

**Alternatives.** Keeping lapsed organizations' data indefinitely (cost and data-protection exposure); deleting at the lapse (no time to pay or export); deletion without a record (unverifiable).
