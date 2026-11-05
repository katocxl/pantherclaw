# ADR-0065 — Partners and shared indicators

**Status:** Proposed (2026-11-05; the [G0 M38](../g0/M38.md) brief records the coordinator decisions D1100–D1107). A stub: it is completed when M38's code is tested.

**Context.** A managed security service provider (MSSP) that watches many customers had to be a member of each customer org, with a customer person's role, or use the operator's support access, which is meant for PantherClaw staff. Nothing let a customer grant an outside org bounded, time-limited reads and the right to suggest a policy change without handing over the change itself. Separately, every org discovered the same bad MCP servers, poisoned tool descriptions and injection text on its own; there was no way to share what one org found without sharing what it saw.

**Decision.**
1. **A partner is an ordinary org linked by the customer** (HR-810; FQ38-1). A partner org requests a link; a customer person with `partner.approve` approves it on a page with a security-key step-up, for at most 90 days, and revokes it at any time. The partner org needs the Enterprise `PartnerAccess` entitlement; the customer needs none.
2. **Partner sessions read only and are re-checked on every call** (HR-811, HR-813). A partner person with `partner.operate` opens one customer with a step-up and gets a session scoped to that customer, modelled on support access; each call re-checks the link, the partner org's edition and the person, and is recorded in the customer's audit log before it runs.
3. **A partner is never a customer person** (HR-812). The partner principal is not human in the customer org, so approvals, step-ups and every human-only path refuse it.
4. **Proposals only draft** (HR-814, HR-815; FQ38-1). A partner proposes a policy version or a pack; the customer accepts it into a draft through its own draft path. Publishing or rolling out a partner-origin version always needs two customer people with security keys.
5. **Summaries carry counts only** (HR-816). The cross-customer view reads each customer in that customer's tenant and records the read there.
6. **A signed, hash-only indicator feed** (HR-817, HR-818; FD13). Indicators are verified against offline roots, rollback is refused, and only hashes or shingles enter or leave.
7. **A match holds or alerts, never refuses** (HR-819, HR-820; FQ38-2). Consuming and sharing are off by default; an org chooses HOLD or ALERT_ONLY.
8. **Contributions and exports carry no org identity** (HR-821); `serverInfo` is captured for matching only (HR-822).

**Consequences.**
- A hash-only feed misses changed text; shingles match only shared text (R-92).
- Partner and customer must be on the same deployment.
- Mirrored partner audit entries are written in the second org's own transaction, after the first.
- The hosted indicator feed, TAXII and licensing for customers of partners are follow-ups.

**Alternatives.**
- A separate MSSP edition or parent and child orgs (rejected: a partner stays an ordinary org with a link).
- Partners acting with a customer person's role, or approving holds (FQ38-1 chose reads and proposals only).
- Proposals that publish after the customer's acceptance (rejected: they only draft, and loosening needs two customer people).
- Refusing on an indicator match (FQ38-2 chose hold or alert only).
- Sharing descriptions or text in the feed (rejected: hashes and shingles only).
