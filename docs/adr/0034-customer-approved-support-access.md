# ADR-0034 — Customer-approved support access

**Status:** Proposed (2026-10-21; G0 M13 founder decision F3; the [G0 M13 brief](../g0/M13.md) records it). The high-level model below is decided; the design (tables, procedures, rules and threats) is added with wave 2, migrations `00173`–`00175`, rules HR-385..389.

**Context.** PN-012.4 (with F597 and F598) requires that support access to a customer's organization is requested for a named task and duration, approved by the customer, visible in scope and audited, with no standing access to credentials or restricted payloads. Today the only way in is the operator command line, with a self-asserted actor. A hosted control plane makes PantherClaw's own staff a potential insider (A7), so support access must be something the customer grants, sees and ends.

**Decision (high-level model, F3).**
1. **The customer approves each request.** A request names the task, the scope and a duration of at most 72 hours. An organization admin approves it with a security-key step-up.
2. **Read-only by default.** Anything beyond reading is a separate, explicit scope in the request.
3. **Never credentials or restricted payloads**, whatever the scope.
4. **A customer-visible audit trail** of the request, the approval and every action taken under it.
5. **Revocable at any time** by the customer; access ends at expiry.
6. **No standing access** for staff, and **no self-approval** by staff.

**Consequences.**
- Support work on a hosted organization waits for the customer's approval; break-glass access (F594, Business) is a separate, narrower path decided with the same wave.
- Support access is an Enterprise feature (FEATURES, unchanged).

**Alternatives.** Standing operator access with after-the-fact audit (contradicts PN-012.4); approval by PantherClaw staff (self-approval); time-unbounded grants.
