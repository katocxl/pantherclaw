# ADR-0050 — Content signals: a written amendment to boundary F789

**Status:** Accepted (2026-11-01; G0 M27 design decisions D503–D505 and D507, founder decisions H4 and V5; the [G0 M27](../g0/M27.md) brief records them). Amends product boundary F789 in [FEATURES](../FEATURES.md).

**Context.** Boundary F789 says PantherClaw makes no claim that instructions, plans or model outputs are safe, and never requires raw conversations or hidden reasoning for core protection. Buyers still expect a hook on tool results for indirect injection, secrets and personal data, even though policy can't read meaning. FEATURES says a request that conflicts with a boundary needs an explicit product decision and is never a silent exception. This ADR is that decision.

**Decision.**
1. **F789 is amended, narrowly.** PantherClaw may look at tool results and outbound bodies, only as an opt-in, restrict-only signal, under its own row, F936. F789's two promises stand: no safety claim, and no raw conversations required for core protection. Core protection works the same with signals off.
2. **Restrict only** (D507, HR-648). A flag becomes a fact on the run, read by later decisions. It can hold or deny, never allow.
3. **Opt-in** (D507, HR-649). Per organization, Watching first, then ACTIVE by step-up, as HR-438 does. Once on, a lapse leaves it on until a person turns it off (D505, HR-651, HR-357).
4. **No safety claim** (D504, HR-650). It says "no known flags", never "clean". Hook, SDK and delegated faces show as not inspected. Alerts are labelled inference.
5. **Local and small** (D503, D507, HR-647, HR-652). Pure Go regex and entropy in the gateway, and a port to a customer-run local service out of process. No third-party API adapter and no in-process model. Scans are bounded at 64 KiB and stored nowhere. A finding keeps kind and location, never value.

**Consequences.**
- PantherClaw now reads content on the route, which it did not do before. Bounds, opt-in and storing nothing are what keep this inside the boundary.
- A flag can stop legitimate work. Watching first shows that before it does.
- Regex and entropy miss most indirect injection, so "no known flags" means only that.
- A clean-looking route may simply not be inspected, which is why those faces say so.
- A customer's classifier is theirs to run and to trust. The gateway takes only a restrict-only result from it.

**Alternatives.** Keep content fully out (V5(b); buyers expect the hook); a safety claim or a safety score (F789, F797); a signal that can allow (F793 and the whole point of restrict-only); a third-party classifier API (D503); a model inside the gateway (D503); storing flagged content for review (D507).
