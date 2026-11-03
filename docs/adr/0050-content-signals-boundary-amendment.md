# ADR-0050 — Content signals: a written amendment to boundary F789

**Status:** Accepted (2026-11-01; G0 M27 design decisions D503–D505 and D507, the rulings D512, D532, D533, D552 and D553, founder decisions H4 and V5; the [G0 M27](../g0/M27.md) brief records them). Amends product boundary F789 in [FEATURES](../FEATURES.md).

**Context.** Boundary F789 says PantherClaw makes no claim that instructions, plans or model outputs are safe, and never requires raw conversations or hidden reasoning for core protection. Buyers still expect a hook on tool results for indirect injection, secrets and personal data, even though policy can't read meaning. FEATURES says a request that conflicts with a boundary needs an explicit product decision and is never a silent exception. This ADR is that decision.

**Decision.**
1. **F789 is amended, narrowly.** PantherClaw may look at tool results and outbound bodies, only as an opt-in, restrict-only signal, under its own row, F936. F789's two promises stand: no safety claim, and no raw conversations required for core protection. Core protection works the same with signals off.
2. **Restrict only** (D507, D512, HR-648). A result flag is a fact on the run tree: later writes hold and reads pass. An outbound flag holds that action. The policy attribute `run.content_flags` lets an org's own rule deny. Nothing allows, lowers, lifts or satisfies an approval on a flag.
3. **Opt-in, Watching first** (D507, HR-647, HR-652). OFF scans nothing. WATCHING records and changes no decision. ACTIVE is reached only from WATCHING, by a person with a fresh security-key step-up (HR-438 pattern). Leaving ACTIVE needs a second person (HR-586 pattern). A lapse leaves a mode on until a person turns it off (D505, HR-357).
4. **Fail closed** (D512, D533, HR-650). In ACTIVE a scan that could not finish holds as `scan_incomplete`: a failed or slow classifier, a body over 64 KiB, an unknown finding kind, or a gateway-carried call without the gateway's scan marker. WATCHING counts what would have held, and the step-up shows the count.
5. **No safety claim** (D504, D532, D552, HR-651). Results say "no known flags", never "clean" or "safe". Hook, SDK, AuthZEN and local connections are not scanned, and they and delegated outcomes show as not inspected. Alerts have basis INFERRED, and agents see only the agent-safe explanation.
6. **Local and small** (D503, D507, D553, HR-649). Pure Go regex and entropy in the gateway, and a port to a customer-run service out of process, on a loopback or private address set in the gateway's own config. No third-party API adapter and no in-process model. The raw body is always scanned, and a server-sent events body gets an extra pass. Scans are bounded at 64 KiB and stored nowhere. A finding keeps kind and location, never value, and a classifier's location is kept only when it is one the gateway already knows.

**Consequences.**
- PantherClaw now reads content on the route, which it did not do before. Bounds, opt-in and storing nothing are what keep this inside the boundary.
- A flag can stop legitimate work. Watching first shows that before it does.
- Regex and entropy know listed phrases and formats only. Re-encoded, split or paraphrased content passes, so "no known flags" means only that (R-68).
- A gateway from before M27 fails closed in ACTIVE, so gateways are upgraded before an org moves to ACTIVE.
- A customer's classifier is theirs to run and to trust. The gateway takes only a restrict-only result from it.

**Alternatives.** Keep content fully out (V5(b); buyers expect the hook); a safety claim or a safety score (F789, F797); a signal that can allow (F793 and the whole point of restrict-only); failing open when a scan cannot finish (D512); a third-party classifier API (D503); a model inside the gateway (D503); storing flagged content for review (D507).
