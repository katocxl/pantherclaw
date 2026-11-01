# ADR-0047 — Compliance reports and real-agent campaigns

**Status:** Accepted (2026-11-01; G0 M25 design decisions D300–D312, founder decisions H4, H6 and H7; the [G0 M25](../g0/M25.md) brief records them).

**Context.** Compliance teams translate PantherClaw's records into control language by hand. The range tests policies, so it does not say whether a customer's real agent can be tricked into trying something. A framework report is easy to read as a certification, and a red-team result is easy to read as proof about a model. Both readings would break F527, PN-009.4 and F801. Packs have a closed manifest: `DecodeManifest` rejects unknown members, so a new field would break older `pclaw verify`.

**Decision.**
1. **A pure mapping table** (D300). `internal/compliance/domain` maps framework to control to evidence kinds, for OWASP ASI, NIST AI RMF, the EU AI Act deployer view, ISO 42001 and SOC 2. The Agent Control Standard, COSAiS and DORA are left out.
2. **A report is its own pack scope** (D301, HR-600). Scope `compliance`, a `compliance.json` file item, a new Kind and a fixed statement. It is never a manifest field, and `bundle/pack.go` re-derives it.
3. **Evidence and gaps, nothing else** (D302, D312, HR-601..606). Control states are EVIDENCED, PARTIAL, GAP and STATED. There is no score and no "compliant". AI Act fields are STATED. Simulated evidence is split and labelled. Evidence comes only from PantherClaw's own records, and what the creator can't read is a gap. The header carries the fixed statement: this shows evidence and gaps and is not a certification or statement of compliance.
4. **Reports stay in public core** (H7). They are under the BSL and gated by edition: OWASP and NIST on Team, the others on Business. Export stays ClassSafety.
5. **A stored row outlives the pack** (D303). `pc.compliance_reports` keeps digest and parameters, so a report re-exports after the pack's 7 days.
6. **Campaigns attack a range twin** (D305, HR-608). The report names the image digest and says it tested a twin, not production.
7. **The key sits beside the sandbox** (D308, H6, HR-607). A local relay outside the agent's container forwards to one model host over HTTPS and adds the key. The key is read once from a file, held in memory, and never reaches the container, the logs or the server. The relay registers as a simulated connection. HR-213 and HR-214 are unchanged.
8. **The boundary is what gets measured** (D306, D309, HR-609, HR-611). The server derives HELD, DENIED, NOT_ROUTED_REPORTED, ALLOWED or NOT_EXERCISED from its own transactions. An edge route report stays labelled reported. Not exercised is a gap. Model traffic is not attack evidence.
9. **Campaigns are not assurance** (D307, HR-610). They have their own origin and statement and never enter an assurance pack, as HR-466 requires of customer scenarios.

**Consequences.**
- An auditor sees gaps as gaps, so a first report will look thin. That is the point of it.
- Older `pclaw verify` keeps working on every existing pack, and the scope is a new thing it must learn to re-derive.
- A customer's model key is in memory on the machine running the campaign, in a process outside the agent's container.
- CI and the exit use a scripted stand-in and a local fake provider, so nothing in CI shows how a real model behaves. The product says the run was scripted, and a real model run is a "Prove it" step (D310).
- Repeat campaign runs make no regression claim, unlike `--baseline` on the range (HR-226).

**Alternatives.** A compliance score (F797, and it reads as a claim); a new manifest field (breaks older `pclaw verify`); reports in a private repository (H7); the key inside the container (HR-213, H6); a model hosted by PantherClaw (H4); campaigns against production (the report could not stand behind them; HR-220); campaign results in assurance packs (HR-466).
