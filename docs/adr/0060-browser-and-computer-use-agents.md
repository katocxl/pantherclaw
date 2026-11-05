# ADR-0060 — Browser and computer-use agents

**Status:** Proposed (2026-11-05; the [G0 M33](../g0/M33.md) brief records the coordinator decisions D974–D989). A stub: it is completed when M33's code is tested.

**Context.** Agents now drive browsers and desktops: they open pages, fill forms, download files and click on a screen. None of that passes a PantherClaw route by itself. The hook face refuses browsers (any `Origin`), and a key kept in a browser profile would be readable by every page script and by the agent.

**Decision.**
1. **A managed extension behind a native host** (HR-751, HR-753, HR-754; founder decision FQ33-1). A Manifest V3 extension holds every top-level navigation, form submit, download and marked click, and asks `pclaw browser host` over Chrome native messaging. The host signs each question as a PAP/1 hook call with the desktop workload key. No key lives in the browser, and no page content leaves it.
2. **`pc.browser` and a site list** (HR-745, HR-748, HR-749; FQ33-2). Five irreversible operations are decided like any other action. An action on a site not on the org's list holds for a person, and an empty list holds every site.
3. **Secret and challenge fields** (HR-747, HR-752; FQ33-4). An agent never types into or submits password, one-time-code or payment fields, and never touches a challenge frame. The extension refuses it in the page, and the gateway refuses a secret-field submit. There is no override.
4. **Takeover** (HR-746). A person takes over a tab from the toolbar popup. The takeover always holds for an approver, lasts at most 10 minutes, and nothing on that tab is decided until it ends.
5. **Deployment** (HR-755). Generated Chrome policy force-installs the extension and turns off incognito and guest mode. The generator installs nothing.
6. **Computer use** (HR-756..758). SDK wrappers ask `pc.computer` before each action. The model route refuses declaring computer use unless the connection allows it, and capture keeps no images.
7. **Cloaking compare** (HR-750, HR-759; FQ33-3). The customer's gateway fetches a marked site as the agent and as a plain browser, reports only a mismatch, and alerts only.

**Consequences.**
- The extension is cooperative (PARTIAL): another browser, page scripts, `form.submit()` and input outside the hooked events are not decided (R-78).
- During a takeover nothing on that tab is decided or recorded (R-79).
- The compare sees header-based cloaking only (R-80).
- Computer use is decided only where the SDK wrappers are used (R-81).
- AML.T0100, AML.T0131, T1696.001 and AML.T0134 (detect, PARTIAL) leave Unaddressed on the threat map.

**Alternatives.**
- A key in the extension, calling the gateway directly (FQ33-1 chose the native host).
- Letting listed sites type into secret fields under a policy (FQ33-4 chose no override).
- A blocking cloaking check (FQ33-3 chose alert only).
- Screenshots as evidence (no page content leaves the browser).
