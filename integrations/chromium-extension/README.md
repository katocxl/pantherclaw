# PantherClaw extension for agent browsers (Apache-2.0)

A Manifest V3 extension for the Chrome or Chromium browser an agent drives. Before that browser opens a page, submits a form, saves a download or clicks an element an admin marked, it asks PantherClaw, and it acts only on allow (G0 M33 D980).

- **No key in the browser.** The extension reaches PantherClaw only through `pclaw browser host` on the same machine, over Chrome native messaging. The host signs each question with the desktop workload key. The gateway still refuses any request that carries an `Origin`.
- **Fails closed.** With no host, a disconnect or a deny, a navigation stays on the hold page, a download is cancelled, and a submit or a marked click does not happen.
- **No page content leaves the browser.** It sends only the action's address, the form's field names (never values), the download's name, type and size, and the marked element's label.
- **Secret and challenge fields.** An agent never types into or submits password, one-time-code or payment fields, and never touches a challenge frame. There is no override: a person does that step after **Take over this tab** in the toolbar popup, which PantherClaw holds for an approval.
- **PARTIAL.** It is cooperative. Another browser, page scripts (fetch or XHR), a scripted `form.submit()` (its navigation is still held, but the POST body is lost) and input from outside the page's events are not decided. During a takeover nothing on that tab is decided or recorded.

## Install

1. Enroll the desktop workload key and start a run (`pclaw workload enroll`, `pclaw run start`).
2. Install the native host: `pclaw browser install-host --gateway URL --connection NAME --key-file FILE --extension-id ID` (add `--system` for every user of the machine).
3. Force-install the extension with the policy `pclaw browser policy generate` writes. It also turns off incognito and guest mode, and it installs nothing itself.

Load `extension/` unpacked for development. It has no build step and no dependencies.
