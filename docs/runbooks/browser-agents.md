# Runbook: Browser and computer-use agents

**Milestone:** M33 ([G0 M33](../g0/M33.md), [ADR-0060](../adr/0060-browser-and-computer-use-agents.md)). **Rules:** HR-745..HR-759. **Edition:** Community, except prompt capture (Business).

An agent that drives a Chrome or Chromium browser, or a desktop, asks PantherClaw before it acts there. Each navigation, form submit, download, marked click and computer-use action is decided per call: allowed, held for a person or refused. That is the runtime firewall (D1205). Who the agent is still comes from the desktop workload key, as for every local connection.

Coverage is PARTIAL. The extension is cooperative: another browser, page scripts (fetch or XHR), a scripted `form.submit()` and CDP or OS input outside the hooked events are not decided (R-78). Computer use is decided only where the SDK wrappers are used (R-81).

This runbook has four parts: [install](#1-install-the-extension-and-the-native-host), [the site list](#2-the-site-list), [takeover](#3-takeover) and [computer use](#4-computer-use).

## Before you start

- A gateway, and a `local` connection that pins `pc.browser` (for the browser) or `pc.computer` (for computer use): `pclaw connection create NAME --kind local --gateway ID --package pc.browser`.
- A grant for the agent that names the `pc.browser` or `pc.computer` operations it may use. No template or default grant names one.
- On the agent's machine: an enrolled desktop workload key (`pclaw workload enroll --key-file FILE --server URL …`) and a run (`pclaw run start AGENT …`).

## 1. Install the extension and the native host

The extension never holds a key. It reaches PantherClaw only through `pclaw browser host` on the same machine, over Chrome native messaging (FQ33-1). The host signs each question as a PAP/1 hook call with the desktop workload key, and the gateway's hook face still refuses any request that carries an `Origin` (HR-753).

### Install the native host

```
pclaw browser install-host --gateway URL --connection NAME --key-file FILE \
  --extension-id ID [--extension-id ID ...] [--run ID] [--browser chrome|chromium|all] [--system]
```

- `--gateway` is the gateway's base URL (https; http only for localhost). `--connection` is the local connection. `--run` defaults to the key file's run.
- `--browser` defaults to `all` (Chrome and Chromium). `--system` installs for every user of the machine.
- Install per user (without `--system`) wherever you can. A `--system` install names one configuration and so one key file: on unix every user's browser then asks with the same workload key, and their actions are one agent's. Use `--system` only on a single-user or kiosk machine.
- Only the given extension ids may start the host: the manifest's `allowed_origins` lists `chrome-extension://<id>/` for each.

It writes three things and prints their paths:

| File | Where (user) | Where (`--system`) |
| --- | --- | --- |
| `host-config.json` (0600 for the user; 0644 and owned by root with `--system`) and the wrapper `pantherclaw-browser-host.bat` (Windows) or `pantherclaw-browser-host.sh` (0755) | `os.UserConfigDir()/PantherClaw/browser` | `%ProgramFiles%\PantherClaw\browser`, `/etc/pantherclaw/browser` or `/Library/Application Support/PantherClaw/browser` |
| Manifest `dev.pantherclaw.browser.json` | Windows: next to the configuration, registered as the default value of `HKCU\Software\Google\Chrome\NativeMessagingHosts\dev.pantherclaw.browser` and `HKCU\Software\Chromium\NativeMessagingHosts\dev.pantherclaw.browser`. Linux: `~/.config/google-chrome/NativeMessagingHosts/` and `~/.config/chromium/NativeMessagingHosts/`. macOS: `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/` and `~/Library/Application Support/Chromium/NativeMessagingHosts/` | Windows: the same keys under `HKLM`. Linux: `/etc/opt/chrome/native-messaging-hosts/` and `/etc/chromium/native-messaging-hosts/`. macOS: `/Library/Google/Chrome/NativeMessagingHosts/` and `/Library/Application Support/Chromium/NativeMessagingHosts/` |

Run it again after moving `pclaw` or the key file: the wrapper names both by absolute path.

`--system` needs an administrator (Windows) or root (`sudo`, unix):

- Windows: a `%ProgramFiles%\PantherClaw` or `%ProgramFiles%\PantherClaw\browser` folder that already exists and is not owned by SYSTEM or Administrators is refused, as is anything there that is not a folder: remove it, or take ownership as an administrator. Both folders get an explicit access list, with nothing inherited: SYSTEM and Administrators full control, Users read and execute. An old configuration, wrapper or manifest there is removed and written again, so it carries only that list.
- Unix: `/etc/pantherclaw/browser` (or the macOS folder) and its parent must be owned by root and not writable by group or others. The configuration is written 0644, owned by root, so every user's browser can start the host.

The configuration holds only the gateway, the connection, the run, the extension ids and the key file's path, never the key. It still decides what the host signs for, so no one but its owner may change it.

What the host does (HR-753):

- It refuses any origin other than a configured extension (exit 1, nothing on stdout). On unix it refuses a configuration that group or others can write, and one they can read unless root owns it (`chmod 600` a user's configuration).
- Messages are Chrome's framing: at most 1 MiB in (a larger one closes the host), inputs at most 64 KiB, replies at most 64 KiB.
- Each decide is one hook call with an 8-second deadline. Any error is a deny with `CANNOT_DECIDE`. Tokens are kept in memory and renewed when less than a minute is left.
- It never logs a message's input, and it exits when the browser closes its stdin.

### Deploy the extension with Chrome policy

```
pclaw browser policy generate --extension-id ID --update-url URL --out DIR [--host-name NAME]
```

It reads the org's browser sites and writes two files. It installs nothing (HR-755):

- `chrome-policy.json`, the Linux managed-policy form: `ExtensionSettings` force-installs and pins the extension from `--update-url` (https), `IncognitoModeAvailability: 1` turns incognito off, `BrowserGuestModeEnabled: false` turns guest mode off, and `3rdparty.extensions.<id>` gives the extension its `host_name` and the `click_rules` of every site with selectors. Copy it into `/etc/opt/chrome/policies/managed/` for Chrome and `/etc/chromium/policies/managed/` for Chromium.
- `chrome-policy.reg`, the same under both `HKEY_LOCAL_MACHINE\Software\Policies\Google\Chrome` and `HKEY_LOCAL_MACHINE\Software\Policies\Chromium` (regedit version 5, UTF-16LE).

Deploy them with your device management. Generate them again after a site's selectors change: click rules reach the extension only through policy. macOS policy generation is a follow-up; there, set the same keys with a configuration profile (`com.google.Chrome`, `org.chromium.Chromium`).

### Automated agents: use a managed profile

The policy reaches only browser profiles that load it. An automated agent (Playwright, Puppeteer, Selenium, a CDP client) must run in a persistent profile of a browser that has the policy, with the extension loaded. With Playwright that is `launchPersistentContext` (Python `launch_persistent_context`) on that profile's user data folder, without `--disable-extensions` (Playwright adds it unless you drop it with `ignoreDefaultArgs`).

Not covered (PARTIAL):

- Incognito and other off-the-record contexts: Playwright's `newContext`, and CDP `Target.createBrowserContext`. The extension is not in them, so nothing there is asked.
- Whether `IncognitoModeAvailability: 1` also stops `Target.createBrowserContext` has not been checked yet; that waits for the Phase C browser tests. Until then, treat a context an agent creates over CDP as not covered.

Managed configuration can only add. `extra_secret_hosts` adds hosts whose frames hold only secret fields, beside the built-in payment hosts (`*.` also covers the subdomains).

For development, load `integrations/chromium-extension/extension/` unpacked. It has no build step.

### Check it

Open the toolbar popup. It says "Connected to PantherClaw (connection …, run …)." when the host answers `status`: the key file reads, the run is an id, and a token is at hand. Otherwise it says "PantherClaw cannot decide: …" with the host's reason.

### What the extension asks, and what it sends

| Act | Hook tool | Sent (HR-754) | Without an allow (HR-751) |
| --- | --- | --- | --- |
| Top-level navigation | `browser_navigate` | the URL, user agent and language | The tab stays on the hold page. A held page asks again every 10 seconds, with the same call and action id, for up to 30 minutes. A server redirect is decided again. A URL over 1800 characters is refused locally (`BROWSER_URL_TOO_LONG`). |
| Form submit | `browser_submit` | the action URL, the page URL, the method, the field names (never values) and `secret_fields` | The form is not sent. |
| Download | `browser_download` | the URL, the page URL, the file name, type and size | It is cancelled, its file removed and its entry erased. |
| Marked click | `browser_click` | the page URL, the admin's selector and the element's label | The click does not happen. |
| Takeover | `browser_takeover` | the page URL and the minutes | The tab stays with the agent. |

No screenshots, DOM, field values or page text leave the browser.

An allowed navigation or submit is let through by a session rule for that one tab and address. The rule goes when the tab commits or fails a navigation, when a request it matches redirects, completes or fails (the `webRequest` permission is for this; the extension only observes, it never blocks or changes a request there), or after 10 seconds, whichever is first. A service-worker restart loses the 10-second timer, so a worker removes every such rule when it starts; a navigation still waiting for its rule is asked again.

Not decided (PARTIAL): navigations inside a frame (only the top-level page is asked), and `file:` pages.

### Secret and challenge fields

An agent never types into or submits password, one-time-code or payment fields, and never touches a challenge frame (FQ33-4, HR-752). There is no override.

- A field is secret by `type=password`, by an `autocomplete` token (`current-password`, `new-password`, `one-time-code`, the `cc-*` tokens), by a name, id, aria-label or placeholder that looks like a password, PIN, code, card, IBAN, routing or account number or SSN, or because its frame is on a payment host (Stripe, Braintree, Adyen, PayPal, Google Pay, or an `extra_secret_hosts` entry).
- In a challenge frame (reCAPTCHA, hCaptcha, Cloudflare challenges, Arkose) every pointer, key and input event is refused.
- A field stays secret once seen as one, and an input whose type leaves `password` stays secret. A field a script puts in place of a removed secret input (same form and name, or same parent and neighbor) is secret too.
- Not seen (PARTIAL): a field inside a closed shadow root; a swap inside any shadow root; a replacement in another form, under another name and in another place; a secret input replaced by a contenteditable; and more than 32 swaps on one page, beyond which the oldest are forgotten.
- Typing, pasting and dropping are prevented, and a value that still arrives is cleared. The page shows "PantherClaw refuses agent input into password, one-time-code, payment and challenge fields. A person can take over this tab from the PantherClaw toolbar button."
- A submit holding a non-empty secret field is refused in the page and still asked with `secret_fields: true`. The gateway refuses it before the Authority is asked (`BROWSER_SECRET_FIELD`, HR-747), so the refusal is recorded. The agent is told to ask a person to take over the tab and continue after.

## 2. The site list

A `pc.browser` action on a site not on the org's list is held for a person (`SITE_NOT_LISTED`), and an empty list holds every site (FQ33-2, HR-745). A site matches when the host equals its host, or it includes subdomains and the host ends with "." and its host. An IP host never matches.

```
pclaw browser sites list
pclaw browser sites add --host HOST [--subdomains] [--compare] [--selector CSS]... [--note TEXT] --reason TEXT
pclaw browser sites remove ID --reason TEXT
```

- `--host` is a lower-case DNS name of at least two labels, at most 253 characters, with no IP and no port.
- `--selector` (repeatable, at most 16, each 1..256 characters) marks elements whose clicks the extension asks about (`browser_click`). It reaches the browser through the policy generator.
- `--compare` puts the site under the gateway's cloaking compare ([below](#cloaking-compare)).
- `--note` is at most 256 characters; `--reason` is 1 to 500 characters.
- At most 500 sites per org (`BROWSER_SITE_LIMIT`).

Permissions and the edition are the owned-accounts service's: reading needs `org.owned_accounts.read`, changing `org.owned_accounts.manage` (HR-749). Adding a site files a change that applies only when a second person confirms it with a security key; the CLI prints the change's id. Removing one applies at once, since it only holds more. Each change is audited (`browser.site_added`, `browser.site_removed`) and moves the gateway configuration version.

To release a held action, an approver approves it in the console or with `pclaw approval approve ID`. A held navigation asks again with the same call and action id and opens the page once it is allowed.

### Cloaking compare

For a site added with `--compare`, after an allowed `browser.navigate` the customer's gateway fetches the page twice without cookies: once with the agent's user agent and language, once with `browser_compare.plain_user_agent` (`PC_GW_BROWSER_COMPARE_PLAIN_USER_AGENT`) (FQ33-3, HR-759). The compare is off while that setting is unset.

- It never delays or changes the decision. Fetches go through the gateway's egress client, follow at most 3 redirects, read at most 1 MiB per body and take at most 10 seconds each.
- At most one compare per connection, host and path digest per hour, and 60 per hour per gateway; a queue of 32 drops the excess.
- Only a mismatch is reported (similarity below 500‰, or one answer 2xx and the other not), as digests, statuses, sizes and the similarity. The server writes `browser.cloaking_suspected`, once per connection, host and path digest per hour, and the `pc.browser.cloaking` detection alerts. It is alert only, never a block (HR-750).
- It sees header-based cloaking only, from the gateway's network (R-80). PARTIAL.

## 3. Takeover

A person takes over a tab to do what an agent may not: sign in, enter a one-time code, pay (FQ33-4).

1. At the agent's browser, open the PantherClaw toolbar popup and choose **Take over this tab**. It works only on http and https tabs, and only from the toolbar popup: the popup opened as a page, or a page's own message, is refused.
2. PantherClaw always holds a takeover for one approver (`BROWSER_TAKEOVER`, HR-746); no grant, policy or exception removes that hold. The approval reads "A person takes over the agent's browser tab on HOST for up to 10 minutes (approve only if a person is at that browser)". Approve it only if you know a person is there. The extension asks again every 10 seconds for up to 15 minutes; the popup shows "PantherClaw holds the takeover for an approval".
3. On allow, the tab shows "A person is in control of this tab until HH:MM". Secret fields are lifted on that tab, and nothing on it is asked.
4. It ends after 10 minutes, with **Give back** in the popup, or when the tab closes. Then the secret-field refusal and the holds come back.

Only the takeover request is recorded. During a takeover nothing on that tab is decided or recorded, and the agent can still act there and read what the person types (R-79). Give the tab back as soon as the step is done.

## 4. Computer use

Computer use is decided only through the SDK wrappers (R-81). Each action becomes a `pc.computer` `computer.input` call on a local connection pinning `pc.computer` (hook tool `computer`): its kind, button, text or keys. Coordinates are sent but are not material: an approval of a `computer.input` binds its kind, button, text and keys, not where on the screen it happens (D984).

### Python and TypeScript SDKs

- Python: `from pantherclaw.computer_use import ComputerUseGuard`; `guard = ComputerUseGuard(client, "CONNECTION")`; then `guard.decide_anthropic(tool_use)` for an Anthropic `computer` tool use, or `guard.decide_openai(computer_call)` for an OpenAI `computer_call`.
- TypeScript: `new ComputerUseGuard(client, "CONNECTION")`, with `decideAnthropic` and `decideOpenAI`.
- Bedrock: pass the Converse `toolUse` block of the Anthropic computer tool (`{toolUseId, name, input}`, or the content block `{toolUse: {...}}`) to `decide_anthropic` / `decideAnthropic`.
- The model's call id (`id`, `toolUseId` or `call_id`) is the call. A held action asked again with the same id is the same call, so it runs once an approver releases it. An id that cannot be a call (more than 128 characters, or other than letters, digits, `_` and `-`) is replaced by a digest of it; only a missing id gets a random call.
- `decide_openai` / `decideOpenAI` takes one `action`. A `computer_call` that batches several in `actions` is refused (`COMPUTER_ACTION_UNKNOWN`); decide each one.
- Each returns `allowed`, `held`, `code`, `reason` and `transaction_id`. Run the action only when `allowed` is true (HR-758).
- Screenshot, wait, cursor position and zoom are allowed locally and never sent. An unknown action is refused locally (`COMPUTER_ACTION_UNKNOWN`), and any error refuses (`CANNOT_DECIDE`).
- Both clients also gain a general hook call (`Client.hook_call(connection, tool, input)` / `hookCall`).

### OpenAI Agents SDK

`guard_computer(computer, guard)` from `pantherclaw_openai_agents` returns a `Computer` or `AsyncComputer` subclass that asks before click, double click, drag, keypress, move, scroll and type, and raises the integration's refusal error on a hold or a refusal. Screenshot and wait pass through.

The Agents SDK calls a `Computer` with each action's arguments only: the `computer_call`'s `call_id` never reaches it, and one `call_id` can carry several actions. So the wrapper makes each call from the action itself, a random value per wrapped computer and a slot: the lowest number no allowed identical action used and none still being decided holds. The slot is taken when the action is asked, so identical actions an async computer decides at once are separate calls; a held or refused action gives its slot back. A held action asked again through the same wrapped computer is the same call, so it runs once released; the same action after an allow is a new call. A new wrapped computer (a restarted process) makes new calls, so an action held before the restart is asked as a new one. Modifier keys the SDK passes with a click, drag, move or scroll are not passed through.

### The model connection

A model call that declares a client-run computer tool (Anthropic `computer_*`, Responses `computer_use_preview`, and Bedrock's `computer_*` tools) is refused with `MODEL_COMPUTER_USE_NOT_ALLOWED` unless the model connection allows `computer_use` (HR-756):

```
pclaw connection update ID --revision N --allow-server-tool computer_use [--allow-server-tool TYPE ...]
```

`--allow-server-tool` replaces the list, so name every type the connection should keep. A newly allowed type widens the connection, so it follows the HR-183 rules for weakening changes. The tool stays client-run: the model route only gates whether computer use may be declared, and each action is still decided by the wrapper.

With prompt capture on (`capture_prompts`, Business), the capture keeps no image, document or screenshot data: each such block is replaced by its type, `omitted`, its size and the SHA-256 of its raw JSON, and a body that cannot be parsed is not kept (HR-757).

## Troubleshooting

| Seen | Cause | Fix |
| --- | --- | --- |
| Popup: "PantherClaw cannot decide: the native host did not answer." | The host is not installed for this browser, the extension id is not in its manifest, or `pclaw` moved | Run `pclaw browser install-host` again with this browser and id |
| Every page holds | The site list is empty, or the site is not on it | `pclaw browser sites add` (a second person confirms) |
| `CANNOT_DECIDE` on every action | The gateway is unreachable, the key file or run is wrong, or the token cannot be issued | Check `status` in the popup; check the host configuration's gateway, connection and run |
| A login form never submits | It has a secret field (`BROWSER_SECRET_FIELD`) | A person takes over the tab and submits it |
| `MODEL_COMPUTER_USE_NOT_ALLOWED` | The model connection does not allow `computer_use` | Allow it on the model connection, if the org wants computer use |
