# Runbook — Scheduled device scans

**Milestone:** M24 ([G0 M24](../g0/M24.md) D233–D237, D246–D254, D282–D286, D292). **Audience:** IT and security teams that manage laptops. This page was written from the brief and the delivery stream's notes, before the commands landed on `main`. Nothing here has been run on a real Intune or Jamf tenant; the M24 exit status records any change.

A scheduled `pclaw scan` finds MCP configurations, hooks, skills and held keys on managed devices and submits them as metadata, so that discovery stays current without an installed service.

## 1. What a scan sends

Metadata only:

| Finding | Sent |
|---|---|
| Hook | Event and executable basename |
| Skill | Name and path |
| Package-run server (`npx`, `uvx`, `bunx`, `pipx run`, `docker run`) | The package or image token; no other arguments |

A scan never sends file contents or prompts. Home paths always become `~`, so no user name leaves the machine, and a `--device` scan sends no hostname unless you pass `--include-hostname`.

Tell the people whose devices you scan what it reads. `--all-users` reads every home directory on the device, with the same limits. Local law or a works agreement may apply to this; that check is yours.

"Not observed" is not "absent": a scan sees what its readers cover on that device, on that day.

## 2. Create a scanner key

1. Create a service account for scanning, with the role `Scanner`. It holds exactly `org.read` and `agent.scan.submit`. It can submit scans for its scope and write nothing else. Like every role it holds `org.read`, which reaches `GetOrg`, `GetModelSettings` and `GetModelDraft`; none of these carries a secret. The role is for service accounts only.
2. Create an API key for it, and keep it out of device-management scripts and logs. Deliver it as a file readable only by SYSTEM or root.
3. Point `PANTHERCLAW_API_KEY_FILE` at that file, which holds one key. If `PANTHERCLAW_API_KEY` is also set, it wins.

A Scanner key must use `--device`:

```
pclaw scan --submit --device [--include-hostname] [--all-users]
```

`--server`, `--key-file` and `--config-dir` stand in for `PANTHERCLAW_SERVER`, `PANTHERCLAW_API_KEY_FILE` and `PANTHERCLAW_CONFIG_DIR`.

A key on many laptops is easy to steal, so plan for it: rotate on a schedule, and revoke if a device is lost. The role limits what a stolen key can do; it does not stop someone submitting false findings for that scope.

## 3. Scope

Each device gets the scope `device:<id>`: the first 16 hex of SHA-256 over the machine id and a salt. The 200-finding cap applies per source and scope, and dropped findings are still reported.

The salt derives from the machine's own id: MachineGuid on Windows, `/etc/machine-id` on Linux, IOPlatformUUID on macOS. If none is readable, it falls back to a file, `%ProgramData%\PantherClaw\device-salt` or `/var/lib/pantherclaw/device-salt`. All of these are writable by admins only, so a non-admin cannot move SYSTEM's scope.

- **Cloned images** that keep their machine id share a scope. Give each clone a fresh id.
- **Keyed findings.** The salt is a labelled hash of the machine id, which local users can read. It hides finding keys from the server, not from someone who knows that id. Keys are HMACed on `--device` scans only; CI and plain scans keep raw keys.

Two org-wide limits apply. Past either one, a scan is refused with `SCAN_DEVICE_LIMIT`, with one audit record per window. A large first rollout can reach the hourly limit, so stagger it.

| Setting | Default |
|---|---|
| `limits.scan.new_device_scopes_per_key_per_hour` | 1000 |
| `limits.scan.open_device_scopes_per_org` | 20000 |

## 4. All users

`--all-users` needs root or SYSTEM and a protected binary. Otherwise it refuses with `SCAN_BINARY_WRITABLE`, because a non-admin who can replace the binary would run as SYSTEM or root.

| Platform | A protected binary is |
|---|---|
| Unix | Root-owned, with no group or world write up the path |
| Windows | Under `%ProgramFiles%` or `%ProgramFiles(x86)%`, or a direct child of `%SystemRoot%\System32`. Under System32 only direct children count as protected |

It reads `/home` and `/root` on Linux, `/Users` and `/var/root` on macOS, and `%SystemDrive%\Users` on Windows. It stays inside each home, follows no links or Windows junctions, and reads no environment.

## 5. Schedule

Run under SYSTEM or root:

```
pclaw scan schedule install --every 24h [--all-users]
pclaw scan schedule status
pclaw scan schedule remove
```

`--every` takes 1h to 720h. Install records `PANTHERCLAW_SERVER`, `PANTHERCLAW_API_KEY_FILE` and `PANTHERCLAW_CONFIG_DIR` from the environment it runs in, never the key value. Scheduled runs use `pclaw scan --submit --device --no-env`, plus `--all-users` if you asked for it.

| Platform | Creates | Notes |
|---|---|---|
| Windows | Scheduled task `PantherClawScan`, `/RU SYSTEM` with `--all-users` | A task cannot carry environment, so the settings go as `--server`, `--key-file` and `--config-dir`. The `/TR` command is limited to 261 characters, and a quotation mark in a value is refused |
| macOS | launchd job `dev.pantherclaw.scan` | |
| Linux | systemd units `pantherclaw-scan.service` and `pantherclaw-scan.timer` | |

Submitted complete scans are compared against inventory (PN-001.3): a material change on an open or claimed discovery notifies its owner, and a discovery missed by 3 complete scans is flagged as vanished, without changing any agent's state or authority.

## 6. Intune (Windows)

1. Package `pclaw` from a verified release ([installation.md](installation.md)) as a Win32 app, and deploy it under `%ProgramFiles%` to the device group.
2. Deliver the key file to a path readable only by SYSTEM.
3. Add a platform script, run as SYSTEM in 64-bit PowerShell, that sets `PANTHERCLAW_SERVER` and `PANTHERCLAW_API_KEY_FILE` for the machine and runs `pclaw scan schedule install --every 24h`.
4. Detect success with `pclaw scan schedule status`.

## 7. Jamf (macOS)

1. Deploy `pclaw` from a verified release as a package, to a smart group.
2. Deliver the key file to a root-only path.
3. Add a policy with a script, run as root, that sets the same two settings and runs `pclaw scan schedule install --every 24h`.
4. Add an extension attribute from `pclaw scan schedule status` to spot devices without a schedule.

## 8. Check it worked

1. On one device, run `pclaw scan schedule status`.
2. In the inventory, look for discoveries with that device's scope.
3. A device that stops reporting shows missed scans on its discoveries. A failed or partial scan never counts as a miss.

## 9. Removing it

Run `pclaw scan schedule remove`, uninstall `pclaw`, delete the key file, and revoke the key if no device still needs it.
