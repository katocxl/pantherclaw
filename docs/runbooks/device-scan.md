# Runbook — Scheduled device scans

**Milestone:** M24 ([G0 M24](../g0/M24.md) D233–D237). **Audience:** IT and security teams that manage laptops. This page follows the brief and was written before the commands landed. Nothing here has been run on a real Intune or Jamf tenant; the M24 exit status records any change.

A scheduled `pclaw scan` finds MCP configurations, hooks, skills and held keys on managed devices and submits them as metadata, so that discovery stays current without an installed service.

## 1. What a scan sends

Metadata only:

| Finding | Sent |
|---|---|
| Hook | Event and executable basename |
| Skill | Name and path |
| Package-run server (`npx`, `uvx`, `bunx`, `pipx run`, `docker run`) | The package or image token; no other arguments |

A scan never sends file contents or prompts. Tell the people whose devices you scan what it reads. `--all-users` reads every home directory on the device, with the same limits. Local law or a works agreement may apply to this; that check is yours.

"Not observed" is not "absent": a scan sees what its readers cover on that device, on that day.

## 2. Create a scanner key

1. Create a service account for scanning, with the role `Scanner`. It holds exactly `org.read` and `agent.scan.submit`, so it can submit scans for its scope and write nothing else. The role is for service accounts only.
2. Create an API key for it, and keep it out of device-management scripts and logs. Deliver it as a file readable only by SYSTEM or root.
3. Point `PANTHERCLAW_API_KEY_FILE` at that file.

A key on many laptops is easy to steal, so plan for it: rotate on a schedule, and revoke if a device is lost. The role limits what a stolen key can do; it does not stop someone submitting false findings for that scope.

## 3. Scope

Each device gets the scope `device:<id>`: the first 16 hex of SHA-256 over the machine id and a local salt, kept in the `pclaw` config directory. The 200-finding cap applies per source and scope, and dropped findings are still reported.

If the `pclaw` config directory is wiped, the device gets a new salt and looks like a new device.

## 4. Schedule

Run under SYSTEM or root:

```
pclaw scan schedule install --every 24h
pclaw scan schedule status
pclaw scan schedule remove
```

This creates a scheduled task on Windows, a launchd job on macOS and a systemd timer on Linux.

Submitted complete scans are compared against inventory (PN-001.3): a material change on an open or claimed discovery notifies its owner, and a discovery missed by 3 complete scans is flagged as vanished, without changing any agent's state or authority.

## 5. Intune (Windows)

1. Package `pclaw` from a verified release ([installation.md](installation.md)) as a Win32 app, and deploy it to the device group.
2. Deliver the key file to a path readable only by SYSTEM.
3. Add a platform script, run as SYSTEM in 64-bit PowerShell, that sets `PANTHERCLAW_SERVER` and `PANTHERCLAW_API_KEY_FILE` for the machine and runs `pclaw scan schedule install --every 24h`.
4. Detect success with `pclaw scan schedule status`.

## 6. Jamf (macOS)

1. Deploy `pclaw` from a verified release as a package, to a smart group.
2. Deliver the key file to a root-only path.
3. Add a policy with a script, run as root, that sets the same two settings and runs `pclaw scan schedule install --every 24h`.
4. Add an extension attribute from `pclaw scan schedule status` to spot devices without a schedule.

## 7. Check it worked

1. On one device, run `pclaw scan schedule status`.
2. In the inventory, look for discoveries with that device's scope.
3. A device that stops reporting shows missed scans on its discoveries. A failed or partial scan never counts as a miss.

## 8. Removing it

Run `pclaw scan schedule remove`, uninstall `pclaw`, delete the key file, and revoke the key if no device still needs it.
