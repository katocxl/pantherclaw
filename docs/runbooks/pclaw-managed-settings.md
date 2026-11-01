# `pclaw managed-settings`

**Milestone:** M23 ([G0 M23](../g0/M23.md) D113, D114). **Audience:** administrators of coding-agent clients. This page follows the brief and was written before the command landed; key names are checked against the vendors' docs while building, and the M23 exit status records any change.

`pclaw managed-settings generate` writes admin settings files that pin PantherClaw's hook and the allowed MCP servers. You deploy the files with your own device management.

```
pclaw managed-settings generate --client claude-code|copilot [--allow-file F] [--out DIR]
```

| Flag | Meaning |
|---|---|
| `--client` | `claude-code` or `copilot` |
| `--allow-file F` | Allowed servers, as JSON: `{"servers":[{"name","url","command"}]}` |
| `--out DIR` | Output directory; without it, stdout. Managed locations, Copilot's managed directories and `.github-private` are refused |

In the allow file, `command` is a string list, or one string that is the whole command and is never split. URLs are exact, with no wildcard, credentials or query. **With no allow file, the lists are empty and block every MCP server**; the command says so on stderr.

| Client | Files |
|---|---|
| Claude Code | `managed-settings.json` (`allowManagedHooksOnly`, PantherClaw's hook, `allowedMcpServers`, and `allowManagedMcpServersOnly: true`, so a user cannot broaden the list) and `managed-mcp.json` |
| Copilot | `managed-settings.json` with allow and deny lists; the deny list is empty |

The command never writes to a managed location, and `pclaw init` never edits managed settings.

## What it does not do

**A settings file changes no coverage state.** Coverage comes from tested routes, not from a file being present. Generating the files, deploying them or finding them raises nothing.

`pclaw init` reports the managed state it can see as `not_found`, `present` or `conflict`. `not_found` shows as "No readable managed settings found": registry, device-management, server-managed and other clients' settings cannot be read from there, so the machine may still be managed.

Scans add a `managed_settings` attribute to existing findings, and the recommendation `unsupported.managed_settings_missing` (Team and up) appears when settings are missing.

From M24, `pclaw mcp catalog export --format managed-allow` writes the `--allow-file` from your catalogue.
