# Agent configuration and memory files

**Milestone:** M30 ([G0 M30](../g0/M30.md) D940–D946; [ADR-0057](../adr/0057-firewall-gaps-from-the-threat-map.md)). **Audience:** developers running coding agents with `pclaw`, and the admins who read scans and alerts. Edition: the scans' edition for digests and drift, the sandbox's for the sandbox. Runtime firewall.

An agent's settings, MCP server list, hooks, skills and memory files decide what it can do next session. An agent, or a file it was told to write, can change them to persist or to widen its own tools. PantherClaw watches them in three places.

## 1. Which files

Project files (relative to the repository): each client's settings, MCP and hook files that `pclaw scan` already knows, skills directories, and the memory files `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`, `.github/copilot-instructions.md` and `.cursor/rules/**`. User files: the same clients' files under your home directory and your configuration directory (for example `~/.claude.json`, `~/.claude/CLAUDE.md` and Claude Desktop's `claude_desktop_config.json`); the hook asks about these as it does about project files. Names compare case-insensitively on every host.

## 2. Scans: digests and drift

- `pclaw scan` reports each listed file by client, scope, class, SHA-256 digest and size. **Never its contents.** A file over 1 MiB reports `too_large` (HR-710).
- A credential format found in such a file (a GitHub token, a private key, an AWS access key, a Slack token, a PantherClaw token) is reported as an `env_secret` finding with `source=config_file` and its format, **never the value**. Rotate the credential and move it out of the file.
- When a submitted scan shows a different digest for the same file, the server writes `agent.config_changed` with the old and new digests, and the built-in rule `pc.agent.config_changed` raises one alert, basis OBSERVED. It holds nothing (HR-711). A first sighting writes nothing new.
- **What to do with the alert:** look at the file on the machine, compare it with what you expect (version control, the managed settings), and revert anything you did not make.

## 3. The hook: writes ask the gateway

- `pclaw init` installs a hook whose matcher includes the write tools (`Write`, `Edit`, `MultiEdit`, `NotebookEdit`) besides the shell tools. Run `pclaw init` again after upgrading so an older matcher gains them.
- A write to a listed file asks the gateway as `agent_config.write`. It is refused unless a grant names `agent_config.write` (HR-712). A write to any other path is decided on the machine with no call.
- The route is **cooperative** (PARTIAL): an agent that writes without the hook is not asked. Scans still see the change afterwards by its digest (R-74).

## 4. The sandbox: read-only, and left out of the patch

- `pclaw sandbox run` binds every listed file in the workspace read-only (HR-713).
- If the agent still changes a listed path, copy-out leaves it out of `changes.patch` and prints which classes changed. Review them, then run again with `--include-protected` to apply them. The evidence records how many changed and their classes.

## 5. When something goes wrong

| Symptom | Cause | Fix |
|---|---|---|
| An agent's edit to `CLAUDE.md` is refused | No grant names `agent_config.write` | Edit it yourself, or grant the operation for that task |
| Edits to config files are not asked about | The hook's matcher predates M30 | Run `pclaw init` again |
| A config-changed alert after your own edit | Your edit changed the digest | Nothing to do; the next scan records the new digest |
| Copy-out says configuration files changed | The agent wrote under a listed path | Review, then `--include-protected` if you want them |
