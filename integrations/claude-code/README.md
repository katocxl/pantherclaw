# PantherClaw for Claude Code & the Claude Agent SDK (Apache-2.0)

**Status:** the Claude Code plugin ships in milestone **M6**; the Agent SDK callback follows in **M8** (see [docs/BUILD_GUIDE.md](../../docs/BUILD_GUIDE.md)).

## The Claude Code plugin (M6)

The plugin adds a `PreToolUse` hook for **Bash and PowerShell** commands ([hooks/hooks.json](hooks/hooks.json)). For each command, Claude Code runs `pclaw hook claude-code`, which:
- signs a request with your desktop workload key;
- asks your PantherClaw gateway's `/hook/{connection}` (G0 M6 design decision 16);
- answers.

- **Allowed:** PantherClaw allowed the command and recorded it as *delegated*. Your machine runs it, and the receipt says so.
- **Blocked:** everything else. The reason goes back to Claude:
  - a denial;
  - a hold, which you approve in PantherClaw (never at the local prompt, because you are not an eligible approver of your own agent's action), then retry the command;
  - any error;
  - no answer within 8 seconds.

  The hook fails closed: the plugin also sets `onFailure: "block"`, so a hook that crashes or times out never lets the command through.
- **Paths:** the working directory is resolved to its final form (links, junctions, 8.3 short names). The gateway normalizes it (drive letter, separators, `.` and `..`) and refuses device paths, alternate data streams and trailing dots or spaces. The command text reaches policy exactly as Claude wrote it.
- **Honest coverage:** a hook is cooperative. PantherClaw labels these routes **PARTIAL** unless the credentials the agent would use are held by PantherClaw (credential custody) or the agent runs in the containment sandbox.

### Setup (per developer, opt-in)

1. Enroll this machine as a desktop workload and start a run ([workload identity runbook](../../docs/runbooks/workload-identity.md)).
2. Ask your gateway admin for a `kind: local` connection serving the `pc.shell` package.
3. Set these in your own environment, never in a repository's shared configuration:
   ```bash
   export PANTHERCLAW_GATEWAY=https://gateway.example.com
   export PANTHERCLAW_HOOK_CONNECTION=shell
   export PANTHERCLAW_WORKLOAD_KEY_FILE=~/.pantherclaw/workload.json
   export PANTHERCLAW_RUN=<run id>
   ```
4. Load the plugin for your own sessions only, for example `claude --plugin-dir integrations/claude-code`, or install it in your user settings.

**Or let `pclaw init` set it up (M8):**

```bash
pclaw login --server https://pantherclaw.example.com --org <org>
pclaw init --gateway https://gateway.example.com --connection shell --key-file ~/.pantherclaw/workload.json --agent <agent id> --dry-run
```

`pclaw init`:
- reports the Claude Code settings it finds (user, project, local and managed), the MCP servers that go around PantherClaw, and agent-framework projects;
- when the key file is not an enrolled workload key, creates it (mode 0600) and enrolls it as `--agent`, signed in as you: an enrollment token is issued to you and used at once, never written, and the instance is admitted with the key fingerprint it showed you (HR-094);
- adds the same hook, in exec form with `onFailure: "block"`, to `.claude/settings.local.json`. Choose another file with `--scope project` or `--scope user`; `CLAUDE_CONFIG_DIR` moves the user one.

It only adds (HR-208):
- every existing deny rule, hook and member stays, in its order;
- the diff is shown and nothing changes until you confirm, or pass `--yes`; `--dry-run` changes nothing;
- each file is backed up and replaced through a temporary file;
- no secret is written, only the gateway URL, the connection, the key file's path and the run.

It fails without changing anything when managed settings would keep the hook from running: `allowManagedHooksOnly` without the hook in managed settings, or `disableAllHooks`. Running it again changes nothing.

With the plugin loaded and PantherClaw unreachable or not configured, **every** Bash and PowerShell command is blocked. That is the point. So dogfooding on the PantherClaw repository stays opt-in per developer, and parallel sessions without a local stack keep working (decision 4).

## The Claude Agent SDK (M8)

A `canUseTool` callback with the same semantics.
