# PantherClaw for VS Code (Apache-2.0)

A read-only view of one agent in VS Code: its coverage, the approvals waiting for it and its decisions of the last 24 hours (G0 M36 D1067).

- **No token in VS Code.** The extension runs the signed-in `pclaw` on the same machine (`pclaw editor status --agent ID --json`), with an argument list and never through a shell. pclaw uses your own session (`pclaw login`).
- **Read only.** There is no approve, decline or edit action anywhere. **Open in console** asks `pclaw editor open approval|transaction ID` for the console page and opens it in your browser, where you decide.
- **Refresh** every 60 seconds, on demand (the view's refresh button or the status bar item) and when a setting changes.

## Settings

- `pantherclaw.pclawPath`: the pclaw program (default `pclaw` on PATH). A machine setting: a workspace cannot change it.
- `pantherclaw.agent`: the agent id. When empty, the extension reads `.pantherclaw/agent` in the first workspace folder, only in a trusted workspace.

## Install

It has no build step and no dependencies. For development, open this folder in VS Code and run the extension host (F5), or package it with `vsce package`. Marketplace and Open VSX publishing come later.
