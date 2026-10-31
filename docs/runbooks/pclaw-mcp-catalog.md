# `pclaw mcp catalog`

**Milestone:** M24 ([G0 M24](../g0/M24.md) D220–D226). **Audience:** platform and security teams. This page follows the brief and was written before the commands landed; the M24 exit status records any change.

The catalogue is your organization's list of MCP servers, in the Team edition. A server is PROPOSED, APPROVED, DENIED or REVOKED. A connection matches an entry only exactly: on URL host and path prefix, image digest or package reference.

## Commands

| Command | What it does |
|---|---|
| `pclaw mcp catalog list` | Lists the catalogue |
| `pclaw mcp catalog propose` | Proposes a server |
| `pclaw mcp catalog approve` | Approves a server |
| `pclaw mcp catalog deny` | Denies a server |
| `pclaw mcp catalog mode` | Shows or sets the mode |
| `pclaw mcp catalog revoke` | Previews and revokes a server |
| `pclaw mcp catalog export` | Writes the catalogue to a file |

## Modes

| Mode | Effect |
|---|---|
| `OFF` | The catalogue has no effect |
| `WATCH` (default) | Reports unapproved servers as findings and stops nothing |
| `ENFORCE` | Refuses to activate a connection to an unapproved server (`SERVER_NOT_APPROVED`) |

Turning on `ENFORCE` shows a preview, then quarantines non-matching connections. Read the preview first: a good server whose address changed will not match. Setting the mode needs a person and a step-up.

Leaving `ENFORCE` always waits for a second person, with no emergency path.

The finding `UNAPPROVED_SERVER` appears only once the catalogue holds at least one approved server.

## Revoking a server

A person revokes a server inside one organization, in two steps: a preview that returns a digest, then the revoke with that digest and a reason. It puts a deny-all control on every matching connection and quarantines versions of the package whose name exactly equals the server's package reference.

An independent second person lifts it, which restores the connections. The server stays REVOKED: `approve` is refused with `SERVER_REVOCATION_ACTIVE` while any control of that revocation is live, and after that needs a person with a step-up. Quarantined package versions return only through fresh review.

A new connection matching a REVOKED server is refused in every mode, including `OFF`, with `SERVER_REVOKED`. Modes govern unapproved servers, not revoked ones. A DENIED server is refused only under `ENFORCE`.

A local server that PantherClaw has seen only through scans comes back as `not_stoppable_here`, with a hint to add it to a deny list. PantherClaw cannot stop that server; use [managed settings](pclaw-managed-settings.md).

## Export

| Format | Output |
|---|---|
| `--format managed-allow` | The allow file for `pclaw managed-settings generate --allow-file`. It never writes a name-only entry; an image-only server is left out and listed on stderr |
| `--format registry-v0` | A static file in the official registry's shape |

There is no HTTP endpoint for the catalogue.
