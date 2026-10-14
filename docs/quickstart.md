# Quickstart: your first 30 minutes

**Audience:** a developer who wants to see PantherClaw hold, allow and block a coding agent, on one machine, with nothing real connected. **Source:** [PRODUCT.md](PRODUCT.md) §6 "First 30 minutes" (F335), run on the simulators. Everything here is local and SIMULATED. Nothing touches a real GitHub account.

The 30 minutes are a target, measured and not guaranteed. The founder's timed run is recorded in [perf/onboarding.md](perf/onboarding.md).

> **Status of this draft (2026-10-14).** Step 1 was run end to end (`task demo:up` is idempotent, starts everything and `task demo:status` reports it). The sign-in in step 2 could not be completed in a Chromium-based browser, and steps 3 to 9 are written from the `pclaw` usage and the M8 and M9 end-to-end tests but were not run. The blockers are listed in the pull request that added this file, and each step that depends on one is marked **Blocked**. Remove this box when a full run has passed.

## What you need

- Windows (Git Bash), Linux or macOS, with Go 1.27, Docker 28 or later, `openssl` and `curl`. On Windows run every command from **Git Bash**, not PowerShell.
- `task`, or use `go tool -modfile=tools/pins/task/go.mod task <name>` in its place.
- A browser, and a security key or a platform authenticator (Windows Hello, Touch ID) for the approval in step 8.
- About 3 GB of free disk space and the first build's patience (the first `task demo:up` takes a few minutes while Go builds and Docker pulls PostgreSQL and Keycloak).

## 1. Start the demo (`task demo:up`)

```bash
task demo:up
. .demo/env.sh
```

`demo:up` is safe to run again. It starts PostgreSQL and the Keycloak development realm, builds the binaries into `bin/`, creates local-only secrets under `deploy/dev/secrets/` and `.demo/`, migrates the database, seeds a demo organization "acme" (a gateway, the `github` and `shell` connections, an agent with a grant), builds the sandbox images, and starts the server, the gateway and the GitHub simulator in the background. Logs and pid files are in `.demo/`.

Expected end of the output:

```text
7/7 server and gateway
  server: started (pid …, log .demo/logs/server.log)
  gateway: started (pid …, log .demo/logs/gateway.log)

The demo is up (all SIMULATED, all on this machine).
```

Check it with `task demo:status` (three processes running, `/readyz` ready). Stop it with `task demo:down`; your data stays.

`. .demo/env.sh` puts `bin/` on your `PATH` and sets the settings the later steps use (`pclaw`'s credentials directory, the sandbox image ids, `DEMO_ORG`, `DEMO_AGENT`, `DEMO_GRANT`, `DEMO_GITHUB`, `DEMO_GATEWAY_ID`). Source it in every terminal you use.

## 2. Sign in (`pclaw login`) — **Blocked**

The seeded organization has no people yet. Ask the server for the one-time administrator token, then sign in as `alice` (the Keycloak development user, password `alice-dev-only`):

```bash
pantherclaw-server org admin-invite --config .demo/server.json --org "$DEMO_ORG"
pclaw login --server "$DEMO_SERVER" --org "$DEMO_ORG" --invitation <the pci_ token>
```

`pclaw` prints a link and a code. Open the link, check that the code matches, choose **Continue to sign in**, and sign in to Keycloak. Expected: `pclaw` ends with `whoami` output naming `alice` and the organization.

Then give yourself the roles the rest of this guide uses, and note your user id:

```bash
ME=$(pclaw whoami | sed -n 's/^user[: ]*//p')          # your user id
for r in gateway_admin agent_owner agent_admitter run_launcher security_admin grant_issuer policy_author policy_publisher; do
  pclaw role bind --role "$r" --user "$ME"
done
```

**Blocked:** in Chromium-based browsers, **Continue to sign in** answers "This request did not come from the PantherClaw sign-in page." The page sets `Referrer-Policy: no-referrer`, which makes the browser send `Origin: null` on the form post, and the handler requires the server's own origin. This needs a product change (see the pull request).

## 3. Wire Claude Code (`pclaw init`)

`pclaw init` finds Claude Code and its MCP servers, enrolls this machine as an agent, and installs the hook that asks the gateway before every shell command. First create the places the agent belongs to, then the agent:

```bash
pclaw team create --slug coding --name Coding
pclaw env create --slug demo --name Demo --kind dev
pclaw agent create --name claude-code --team <team id> --env <env id> --owner "$ME" --context desktop
```

Dry-run `init` against a project directory (it changes nothing), then run it for real:

```bash
pclaw init --gateway "$DEMO_GATEWAY" --connection shell --key-file .demo/claude-code.key \
  --agent <agent id> --mcp github=github --project . --dry-run
pclaw init --gateway "$DEMO_GATEWAY" --connection shell --key-file .demo/claude-code.key \
  --agent <agent id> --mcp github=github --project .
```

## 4. Enroll the agent and confirm its fingerprint

`init` shows the new key's fingerprint before it enrolls anything (HR-094). Compare it with what you see in `pclaw instance list <agent id>`, and answer yes. Expected: the instance is `ADMITTED`, and `init` lists the Claude Code settings file it changed, with a backup beside it.

## 5. Apply the "coding to production" template

Reading, branching and opening pull requests are allowed. Merging needs an independent reviewer (`code_reviewer`). A deployment consequence needs a release approver in an open change window.

```bash
pclaw template apply coding-to-production --repos acme/payments --agent "$DEMO_AGENT" --team <team id> --dry-run
pclaw template apply coding-to-production --repos acme/payments --agent "$DEMO_AGENT" --team <team id> --yes
```

Expected: the plan lists the guardrail, the policy, the change window and the grant, then `Done:` for each. Running it again prints `Nothing to change`.

## 6. Connect the GitHub App

The GitHub simulator is installed as an App (client id `Iv23liSimulated`, installation `1`, account `acme`) with its key at `.demo/github-app.pem`, and the demo's `github` connection waits for that key. Seal it to the gateway, so that the agent never holds a GitHub credential:

```bash
pclaw gateway get "$DEMO_GATEWAY_ID"                      # note the active broker key's fingerprint
pclaw seal --connection "$DEMO_GITHUB" --github-app Iv23liSimulated --installation 1 --account acme \
  --from-file .demo/github-app.pem --fingerprint sha256:<that fingerprint>
rm .demo/github-app.pem
```

Expected: `pclaw connection get "$DEMO_GITHUB"` shows the installation. (To connect a real App instead, follow [runbooks/github-app.md](runbooks/github-app.md); the demo does not need one.)

## 7. Run the agent in the sandbox (`pclaw sandbox run`)

Tell the connection which host names agents use, so that the sandbox maps `api.github.com` to the gateway:

```bash
REV=$(pclaw connection get "$DEMO_GITHUB" | sed -n 's/^revision[: ]*//p')
pclaw connection update "$DEMO_GITHUB" --revision "$REV" --agent-host api.github.com
```

The agent is the demo agent (`pantherclaw-demo-agent`), which `demo:up` built into `$DEMO_AGENT_IMAGE`. Its workspace, `$DEMO_WORKSPACE`, holds a made-up personal access token in `.env` and a made-up SSH key, the kind of leftovers a developer forgets. Look up the commit the pull request will start from, then run the agent for its first, allowed task:

```bash
GH=http://127.0.0.1:9092; TOKEN=$(cat .demo/github-mcp.token)
MAIN=$(curl -s -H "Authorization: Bearer $TOKEN" $GH/repos/acme/payments/branches/main | grep -o '"sha": *"[0-9a-f]*"' | head -1 | grep -o '[0-9a-f]\{20,\}')
pclaw sandbox run --agent "$DEMO_AGENT" --connection "$DEMO_GITHUB" --grant "$DEMO_GRANT" --gateway "$DEMO_GATEWAY" \
  --image "$DEMO_AGENT_IMAGE" --workspace "$DEMO_WORKSPACE" --out .demo/sandbox-out -- allowed acme/payments "$MAIN"
```

Expected: the agent's lines `read`, `branch`, `write` and `pr` with HTTP 200 or 201, and near the end `connection …: sandbox closure PASSED (closure …), evidence for ENFORCED until <time>`.

## 8. Read the coverage card (`pclaw coverage list`)

```bash
pclaw coverage list --agent "$DEMO_AGENT" --connection "$DEMO_GITHUB"
```

Expected: the repository operations the run used show `ENFORCED`, with an expiry within 24 hours.

## 9. Guided tests: one allowed, one held, one blocked

1. **Allowed.** Step 7 was it: reading a file, creating a branch, writing a file and opening a pull request went through the gateway, which decided each one.
2. **Held.** The agent merges the pull request with a raw request, as `curl` would send it. The gateway maps it to the same action as the GitHub MCP server's merge (F099), and policy holds it, because nobody independent has reviewed the pull request:

   ```bash
   HEAD=$(curl -s -H "Authorization: Bearer $TOKEN" $GH/repos/acme/payments/pulls/1 | grep -o '"sha": *"[0-9a-f]*"' | head -1 | grep -o '[0-9a-f]\{20,\}')
   pclaw sandbox run --agent "$DEMO_AGENT" --connection "$DEMO_GITHUB" --grant "$DEMO_GRANT" --gateway "$DEMO_GATEWAY" \
     --image "$DEMO_AGENT_IMAGE" --workspace "$DEMO_WORKSPACE" -- held acme/payments 1 "$HEAD"
   ```

   Expected: the agent's line `merge 202 …` or `merge 409 …` naming the hold and the reason `MERGES_NEED_AN_INDEPENDENT_REVIEW`, and an approval request in `pclaw approval list`. A second person (`bob`, Keycloak password `bob-dev-only`) with the `code_reviewer` role approves it on the approval page with a security key: `pclaw approval approve <id>`.
   - Approvals count only from people, roles and keys of a minimum age (G0 M5 part 2, decision 5), which real orgs cannot shorten. For the demo only, `bash tools/scripts/demo.sh age` backdates the demo organization by 30 days. This simulates a week-old org, by editing the local demo database directly.
   - A reviewer of a GitHub merge must also have linked a GitHub account. The simulator's command line has no sign-in App, so `bash tools/scripts/demo.sh link-github bob@example.test reviewer-bob` links the reviewer directly (also raw SQL on the local demo database, which both commands refuse to touch unless it is local). Real orgs link with `pclaw github link` and keep the cooldowns.
3. **Blocked.** The agent pushes with the personal access token it found in `.env`, over HTTPS, and with the SSH key, to `github.com` and to GitHub's address. The sandbox holds no reusable credential and its egress is closed:

   ```bash
   pclaw sandbox run --agent "$DEMO_AGENT" --connection "$DEMO_GITHUB" --grant "$DEMO_GRANT" --gateway "$DEMO_GATEWAY" \
     --image "$DEMO_AGENT_IMAGE" --workspace "$DEMO_WORKSPACE" -- blocked acme/payments
   ```

   Expected: `https-push` refused, `ssh … blocked` for both addresses, and `sandbox closure PASSED`: the probes found every route closed.

## Troubleshooting

- **`task demo:up` stops at Keycloak.** Docker Desktop can start a container without publishing its port. Run `docker restart pantherclaw-keycloak-1` and `task demo:up` again.
- **`task demo:up` says the gateway's enrollment failed.** The enrollment file `dev seed` writes lasts 15 minutes. Delete `.demo/seed.done` and `.demo/gateway/identity`, then run `task demo:up` again to seed a new organization.
- **Ports.** The demo uses 8080 (API), 8443 (gateway to server), 8090 (gateway), 9092 and 9093 (simulator), 5432 (PostgreSQL) and 8180 (Keycloak), all on 127.0.0.1.
- **Start over.** `task demo:down`, delete `.demo/`, run `task down PROFILE=core` and `task up PROFILE=core`. The secrets under `deploy/dev/secrets/` are shared with the other development tasks; leave them.
