# Quickstart: your first 30 minutes

**Audience:** a developer who wants to see PantherClaw hold, allow and block a coding agent, on one machine, with nothing real connected. **Source:** [PRODUCT.md](PRODUCT.md) §6 "First 30 minutes" (F335), run on the simulators. Everything here is local and SIMULATED. Nothing touches a real GitHub account.

The 30 minutes are a target, measured and not guaranteed. The founder's timed run is recorded in [perf/onboarding.md](perf/onboarding.md).

## What you need

- Windows (Git Bash), Linux or macOS, with Go 1.27, Docker 28 or later, `openssl` and `curl`. On Windows run every command from **Git Bash**, not PowerShell.
- `task`, or use `go tool -modfile=tools/pins/task/go.mod task <name>` in its place.
- A browser, and a security key or a platform authenticator (Windows Hello, Touch ID) for the approval in step 9.
- About 3 GB of free disk space and some patience on the first run: the first `task demo:up` takes several minutes while Go builds and Docker pulls PostgreSQL and Keycloak.

`pclaw` prints JSON. Where a step needs an id, copy it from the output; the `pcid` helper that `. .demo/env.sh` defines prints the first `"id"` of its input, so the commands below do that for you.

## 1. Start the demo (`task demo:up`)

```bash
task demo:up
. .demo/env.sh
```

`demo:up` is safe to run again. It starts PostgreSQL and the Keycloak development realm, builds the binaries into `bin/`, creates local-only secrets under `deploy/dev/secrets/` and `.demo/`, migrates the database, seeds a demo organization "acme" (a gateway, the `github` and `shell` connections), builds the sandbox images (edge, probe and the demo agent), starts the server, the gateway and the GitHub simulator in the background, and prepares two folders: a project with a GitHub MCP server for `pclaw init`, and a workspace with a made-up token and SSH key for the sandboxed agent. Logs and pid files are in `.demo/`.

Expected end of the output:

```text
7/7 server and gateway
  server: started (pid …, log .demo/logs/server.log)
  gateway: started (pid …, log .demo/logs/gateway.log)

The demo is up (all SIMULATED, all on this machine).
```

Check it with `task demo:status`. Stop it with `task demo:down`; your data stays. `. .demo/env.sh` puts `bin/` on your `PATH` and sets what the later steps use (`DEMO_ORG`, `DEMO_GITHUB`, `DEMO_GATEWAY_ID`, `DEMO_AGENT_IMAGE`, `DEMO_WORKSPACE`, `DEMO_PROJECT`, the sandbox image ids). Source it in every terminal you use.

## 2. Sign in (`pclaw login`)

The seeded organization has no people yet. Ask the server for the one-time administrator token, then sign in as `alice` (the Keycloak development user, password `alice-dev-only`):

```bash
pantherclaw-server org admin-invite --config .demo/server.json --org "$DEMO_ORG"
pclaw login --server "$DEMO_SERVER" --org "$DEMO_ORG" --invitation <the pci_ token>
```

`pclaw` prints a link and a code. Open the link, check that the code matches, choose **Continue to sign in**, and sign in to Keycloak. Expected: `Signed in to acme (…) as alice@example.test` and `Roles: org_admin (org)`.

Give yourself the roles the rest of this guide uses:

```bash
ME=$(pclaw role bindings | grep -A4 '"role": *"org_admin"' | pcid)
for r in gateway_admin agent_owner agent_admitter run_launcher security_admin grant_issuer policy_author policy_publisher; do
  pclaw role bind --role "$r" --user "$ME"
done
```

## 3. Wire Claude Code (`pclaw init`)

`pclaw init` finds Claude Code's settings and MCP servers, enrolls a key as an agent, and installs the hook that asks the gateway before every shell command. The demo wires a throwaway project (`$DEMO_PROJECT`), never your own Claude Code settings. First create the team, environment and agent:

```bash
TEAM=$(pclaw team create --slug coding --name Coding | pcid)
ENV=$(pclaw env create --slug demo --name Demo --kind dev | pcid)
CC=$(pclaw agent create --name claude-code --team "$TEAM" --env "$ENV" --owner "$ME" --context desktop | pcid)
pclaw workload init --key-file .demo/claude-code.key
```

`workload init` prints the new key's fingerprint. Look at what `init` would change (it changes nothing with `--dry-run`):

```bash
pclaw init --gateway "$DEMO_GATEWAY" --connection shell --key-file .demo/claude-code.key \
  --agent "$CC" --mcp github=github --project "$DEMO_PROJECT" --scope project --dry-run
```

Expected: a diff that adds the `PreToolUse` hook (`pclaw hook claude-code`) and a `pantherclaw-github` MCP server to the project's settings, and denies the original `github` server, which holds a token in its headers (a route around PantherClaw).

## 4. Enroll the agent and confirm its fingerprint

Run it for real, giving the fingerprint `workload init` printed (HR-094: you compare it before anything is enrolled):

```bash
pclaw init --gateway "$DEMO_GATEWAY" --connection shell --key-file .demo/claude-code.key \
  --agent "$CC" --mcp github=github --project "$DEMO_PROJECT" --scope project --yes --fingerprint <the fingerprint>
```

Expected: `Enrolled and admitted instance … of agent …`, then the settings file it wrote, with a backup of the MCP file beside it. `pclaw instance list "$CC"` shows the instance `INSTANCE_STATE_ADMITTED`.

## 5. Apply the "coding to production" template

The agent that runs in the sandbox is a second agent, `coder`, that you own: the agent `dev seed` created has no human owner, and only an agent's owner may admit its sandbox instance. Its only way out is the sandbox. Create it, then apply the template to it. Reading, branching and opening pull requests are allowed. Merging needs an independent reviewer (`code_reviewer`). A deployment consequence needs a release approver in an open change window.

```bash
CODER=$(pclaw agent create --name coder --team "$TEAM" --env "$ENV" --owner "$ME" --context desktop | pcid)
pclaw template apply coding-to-production --repos acme/payments --agent "$CODER" --team "$TEAM" --dry-run
pclaw template apply coding-to-production --repos acme/payments --agent "$CODER" --team "$TEAM" --yes
```

Expected: the plan lists the policy rules, the change window, the guardrail and the grant, then a `Done:` line for each. Running it again prints `Nothing to change`. The grant it issues is the one the sandbox run uses:

```bash
GRANT=$(pclaw grant list --agent "$CODER" | pcid)
```

## 6. Connect the GitHub App

The GitHub simulator is installed as an App (client id `Iv23liSimulated`, installation `1`, account `acme`) with its key at `.demo/github-app.pem`, and the demo's `github` connection waits for that key. Seal it to the gateway, so that the agent never holds a GitHub credential:

```bash
FP=$(pclaw gateway get "$DEMO_GATEWAY_ID" | grep -o 'sha256:[0-9a-f]\{64\}' | head -1)
pclaw seal --connection "$DEMO_GITHUB" --github-app Iv23liSimulated --installation 1 --account acme \
  --from-file .demo/github-app.pem --fingerprint "$FP"
```

Expected: a credential of kind `github_app`, and `pclaw connection get "$DEMO_GITHUB"` shows the installation. Leave `.demo/github-app.pem` where it is: it is the simulator's own key, and the simulator needs it when it restarts. (To connect a real App instead, follow [runbooks/github-app.md](runbooks/github-app.md); the demo does not need one.)

## 7. Run the agent in the sandbox (`pclaw sandbox run`)

Tell the connection which host names agents use, so that the sandbox maps `api.github.com` to the gateway:

```bash
REV=$(pclaw connection get "$DEMO_GITHUB" | sed -n 's/.*"revision": *\([0-9]*\).*/\1/p' | head -1)
pclaw connection update "$DEMO_GITHUB" --revision "$REV" --agent-host api.github.com
```

The agent is the demo agent (`pantherclaw-demo-agent`), which `demo:up` built into `$DEMO_AGENT_IMAGE`. Its workspace, `$DEMO_WORKSPACE`, holds a made-up personal access token in `.env` and a made-up SSH key, the kind of leftovers a developer forgets. Look up the commit the pull request will start from, then run the agent for its first task:

```bash
GH=http://127.0.0.1:9092; TOKEN=$(cat .demo/github-mcp.token)
MAIN=$(curl -s -H "Authorization: Bearer $TOKEN" $GH/repos/acme/payments/branches/main | grep -o '"sha": *"[0-9a-f]*"' | head -1 | grep -o '[0-9a-f]\{20,\}')
pclaw sandbox run --agent "$CODER" --connection "$DEMO_GITHUB" --grant "$GRANT" --gateway "$DEMO_GATEWAY" \
  --image "$DEMO_AGENT_IMAGE" --workspace "$DEMO_WORKSPACE" -- allowed acme/payments "$MAIN"
```

The first run opens a sandbox session, so Docker needs a minute. Expected: `sandbox closure PASSED (closure …), evidence for ENFORCED until <time>`, then the agent's lines: `read 200`, `branch 201`, `write 201` and `pr 201`.

## 8. Read the coverage card (`pclaw coverage list`)

```bash
pclaw coverage reassess "$DEMO_GITHUB" --agent "$CODER"      # the server does this every 60 s; this asks for it now
pclaw coverage list --agent "$CODER" --connection "$DEMO_GITHUB"
```

Expected: every repository operation the run used (`github.contents.read`, `github.branch.create`, `github.contents.write`, `github.pull.create`) shows `COVERAGE_STATE_ENFORCED` with an expiry within 24 hours, naming the closure.

## 9. Guided tests: one allowed, one held, one blocked

1. **Allowed.** Step 7 was it: reading a file, creating a branch, writing a file and opening a pull request went through the gateway, which decided each one (`ALLOW`, `GRANT_COVERS`).
2. **Held.** The agent merges the pull request with a raw request, as `curl` would send it. The gateway maps it to the same action as the GitHub MCP server's merge (F099), and policy holds it, because nobody independent has reviewed the pull request:

   ```bash
   HEAD=$(curl -s -H "Authorization: Bearer $TOKEN" $GH/repos/acme/payments/pulls/1 | grep -o '"sha": *"[0-9a-f]*"' | head -1 | grep -o '[0-9a-f]\{20,\}')
   pclaw sandbox run --agent "$CODER" --connection "$DEMO_GITHUB" --grant "$GRANT" --gateway "$DEMO_GATEWAY" \
     --image "$DEMO_AGENT_IMAGE" --workspace "$DEMO_WORKSPACE" -- held acme/payments 1 "$HEAD"
   ```

   Expected: `merge 403 {"error_class":"held",…,"decision":"REQUIRE_APPROVAL","reasons":["MERGE_NEEDS_REVIEW","DEPLOYMENT_NEEDS_RELEASE"],…}`, and a pending request in `pclaw approval list` that needs a `code_reviewer` who is independent of the pull request.
3. **Blocked.** The agent pushes with the personal access token it found in `.env`, over HTTPS, and with the SSH key, to `github.com` and to GitHub's address. The sandbox holds no reusable credential and its egress is closed:

   ```bash
   pclaw sandbox run --agent "$CODER" --connection "$DEMO_GITHUB" --grant "$GRANT" --gateway "$DEMO_GATEWAY" \
     --image "$DEMO_AGENT_IMAGE" --workspace "$DEMO_WORKSPACE" -- blocked acme/payments
   ```

   Expected: `https-push … Forbidden`, `ssh github.com:22 blocked`, `ssh 140.82.112.3:22 blocked`, `sandbox closure PASSED`, and `the edge refused or stripped 1 routes of the agent`: the probes found every route closed.

### Approve the held merge (as a second person)

An independent reviewer approves on the approval page with a security key. Invite `bob`, sign in as him, and give him the reviewer roles:

```bash
pclaw invite create --email bob@example.test --role approver        # copy the pci_ token from the output
PANTHERCLAW_CONFIG_DIR=$PWD/.demo/pclaw-bob pclaw login --server "$DEMO_SERVER" --org "$DEMO_ORG" --invitation <the pci_ token>
```

Before bob signs in, sign out of Keycloak in the browser (`http://127.0.0.1:8180/realms/pantherclaw/protocol/openid-connect/logout`), then sign in as `bob` (password `bob-dev-only`). Bind him as reviewer, using his user id from the invitation or from `pclaw role bindings`:

```bash
pclaw role bind --role code_reviewer --user <bob's user id>
pclaw role bind --role release_approver --user <bob's user id>
```

Two things a fresh demo cannot satisfy, which the demo simulates **for the demo only** by editing the local demo database directly (both commands refuse to touch any database that is not local):

- Approvals count only from people, roles and keys of a minimum age (G0 M5 part 2, decision 5), which real orgs cannot shorten. `bash tools/scripts/demo.sh age` backdates the demo organization by 30 days, so it looks like a week-old org.
- A reviewer of a GitHub merge must have linked a GitHub account. The simulator's command line has no sign-in App, so `bash tools/scripts/demo.sh link-github bob@example.test reviewer-bob` links him directly. Real orgs link with `pclaw github link` and keep the cooldowns.

Then, as bob, add a security key at `http://localhost:8080/account`, run `bash tools/scripts/demo.sh age` again (so the new key is old enough), export the approver keys for the gateway, and approve:

```bash
PANTHERCLAW_CONFIG_DIR=$PWD/.demo/pclaw-bob pclaw approver-keys export --out .demo/approver-keys.json
PANTHERCLAW_CONFIG_DIR=$PWD/.demo/pclaw-bob pclaw approval approve <the request id from pclaw approval list>
```

`approve` prints the approval page's address. Open it, check the binding hash, and approve with the key. Run the `held` command again: the request is now approved.

## Troubleshooting

- **`task demo:up` stops at Keycloak.** Docker Desktop can start a container without publishing its port. Run `docker restart pantherclaw-keycloak-1` and `task demo:up` again.
- **The gateway's enrollment failed.** The enrollment file `dev seed` writes lasts 15 minutes. Delete `.demo/seed.done` and `.demo/gateway/identity`, then run `task demo:up` again to seed a new organization.
- **Ports.** The demo uses 8080 (API), 8443 (gateway to server), 8090 (gateway), 9092 and 9093 (simulator), 5432 (PostgreSQL) and 8180 (Keycloak), all on 127.0.0.1.
- **Start over.** `task demo:down`, delete `.demo/`, run `task down PROFILE=core` and `task up PROFILE=core`. The secrets under `deploy/dev/secrets/` are shared with the other development tasks; leave them.
