# Containment sandbox (`pclaw sandbox run`)

**Milestone:** M9 · **Owner:** agent owners and developers (`sandbox.run`) · **Status:** procedure, covered by the Docker-gated tests (`task test:sandbox`); the M9 exit end-to-end test is pending

How to run an agent in the containment sandbox, read what it proved, and get its work back. Background: [g0/M9.md](../g0/M9.md) (track B), [ADR-0022](../adr/0022-containment-sandbox-edge.md).

## 1. What you need

- Docker 28 or later with a Linux engine, its default seccomp profile, and runc (gVisor's runsc is detected and recorded when present). `pclaw` refuses anything else (HR-218).
- Linux and Docker Desktop both work. Docker Desktop gives containers `host.docker.internal`. A native Linux engine does not, and no container is given extra host entries (HR-216), so there the edge reaches a gateway on this host through a per-session relay that `pclaw` binds to the host's address on the sandbox's uplink network and that takes that edge's connections only (HR-228). The relay needs nothing from you: leave `--gateway-addr` unset for a gateway on this host's loopback, or give the host-side address (not `host.docker.internal`). A gateway that runs connectors (`connectors.egress_listen`) gets the same relay per connector; `connectors.egress_addr` is then not needed.
- The edge and probe images, built locally:
  ```bash
  task sandbox:images
  ```
  Pass the printed ids as `--edge-image` and `--probe-image`, or set `PANTHERCLAW_SANDBOX_EDGE_IMAGE` and `PANTHERCLAW_SANDBOX_PROBE_IMAGE`. Images are always pinned by digest or local id; a tag is refused.
  To use the released images instead, see "Use the released images" below.
- The agent's image, pinned by digest (`--image repo@sha256:…`).
- The connections the agent uses, each active, served by one gateway, with a pinned package and the host names agents use for its API:
  ```bash
  pclaw connection update <connection> --agent-host api.github.com
  ```
- A grant for the agent (`--grant`) and the `sandbox.run` permission over the agent (Agent Owner or Developer).

### Use the released images

Each release publishes the edge and probe images (linux/amd64 and linux/arm64, on the pinned distroless base) as `ghcr.io/katocxl/pantherclaw-edge` and `ghcr.io/katocxl/pantherclaw-probe`, tagged with the version and never `latest`. The release notes list both digests. Pin the digest, never the tag:

```bash
docker pull ghcr.io/katocxl/pantherclaw-edge@sha256:<digest>
docker pull ghcr.io/katocxl/pantherclaw-probe@sha256:<digest>
gh attestation verify oci://ghcr.io/katocxl/pantherclaw-edge@sha256:<digest> --repo katocxl/pantherclaw
gh attestation verify oci://ghcr.io/katocxl/pantherclaw-probe@sha256:<digest> --repo katocxl/pantherclaw
```

Then set `sandbox.images` (edge and probe) to those `repo@sha256:<digest>` references, or pass them as `--edge-image` and `--probe-image`. Do not run an image whose attestation does not verify.

## 2. Run an agent

```bash
pclaw sandbox run --agent <agent> --connection <connection> --grant <grant> --gateway https://gateway.example.com \
  --image registry.example.com/acme/coder@sha256:<digest> --workspace ./repo --out ./sandbox-out -- <command> <args>
```

The run, in order:
1. checks Docker;
2. opens a session with two keys it creates outside every container (the probe key and the host key; the host key never leaves `pclaw`);
3. enrolls the session's sandbox instance; you admit it after checking its fingerprint;
4. creates the sandbox network and the edge;
5. copies the workspace in (section 3);
6. runs the probes, the control run and the canary, and submits the signed reports;
7. starts the agent, which reaches mapped hosts only through the edge;
8. streams its output;
9. reports the routes the edge saw;
10. writes the agent's changes to `--out`;
11. ends the session and removes everything it created, also on Ctrl-C.

## 3. What goes in, what comes back (patch only)

The founder's decision of 2026-10-11:
- **In:** everything under `--workspace`, except that the repository goes in cleaned. Only its objects, refs, HEAD, index, packed-refs and shallow go in, with a generated config. Hooks, the host's git config (remotes, credential helpers, `fsmonitor`, `hooksPath`, `sshCommand`), logs, modules and nested repositories stay on the host.
  - **Everything else is within the agent's reach, `.env` files included.** Point `--workspace` at a checkout without secrets.
- **Out:** never a `.git` and never the tree. `--out` (empty or new) gets:
  - `changes.patch`: the agent's text changes in git's format. Read it, then apply it in your repository:
    ```bash
    git apply --check sandbox-out/changes.patch && git apply sandbox-out/changes.patch
    ```
  - `changes.txt`: every change. `binary` marks binary files and `review` marks dotfiles, editor and task files.
  - `binary/`: the new content of changed binary files, never executable, for you to copy. git applies binary patches only by SHA-1 ids, which PantherClaw's code does not use (SB-3).
    - **Never copy `binary/` wholesale over your checkout.** Copy only the files `changes.txt` marks `binary` that you mean to take, one by one, after looking at each. A binary is as untrusted as any file the agent wrote: an executable, a library or a compiled hook runs if anything on your host picks it up.
- **Review before running anything.** `pclaw` lists the dotfiles, editor and task files the agent changed, such as `.envrc`, `.vscode/`, `.idea/`, `.githooks/`, `Makefile`, `package.json` and `Taskfile.yml`. Tools run or load these on their own: read them before you open the project in an editor, run a build, or let direnv load.

## 4. Read the outcome

- `connection <id>: sandbox closure PASSED (closure …), evidence for ENFORCED until <time>`. The probes found every route the closure contract names closed. Coverage may show the scope `ENFORCED` until that time (24 hours by default, `coverage.enforced_ttl`), as long as nothing about the connection changes.
- `… FAILED (closure …): <results>`. The named probes or controls did not hold. A failed negative control means the sandbox was not isolated; the closure is stored as evidence and drops any current `ENFORCED` for the scope at once.
- `the edge refused or stripped N routes of the agent (M new to coverage)`. These are destinations the edge refused the agent and credentials it stripped from the agent's requests, recorded as observed routes. They are untrusted and never grant anything.

## 5. When something goes wrong

- **`SANDBOX_SESSION_STALE`**: a mapped connection changed while the session was open (its revision, gateway, package or credential, or another change that invalidates closures). Nothing was recorded. Run again.
- **`PROBE_REPORT_REJECTED`**: a report did not verify. The reason is in the audit log (`sandbox.report_rejected`), never in the answer.
- **An interrupted run** (killed, or a laptop asleep): the session ends at its expiry (`--ttl`, at most 24 hours). Within a minute after that, the server ends it as EXPIRED and revokes its instance (`sandbox.session_expired` in the audit log). To end it at once:
  ```bash
  pclaw sandbox end <session>
  ```
  `pclaw sandbox list --agent <agent>` and `pclaw sandbox get <session>` show the sessions. Docker resources left behind carry the session's label; remove them with:
  ```bash
  docker ps -aq --filter label=org.pantherclaw.sandbox.session=<session> | xargs -r docker rm -f
  docker network ls -q --filter label=org.pantherclaw.sandbox.session=<session> | xargs -r docker network rm
  docker volume ls -q --filter label=org.pantherclaw.sandbox.session=<session> | xargs -r docker volume rm
  ```
