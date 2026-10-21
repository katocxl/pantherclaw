# Runbook — Deploy hosted staging (G3)

**Milestone:** M13 ([G0 M13](../g0/M13.md) D3, D4, D12–D15, D14 amended, D19, D23–D26, D29, D37, F10; [ADR-0032](../adr/0032-hosted-deployment-kek-custody-and-backups.md); HR-370, HR-371, HR-346, HR-379, R-62). **Audience:** the founder, as operator of hosted staging (test layer L3). The host scripts, the compose stack and the deploy workflow live in the commercial distribution; this runbook is the procedure they implement. Production (L4) follows at v1.0 on a paid host. Command flags follow the brief; the M13 exit status records any change.

## 1. What runs where

| Piece | Where |
|---|---|
| Host | Oracle Cloud Always Free Arm VM, Ubuntu 24.04; nftables allows SSH only from the founder's addresses, 443, 8443, and 80 for certificate issuance (opened in the Oracle security list as well) |
| Console and API | `staging.app.pantherclaw.dev:443`, TLS terminated by the server (certificates reloaded from disk, HR-371) |
| Gateway endpoint | the same host on 8443, mutual TLS terminated by the server |
| Database | `postgres:17` in the compose stack, data on the block volume |
| DNS | Cloudflare, DNS only (not proxied: client addresses and client certificates must reach the server) |
| Backups | nightly to Backblaze B2 under Object Lock (at least 60 days, compliance mode; [backup-restore.md](backup-restore.md)) |
| Directories | `/srv/pantherclaw/{config,secrets,certs,pgdata,backups}` and `/srv/pantherclaw/deploy/previous` (the previous image digest) |

## 2. First setup (once)

1. Create the VM with the cloud-init file from the commercial distribution; attach the block volume. Cloud-init installs Docker with the compose plugin, nftables, unattended upgrades and the `pantherclaw` service user, and runs the idempotent bootstrap script (safe to run again).
2. Bootstrap generates the secrets into a root-only environment file: the database role passwords (the backup role `pc_backup` included, HR-378) and the KEK (`pantherclaw-server keys gen-kek --out FILE`). Nothing secret is ever committed.
3. **Escrow the KEK now**, before any data exists ([backup-restore.md](backup-restore.md) §3).
4. Create the DNS records with the DNS script, run **on the founder's machine** with the founder's Cloudflare API token. No DNS token is ever stored on the VM.
5. Certificates come from ACME HTTP-01 ([G0 M13](../g0/M13.md) D25): `certbot --standalone` listens on port 80 only while it issues or renews, and writes into `/srv/pantherclaw/certs`. A daily systemd timer (`pantherclaw-certbot.timer`) runs `certbot renew`; there is no long-running certbot container. The server picks up a renewed pair within about a minute, without a restart (HR-371).
6. The configuration sets `deployment: staging`. The server shows the staging banner from `WhoAmI` and refuses development seams only in production (HR-346, HR-359); on staging, billing is the faked adapter until the payment provider's sandbox account exists.

## 3. Signing in to staging

- **Until the hosted OIDC provider's staging environment exists**, the console and API listener binds to `127.0.0.1` on the VM. Reach it through an SSH tunnel from the founder's machine:
  1. Map the public name to your own machine in your hosts file (`/etc/hosts`, or `C:\Windows\System32\drivers\etc\hosts` on Windows): `127.0.0.1 staging.app.pantherclaw.dev`.
  2. Forward your local port 443 to the VM's loopback listener (binding local port 443 needs administrator rights):
     ```bash
     ssh -N -L 443:127.0.0.1:443 <your admin user>@<staging host IP>
     ```
     Use the VM's IP address here, since the name now points at your own machine.
  3. Open `https://staging.app.pantherclaw.dev/app/`. The origin, the WebAuthn relying-party id and the OIDC redirects then match the public name, and the real certificate validates with no warning.

  Never sign in through `localhost` or another name: the origin checks (HR-342, HR-151), security keys (HR-153) and sign-in redirects are bound to the public name and fail. Remove the hosts entry when the public listener goes live.
  The gateway listener on 8443 is public: gateways authenticate with mutual TLS.
- **Once the staging provider exists**, its client is configured, the listener binds publicly on 443 and sign-in goes through the provider.
- Development OIDC providers are never exposed publicly, on staging or anywhere else.

## 4. Deploy

Deploys and the restore drill run on a **GitHub self-hosted runner installed on the VM** ([G0 M13](../g0/M13.md) D23):
- **Connection.** The runner connects outbound to GitHub only and carries the repository-level label `pantherclaw-staging`. GitHub never opens an inbound SSH connection; SSH (22) stays limited to the founder's addresses.
- **Runner user.** The runner runs as an unprivileged user. Its sudo is limited to the installed `/srv/pantherclaw/bin/deploy.sh`, by a sudoers entry for that path only.
- **Workflows.** The workflows that touch the VM are `workflow_dispatch` only (nothing deploys on push) and run with `runs-on: [self-hosted, pantherclaw-staging]`. The image is pulled with the job's own token (read access to packages).
- **Why it is acceptable, and its limits** (D29). Only the founder's credentials push to the private repository, but build agents push branches with them, and any pushed workflow can target the runner's label. So the runner is set up to be safe even when a hostile workflow runs on it:
  - **Signed images only.** The deploy script verifies the image's **Sigstore keyless signature** (cosign) and refuses any image whose signature was not made by the private repository's `.github/workflows/image.yml` at `refs/heads/main` (F10). Each signed build appears in Sigstore's public Rekor log: repository name, workflow path, commit SHA and image digest, with no code and no secrets.
  - **No secrets in jobs.** The drill reads its `age` identity and the staging KEK from root-only files on the VM, so no job receives secrets.
  - **Root-owned runner.** The installation is root-owned except its work and diagnostics directories, and is started with `--disableupdate`. To upgrade it, bump the pinned version and SHA-256 in the repository and re-run bootstrap.
  - **Workflow check.** A GitHub-hosted check fails any change that adds `self-hosted` to a workflow other than the deploy and drill workflows. Those two run only on `main`, and the drill also runs monthly.
  - **Cleanup around every job** (D37). Runner job hooks, which are root-owned scripts, call a root-owned cleanup script through a sudoers entry that takes no arguments, before and after every job. The script kills every runner-user process outside the runner service's cgroup, clears the runner user's cron and `at` jobs, and resets its home and work directories (except the current checkout at job start). The service uses `KillMode=control-group`.
  - **Authoritative G3 records.** The deploy script writes them root-only on the VM, in `/srv/pantherclaw/deploy/g3/<ts>.json`; the workflow only prints them back. The staging tag is a convenience only, because the VM re-verifies the signature on every deploy.
  - **The guard is a merge gate, not a runtime control.** A pushed branch's job runs before CI does. The guard parses the workflow YAML with a pinned `yq`:
    - every `runs-on` must be a literal `ubuntu-*`;
    - the two allowed jobs are the exception, and they must be exactly `[self-hosted, pantherclaw-staging]` with the exact main-only condition;
    - job-level `uses:` and `${{` in `runs-on` are refused.
  - **What remains.** A pushed branch can still run code as the unprivileged runner user, with no docker group, no secrets and no sudo beyond the verified deploy and the cleanup (R-62). This is accepted for $0 staging, which holds no customer data. Just-in-time ephemeral runners, minted per job through a GitHub App, follow the GitHub organization move.

  Never enable a self-hosted runner like this on a public repository.
- **Fallback.** Run the setup script over SSH by hand, with the digest to deploy.

1. Start the deploy workflow with the image digest to deploy (or let it build and publish the image and use the new digest).
2. The job runs on the VM's runner, which calls the deploy script and:
   1. verifies the new image's Sigstore signature against the expected workflow identity (F10), and stops without changing anything if it does not verify;
   2. saves the running digest to `/srv/pantherclaw/deploy/previous`;
   3. `docker compose pull` of the new digest;
   4. runs the one-shot `migrate` service (`pantherclaw-server migrate up` as `pc_migrator`). The migrator password is mounted only into this service; the server's own configuration has no migrator password file;
   5. `docker compose up -d`;
   6. waits up to 5 minutes for `/readyz` to answer 200 (§5), checked on the host.
3. **If readiness does not come**, it rolls back: the previous digest is started again and the result is recorded as a failed deploy. A migration is never rolled back automatically: an older binary refuses a newer schema (`SCHEMA_NEWER`, HR-370), so a failed deploy after a migration needs the operator (§6).
4. **G3 record.** Every run writes the artifact digest, the configuration hash, the previous digest, the operator, the time and the result. The authoritative copy is root-only on the VM (`/srv/pantherclaw/deploy/g3/<ts>.json`, D37); the job summary and artifact only print it back. The G3 rows are copied to [GATES_AND_REVIEW §7](../security/GATES_AND_REVIEW.md#7-gate-decision-log) at landing.

## 5. Health and readiness

| Endpoint | Answers 200 when | Use |
|---|---|---|
| `/livez` | the process serves HTTP | restart a hung process |
| `/readyz` | the database answers, the schema version in `pc.schema_info` (written by `migrate up`) equals the binary's latest migration, and (roles `worker` and `all`) the job workers have a heartbeat within 30 s (HR-370) | deploy waits, load balancers, monitoring |

The `/readyz` body is a fixed JSON, `{"ready": …, "checks": {"db": …, "schema": …, "workers": …}}`, without versions or error text. To find out why a check fails, read the server's logs on the host, not the endpoint.

`serve` itself refuses to start with `SCHEMA_NEWER` (the binary is older than the database) or `SCHEMA_PENDING` (migrations not applied, including a database from before `00169` that has no `pc.schema_info`; only a warning in `deployment: development`).

Further notes ([G0 M13](../g0/M13.md) D24, D26):
- **Worker heartbeat.** The `workers` check means the River client is running.
- **Worker-only processes.** A process with role `worker` serves `/livez` and `/readyz` on its health listener `health.addr` (HR-397), which the Helm chart probes.
- **Rolling deploys** (Helm or a paid host with several replicas). Once `migrate up` has run, replicas still on the old binary answer 503 until they are replaced. Expect this; it is not a failure of the new release.
- **Maintenance hold.** While `maintenance.hold` is on (a restore, [backup-restore.md](backup-restore.md) §7), `/readyz` reports not ready and every decision path refuses `MAINTENANCE_HOLD` (HR-379). The images are distroless with no shell or curl (HR-374), so health is checked from outside the container.

## 6. Roll back by hand

1. Read the digest in `/srv/pantherclaw/deploy/previous`.
2. If the failed deploy applied a migration, check `pantherclaw-server migrate status`: the previous binary refuses a newer schema. Either fix forward with a new image, or restore the database from the dump taken before the deploy ([backup-restore.md](backup-restore.md) §7, including the epoch bump).
3. Start the previous digest and wait for `/readyz`.
4. Record the rollback as a G3 row with the reason.

## 7. Certificates

- Renewal is automatic (certbot standalone, HTTP-01, from the daily systemd timer; port 80 must stay open in nftables and the Oracle security list). The server re-reads the certificate files every 60 s and swaps only to a pair that parses and whose leaf is currently valid; a bad pair keeps the last good one and logs `tls.reload_failed` without key material (HR-371).
- If `tls.reload_failed` appears, check the files in `/srv/pantherclaw/certs` (key and certificate match, not expired); the server keeps serving the old certificate until it expires.
