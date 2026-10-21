# Runbook — Deploy hosted staging (G3)

**Milestone:** M13 ([G0 M13](../g0/M13.md) D3, D4, D12–D15, D14 amended, D19; [ADR-0032](../adr/0032-hosted-deployment-kek-custody-and-backups.md); HR-370, HR-371, HR-346). **Audience:** the founder, as operator of hosted staging (test layer L3). The host scripts, the compose stack and the deploy workflow live in the commercial distribution; this runbook is the procedure they implement. Production (L4) follows at v1.0 on a paid host. Command flags follow the brief; the M13 exit status records any change.

## 1. What runs where

| Piece | Where |
|---|---|
| Host | Oracle Cloud Always Free Arm VM, Ubuntu 24.04; nftables allows SSH only from the founder's addresses, 443 and 8443 |
| Console and API | `staging.app.pantherclaw.dev:443`, TLS terminated by the server (certificates reloaded from disk, HR-371) |
| Gateway endpoint | the same host on 8443, mutual TLS terminated by the server |
| Database | `postgres:17` in the compose stack, data on the block volume |
| DNS | Cloudflare, DNS only (not proxied: client addresses and client certificates must reach the server) |
| Backups | nightly to Backblaze B2 ([backup-restore.md](backup-restore.md)) |
| Directories | `/srv/pantherclaw/{config,secrets,certs,pgdata,backups}` and `/srv/pantherclaw/deploy/previous` (the previous image digest) |

## 2. First setup (once)

1. Create the VM with the cloud-init file from the commercial distribution; attach the block volume. Cloud-init installs Docker with the compose plugin, nftables, unattended upgrades and the `pantherclaw` service user, and runs the idempotent bootstrap script (safe to run again).
2. Bootstrap generates the secrets into a root-only environment file: the database role passwords (the backup role `pc_backup` included, HR-378) and the KEK (`pantherclaw-server keys gen-kek --out FILE`). Nothing secret is ever committed.
3. **Escrow the KEK now**, before any data exists ([backup-restore.md](backup-restore.md) §3).
4. Create the DNS records with the DNS script and the founder's Cloudflare API token.
5. `certbot` obtains the certificate through the DNS-01 challenge and renews it into `/srv/pantherclaw/certs`; the server picks up a renewal within about a minute without a restart (HR-371).
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

Deploys run only from the manually started deploy workflow (a deploy key in the repository's secrets; nothing deploys on push).

1. Start the workflow with the image digest to deploy (or let it build and publish the image and use the new digest).
2. The workflow connects over SSH and:
   1. saves the running digest to `/srv/pantherclaw/deploy/previous`;
   2. `docker compose pull` of the new digest;
   3. runs the one-shot `migrate` service (`pantherclaw-server migrate up` as `pc_migrator`);
   4. `docker compose up -d`;
   5. waits up to 5 minutes for `/readyz` to answer 200 (§5), checked from the host over SSH.
3. **If readiness does not come**, it rolls back: the previous digest is started again and the result is recorded as a failed deploy. A migration is never rolled back automatically: an older binary refuses a newer schema (`SCHEMA_NEWER`, HR-370), so a failed deploy after a migration needs the operator (§6).
4. **G3 record.** Every run writes the artifact digest, the configuration hash, the previous digest, the operator, the time and the result to the job summary and as an artifact. The G3 rows are copied to [GATES_AND_REVIEW §7](../security/GATES_AND_REVIEW.md#7-gate-decision-log) at landing.

## 5. Health and readiness

| Endpoint | Answers 200 when | Use |
|---|---|---|
| `/livez` | the process serves HTTP | restart a hung process |
| `/readyz` | the database answers, the schema version in `pc.schema_info` (written by `migrate up`) equals the binary's latest migration, and (roles `worker` and `all`) the job workers have a heartbeat within 30 s (HR-370) | deploy waits, load balancers, monitoring |

The `/readyz` body is a fixed JSON, `{"ready": …, "checks": {"db": …, "schema": …, "workers": …}}`, without versions or error text. To find out why a check fails, read the server's logs on the host, not the endpoint.

`serve` itself refuses to start with `SCHEMA_NEWER` (the binary is older than the database) or `SCHEMA_PENDING` (migrations not applied; only a warning in `deployment: development`). The images are distroless with no shell or curl (HR-374), so health is checked from outside the container.

## 6. Roll back by hand

1. Read the digest in `/srv/pantherclaw/deploy/previous`.
2. If the failed deploy applied a migration, check `pantherclaw-server migrate status`: the previous binary refuses a newer schema. Either fix forward with a new image, or restore the database from the dump taken before the deploy ([backup-restore.md](backup-restore.md) §7, including the epoch bump).
3. Start the previous digest and wait for `/readyz`.
4. Record the rollback as a G3 row with the reason.

## 7. Certificates

- Renewal is automatic (certbot, DNS-01). The server re-reads the certificate files every 60 s and swaps only to a pair that parses and whose leaf is currently valid; a bad pair keeps the last good one and logs `tls.reload_failed` without key material (HR-371).
- If `tls.reload_failed` appears, check the files in `/srv/pantherclaw/certs` (key and certificate match, not expired); the server keeps serving the old certificate until it expires.
