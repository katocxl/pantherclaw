# Runbook — Installation: `install.sh`, `pclaw up` and the Helm chart

**Milestone:** M13 wave 2 ([G0 M13](../g0/M13.md) D35, D36, D39; HR-374, HR-396..398, T-179; PN-010.1, PN-012.6). **Audience:** anyone installing PantherClaw themselves. Commands and values follow the brief; the M13 exit status records any change. For a guided first 30 minutes on the demo stack, see [quickstart.md](../quickstart.md).

## 1. Get a verified release (`install.sh`)

`install.sh` does the following:
1. downloads the release archive for your platform and `checksums.txt`;
2. verifies the archive's SHA-256 against `checksums.txt`, and stops on a mismatch;
3. if the GitHub CLI (`gh`) is installed, verifies the GitHub build attestation:
   ```bash
   gh attestation verify <archive> --repo katocxl/pantherclaw
   ```
   Without `gh` it prints this command for you to run elsewhere. Do not skip it for a production install.

Images are verified the same way: the server and gateway images are published with attestations, and their digests are listed in the release notes. Pull them by digest.

**FIPS builds.** `*-fips` archives are built with `GOFIPS140=v1.0.0`. They use only approved algorithms (HR-396). Credentials sealed by a non-FIPS install do not open in a FIPS install (`SEAL_SUITE_NOT_FIPS`), so FIPS installs start fresh.

## 2. A single node on your machine (`pclaw up`)

`pclaw up` needs Docker and writes its stack to `~/.pantherclaw/node` ([G0 M13](../g0/M13.md) D36, D39). By default it is a **production** node (Community production), so it needs your own sign-in provider: an OIDC provider, GitHub, or both.

```bash
pclaw up --oidc-issuer https://idp.example.com --oidc-client-id pantherclaw \
         --oidc-client-secret-file ./oidc.secret [--oidc-name corp]
# or: --github-client-id <id> --github-client-secret-file ./github.secret
pclaw status
pclaw down
```

The first `pclaw up`:
1. generates a Docker Compose stack: Postgres 17 and the server image at the digest embedded in your `pclaw` release;
2. generates a KEK. **Escrow it** ([backup-restore.md](backup-restore.md) §3);
3. runs `db bootstrap` and `migrate` through `docker compose run --rm server …`;
4. creates an organization and an admin invitation;
5. prints the URL and the login line.

Without a sign-in flag the node still starts and prints how to add one.

**Then enroll the gateway.** Run `pclaw login`, then `pclaw up` again. It creates the gateway "local" with your session, writes its enrollment into `~/.pantherclaw/node` and starts it.

**Listeners.** The server is published on `127.0.0.1:8080` only (plaintext behind the loopback publish), and so is the gateway's agent-facing listener. The gateway reaches the server over mTLS with the internal CA. To serve other machines, put a TLS-terminating proxy in front, or use the Helm chart.

**Trying it out (`--dev`).** `pclaw up --dev` sets `deployment: development` and takes the same sign-in flags. It bundles no identity provider. For a throwaway sign-in, run the server on your host and the development OIDC provider next to it with `go run ./test/devoidc` (see [BUILD_GUIDE](../BUILD_GUIDE.md) §4). Never expose a development node.

Containers run as your own uid:gid on Unix.

## 3. Kubernetes (Helm)

```bash
helm install pantherclaw deploy/helm/pantherclaw -f values.yaml
```

**What the chart deploys:**
- API and worker Deployments. The worker serves `/livez` and `/readyz` on its health listener (`health.addr`, HR-397) for probes.
- A migrate Job that runs before install and upgrade.
- A gateway Service with mTLS passthrough: do not terminate TLS in front of it.
- A NetworkPolicy and a PodDisruptionBudget.
- **Defaults:** non-root, a read-only root file system, no privilege escalation, all capabilities dropped (HR-398). Do not loosen them.

**Values to set:**
- **Secrets.** Database passwords, the KEK and TLS come from existing Secrets you create; the chart never generates or stores them.
- **Maintenance hold.** `maintenanceHold: true` puts every replica in the maintenance hold, for a restore ([backup-restore.md](backup-restore.md) §7).

**Rolling upgrades.** After the migrate Job runs, replicas still on the old version answer 503 on `/readyz` until they are replaced. That is expected ([deploy.md](deploy.md) §5).

## 4. After installing

- Check `/readyz` (database, schema, workers).
- Sign in and register a security key.
- Enroll a gateway ([gateway.md](gateway.md)).
- Set up nightly backups and run one restore drill ([backup-restore.md](backup-restore.md)).
