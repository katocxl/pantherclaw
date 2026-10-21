# Runbook — Backup and restore

**Milestone:** M13 ([G0 M13](../g0/M13.md) D2, D6, D16, D17, D20, D21; [ADR-0032](../adr/0032-hosted-deployment-kek-custody-and-backups.md); HR-372, HR-373, HR-378, T-171, T-172, R-61). **Audience:** the operator of a hosted or self-hosted deployment. The hosted staging scripts live in the commercial distribution; the steps below are what they do, so a self-hosted operator can follow them by hand. Command flags follow the brief; the M13 exit status records any change.

## 1. Targets

| Deployment | RPO (data you can lose) | RTO (time to serve again) | How |
|---|---|---|---|
| Hosted staging (one VM, Postgres in a container) | ≤ 24 h | ≤ 4 h | nightly encrypted dump off site; restore onto a new VM or the same one |
| Paid host with a managed database (later, ADR-0032) | ≤ 5 min (point-in-time recovery); ≤ 24 h if the database provider is lost | ≤ 4 h (point-in-time recovery); ≤ 24 h for a full rebuild | provider PITR (at least 7 days) plus the nightly encrypted dump at a second provider |
| Self-hosted single node | your choice; ≤ 24 h with the nightly dump below | your choice | the same nightly dump; add WAL archiving for point-in-time recovery |

The restore drill (§5) measures the real values; record them as described in §6.

## 2. What is backed up, and what is not

- **In the nightly dump:** the PantherClaw database (every schema the migrations create, River's tables included). Sealed rows stay sealed: they are useless without the KEK.
- **Never in the same place as the dump:** the KEK. It is escrowed offline (§3). Whoever holds a dump and the KEK holds every sealed credential and payload.
- **Not backed up:** gateway broker keys (they live on the gateway hosts; a lost gateway enrolls again and credentials are sealed again, [key-rotation.md](key-rotation.md) §5); the offline licence and package roots (two offline media, [BUILD_GUIDE](../BUILD_GUIDE.md) §1 item 6); TLS certificates (renewed by the DNS challenge on a new host).

## 3. KEK escrow (once, and after every KEK rotation)

The server's KEK is a file (mode 0400, owned by the service user; on staging on the VM's encrypted boot volume). Keep an offline copy, encrypted with a passphrase:

```bash
age --passphrase --output kek.age /srv/pantherclaw/secrets/kek    # asks for the passphrase twice
```

1. Copy `kek.age` to two offline media kept apart (as for the offline roots). Never upload it to the backup bucket or a repository.
2. Store the passphrase separately from the media (a password manager the founder controls).
3. Check the copy once: `age --decrypt kek.age | sha256sum` equals `sha256sum /srv/pantherclaw/secrets/kek`.
4. For staging only, the drill also needs the KEK: keep a staging escrow copy the drill workflow can open (§5). Never give a production KEK to a workflow.

## 4. Nightly backup

Runs at 02:15 UTC (the `backup` job of the staging stack; a cron entry on a self-hosted node):

1. `pg_dump --format=custom` as the **backup role `pc_backup`** (HR-378; [G0 M13](../g0/M13.md) D21). Every tenant table forces row-level security, so a dump needs a role that bypasses it: `pc_backup` is `LOGIN NOINHERIT BYPASSRLS` with USAGE on schema `pc` and SELECT on every table and sequence (default privileges cover tables the migrator creates later), and nothing else. `pantherclaw-server db bootstrap` creates it when given the optional `--backup-password-file`; migration `00180` re-grants SELECT on existing tables when the role exists. Its password lives only with the backup job (on staging, the root-only environment file). Never dump as `pc_app` or the migrator.
2. Encrypt before it leaves the host: `age --recipient <founder's age public key> --output pantherclaw-<UTC timestamp>.dump.age`. The private identity stays offline with the founder; a separate staging drill identity is added as a second recipient on staging only.
3. Copy with `rclone` to a Backblaze B2 bucket. The B2 application key is scoped to that one bucket.
4. Retention by the bucket's lifecycle rules: 14 daily and 8 weekly copies.
5. Check the newest object's age and size. A failed check is logged now and alerts through Grafana once the observability wave lands. Investigate the same day: with a 24-hour RPO, a missed night already uses up the target.

Delete the local copy after the upload succeeds.

## 5. The restore sequence (drill and real restore)

This sequence has passed on staging and serves both the monthly drill and a real restore. On staging it is the commercial distribution's restore-drill script, which runs as a monthly workflow or by hand ([G0 M13](../g0/M13.md) D17, D20, D21). A self-hosted operator follows the steps below.

The drill restores into a **throwaway** database, never over the running one. The founder runs production drills by hand, with the production identity and KEK.

Start the clock now. The RTO runs from here to step 9; the RPO is the age of the newest backup at this moment.

1. **Fetch and decrypt.** Fetch the newest `*.dump.age` from the bucket and decrypt it with `age -d -i <identity file>` (for a drill, the staging drill identity).
2. **Fresh database.** Start a fresh PostgreSQL 17 with an empty database.
3. **Roles.** Roles are not in the dump. Run `pantherclaw-server db bootstrap` with new role passwords, including `--backup-password-file`: it creates `pc_backup`, which the dump's grants name.
4. **Restore.** As the superuser, run `pg_restore --clean --if-exists --exit-on-error -d <database> <dump>`. `--clean` replaces the empty `pc` schema that bootstrap created.
5. **Schema.** Run `pantherclaw-server migrate status`, then `migrate up` (it must apply nothing), then `migrate status` again: it must show the same version (HR-370).
6. **RLS smoke test.**
   - As `pc_app` without an organization context, `pc.orgs` counts 0.
   - As `pc_app` with `app.org_id` set to the platform organization, other organizations count 0.
   - As the superuser, at least one organization exists.
7. **KEK check.** A sealed platform key exists, and `pantherclaw-server serve` (role `api`), started with the escrowed KEK in `kek_files`, answers `/readyz` with 200. At start it unwraps every platform signing key and fails closed if it cannot.
8. **Re-apply post-dump changes (D20).** The gateway port stays closed at the firewall and the kill switch stays on for every organization. Re-apply every revocation and containment change logged after the dump's time, from the shipped structured logs (§7).
9. **Epoch bump.** Raise every organization's containment epoch (HR-373; [key-rotation.md](key-rotation.md) §8.2):
   ```bash
   pantherclaw-server keys bump-epochs --all --confirm
   ```
   - Each organization, of any status, gets its own tenant transaction.
   - The new epoch is `max(epoch + 1, the current Unix time in milliseconds)`, so it is above any value a gateway cached after the backup.
   - `containment.epoch_bumped_after_restore` is audited per organization.
   - Without `--confirm` nothing changes.
10. **Reopen and record.** Reopen the gateway port. Record the RPO and the RTO (from the start to step 9). After a drill, destroy the throwaway database and the decrypted files.

## 6. Record the result

Write the date, the dump's timestamp, the measured RPO and RTO and any step that failed in the drill's summary. The first drill on staging and every production drill are recorded as a G4 entry in [GATES_AND_REVIEW §7](../security/GATES_AND_REVIEW.md#7-gate-decision-log). A drill that misses its target is a finding, not a pass.

## 7. A real restore

A restored database is the state at the dump's time: everything revoked or contained after it comes back active (T-171). Gateways must not reconnect until that is undone ([G0 M13](../g0/M13.md) D20, [ADR-0032](../adr/0032-hosted-deployment-kek-custody-and-backups.md) §6).

1. **Contain first** if the cause may be an attack: follow [incident-response.md](incident-response.md).
2. Stop the server (all roles) so nothing writes to the damaged database. **Close the gateway port (8443) at the firewall.**
3. Follow §5 steps 1–7, restoring into the database the server will use. Use a new volume, not the damaged one, which you keep for investigation.
4. With the gateway port still closed, **engage the kill switch for every organization** ([kill-switch.md](kill-switch.md)).
5. **Re-apply every revocation and containment change logged after the dump's time**, from the shipped structured logs: signing-key revocations, gateway-certificate revocations, API key, credential and grant revocations, containment and kill-switch changes. Anything the logs do not hold comes back as it was at the dump (R-61).
6. Signing keys created after the dump are lost with it: receipts and evidence they signed stop verifying until their public keys are published again from the logs. Tell verifiers.
7. Run the epoch bump (§5 step 9; [key-rotation.md](key-rotation.md) §8.2). Gateways then load a fresh containment snapshot before serving (HR-010).
8. Wait for `/readyz` to answer 200 (database, schema and workers; [deploy.md](deploy.md) §5), reopen the gateway port, and lift the kill switch for each organization once its state is checked.
9. Tell users what happened and the RPO: actions decided after the dump's timestamp are not in the restored ledger. The targets' own records are the way to find them; reconcile what matters.
10. Take a fresh backup at once, and record a G4 entry with the recovery evidence.

Take a backup right after any key rotation or revocation as well, so a later restore does not lose it.

**Rolling back across a migration is a restore.** The previous binary refuses a newer schema (`SCHEMA_NEWER`, HR-370). To go back to it after a deploy that applied a migration, restore the dump taken before that deploy, following this section, or fix forward with a new image ([deploy.md](deploy.md) §6).
