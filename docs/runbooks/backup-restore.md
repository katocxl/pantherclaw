# Runbook — Backup and restore

**Milestone:** M13 ([G0 M13](../g0/M13.md) D2, D6, D16, D17; [ADR-0032](../adr/0032-hosted-deployment-kek-custody-and-backups.md); HR-372, HR-373, T-171). **Audience:** the operator of a hosted or self-hosted deployment. The hosted staging scripts live in the commercial distribution; the steps below are what they do, so a self-hosted operator can follow them by hand. Command flags follow the brief; the M13 exit status records any change.

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

1. `pg_dump --format=custom` as a **read-only backup role** (never the application role `pc_app` or the migrator).
2. Encrypt before it leaves the host: `age --recipient <founder's age public key> --output pantherclaw-<UTC timestamp>.dump.age`. The private identity stays offline with the founder; a separate staging drill identity is added as a second recipient on staging only.
3. Copy with `rclone` to a Backblaze B2 bucket. The B2 application key is scoped to that one bucket.
4. Retention by the bucket's lifecycle rules: 14 daily and 8 weekly copies.
5. Check the newest object's age and size. A failed check is logged now and alerts through Grafana once the observability wave lands. Investigate the same day: with a 24-hour RPO, a missed night already uses up the target.

Delete the local copy after the upload succeeds.

## 5. Restore drill (monthly on staging, and before every release)

The drill restores into a **throwaway** database, never over the running one. On staging it runs as a monthly workflow and can be started by hand; production drills are run by the founder by hand with the production identity and KEK.

1. Note the time: the drill's RTO clock starts now.
2. Fetch the newest dump: `rclone copy b2:<bucket>/<newest> .`; note its timestamp (the RPO is the time between it and the start of the drill, or of the incident in a real restore).
3. Decrypt: `age --decrypt --identity <drill identity file> --output restore.dump pantherclaw-<timestamp>.dump.age`.
4. Start a throwaway `postgres:17` container, create the roles and schema once with `pantherclaw-server db bootstrap` (as for a new database, [BUILD_GUIDE](../BUILD_GUIDE.md) §4), and restore the dump into it with `pg_restore`.
5. Check the schema: `pantherclaw-server migrate status --config <drill config>` shows nothing pending for the binary you will run (HR-370). A newer schema means the binary is too old; a pending one means `migrate up` before serving.
6. RLS smoke test: as `pc_app`, inside one organization's context, a read of another organization's rows returns nothing.
7. Sealed rows: with the escrowed KEK in the drill configuration's `kek_files`, open one sealed staging row and confirm it decrypts.
8. Raise every organization's containment epoch (HR-373):
   ```bash
   pantherclaw-server keys bump-epochs --all --confirm --config <drill config>
   ```
   One transaction raises each organization's epoch by one and audits `containment.epoch_bumped_after_restore` per organization. Without `--confirm` nothing changes.
9. Evidence: `pclaw verify` on one recent bundle from the restored copy passes with the trust file pinned before the drill (retired keys stay published, HR-372).
10. Stop the clock: the RTO is the time from step 1 to here. Destroy the throwaway container and the decrypted files.

## 6. Record the result

Write the date, the dump's timestamp, the measured RPO and RTO and any step that failed in the drill's summary. The first drill on staging and every production drill are recorded as a G4 entry in [GATES_AND_REVIEW §7](../security/GATES_AND_REVIEW.md#7-gate-decision-log). A drill that misses its target is a finding, not a pass.

## 7. A real restore

1. **Contain first** if the cause may be an attack: engage the kill switch ([kill-switch.md](kill-switch.md)) and follow [incident-response.md](incident-response.md).
2. Stop the server (all roles) so nothing writes to the damaged database.
3. Restore as in §5 steps 2–7, into the database the server will use (a new volume, not over the damaged one, which you keep for investigation).
4. Run the epoch bump (§5 step 8) **before any gateway reconnects**. Gateways then load a fresh containment snapshot before serving (HR-010), so nothing is acted on from before the restore.
5. Start the server and wait for `/readyz` to answer 200 (database, schema and workers; [deploy.md](deploy.md) §5).
6. Tell users what happened and the RPO: actions decided after the dump's timestamp are not in the restored ledger. The targets' own records are the way to find them; reconcile what matters.
7. Record a G4 entry with the recovery evidence.
