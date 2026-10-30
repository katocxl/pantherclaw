# Runbook — Backup and restore

**Milestone:** M13 ([G0 M13](../g0/M13.md) D2, D6, D16, D17, D20, D21, D24–D26, D31, D41; [ADR-0032](../adr/0032-hosted-deployment-kek-custody-and-backups.md); HR-372, HR-373, HR-378, HR-379, HR-383, HR-384, T-171, T-172, R-61). **Audience:** the operator of a hosted or self-hosted deployment. The hosted staging scripts live in the commercial distribution; the steps below are what they do, so a self-hosted operator can follow them by hand. Command flags follow the brief; the M13 exit status records any change.

- After restore, keep the maintenance hold on while replaying the shipped tightening security events and running `pantherclaw-server keys bump-epochs --all --confirm`. The command raises every non-DELETED org's epoch, including SUSPENDED orgs, and reports the number of irreversible DELETED orgs it skipped without writing to them (D57). Gateways must re-sync containment snapshots before serving.

## Durable security-event delivery

The ledger chainer stores the bounded security projection in `pc.security_event_outbox` in the same transaction as its ledger link. A worker retries unacknowledged rows in batches of 500, at least five minutes after their last attempt. An attempt records local scheduling state; writing a log line does not prove that the external log store saved it. Duplicate `(org, ledger_seq)` records are expected and restore deduplicates identical copies. Conflicting copies fail validation before any changes.

The operator can export a page to a new exclusive file. Successful export fsyncs the file and leaves all rows unacknowledged:

```sh
pantherclaw-server security-log export --org ORG_UUID --out security-001.ndjson --limit 500 --config server.json
# Continue with --after LAST_SEQUENCE into a different new file.
```

Copy each page to the durable external log store, verify the complete prefix there, then explicitly acknowledge the last stored security-event sequence:

```sh
pantherclaw-server security-log ack --org ORG_UUID --through LAST_SEQUENCE --confirm --config server.json
```

ACK is audited and retains the outbox rows. Never acknowledge a prefix on the strength of a local log write or export alone. Before restoring, obtain the external security-event log covering the backup time through the incident; keep the maintenance hold on if any required record or deletion handler is missing.

Irreversible org and account erasure waits until the exact deletion-intent event is chained and explicitly ACKed after external-copy verification (F19). A missing event, an emission attempt, or an exported local file keeps the org frozen or the account pending and allows retry. Verify the external copy before using `ack`; acknowledging the wrong prefix can defeat this restore safeguard.

```sh
pantherclaw-server restore reapply --from shipped-security.ndjson --since BACKUP_RFC3339 --confirm --config server.json
pantherclaw-server keys bump-epochs --all --confirm --config server.json
```

`org.deletion_started` and `account.deletion_started` describe durable deletion intent, not verified completion. Restore applies them through the same restricted deletion handlers as their completion events, preserving the closed state while erasure resumes. Completion events carry the signed record digest separately. The external shipper and its durable retention remain operating dependencies.
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

1. `pg_dump --format=custom` as the **backup role `pc_backup`** (HR-378; [G0 M13](../g0/M13.md) D21). Every tenant table forces row-level security, so a dump needs a role that bypasses it: `pc_backup` is `LOGIN NOINHERIT BYPASSRLS` with USAGE on schema `pc` and SELECT on every table and sequence (default privileges cover tables the migrator creates later), and nothing else. `pantherclaw-server db bootstrap` creates it when given the optional `--backup-password-file`; migration `00169` re-grants SELECT on existing tables when the role exists. Its password lives only with the backup job (on staging, the root-only environment file). Never dump as `pc_app` or the migrator.
2. Encrypt before it leaves the host: `age --recipient <founder's age public key> --output pantherclaw-<UTC timestamp>.dump.age`. The private identity stays offline with the founder; a separate staging drill identity is added as a second recipient on staging only.
3. Copy with `rclone` to a Backblaze B2 bucket. The B2 application key is scoped to that one bucket.
4. Retention by the bucket's lifecycle rules: 14 daily and 8 weekly copies. The bucket has B2 Object Lock with a default retention of at least 60 days in compliance mode, so a compromised VM cannot hide or delete backups ([G0 M13](../g0/M13.md) D25).
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
5. **Schema.** Run `pantherclaw-server migrate up`: **it must apply nothing**. That is the check (HR-370; [G0 M13](../g0/M13.md) D24). `migrate status` before and after shows goose's version only, and it must not change.
6. **RLS smoke test.**
   - As `pc_app` without an organization context, `pc.orgs` counts 0.
   - As `pc_app` with `app.org_id` set to the platform organization, other organizations count 0.
   - As the superuser, at least one organization exists.
7. **KEK check.** A sealed platform key exists, and `pantherclaw-server serve` (role `api`) starts with the escrowed KEK in `kek_files`: at start it unwraps every platform signing key and fails closed if it cannot. In a drill (a throwaway database, no gateways) it runs without the hold and `/readyz` answers 200. In a real restore it runs with the maintenance hold on (§7), and `/readyz` reports not ready by design until step 10.
8. **Re-apply post-dump changes (D20, D26).** The server runs with the maintenance hold (`maintenance.hold: true`, HR-379): no decision is made from any path, while the management API and the operator command line keep working. The gateway port stays closed. Re-apply every revocation and containment change logged after the dump's time, from the shipped `security_event` lines with `restore reapply` (§7 step 5; HR-384).
9. **Epoch bump.** Raise every organization's containment epoch (HR-373; [key-rotation.md](key-rotation.md) §8.2):
   ```bash
   pantherclaw-server keys bump-epochs --all --confirm --config <file>
   ```
   - Each organization, of any status, gets its own tenant transaction.
   - The new epoch is `max(epoch + 1, the current Unix time in milliseconds)`, so it is above any value a gateway cached after the backup.
   - `containment.epoch_bumped_after_restore` is audited per organization.
   - Without `--confirm` nothing changes.
10. **Reopen and record.** Restart the server without the hold, wait for `/readyz` to answer 200, and reopen the gateway port. Record the RPO and the RTO (from the start to step 9). After a drill, destroy the throwaway database and the decrypted files.

## 6. Record the result

Write the date, the dump's timestamp, the measured RPO and RTO and any step that failed in the drill's summary. The first drill on staging and every production drill are recorded as a G4 entry in [GATES_AND_REVIEW §7](../security/GATES_AND_REVIEW.md#7-gate-decision-log). A drill that misses its target is a finding, not a pass.

## 7. A real restore

A restored database is the state at the dump's time: everything revoked or contained after it comes back active (T-171). Gateways must not reconnect until that is undone ([G0 M13](../g0/M13.md) D20, [ADR-0032](../adr/0032-hosted-deployment-kek-custody-and-backups.md) §6).

1. **Contain first** if the cause may be an attack: follow [incident-response.md](incident-response.md).
2. Stop the server (all roles) so nothing writes to the damaged database. **Close the gateway port (8443)**: at the firewall and the cloud security list; on staging, Docker-published ports bypass nftables, so bind the gateway port to loopback in the stack's configuration.
3. Set `maintenance.hold: true` (or `PC_MAINTENANCE_HOLD`) in the server's configuration **before its first start on the restored database** (HR-379; [G0 M13](../g0/M13.md) D26). While the hold is on, no decision is made from any path: gateway control and stream, workload, `Authorize`, hooks, `/sdk`, MCP faces and AuthZEN all refuse `MAINTENANCE_HOLD`, and gateways fail closed. The management API and the operator command line keep working. The start is audited (`platform.maintenance_hold_on`).
4. Follow §5 steps 1–7, restoring into the database the server will use. Use a new volume, not the damaged one, which you keep for investigation.
5. **Re-apply every revocation and containment change logged after the dump's time.** The source is the shipped `security_event` log lines ([observability.md](observability.md) §4; HR-383): signing-key, gateway-certificate, API key, credential and grant revocations, disablements, containment and kill-switch changes, and organization and account deletions (D41). Export them as NDJSON from your log store and run:
   ```bash
   pantherclaw-server restore reapply --from security-events.ndjson --since <dump time> --confirm --config <file>
   ```
   - It applies only tightening events, idempotently, one organization per transaction.
   - A deleted organization is set to DELETED again at once and fails closed; its deletion is requeued, and a new deletion record refers to the original. Deleted accounts are pseudonymised again and their sessions revoked ([data-requests.md](data-requests.md) §5).
   - It is audited as `restore.reapplied`.
   - It refuses unless the hold is on, and it reports unknown kinds (HR-384).
   - Without `--confirm` nothing changes.
   - Anything the logs do not hold comes back as it was at the dump (R-61). Re-apply such changes by hand through the management API.
6. Signing keys created after the dump are lost with it: receipts and evidence they signed stop verifying until their public keys are published again from the logs. Tell verifiers.
7. Run the epoch bump (§5 step 9; [key-rotation.md](key-rotation.md) §8.2). Gateways then load a fresh containment snapshot before serving (HR-010).
8. Remove the hold and restart the server; the first start without it is audited (`platform.maintenance_hold_off`). Wait for `/readyz` to answer 200 (database, schema and workers; [deploy.md](deploy.md) §5), then reopen the gateway port.
9. Tell users what happened and the RPO: actions decided after the dump's timestamp are not in the restored ledger. The targets' own records are the way to find them; reconcile what matters.
10. Take a fresh backup at once, and record a G4 entry with the recovery evidence.

Take a backup right after any key rotation or revocation as well, so a later restore does not lose it.

**Rolling back across a migration is a restore.** The previous binary refuses a newer schema (`SCHEMA_NEWER`, HR-370). To go back to it after a deploy that applied a migration, restore the dump taken before that deploy, following this section, or fix forward with a new image ([deploy.md](deploy.md) §6).

## 8. Database failover (M19)

- Configure `database.hosts` with the primary and its standbys, or `database.host` with a stable endpoint (a managed service or a proxy) that always names the primary. Every host needs `sslmode=verify-full`. The server connects only to the read-write primary and never serves from a standby. While no primary answers, no decision is made and `/readyz` fails.
- For production HA, run one synchronous standby with `synchronous_commit=remote_apply` and `synchronous_standby_names` set, and set `database.replication: sync`. Each process checks those settings at start-up. After a promotion, a running process keeps serving only if both the old primary and the new one confirm sync.
- **A silent old primary can delay delivery, never open a gateway.** A first host in `database.hosts` that accepts connections and never answers holds each new connection for the 5 s connect timeout. Each containment read gives up after 500 ms, so a change may take longer than 2 s to reach the gateways until a connection to the new primary exists. Meanwhile a gateway that hears nothing refuses on its own within 2 s (`Check()` is local), so nothing fails open.
- **A containment read over 500 ms fails closed.** A large organization or a saturated connection pool can make reads time out. That organization then stays unconfirmed, its gateways refuse, and `gateways.containment_read_failed` is logged. Each timeout also discards a connection. If you see this without a failover, check the pool's size and the database's load.
- **After an asynchronous promotion, every replica restarts into the maintenance hold until `keys bump-epochs`.** A running process refuses the new primary, and its `/readyz` and `/livez` fail, so the orchestrator restarts it. On start-up it sees the new timeline and starts in the hold. Run `pantherclaw-server keys bump-epochs --all --confirm --config <file>`, which raises every epoch and acknowledges the new timeline. Then restart every replica.
