# Runbook — The M13 exit journey

**Milestone:** M13 wave 3 ([G0 M13](../g0/M13.md) exit criteria; [GATES §7](../security/GATES_AND_REVIEW.md#7-gate-decision-log) G4). **Audience:** the founder. The journey runs in two places. A local run is local evidence only; the exit needs the hosted run on staging.

## 1. Locally (every change, CI and `task test:integration`)

`TestE2E_M13_ExitJourney` (`test/e2e/m13_exit_e2e_test.go`) starts the full stack on the test cluster (`task up PROFILE=test`) and walks the journey:

1. an organization on an active plan; its gateway enrolled with its one-time token over mTLS; its agent's workload enrolled;
2. the admin signs in with `pclaw login`; an approver signs in in a browser and registers a security key;
3. an agent's refund is decided through the gateway, and its receipts verify offline with `pclaw verify` against the keys pinned with `pclaw evidence trust`;
4. `/readyz` refuses a pending schema and recovers; the usage meters are visible; one browser session is rate limited with `Retry-After` while another credential is not;
5. a support access request is approved with a security key, used read-only and revoked;
6. a tenant export downloads and verifies offline (`pclaw verify export`);
7. the organization is deleted after its window on an accelerated clock, once the operator exported and acknowledged the security-event log; its gateway fails closed and the signed deletion record verifies (`pclaw verify deletion`).

```bash
go tool -modfile=tools/pins/task/go.mod task up PROFILE=test
go tool -modfile=tools/pins/task/go.mod task test:integration     # or only the journey:
set -a; . deploy/compose/.env; set +a
PC_TEST_REQUIRE_DB=1 PC_TEST_PG_ADMIN_URL="postgres://postgres:${PC_PG_TEST_PASSWORD}@127.0.0.1:5433/postgres?sslmode=disable" \
  go test -tags integration -count=1 -run TestE2E_M13_ExitJourney ./test/e2e/
```

## 2. On hosted staging (once, for the exit)

Staging must be deployed from `main` with its G3 record ([deploy.md](deploy.md)). Use a test organization that holds no customer data. The browser steps are manual because they need a real security key and the hosted sign-in.

1. **Sign in and create the organization.** Sign in at the staging console, create the organization "m13-exit", and start its plan (test mode).
2. **Security key.** Register a security key under Account › Security keys.
3. **Gateway and agent over mTLS.** Create a gateway (Gateways › Add) and start it with its enrollment file on a machine that reaches staging's gateway port 8443; enroll an agent (`pclaw init` or Agents › Add) and point it at the gateway.
4. **A decided action.** Let the agent make one call that PantherClaw decides (for example the quickstart's refund against the payments simulator). Export its evidence: `pclaw evidence bundle --txn <id> --out exit-bundle.json`.
5. **Support access** (Enterprise test plan). Have a staff account request access with a task; approve it with the security key; open the session and read the agents page; revoke it and check the session is refused. Check Settings › Audit shows each support call.
6. **Export.** Settings › Data › Export, confirm with the security key, download the manifest and every part into one directory.
7. **Run the hosted test** from the repository, with an API key of a service account of the test organization that holds `entitlements.read`:

```bash
PC_E2E_STAGING_URL=https://<staging host> \
PC_E2E_STAGING_API_KEY_FILE=~/m13-exit/api-key \
PC_E2E_STAGING_BUNDLE=~/m13-exit/exit-bundle.json \
PC_E2E_STAGING_EXPORT=~/m13-exit/export/manifest.jws \
  go test -tags integration -count=1 -run TestE2E_M13_StagingJourney -v ./test/e2e/
```

It checks `/readyz`, `WhoAmI` and the usage meters with the API key, pins the evidence keys from staging (`pclaw evidence trust`), and verifies the bundle and the export offline. It changes nothing on staging. It is skipped while `PC_E2E_STAGING_URL` is unset and refuses anything but an `https` origin.

8. **Deletion.** Request deletion of "m13-exit" (Settings › Data › Delete, security key). After the 7-day window and the security-log acknowledgement ([backup-restore.md](backup-restore.md)), check the gateway from step 3 refuses at once, download the deletion record (`GetDeletionRecord`) and run the hosted test again with `PC_E2E_STAGING_DELETION=<file>`.
9. **Record it.** Add the run (date, staging digest from the G3 record, the test output, the restore drill's RPO and RTO) to the G4 entry in GATES §7 and to the exit status in the brief.
