// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package datarequests

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/evidence/securityevent"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/restore"
)

func setup(t *testing.T) (*dbtest.DB, *Service, ids.OrgID) {
	t.Helper()
	d := dbtest.New(t)
	pool := d.AppPool(t)
	org := ids.New[ids.Org]()
	if err := pool.InTenantTx(t.Context(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "INSERT INTO pc.orgs(id,name) VALUES($1,'data-test')", org)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	reg := keys.NewRegistry()
	for _, p := range []keys.Purpose{keys.PurposeReceipts, keys.PurposeEvidencePacks} {
		k, err := keys.GenerateSigningKey(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := reg.Put(k); err != nil {
			t.Fatal(err)
		}
	}
	jc, err := jobs.NewClient(pool, nil, jobs.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return d, &Service{Pool: pool, Deleter: d.Pool(t, d.Deleter), Keys: reg, Jobs: jc, Bundles: evapp.New(pool, "https://test.example/log"), BackupRetentionDays: 60, LapseEnabled: true}, org
}

func deletionRequest(t *testing.T, s *Service, org ids.OrgID, when time.Time) ids.UUID {
	t.Helper()
	id := ids.NewV7()
	user := ids.NewV7()
	reason := "requested"
	if err := s.Pool.InTenantTx(t.Context(), org, func(ctx context.Context, tx db.TenantTx) error {
		return dbq.New(tx).InsertDataRequest(ctx, dbq.InsertDataRequestParams{OrgID: org, ID: id, Kind: "DELETION", State: "PENDING", CreatedBy: &user, Reason: &reason, WindowEnd: &when, AdminAccounts: []ids.UUID{}})
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

// Tests model the operator's explicit confirmation after checking the
// exported copy; neither a mere emission nor a local export is an ACK.
func acknowledgeIntents(t *testing.T, s *Service) {
	t.Helper()
	chainPlatform(t, s)
	if err := s.Pool.InTenantTx(t.Context(), ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
		var seq int64
		if err := tx.QueryRow(ctx, "SELECT coalesce(max(ledger_seq),0) FROM pc.security_event_outbox WHERE org_id=$1", ids.PlatformOrg).Scan(&seq); err != nil {
			return err
		}
		if _, err := securityevent.AcknowledgeIn(ctx, tx, seq); err != nil {
			return err
		}
		_, err := audit.Record(ctx, tx, audit.Event{Name: "security_log.acknowledged", Actor: evdomain.Actor{Type: "operator", ID: "test-external-copy-verified"}, Outcome: audit.Success})
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func finishDeletion(t *testing.T, s *Service, org ids.OrgID, id ids.UUID) {
	t.Helper()
	if err := s.DeleteOrg(t.Context(), org, id); !errors.Is(err, ErrAwaitingSecurityCopy) {
		t.Fatalf("first erasure must wait for external intent: %v", err)
	}
	acknowledgeIntents(t, s)
	if err := s.DeleteOrg(t.Context(), org, id); err != nil {
		t.Fatal(err)
	}
}

func TestHR390_DeletionResumesAfterRowsAndRequestAreGone(t *testing.T) {
	d, s, org := setup(t)
	ctx := t.Context()
	id := deletionRequest(t, s, org, time.Now().Add(-time.Hour))
	reg := s.Keys
	snap, err := s.freeze(ctx, org, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Pool.InTenantTx(ctx, ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error { return s.persistIntent(ctx, tx, *snap, id, org) }); err != nil {
		t.Fatal(err)
	}
	acknowledgeIntents(t, s)
	if err := s.removeOrgRows(ctx, org); err != nil {
		t.Fatal(err)
	}
	var requests int
	d.AdminQueryRow(t, "SELECT count(*) FROM pc.data_requests WHERE org_id=$1", []any{org}, &requests)
	if requests != 0 {
		t.Fatalf("request not removed before simulated signing crash: %d", requests)
	}
	s.Keys = nil
	if err := s.DeleteOrg(ctx, org, id); err == nil {
		t.Fatal("completion succeeded with unavailable signing registry")
	}
	s.Keys = reg
	if err := s.DeleteOrg(ctx, org, id); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteOrg(ctx, org, id); err != nil {
		t.Fatal("completed retry:", err)
	}
	var records int
	var raw []byte
	var signed string
	d.AdminQueryRow(t, "SELECT count(*) FROM pc.deletion_records WHERE deleted_org_id=$1", []any{org}, &records)
	if records != 1 {
		t.Fatalf("completion duplicated: %d", records)
	}
	d.AdminQueryRow(t, "SELECT record,signed_record FROM pc.deletion_records WHERE deleted_org_id=$1", []any{org}, &raw, &signed)
	var rec DeletionRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	if !rec.Verified || !rec.BackupExpireTime.Equal(rec.CompleteTime.Add(60*24*time.Hour)) {
		t.Fatalf("invalid completion: %+v", rec)
	}
	index := slices.IndexFunc(rec.Tables, func(c TableCount) bool { return c.Table == "data_requests" })
	if index < 0 || rec.Tables[index].Rows != 1 {
		t.Fatalf("lost pre-deletion count: %+v", rec.Tables)
	}
	verifier, err := reg.Verifier(keys.PurposeReceipts, DeletionJWSType)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifier.Verify(signed); err != nil {
		t.Fatal(err)
	}
	var data int
	d.AdminQueryRow(t, "SELECT count(*) FROM pc.org_deletion_journal WHERE org_id=$1 AND complete", []any{ids.PlatformOrg}, &data)
	if data != 1 {
		t.Fatal("journal not complete")
	}
}

func TestHR392_DeletedOrgRefusesNewWritesAndPreservesOtherTenant(t *testing.T) {
	d, s, org := setup(t)
	ctx := t.Context()
	other := ids.New[ids.Org]()
	d.AdminExec(t, "INSERT INTO pc.orgs(id,name) VALUES($1,'other')", other)
	id := deletionRequest(t, s, org, time.Now().Add(-time.Hour))
	finishDeletion(t, s, org, id)
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := audit.Record(ctx, tx, audit.Event{Name: "test.after_delete", Actor: evdomain.Actor{Type: "system", ID: "test"}, Outcome: audit.Success})
		return err
	})
	if err == nil {
		t.Fatal("post-deletion insert succeeded")
	}
	err = s.Pool.InTenantTx(ctx, other, func(ctx context.Context, tx db.TenantTx) error {
		_, err := audit.Record(ctx, tx, audit.Event{Name: "test.other_org", Actor: evdomain.Actor{Type: "system", ID: "test"}, Outcome: audit.Success})
		return err
	})
	if err != nil {
		t.Fatal("other tenant blocked:", err)
	}
	err = d.Pool(t, d.Retention).InTenantTx(ctx, other, func(ctx context.Context, tx db.TenantTx) error {
		var count int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM pc.orgs WHERE id=$1", org).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			t.Error("retention sees another org")
		}
		_, err := tx.Exec(ctx, "UPDATE pc.orgs SET state='DELETED' WHERE id=$1", other)
		return err
	})
	if !db.IsPermissionDenied(err) {
		t.Fatalf("retention may modify org: %v", err)
	}
	var has bool
	d.AdminQueryRow(t, "SELECT has_column_privilege('pc_retention','pc.orgs','name','SELECT')", nil, &has)
	if has {
		t.Fatal("retention can read org names")
	}
}

func TestT177_DeletionWindowAndPlatformRefused(t *testing.T) {
	_, s, org := setup(t)
	id := deletionRequest(t, s, org, time.Now().Add(time.Hour))
	if err := s.DeleteOrg(t.Context(), org, id); !errors.Is(err, ErrWindow) {
		t.Fatalf("window bypass: %v", err)
	}
	if err := s.DeleteOrg(t.Context(), ids.PlatformOrg, id); err == nil {
		t.Fatal("platform deletion accepted")
	}
}

func TestHR390_ExportRegistryAndStandardZipParts(t *testing.T) {
	d, s, org := setup(t)
	ctx := t.Context()
	user, id := ids.NewV7(), ids.NewV7()
	d.AdminExec(t, "INSERT INTO pc.users(org_id,id,issuer,subject,email,display_name) VALUES($1,$2,'test','person','own@example.com','Own identity')", org, user)
	d.AdminExec(t, "INSERT INTO pc.role_bindings(org_id,id,role,user_id,scope_type,created_by) VALUES($1,$2,'org_admin',$3,'ORG','system:test')", org, ids.NewV7(), user)
	if err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		return dbq.New(tx).InsertDataRequest(ctx, dbq.InsertDataRequestParams{OrgID: org, ID: id, Kind: "EXPORT", State: "BUILDING", CreatedBy: &user, AdminAccounts: []ids.UUID{}})
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Build(ctx, org, id); err != nil {
		t.Fatal(err)
	}
	var signed string
	d.AdminQueryRow(t, "SELECT manifest FROM pc.data_requests WHERE org_id=$1 AND id=$2", []any{org, id}, &signed)
	verifier, err := s.Keys.Verifier(keys.PurposeEvidencePacks, ExportJWSType)
	if err != nil {
		t.Fatal(err)
	}
	payload, _, err := verifier.Verify(signed)
	if err != nil {
		t.Fatal(err)
	}
	var manifest ExportManifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.RegistryVersion != 1 || len(manifest.Projections) != 20 || len(manifest.Excluded) == 0 || len(manifest.Files) != 20 {
		t.Fatalf("incomplete scope: %+v", manifest)
	}
	var content []byte
	d.AdminQueryRow(t, "SELECT content FROM pc.data_request_parts WHERE org_id=$1 AND request_id=$2 AND number=1", []any{org, id}, &content)
	z, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	if len(z.File) != 20 {
		t.Fatalf("ZIP files=%d", len(z.File))
	}
}

func TestHR391_AllTenantTablesHaveWriteBarrier(t *testing.T) {
	d, _, _ := setup(t)
	var missing int
	d.AdminQueryRow(t, `SELECT count(*) FROM pg_policies p WHERE p.schemaname='pc' AND p.policyname='tenant_isolation' AND p.tablename<>'orgs'
        AND NOT EXISTS(SELECT 1 FROM pg_trigger g WHERE g.tgrelid=('pc.'||p.tablename)::regclass AND g.tgname='org_write_guard' AND NOT g.tgisinternal)`, nil, &missing)
	if missing != 0 {
		t.Fatalf("%d tenant tables missing the deletion barrier", missing)
	}
}

func TestT176_RestoreRequeuesDeletionWhenOriginalRequestIsMissing(t *testing.T) {
	d, s, org := setup(t)
	ctx := t.Context()
	r := restore.NewRegistry()
	if err := s.RegisterRestore(r); err != nil {
		t.Fatal(err)
	}
	e := restore.Event{Org: ids.PlatformOrg, Kind: "org.deleted", Object: securityevent.Object{Type: "org", ID: org.String()}, RecordDigest: strings.Repeat("a", 64), LedgerSeq: 1, Direction: "tighten", Timestamp: time.Now(), Actor: evdomain.Actor{Type: "system", ID: "test"}}
	if err := r.Reapply(ctx, s.Pool, []restore.Event{e}, true, evdomain.Actor{Type: "operator", ID: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Reapply(ctx, s.Pool, []restore.Event{e}, true, evdomain.Actor{Type: "operator", ID: "test"}); err != nil {
		t.Fatal("repeat:", err)
	}
	var id ids.UUID
	d.AdminQueryRow(t, "SELECT id FROM pc.org_deletion_journal WHERE deleted_org_id=$1", []any{org}, &id)
	finishDeletion(t, s, org, id)
	var from []byte
	d.AdminQueryRow(t, "SELECT reapplied_from FROM pc.deletion_records WHERE deleted_org_id=$1", []any{org}, &from)
	if len(from) != 32 {
		t.Fatal("original deletion digest lost")
	}
}

// chainPlatform chains the platform org until every committed entry is
// chained. The chainer takes only entries below the cluster-wide xmin, so
// a transaction open in a concurrently running test package can hold new
// entries back briefly.
func chainPlatform(t *testing.T, s *Service) {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for {
		if _, err := ledger.ChainOrg(t.Context(), s.Pool, ids.PlatformOrg, 10000); err != nil {
			t.Fatal(err)
		}
		var left int
		if err := s.Pool.InTenantTx(t.Context(), ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM pc.ledger_entries e WHERE org_id = $1
				AND NOT EXISTS (SELECT 1 FROM pc.ledger_chain c WHERE c.org_id = e.org_id AND c.entry_id = e.id)`, ids.PlatformOrg).Scan(&left)
		}, db.ReadOnly()); err != nil {
			t.Fatal(err)
		}
		if left == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("platform entries not chained within a minute")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestHR390_DeletingAnOrgEndsItsHostedGatewayAndFreesItsSlug: the freeze
// marks the org's hosted gateway for stopping while the host can still see
// it, and the finished deletion leaves no record and no customer-chosen
// name behind. The host agent removes a process with no record
// (TestAProcessNoAssignmentNamesIsRemoved) (D228).
//
// Covers: PN-010.4
func TestHR390_DeletingAnOrgEndsItsHostedGatewayAndFreesItsSlug(t *testing.T) {
	d, s, org := setup(t)
	gateway, hosted := ids.NewV7(), ids.NewV7()
	d.AdminExec(t, `INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'hosted-acme', 'test')`, org, gateway)
	d.AdminExec(t, `INSERT INTO pc.hosted_gateways (org_id, id, slug, state, gateway_id, host_id, milli_cpus, memory_mib, pids, created_by)
		VALUES ($1, $2, 'acme', 'RUNNING', $3, $4, 500, 256, 128, 'test')`, org, hosted, gateway, ids.NewV7())
	d.AdminExec(t, `INSERT INTO pc.hosting_slugs (slug, org_id, hosted_id) VALUES ('acme', $1, $2)`, org, hosted)
	d.AdminExec(t, `INSERT INTO pc.hosting_slugs (slug, org_id, hosted_id) VALUES ('other', $1, $2)`, ids.NewV7(), ids.NewV7())
	id := deletionRequest(t, s, org, time.Now().Add(-time.Hour))
	if err := s.DeleteOrg(t.Context(), org, id); !errors.Is(err, ErrAwaitingSecurityCopy) {
		t.Fatalf("first erasure must wait for external intent: %v", err)
	}
	var state string
	d.AdminQueryRow(t, `SELECT state FROM pc.hosted_gateways WHERE id = $1`, []any{hosted}, &state)
	if state != "DEPROVISIONING" {
		t.Fatalf("after the freeze: %s", state)
	}
	acknowledgeIntents(t, s)
	if err := s.DeleteOrg(t.Context(), org, id); err != nil {
		t.Fatal(err)
	}
	var records, slugs int
	d.AdminQueryRow(t, `SELECT (SELECT count(*) FROM pc.hosted_gateways WHERE org_id = $1), (SELECT count(*) FROM pc.hosting_slugs WHERE slug = 'acme')`, []any{org}, &records, &slugs)
	if records != 0 || slugs != 0 {
		t.Fatalf("%d records and %d slugs left", records, slugs)
	}
	var others int
	d.AdminQueryRow(t, `SELECT count(*) FROM pc.hosting_slugs WHERE slug = 'other'`, nil, &others)
	if others != 1 {
		t.Fatal("another org's slug went too")
	}
}

// TestHR390_AnOrgWithTicketWebhooksIsDeleted: the append-only ticket inbound
// log does not stop an organization's deletion: pc_deleter removes its rows
// (00177's exception), and nobody else can.
func TestHR390_AnOrgWithTicketWebhooksIsDeleted(t *testing.T) {
	d, s, org := setup(t)
	gw, conn, config, event := ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7()
	secret := make([]byte, 16)
	if err := s.Pool.InTenantTx(t.Context(), org, func(ctx context.Context, tx db.TenantTx) error {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{"INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'gw', 'test')", []any{org, gw}},
			{`INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, created_by, updated_by)
				VALUES ($1, $2, 'jira', 'http', $3, 'pc.jira', 'https://example.atlassian.net', 'none', 'test', 'test')`, []any{org, conn, gw}},
			{`INSERT INTO pc.ticket_sync_configs (org_id, id, system, connection_id, project_key, webhook_secret, created_by)
				VALUES ($1, $2, 'jira', $3, 'SEC', $4, 'test')`, []any{org, config, conn, secret}},
			{`INSERT INTO pc.ticket_inbound_events (org_id, id, config_id, delivery_id, body_sha256, outcome)
				VALUES ($1, $2, $3, 'delivery-1', $4, 'UNLINKED')`, []any{org, event, config, make([]byte, 32)}},
		} {
			if _, err := tx.Exec(ctx, q.sql, q.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Pool.InTenantTx(t.Context(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "DELETE FROM pc.ticket_inbound_events WHERE org_id = $1", org)
		return err
	}); err == nil {
		t.Fatal("pc_app deleted from the inbound log")
	}
	finishDeletion(t, s, org, deletionRequest(t, s, org, time.Now().Add(-time.Hour)))
	var left int
	d.AdminQueryRow(t, "SELECT count(*) FROM pc.ticket_inbound_events WHERE org_id = $1", []any{org}, &left)
	if left != 0 {
		t.Fatalf("%d inbound rows left", left)
	}
}
