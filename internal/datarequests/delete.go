// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package datarequests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/evidence/securityevent"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

const (
	DeletionJWSType       = "pap-deletion+jwt"
	DeletionIntentJWSType = "pap-deletion-intent+jwt"
)

// DeletionIntent proves the durable pre-erasure snapshot. It makes no
// assertion that data removal is complete or verified.
type DeletionIntent struct {
	Format         string    `json:"format"`
	Org            string    `json:"org"`
	Request        string    `json:"request"`
	Reason         string    `json:"reason"`
	StartedAt      time.Time `json:"started_at"`
	SnapshotSHA256 string    `json:"snapshot_sha256"`
	ReappliedFrom  string    `json:"reapplied_from,omitzero"`
	ReappliedKind  string    `json:"reapplied_kind,omitzero"`
}

type TableCount struct {
	Table string `json:"table"`
	Rows  int64  `json:"rows"`
}

// DeletionRecord is the exact canonical payload of pap-deletion+jwt.
// BackupExpireTime reflects configured retention, never a physical-erasure claim.
type DeletionRecord struct {
	Format             string       `json:"format"`
	Org                string       `json:"org"`
	Request            string       `json:"request"`
	Reason             string       `json:"reason"`
	RequestedByAccount string       `json:"requested_by_account,omitzero"`
	RequestTime        time.Time    `json:"request_time"`
	WindowEndTime      time.Time    `json:"window_end_time"`
	StartTime          time.Time    `json:"start_time"`
	CompleteTime       time.Time    `json:"complete_time"`
	Tables             []TableCount `json:"tables"`
	Verified           bool         `json:"verified"`
	BackupExpireTime   time.Time    `json:"backup_expire_time"`
	ReappliedFrom      string       `json:"reapplied_from,omitzero"`
	ReappliedKind      string       `json:"reapplied_kind,omitzero"`
}

type deletionSnapshot struct {
	Record   DeletionRecord `json:"record"`
	Accounts []ids.UUID     `json:"accounts"`
}

func writeBarrier(ctx context.Context, tx db.TenantTx) error {
	_, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended('pc.org.write/' || $1::text, 0))", tx.OrgID().String())
	return err
}

// DeleteOrg deliberately commits three phases: freeze/snapshot, durable
// platform journal, then removal and signed completion. A retry may start
// after the request row itself was removed; the platform journal survives.
func (s *Service) DeleteOrg(ctx context.Context, org ids.OrgID, id ids.UUID) error {
	if org.IsZero() || org == ids.PlatformOrg {
		return errors.New("datarequests: refusing platform deletion")
	}
	if s.Deleter == nil {
		return ErrRole
	}
	var exists bool
	err := s.Pool.InTenantTx(ctx, ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pc.org_deletion_journal WHERE org_id=$1 AND id=$2 AND deleted_org_id=$3)", ids.PlatformOrg, id, org).Scan(&exists)
	}, db.ReadOnly())
	if err != nil {
		return err
	}
	if !exists {
		snapshot, err := s.freeze(ctx, org, id)
		if err != nil {
			return err
		}
		if snapshot == nil {
			return nil
		}
		err = s.Pool.InTenantTx(ctx, ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
			return s.persistIntent(ctx, tx, *snapshot, id, org)
		})
		if err != nil {
			return err
		}
	}
	// A local database commit alone cannot protect an older backup from
	// resurrection. Wait for the exact linked intent to be explicitly
	// acknowledged after the operator verifies its external durable copy.
	var signedIntent string
	err = s.Pool.InTenantTx(ctx, ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT signed_intent FROM pc.org_deletion_journal WHERE org_id=$1 AND id=$2 AND deleted_org_id=$3", ids.PlatformOrg, id, org).Scan(&signedIntent)
	}, db.ReadOnly())
	if err != nil {
		return err
	}
	intentDigest := sha256.Sum256([]byte(signedIntent))
	acked, err := securityevent.IntentAcknowledged(ctx, s.Pool, "org.deletion_started", org.UUID(), hex.EncodeToString(intentDigest[:]))
	if err != nil {
		return err
	}
	if !acked {
		return ErrAwaitingSecurityCopy
	}
	// Hold the one journal row while removing data, preventing two workers
	// from racing completion. Failure rolls back only this phase; the
	// already committed journal and fail-closed org tombstone remain.
	return s.Pool.InTenantTx(ctx, ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
		var raw []byte
		var done bool
		if err := tx.QueryRow(ctx, "SELECT snapshot,complete FROM pc.org_deletion_journal WHERE org_id=$1 AND id=$2 AND deleted_org_id=$3 FOR UPDATE", ids.PlatformOrg, id, org).Scan(&raw, &done); err != nil {
			return err
		}
		if done {
			return nil
		}
		var snap deletionSnapshot
		if err := json.Unmarshal(raw, &snap); err != nil {
			return err
		}
		if err := s.removeOrgRows(ctx, org); err != nil {
			return err
		}
		now, err := dbq.New(tx).TenantDatabaseTime(ctx)
		if err != nil {
			return err
		}
		snap.Record.CompleteTime = now
		snap.Record.Verified = true
		retention := s.BackupRetentionDays
		if retention == 0 {
			retention = 60
		}
		if retention < 1 || retention > 3650 {
			return errors.New("datarequests: invalid backup retention")
		}
		snap.Record.BackupExpireTime = now.Add(time.Duration(retention) * 24 * time.Hour)
		if err := s.recordDeletion(ctx, tx, snap); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, "UPDATE pc.org_deletion_journal SET complete=true WHERE org_id=$1 AND id=$2 AND NOT complete", ids.PlatformOrg, id)
		return db.ExpectOneRow(tag, err)
	})
}

func (s *Service) persistIntent(ctx context.Context, tx db.TenantTx, snap deletionSnapshot, id ids.UUID, org ids.OrgID) error {
	if s.Keys == nil {
		return errors.New("datarequests: signing registry unavailable")
	}
	raw, err := pack.Canonical(snap)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	intent := DeletionIntent{Format: "pantherclaw.deletion-intent/v1", Org: org.String(), Request: id.String(), Reason: snap.Record.Reason, StartedAt: snap.Record.StartTime, SnapshotSHA256: hex.EncodeToString(sum[:]), ReappliedFrom: snap.Record.ReappliedFrom, ReappliedKind: snap.Record.ReappliedKind}
	payload, err := pack.Canonical(intent)
	if err != nil {
		return err
	}
	signer, err := s.Keys.Signer(keys.PurposeReceipts)
	if err != nil {
		return err
	}
	signed, err := signer.Sign(DeletionIntentJWSType, payload)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, "INSERT INTO pc.org_deletion_journal(org_id,id,deleted_org_id,snapshot,signed_intent) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING", ids.PlatformOrg, id, org, raw, signed)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	digest := sha256.Sum256([]byte(signed))
	_, err = audit.Record(ctx, tx, audit.Event{Name: "org.deletion_started", Actor: evdomain.Actor{Type: "system", ID: "data.delete_org"}, Outcome: audit.Success, Object: &audit.Object{Type: "org", ID: org.String()}, Details: map[string]string{"request_id": id.String(), "journal_digest": hex.EncodeToString(digest[:])}})
	return err
}

func (s *Service) freeze(ctx context.Context, org ids.OrgID, id ids.UUID) (*deletionSnapshot, error) {
	var out *deletionSnapshot
	var held bool
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		// The exclusive barrier precedes the last hold check, so every
		// already-started legal hold/write commits before this snapshot.
		if err := writeBarrier(ctx, tx); err != nil {
			return err
		}
		q := dbq.New(tx)
		if err := q.LockOrgAdmins(ctx, org); err != nil {
			return err
		}
		r, err := q.LockDataRequest(ctx, org, id)
		if err != nil {
			return err
		}
		if r.Kind != "DELETION" || r.State == "CANCELED" || r.State == "FAILED" {
			return nil
		}
		now, err := q.TenantDatabaseTime(ctx)
		if err != nil {
			return err
		}
		if r.WindowEnd == nil || now.Before(*r.WindowEnd) {
			return ErrWindow
		}
		state, err := q.LockOrgState(ctx, org)
		if err != nil {
			return err
		}
		if state != "DELETED" {
			activeHold, err := q.ActiveOrgLegalHold(ctx, org)
			if err != nil {
				return err
			}
			if activeHold {
				held = true
				if r.State != "HELD" {
					_, err := q.SetDataRequestState(ctx, dbq.SetDataRequestStateParams{State: "HELD", OrgID: org, ID: id, FromState: r.State})
					return err
				}
				return nil
			}
			if r.Reason != nil && *r.Reason == "lapse_90d" {
				lapse, err := q.RefreshPlanLapse(ctx, org)
				if err != nil {
					return err
				}
				// Paying again before the irreversible barrier wins.
				if lapse == nil || r.LapsedAt == nil || !lapse.Equal(*r.LapsedAt) {
					code := "PLAN_RESTORED"
					_, err := q.FailDataRequest(ctx, &code, org, id)
					return err
				}
				admins, err := deletionAdmins(ctx, q, org)
				if err != nil {
					return err
				}
				r.AdminAccounts, err = q.AccountsOfUsers(ctx, org, admins)
				if err != nil {
					return err
				}
				if err := q.SetDeletionAdminAccounts(ctx, r.AdminAccounts, org, id); err != nil {
					return err
				}
			}
			if _, err := q.SetDataRequestState(ctx, dbq.SetDataRequestStateParams{State: "DELETING", OrgID: org, ID: id, FromState: r.State}); err != nil {
				return err
			}
			if _, err := q.MarkOrgDeleted(ctx, org); err != nil {
				return err
			}
		}
		d, err := q.OrgDeletedAt(ctx, org)
		if err != nil {
			return err
		}
		if d.DeletedAt == nil {
			return errors.New("datarequests: missing deletion time")
		}
		tables, err := tenantTables(ctx, tx)
		if err != nil {
			return err
		}
		counts := make([]TableCount, 0, len(tables))
		for _, t := range tables {
			var n int64
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+pgx.Identifier{"pc", t}.Sanitize()+" WHERE org_id=$1", org).Scan(&n); err != nil { // nosemgrep: pc-sql-built-with-sprintf -- table names from the pg_catalog policy list (migrations only), quoted by pgx.Identifier; org is a parameter
				return err
			}
			counts = append(counts, TableCount{Table: t, Rows: n})
		}
		reason := "requested"
		if r.Reason != nil {
			reason = *r.Reason
		}
		rec := DeletionRecord{Format: "pantherclaw.deletion/v1", Org: org.String(), Request: id.String(), Reason: reason, RequestTime: r.CreatedAt, WindowEndTime: *r.WindowEnd, StartTime: *d.DeletedAt, Tables: counts}
		if r.CreatedByAccount != nil {
			rec.RequestedByAccount = r.CreatedByAccount.String()
		}
		out = &deletionSnapshot{Record: rec, Accounts: r.AdminAccounts}
		return nil
	})
	if err == nil && held {
		return nil, ErrHeld
	}
	return out, err
}

func tenantTables(ctx context.Context, tx db.TenantTx) ([]string, error) {
	rows, err := tx.Query(ctx, "SELECT tablename FROM pg_policies WHERE schemaname='pc' AND policyname='tenant_isolation' AND tablename NOT IN ('orgs','deletion_records') ORDER BY tablename")
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// deletionOrder derives dependencies from the live catalog. Unknown cycles
// fail closed; the reviewed feedback edges (00181, 00183) are deferrable
// and removeOrgRows defers them.
func deletionOrder(ctx context.Context, tx db.TenantTx, tables []string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT child.relname,parent.relname FROM pg_constraint c
        JOIN pg_class child ON child.oid=c.conrelid JOIN pg_class parent ON parent.oid=c.confrelid
        JOIN pg_namespace n ON n.oid=child.relnamespace
        WHERE c.contype='f' AND n.nspname='pc' AND NOT c.condeferrable AND c.conrelid<>c.confrelid`)
	if err != nil {
		return nil, err
	}
	type edge struct{ Child, Parent string }
	edges, err := pgx.CollectRows(rows, pgx.RowToStructByPos[edge])
	if err != nil {
		return nil, err
	}
	left := slices.Clone(tables)
	var order []string
	for len(left) > 0 {
		progress := false
		for _, table := range slices.Clone(left) {
			blocked := false
			for _, e := range edges {
				if e.Parent == table && slices.Contains(left, e.Child) {
					blocked = true
					break
				}
			}
			if !blocked {
				order = append(order, table)
				left = slices.DeleteFunc(left, func(t string) bool { return t == table })
				progress = true
			}
		}
		if !progress {
			return nil, fmt.Errorf("datarequests: unreviewed foreign-key cycle: %v", left)
		}
	}
	return order, nil
}

func (s *Service) removeOrgRows(ctx context.Context, org ids.OrgID) error {
	return s.Deleter.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		if err := writeBarrier(ctx, tx); err != nil {
			return err
		}
		state, err := dbq.New(tx).OrgState(ctx, org)
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if state != "DELETED" {
			return errors.New("datarequests: org is not deleted")
		}
		if _, err := tx.Exec(ctx, "SET CONSTRAINTS pc.automations_enabled_version_fk, pc.agent_instances_sandbox_session_fk, pc.automation_triggers_execution_fk DEFERRED"); err != nil {
			return err
		}
		tables, err := tenantTables(ctx, tx)
		if err != nil {
			return err
		}
		order, err := deletionOrder(ctx, tx, tables)
		if err != nil {
			return err
		}
		for _, t := range order {
			table := pgx.Identifier{"pc", t}.Sanitize()
			for {
				tag, err := tx.Exec(ctx, "DELETE FROM "+table+" WHERE org_id=$1 AND ctid IN (SELECT ctid FROM "+table+" WHERE org_id=$1 LIMIT 1000)", org) // nosemgrep: pc-sql-built-with-sprintf -- table names from the pg_catalog policy list (migrations only), quoted by pgx.Identifier; org is a parameter
				if err != nil {
					return fmt.Errorf("datarequests: remove %s: %w", t, err)
				}
				if tag.RowsAffected() == 0 {
					break
				}
			}
		}
		for _, t := range tables {
			var n int64
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+pgx.Identifier{"pc", t}.Sanitize()+" WHERE org_id=$1", org).Scan(&n); err != nil { // nosemgrep: pc-sql-built-with-sprintf -- table names from the pg_catalog policy list (migrations only), quoted by pgx.Identifier; org is a parameter
				return err
			}
			if n != 0 {
				return fmt.Errorf("datarequests: %s still has rows", t)
			}
		}
		_, err = tx.Exec(ctx, "UPDATE pc.orgs SET name='deleted',slug=NULL,created_by_account=NULL,updated_at=now() WHERE id=$1 AND state='DELETED'", org)
		return err
	})
}

func (s *Service) recordDeletion(ctx context.Context, tx db.TenantTx, snap deletionSnapshot) error {
	if s.Keys == nil {
		return errors.New("datarequests: signing registry unavailable")
	}
	payload, err := pack.Canonical(snap.Record)
	if err != nil {
		return err
	}
	signer, err := s.Keys.Signer(keys.PurposeReceipts)
	if err != nil {
		return err
	}
	signed, err := signer.Sign(DeletionJWSType, payload)
	if err != nil {
		return err
	}
	org, err := ids.Parse[ids.Org](snap.Record.Org)
	if err != nil {
		return err
	}
	var account *ids.UUID
	if snap.Record.RequestedByAccount != "" {
		id, err := ids.ParseUUID(snap.Record.RequestedByAccount)
		if err != nil {
			return err
		}
		account = &id
	}
	var from []byte
	if snap.Record.ReappliedFrom != "" {
		from, err = hex.DecodeString(snap.Record.ReappliedFrom)
		if err != nil {
			return err
		}
	}
	err = dbq.New(tx).InsertDeletionRecord(ctx, dbq.InsertDeletionRecordParams{OrgID: ids.PlatformOrg, ID: ids.NewV7(), DeletedOrgID: org.UUID(), Reason: snap.Record.Reason, RequestedByAccount: account, Accounts: snap.Accounts, ReappliedFrom: from, Record: payload, SignedRecord: signed})
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(signed))
	_, err = audit.Record(ctx, tx, audit.Event{Name: "org.deleted", Actor: evdomain.Actor{Type: "system", ID: "data.delete_org"}, Outcome: audit.Success, Object: &audit.Object{Type: "org", ID: org.String()}, Details: map[string]string{"record_digest": hex.EncodeToString(digest[:])}})
	return err
}
