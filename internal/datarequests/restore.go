// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package datarequests

import (
	"context"
	"encoding/hex"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/securityevent"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/restore"
)

// RegisterRestore installs only the reviewed scoped deletion handlers.
func (s *Service) RegisterRestore(r *restore.Registry) error {
	if err := r.RegisterScoped("org.deleted", s.reapplyOrg); err != nil {
		return err
	}
	if err := r.RegisterScoped("org.deletion_started", s.reapplyOrg); err != nil {
		return err
	}
	for _, kind := range []string{"account.deleted", "account.deletion_started"} {
		if err := r.RegisterScoped(kind, func(ctx context.Context, _ *db.Pool, e restore.Event, actor evdomain.Actor) error {
			if s.ReapplyAccount == nil {
				return errors.New("datarequests: account replay unavailable")
			}
			id, err := ids.ParseUUID(e.Object.ID)
			if err != nil {
				return err
			}
			digest := e.RecordDigest
			if e.Kind == "account.deletion_started" {
				digest = e.JournalDigest
			}
			return s.ReapplyAccount(ctx, id, digest, actor)
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) reapplyOrg(ctx context.Context, _ *db.Pool, e restore.Event, actor evdomain.Actor) error {
	org, err := ids.Parse[ids.Org](e.Object.ID)
	if err != nil {
		return err
	}
	if org == ids.PlatformOrg {
		return errors.New("datarequests: refusing platform deletion")
	}
	id := ids.NewV7()
	snap := deletionSnapshot{Accounts: []ids.UUID{}}
	err = s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		if err := writeBarrier(ctx, tx); err != nil {
			return err
		}
		q := dbq.New(tx)
		now, err := q.TenantDatabaseTime(ctx)
		if err != nil {
			return err
		}
		source := e.RecordDigest
		if e.Kind == "org.deletion_started" {
			source = e.JournalDigest
		}
		if len(source) != 64 {
			return errors.New("datarequests: missing replay provenance")
		}
		snap.Record = DeletionRecord{Format: "pantherclaw.deletion/v1", Org: org.String(), Request: id.String(), Reason: "requested", RequestTime: now, WindowEndTime: now, StartTime: now, ReappliedFrom: source, ReappliedKind: e.Kind, Tables: []TableCount{}}
		state, err := q.LockOrgState(ctx, org)
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if state != "DELETED" {
			if _, err := q.MarkOrgDeleted(ctx, org); err != nil {
				return err
			}
		}
		// This is a new replay attempt, even when the backup already held
		// the irreversible tombstone. Its erasure starts now; using an old
		// deleted_at would put start_time before this request's window.
		admins, err := deletionAdmins(ctx, q, org)
		if err != nil {
			return err
		}
		snap.Accounts, err = q.AccountsOfUsers(ctx, org, admins)
		if err != nil {
			return err
		}
		tables, err := tenantTables(ctx, tx)
		if err != nil {
			return err
		}
		for _, t := range tables {
			var n int64
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+pgx.Identifier{"pc", t}.Sanitize()+" WHERE org_id=$1", org).Scan(&n); err != nil {
				return err
			}
			snap.Record.Tables = append(snap.Record.Tables, TableCount{Table: t, Rows: n})
		}
		return nil
	})
	if err != nil {
		return err
	}
	return s.Pool.InTenantTx(ctx, ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
		var existing ids.UUID
		var done bool
		err := tx.QueryRow(ctx, "SELECT id,complete FROM pc.org_deletion_journal WHERE org_id=$1 AND deleted_org_id=$2 AND snapshot->'record'->>'reapplied_from'=$3 FOR UPDATE", ids.PlatformOrg, org, snap.Record.ReappliedFrom).Scan(&existing, &done)
		switch {
		case db.IsNoRows(err):
			if err := s.persistIntent(ctx, tx, snap, id, org); err != nil {
				return err
			}
		case err != nil:
			return err
		default:
			id = existing
		}
		if !done {
			if err := enqueue(ctx, s.Jobs, tx, org, id, true, snap.Record.StartTime); err != nil {
				return err
			}
		}
		return restore.Audit(ctx, tx, []restore.Event{e}, actor)
	})
}

// RecordDeletedAccount is retryable after the account journal's final
// commit. The account owner must call it again when resuming a completed
// journal so a crash between that commit and this ledger append is closed.
func (s *Service) RecordDeletedAccount(ctx context.Context, account ids.UUID, recordDigest string, actor evdomain.Actor) error {
	return s.recordAccountEvent(ctx, account, recordDigest, "account.deleted", "record_digest", actor)
}

// RecordAccountDeletionIntent must complete before the account journal
// enters irreversible erasure. Its dedupe row and audit event commit
// together in the platform tenant, never in a caller's account transaction.
func (s *Service) RecordAccountDeletionIntent(ctx context.Context, account ids.UUID, journalDigest string, actor evdomain.Actor) error {
	if err := s.recordAccountEvent(ctx, account, journalDigest, "account.deletion_started", "journal_digest", actor); err != nil {
		return err
	}
	acked, err := securityevent.IntentAcknowledged(ctx, s.Pool, "account.deletion_started", account, journalDigest)
	if err != nil {
		return err
	}
	if !acked {
		return ErrAwaitingSecurityCopy
	}
	return nil
}

func (s *Service) recordAccountEvent(ctx context.Context, account ids.UUID, recordDigest, kind, detail string, actor evdomain.Actor) error {
	digest, err := hex.DecodeString(recordDigest)
	if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != recordDigest || account.IsZero() {
		return errors.New("datarequests: invalid account deletion record")
	}
	return s.Pool.InTenantTx(ctx, ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
		tag, err := tx.Exec(ctx, "INSERT INTO pc.account_deletion_events(org_id,id,account_id,kind,record_digest) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING", ids.PlatformOrg, ids.NewV7(), account, kind, digest)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		_, err = audit.Record(ctx, tx, audit.Event{Name: kind, Actor: actor, Outcome: audit.Success, Object: &audit.Object{Type: "account", ID: account.String()}, Details: map[string]string{detail: recordDigest}})
		return err
	})
}
