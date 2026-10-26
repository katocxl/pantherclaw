// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package datarequests

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/accounts"
	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const Window = 7 * 24 * time.Hour

var (
	ErrStepUp               = pcerr.New(pcerr.FailedPrecondition, "STEP_UP_REQUIRED", "confirm on the server's security-key page")
	ErrNotFound             = pcerr.New(pcerr.NotFound, "DATA_REQUEST_NOT_FOUND", "unknown data request")
	ErrHeld                 = pcerr.New(pcerr.FailedPrecondition, "DELETION_HELD", "an organisation legal hold blocks deletion")
	ErrPending              = pcerr.New(pcerr.FailedPrecondition, "DELETION_PENDING", "a deletion is already pending")
	ErrBuilding             = pcerr.New(pcerr.FailedPrecondition, "EXPORT_IN_PROGRESS", "an export is already building")
	ErrWindow               = pcerr.New(pcerr.FailedPrecondition, "CANCELLATION_WINDOW_ENDED", "the deletion cancellation window has ended")
	ErrExportUnavailable    = pcerr.New(pcerr.FailedPrecondition, "EXPORT_UNAVAILABLE", "the export is not ready or has expired")
	ErrTooLarge             = pcerr.New(pcerr.ResourceExhausted, "EXPORT_TOO_LARGE", "the export exceeds 2 GiB")
	ErrRole                 = pcerr.New(pcerr.FailedPrecondition, "ROLE_UNAVAILABLE", "the organisation deletion role is not configured")
	ErrAwaitingSecurityCopy = pcerr.New(pcerr.FailedPrecondition, "DELETION_AWAITING_SECURITY_COPY", "deletion intent is awaiting confirmation of a durable external security log copy")
	ErrAdminLimit           = pcerr.New(pcerr.ResourceExhausted, "DELETION_ADMIN_LIMIT", "deletion supports at most 10000 organisation administrators")
)

// Service owns only the application's pool; Deleter is the separately
// authenticated pc_deleter pool and is used exclusively by DeleteOrg.
type Service struct {
	Pool                *db.Pool
	Deleter             *db.Pool
	Keys                *keys.Registry
	Jobs                *jobs.Client
	Notify              *napp.Service
	Bundles             *evapp.Service
	BackupRetentionDays int
	Cosign              bool
	LapseEnabled        bool
	// ReapplyAccount is supplied by the hosted account deletion service.
	ReapplyAccount   func(context.Context, ids.UUID, string, evdomain.Actor) error
	CheckExportLimit func(context.Context, ids.OrgID) error
}

func human(ctx context.Context, permission td.Permission) (tapp.Caller, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if !c.Human() {
		return c, td.ErrPermissionDenied(permission)
	}
	return c, c.Require(permission, td.OrgPath(c.Org))
}

// Every linked administrator must retain access to the completion record.
// The one extra row detects overflow; no caller may silently truncate ACLs.
func deletionAdmins(ctx context.Context, q *dbq.Queries, org ids.OrgID) ([]ids.UUID, error) {
	admins, err := q.DataRequestAdmins(ctx, org)
	if err != nil {
		return nil, err
	}
	if len(admins) > 10000 {
		return nil, ErrAdminLimit
	}
	return admins, nil
}

func stepped(ctx context.Context, q *dbq.Queries, c tapp.Caller) error {
	if c.Credential != tapp.CredBrowserSession || c.Session.IsZero() {
		return ErrStepUp
	}
	u, err := q.SessionStepUp(ctx, c.Org, c.Session, c.Principal.ID)
	if db.IsNoRows(err) {
		return ErrStepUp
	}
	if err != nil {
		return err
	}
	if u.StepUpAt.IsZero() || u.StepUpAt.Before(u.DbNow.Add(-5*time.Minute)) || u.StepUpAt.After(u.DbNow) {
		return ErrStepUp
	}
	return nil
}

func requestAudit(ctx context.Context, tx db.TenantTx, c tapp.Caller, kind string, id ids.UUID) error {
	_, err := audit.Record(ctx, tx, audit.Event{Name: kind, Actor: c.Actor(), Outcome: audit.Success,
		Object: &audit.Object{Type: "data_request", ID: id.String()}})
	return err
}

// CreateExportPage is called only by the canonical confirmation page.
// The Connect mutation deliberately never calls it (D47).
func (s *Service) CreateExportPage(ctx context.Context) (dbq.PcDataRequest, error) {
	c, err := human(ctx, td.PermDataExport)
	if err != nil {
		return dbq.PcDataRequest{}, err
	}
	if s.CheckExportLimit != nil {
		if err := s.CheckExportLimit(ctx, c.Org); err != nil {
			return dbq.PcDataRequest{}, err
		}
	}
	var out dbq.PcDataRequest
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.LockOrgAdmins(ctx, c.Org); err != nil {
			return err
		}
		if err := stepped(ctx, q, c); err != nil {
			return err
		}
		id := ids.NewV7()
		account, err := q.AccountOfUser(ctx, c.Org, c.Principal.ID)
		if err != nil {
			return err
		}
		err = q.InsertDataRequest(ctx, dbq.InsertDataRequestParams{OrgID: c.Org, ID: id, Kind: "EXPORT", State: "BUILDING", CreatedBy: &c.Principal.ID, CreatedByAccount: account, AdminAccounts: []ids.UUID{}})
		if db.IsUniqueViolation(err) {
			return ErrBuilding
		}
		if err != nil {
			return err
		}
		if s.Jobs == nil {
			return errors.New("datarequests: jobs are unavailable")
		}
		if err := enqueue(ctx, s.Jobs, tx, c.Org, id, false, time.Time{}); err != nil {
			return err
		}
		if err := requestAudit(ctx, tx, c, "data.export_requested", id); err != nil {
			return err
		}
		out, err = q.GetDataRequest(ctx, c.Org, id)
		return err
	})
	return out, err
}

func (s *Service) RequestDeletionPage(ctx context.Context) (dbq.PcDataRequest, error) {
	c, err := human(ctx, td.PermOrgDelete)
	if err != nil {
		return dbq.PcDataRequest{}, err
	}
	if c.Org == ids.PlatformOrg {
		return dbq.PcDataRequest{}, td.ErrPermissionDenied(td.PermOrgDelete)
	}
	var out dbq.PcDataRequest
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.LockOrgAdmins(ctx, c.Org); err != nil {
			return err
		}
		if err := stepped(ctx, q, c); err != nil {
			return err
		}
		held, err := q.ActiveOrgLegalHold(ctx, c.Org)
		if err != nil {
			return err
		}
		if held {
			return ErrHeld
		}
		now, err := q.TenantDatabaseTime(ctx)
		if err != nil {
			return err
		}
		admins, err := deletionAdmins(ctx, q, c.Org)
		if err != nil {
			return err
		}
		accts, err := q.AccountsOfUsers(ctx, c.Org, admins)
		if err != nil {
			return err
		}
		account, err := q.AccountOfUser(ctx, c.Org, c.Principal.ID)
		if err != nil {
			return err
		}
		id, reason, end := ids.NewV7(), "requested", now.Add(Window)
		if err := q.InsertDataRequest(ctx, dbq.InsertDataRequestParams{OrgID: c.Org, ID: id, Kind: "DELETION", State: "PENDING", CreatedBy: &c.Principal.ID, CreatedByAccount: account, Reason: &reason, WindowEnd: &end, AdminAccounts: accts}); err != nil {
			if db.IsUniqueViolation(err) {
				return ErrPending
			}
			return err
		}
		if err := enqueue(ctx, s.Jobs, tx, c.Org, id, true, end); err != nil {
			return err
		}
		if err := s.notice(ctx, tx, admins, "data.deletion_requested", id.String()); err != nil {
			return err
		}
		if err := requestAudit(ctx, tx, c, "data.deletion_requested", id); err != nil {
			return err
		}
		out, err = q.GetDataRequest(ctx, c.Org, id)
		return err
	})
	return out, err
}

func (s *Service) notice(ctx context.Context, tx db.TenantTx, admins []ids.UUID, kind, key string) error {
	if s.Notify == nil {
		return nil
	}
	_, err := s.Notify.Enqueue(ctx, tx, napp.Message{Org: tx.OrgID(), Type: kind, Params: map[string]string{}, Personal: admins, PersonalOnly: true, DedupeKey: kind + ":" + key})
	return err
}

func (s *Service) Get(ctx context.Context, id ids.UUID) (dbq.PcDataRequest, error) {
	c, err := human(ctx, td.PermDataRequestsRead)
	if err != nil {
		return dbq.PcDataRequest{}, err
	}
	var out dbq.PcDataRequest
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = dbq.New(tx).GetDataRequest(ctx, c.Org, id)
		return err
	}, db.ReadOnly())
	if db.IsNoRows(err) {
		return out, ErrNotFound
	}
	return out, err
}

func (s *Service) List(ctx context.Context, before ids.UUID, n int32) ([]dbq.PcDataRequest, error) {
	c, err := human(ctx, td.PermDataRequestsRead)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		n = 50
	}
	if n < 1 || n > 200 {
		return nil, pcerr.New(pcerr.InvalidArgument, "INVALID_PAGE", "invalid page size")
	}
	var out []dbq.PcDataRequest
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = dbq.New(tx).ListDataRequests(ctx, c.Org, before, n)
		return err
	}, db.ReadOnly())
	return out, err
}

func (s *Service) Cancel(ctx context.Context, id ids.UUID) (dbq.PcDataRequest, error) {
	c, err := human(ctx, td.PermOrgDelete)
	if err != nil {
		return dbq.PcDataRequest{}, err
	}
	var out dbq.PcDataRequest
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.LockOrgAdmins(ctx, c.Org); err != nil {
			return err
		}
		n, err := q.CancelDeletionRequest(ctx, &c.Principal.ID, c.Org, id)
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrWindow
		}
		if err := s.noticeCancellation(ctx, tx, q, id); err != nil {
			return err
		}
		if err := requestAudit(ctx, tx, c, "data.deletion_canceled", id); err != nil {
			return err
		}
		out, err = q.GetDataRequest(ctx, c.Org, id)
		return err
	})
	return out, err
}

// Cancellation never depends on the snapshot ACL bound. Page its recipient
// fan-out so an org that gained administrators can still stop erasure.
func (s *Service) noticeCancellation(ctx context.Context, tx db.TenantTx, q *dbq.Queries, id ids.UUID) error {
	if s.Notify == nil {
		return nil
	}
	var after ids.UUID
	for {
		admins, err := q.DataRequestAdminsPage(ctx, tx.OrgID(), after)
		if err != nil {
			return err
		}
		if len(admins) == 0 {
			return nil
		}
		if err := s.notice(ctx, tx, admins, "data.deletion_canceled", id.String()+":"+after.String()); err != nil {
			return err
		}
		after = admins[len(admins)-1]
		if len(admins) < 1000 {
			return nil
		}
	}
}

// Download checks expiry and writes the audit before returning any bytes.
func (s *Service) Download(ctx context.Context, id ids.UUID, part int32) (dbq.GetDataRequestPartRow, error) {
	c, err := human(ctx, td.PermDataExport)
	if err != nil {
		return dbq.GetDataRequestPartRow{}, err
	}
	var out dbq.GetDataRequestPartRow
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.GetDataRequest(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		now, err := q.TenantDatabaseTime(ctx)
		if err != nil {
			return err
		}
		if r.State != "READY" || r.ExpiresAt == nil || !now.Before(*r.ExpiresAt) {
			return ErrExportUnavailable
		}
		out, err = q.GetDataRequestPart(ctx, c.Org, id, part)
		if db.IsNoRows(err) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		return requestAudit(ctx, tx, c, "data.export_downloaded", id)
	})
	return out, err
}

// DeletionRecord is account-scoped even after the target org is gone.
func (s *Service) DeletionRecord(ctx context.Context, org ids.OrgID) (dbq.PcDeletionRecord, error) {
	c, ok := accounts.CallerFrom(ctx)
	if !ok {
		return dbq.PcDeletionRecord{}, accounts.ErrNoAccount
	}
	var out dbq.PcDeletionRecord
	err := s.Pool.InTenantTx(ctx, ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
		r, err := dbq.New(tx).LatestDeletionRecord(ctx, ids.PlatformOrg, org.UUID())
		if db.IsNoRows(err) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if !slices.Contains(r.Accounts, c.Account) {
			return ErrNotFound
		}
		out = r
		_, err = audit.Record(ctx, tx, audit.Event{Name: "data.deletion_record_read", Actor: evdomain.Actor{Type: "account", ID: c.Account.String()}, Outcome: audit.Success, Object: &audit.Object{Type: "org", ID: org.String()}})
		return err
	})
	return out, err
}
