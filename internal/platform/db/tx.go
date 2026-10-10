// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package db

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// DBTX is the query interface shared by TenantTx and GlobalTx; sqlc-generated
// queries accept it.
type DBTX interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// queryTx exposes only the query methods of a transaction: callbacks cannot
// commit, roll back or change the tenant mid-transaction.
type queryTx struct{ tx pgx.Tx }

// Exec executes a statement.
func (q queryTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return q.tx.Exec(ctx, sql, args...)
}

// Query runs a query returning rows.
func (q queryTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return q.tx.Query(ctx, sql, args...)
}

// QueryRow runs a query returning at most one row.
func (q queryTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return q.tx.QueryRow(ctx, sql, args...)
}

// Pgx returns the underlying transaction for infrastructure that requires a
// pgx.Tx (River InsertTx). Never commit or roll it back.
func (q queryTx) Pgx() pgx.Tx { return q.tx }

// TenantTx is a transaction whose tenant context is set to one org.
type TenantTx struct {
	queryTx
	org ids.OrgID
}

// OrgID returns the tenant the transaction is scoped to.
func (t TenantTx) OrgID() ids.OrgID { return t.org }

// GlobalTx is a transaction without tenant context: tenant tables return no
// rows. It is only for global tables (licence state, jobs) and the audited
// cross-org lister.
type GlobalTx struct {
	queryTx
	purpose GlobalPurpose
}

// Purpose returns why the global transaction was opened.
func (g GlobalTx) Purpose() GlobalPurpose { return g.purpose }

// GlobalPurpose names the few reasons code may work outside a tenant.
type GlobalPurpose string

// Registered global purposes ("InGlobalTx (restricted)", BUILD_GUIDE §8 M1).
const (
	GlobalLicence      GlobalPurpose = "licence"        // licence_state (global table)
	GlobalJobs         GlobalPurpose = "jobs"           // River tables
	GlobalCrossOrgList GlobalPurpose = "cross_org_list" // pc.cross_org_list only
	GlobalHealth       GlobalPurpose = "health"         // readiness probes
)

var globalPurposes = []GlobalPurpose{GlobalLicence, GlobalJobs, GlobalCrossOrgList, GlobalHealth}

// TxOption customizes a transaction.
type TxOption func(*pgx.TxOptions)

// Serializable runs the transaction at SERIALIZABLE isolation.
func Serializable() TxOption {
	return func(o *pgx.TxOptions) { o.IsoLevel = pgx.Serializable }
}

// RepeatableRead runs the transaction at REPEATABLE READ isolation: every
// statement sees the snapshot taken by its first one.
func RepeatableRead() TxOption {
	return func(o *pgx.TxOptions) { o.IsoLevel = pgx.RepeatableRead }
}

// ReadOnly marks the transaction read-only.
func ReadOnly() TxOption {
	return func(o *pgx.TxOptions) { o.AccessMode = pgx.ReadOnly }
}

// ErrNoTenant reports InTenantTx called without an org.
var ErrNoTenant = pcerr.New(pcerr.Internal, "NO_TENANT", "tenant context missing")

// InTenantTx runs fn in a transaction scoped to org. The tenant is set with
// set_config('app.org_id', $1, true) as the first statement, so it is
// transaction-local and cleared on commit or rollback (HR-051). fn's error
// rolls the transaction back.
func (p *Pool) InTenantTx(ctx context.Context, org ids.OrgID, fn func(context.Context, TenantTx) error, opts ...TxOption) error {
	if org.IsZero() {
		return ErrNoTenant
	}
	return pgx.BeginTxFunc(ctx, p.pool, txOptions(opts), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT set_config('app.org_id', $1::text, true)", org.String()); err != nil {
			return fmt.Errorf("db: set tenant: %w", err)
		}
		return fn(ctx, TenantTx{queryTx: queryTx{tx: tx}, org: org})
	})
}

// InGlobalTx runs fn in a transaction without tenant context. The tenant
// setting is explicitly cleared so tenant tables match nothing.
func (p *Pool) InGlobalTx(ctx context.Context, purpose GlobalPurpose, fn func(context.Context, GlobalTx) error, opts ...TxOption) error {
	if !slices.Contains(globalPurposes, purpose) {
		return fmt.Errorf("db: unregistered global purpose %q", purpose)
	}
	return pgx.BeginTxFunc(ctx, p.pool, txOptions(opts), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT set_config('app.org_id', '', true)"); err != nil {
			return fmt.Errorf("db: clear tenant: %w", err)
		}
		return fn(ctx, GlobalTx{queryTx: queryTx{tx: tx}, purpose: purpose})
	})
}

func txOptions(opts []TxOption) pgx.TxOptions {
	o := pgx.TxOptions{IsoLevel: pgx.ReadCommitted}
	for _, f := range opts {
		f(&o)
	}
	return o
}

// ErrLostRace reports a conditional update that matched no row: another
// transaction changed the state first (HR-004). Callers re-read and decide;
// they never assume success.
var ErrLostRace = pcerr.New(pcerr.Aborted, "LOST_RACE", "the record changed concurrently")

// ExpectOneRow checks the result of a conditional state transition
// (`UPDATE … WHERE id = $1 AND state = $expected`). Zero rows is a lost race;
// more than one row is a bug and fails closed.
func ExpectOneRow(tag pgconn.CommandTag, err error) error {
	if err != nil {
		return err
	}
	switch n := tag.RowsAffected(); n {
	case 1:
		return nil
	case 0:
		return ErrLostRace
	default:
		return pcerr.Wrap(fmt.Errorf("conditional update touched %d rows", n), pcerr.Internal, "TRANSITION_FANOUT", "internal error")
	}
}

// OrgRef is one (org, id) pair returned by the cross-org lister.
type OrgRef struct {
	Org ids.OrgID
	ID  ids.UUID
}

// ListerPurpose selects one of the static queries of pc.cross_org_list.
type ListerPurpose string

// Lister purposes (extended by later migrations).
const (
	ListActiveOrgs      ListerPurpose = "orgs"
	ListLedgerUnchained ListerPurpose = "ledger_unchained" // orgs with entries above their chain watermark
	// ListVerificationsDue lists orgs with verification tasks past their
	// deadline or with expired leases (G0 M7, HR-190).
	ListVerificationsDue ListerPurpose = "verifications_due"
	// ListCheckpointsDue lists orgs whose chain grew past their latest
	// checkpoint and whose checkpointing has not stopped (G0 M7, HR-194).
	ListCheckpointsDue ListerPurpose = "checkpoints_due"
	// ListIntegrityDue lists orgs with a checkpoint whose chain was not
	// re-verified in the last day (HR-194).
	ListIntegrityDue ListerPurpose = "integrity_due"
)

// CrossOrgList calls the single audited cross-org lister (HR-053, HR-054).
// Callers must then process each org in its own InTenantTx.
func (p *Pool) CrossOrgList(ctx context.Context, purpose ListerPurpose, maxRows int) ([]OrgRef, error) {
	var out []OrgRef
	err := p.InGlobalTx(ctx, GlobalCrossOrgList, func(ctx context.Context, tx GlobalTx) error {
		rows, err := tx.Query(ctx, "SELECT org_id, id FROM pc.cross_org_list($1, $2)", string(purpose), maxRows)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var ref OrgRef
			if err := rows.Scan(&ref.Org, &ref.ID); err != nil {
				return err
			}
			out = append(out, ref)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("db: cross-org list %q: %w", purpose, err)
	}
	return out, nil
}

// IsUniqueViolation reports a unique-constraint violation.
func IsUniqueViolation(err error) bool { return hasCode(err, "23505") }

// IsPermissionDenied reports SQLSTATE 42501 (insufficient_privilege), which
// PostgreSQL also uses for row-level-security WITH CHECK violations.
func IsPermissionDenied(err error) bool { return hasCode(err, "42501") }

// IsDeadlock reports SQLSTATE 40P01 (deadlock_detected). Code that locks rows
// in one fixed order never sees it; tests use it to prove that.
func IsDeadlock(err error) bool { return hasCode(err, "40P01") }

func hasCode(err error, code string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == code
}
