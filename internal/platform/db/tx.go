// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package db

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/tenantctx"
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
	// GlobalAnchors is the anchoring job's pc.anchors (G0 M7 design decision
	// 12): the one global evidence table, blinded leaves and roots only.
	GlobalAnchors GlobalPurpose = "anchors"
	// GlobalAccounts is the hosted account tables (G0 UI D8, D41): sign-in
	// callbacks, account creation and account sessions. Those tables'
	// policies show their rows only in this purpose (app.purpose) or in
	// the account's own context (app.account_id).
	GlobalAccounts GlobalPurpose = "accounts"
)

var globalPurposes = []GlobalPurpose{GlobalLicence, GlobalJobs, GlobalCrossOrgList, GlobalHealth, GlobalAnchors, GlobalAccounts}

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
		if _, err := tx.Exec(ctx, tenantSetup, org.String()); err != nil {
			return fmt.Errorf("db: set tenant: %w", err)
		}
		// Entitlement lookups inside the transaction are for its org (G0 UI D9).
		return fn(tenantctx.WithOrg(ctx, org), TenantTx{queryTx: queryTx{tx: tx}, org: org})
	})
}

// InGlobalTx runs fn in a transaction without tenant context. The tenant
// setting is explicitly cleared so tenant tables match nothing.
func (p *Pool) InGlobalTx(ctx context.Context, purpose GlobalPurpose, fn func(context.Context, GlobalTx) error, opts ...TxOption) error {
	if !slices.Contains(globalPurposes, purpose) {
		return fmt.Errorf("db: unregistered global purpose %q", purpose)
	}
	return pgx.BeginTxFunc(ctx, p.pool, txOptions(opts), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, globalSetup, string(purpose)); err != nil {
			return fmt.Errorf("db: clear tenant: %w", err)
		}
		return fn(ctx, GlobalTx{queryTx: queryTx{tx: tx}, purpose: purpose})
	})
}

// The first statement of every transaction. A tenant transaction never has
// a global purpose or an account context (D41); a global one records its
// purpose, which the hosted account tables' policies read.
const (
	tenantSetup = "SELECT set_config('app.org_id', $1::text, true), set_config('app.purpose', '', true), " +
		"set_config('app.account_id', '', true)"
	globalSetup = "SELECT set_config('app.org_id', '', true), set_config('app.purpose', $1::text, true), " +
		"set_config('app.account_id', '', true)"
)

// ErrNoAccount reports an account context without an account.
var ErrNoAccount = pcerr.New(pcerr.Internal, "NO_ACCOUNT", "account context missing")

// SetAccountContext makes one hosted account's own rows visible for the
// rest of tx (D41: the account context, app.account_id). The server sets it
// only for that account's own actions, such as linking the account's user
// in an org.
func SetAccountContext(ctx context.Context, tx DBTX, account ids.UUID) error {
	if account.IsZero() {
		return ErrNoAccount
	}
	_, err := tx.Exec(ctx, "SELECT set_config('app.account_id', $1::text, true)", account.String())
	return err
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
	ListActiveOrgs ListerPurpose = "orgs"
	// ListAllOrgs lists every org whatever its state, for the post-restore
	// epoch bump (G0 M13 D6, HR-373).
	ListAllOrgs         ListerPurpose = "orgs_all"
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
	// ListAccountMemberships lists the (org, user) pairs of one hosted
	// account's active memberships (G0 UI D8, HR-349). It takes the account
	// as the ListerParams AccountID.
	ListAccountMemberships ListerPurpose = "account_memberships"
	// ListAccountUsers includes disabled users and organisations for deletion.
	ListAccountUsers ListerPurpose = "account_users"
	// ListBillingLink finds the (org, link) of one billing ref (G0 UI D37).
	// It takes the ref as the ListerParams Billing*.
	ListBillingLink ListerPurpose = "billing_link_lookup"
	// ListLapsedOrgs lists the active orgs whose hosted plan lapsed, for
	// the daily reminder and day-90 deletion job (G0 M13 D34, HR-393).
	ListLapsedOrgs ListerPurpose = "orgs_lapsed"
)

// ListerParams are the inputs of the parameterized lister purposes, set
// for the lister's transaction only and recorded in its audit row.
type ListerParams struct {
	AccountID                                ids.UUID
	BillingProvider, BillingKind, BillingRef string
}

func (lp ListerParams) settings() [][2]string {
	var out [][2]string
	if !lp.AccountID.IsZero() {
		out = append(out, [2]string{"app.account_id", lp.AccountID.String()})
	}
	if lp.BillingProvider != "" || lp.BillingKind != "" || lp.BillingRef != "" {
		out = append(out, [2]string{"app.billing_provider", lp.BillingProvider},
			[2]string{"app.billing_kind", lp.BillingKind}, [2]string{"app.billing_ref", lp.BillingRef})
	}
	return out
}

// CrossOrgListWith calls the audited cross-org lister for a parameterized
// purpose in its own global transaction.
func (p *Pool) CrossOrgListWith(ctx context.Context, purpose ListerPurpose, maxRows int, lp ListerParams) ([]OrgRef, error) {
	var out []OrgRef
	err := p.InGlobalTx(ctx, GlobalCrossOrgList, func(ctx context.Context, tx GlobalTx) error {
		var err error
		out, err = CrossOrgListIn(ctx, tx, purpose, maxRows, lp)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("db: cross-org list %q: %w", purpose, err)
	}
	return out, nil
}

// CrossOrgListIn calls the audited cross-org lister inside tx, for a writer
// that must check a cross-org uniqueness in the same transaction as its
// insert (G0 UI D37). The parameters stay set for the rest of tx.
func CrossOrgListIn(ctx context.Context, tx DBTX, purpose ListerPurpose, maxRows int, lp ListerParams) ([]OrgRef, error) {
	for _, s := range lp.settings() {
		if _, err := tx.Exec(ctx, "SELECT set_config($1::text, $2::text, true)", s[0], s[1]); err != nil {
			return nil, err
		}
	}
	rows, err := tx.Query(ctx, "SELECT org_id, id FROM pc.cross_org_list($1, $2)", string(purpose), maxRows)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OrgRef
	for rows.Next() {
		var ref OrgRef
		if err := rows.Scan(&ref.Org, &ref.ID); err != nil {
			return nil, err
		}
		out = append(out, ref)
	}
	return out, rows.Err()
}

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

// IsLockTimeout reports SQLSTATE 55P03 (lock_not_available): a lock wait
// reached lock_timeout.
func IsLockTimeout(err error) bool { return hasCode(err, "55P03") }

func hasCode(err error, code string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == code
}

// ErrTenantMismatch reports a transaction whose tenant context is not the
// org a caller expected.
var ErrTenantMismatch = pcerr.New(pcerr.Internal, "TENANT_MISMATCH", "tenant context mismatch")

// AdoptTenantTx returns the TenantTx of a pgx transaction InTenantTx began
// for org, for ports that pass a pgx.Tx across packages (the Reflex ports,
// G0 M10 D1). It checks the transaction's tenant setting first, so it never
// widens a transaction to another org or to none.
func AdoptTenantTx(ctx context.Context, tx pgx.Tx, org ids.OrgID) (TenantTx, error) {
	if org.IsZero() || tx == nil {
		return TenantTx{}, ErrNoTenant
	}
	var current string
	if err := tx.QueryRow(ctx, "SELECT coalesce(current_setting('app.org_id', true), '')").Scan(&current); err != nil {
		return TenantTx{}, fmt.Errorf("db: read tenant: %w", err)
	}
	if current != org.String() {
		return TenantTx{}, ErrTenantMismatch
	}
	return TenantTx{queryTx: queryTx{tx: tx}, org: org}, nil
}

// Savepoint runs fn inside a savepoint of t: when fn fails, everything it
// wrote is rolled back and t stays usable; when it succeeds, its writes
// stay in t. name is a fixed identifier chosen by the caller; it labels
// errors only. The savepoint itself is pgx's nested transaction, so no
// SQL is built from the name.
func (t TenantTx) Savepoint(ctx context.Context, name string, fn func() error) error {
	if !savepointName.MatchString(name) {
		return errors.New("db: invalid savepoint name")
	}
	sp, err := t.tx.Begin(ctx)
	if err != nil {
		return fmt.Errorf("db: savepoint %s: %w", name, err)
	}
	if err := fn(); err != nil {
		if rerr := sp.Rollback(ctx); rerr != nil {
			return errors.Join(err, fmt.Errorf("db: roll back savepoint %s: %w", name, rerr))
		}
		return err
	}
	if err := sp.Commit(ctx); err != nil {
		return fmt.Errorf("db: release savepoint %s: %w", name, err)
	}
	return nil
}

var savepointName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,40}$`)
