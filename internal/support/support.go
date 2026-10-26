// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package support is customer-approved support access (G0 M13 D32, D38;
// ADR-0034; HR-385..388; Enterprise, hosted servers only).
//
// Support staff are users of the operator's staff org (support.staff_org)
// whose linked hosted account is on the staff list (support.staff_accounts,
// issuer and subject). From their own browser session in the staff org,
// after a security-key step-up of at most five minutes, they ask a customer
// org for read-only access for a named task and at most 72 hours. The
// request is recorded in the customer org, audited there, and its org
// admins are notified. An org admin approves or denies it on its page with
// a step-up of their own, and never one whose linked account asked
// (HR-386). Approval creates the request's one grant; any admin revokes it
// at any time. Staff then open a support session under the grant (again
// after a step-up): a browser session of principal kind support, holding
// only the internal support roles of the grant's scope (HR-387). Only an
// approved, unexpired, unrevoked grant authenticates (HR-385), and every
// call in a support session is recorded in the org's audit ledger with the
// staff member's account and the grant (HR-388).
package support

import (
	"context"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Limits (D32, D38).
const (
	MaxTaskRunes  = 200
	MaxHours      = 72
	PendingFor    = 7 * 24 * time.Hour
	SessionIdle   = 30 * time.Minute
	SessionMaxAge = 12 * time.Hour
)

// Errors.
var (
	ErrOff = pcerr.New(pcerr.FailedPrecondition, "SUPPORT_ACCESS_OFF", "support access is not configured on this server")
	// ErrNeedsHosted: self-hosted servers take their entitlements from the
	// licence; support access is for hosted organizations (D32).
	ErrNeedsHosted = pcerr.New(pcerr.FailedPrecondition, "SUPPORT_NEEDS_HOSTED",
		"support access is for hosted organizations; a self-hosted server never grants it")
	ErrNotStaff = pcerr.New(pcerr.PermissionDenied, "NOT_SUPPORT_STAFF", "only the support staff may do this")
	ErrEdition  = pcerr.New(pcerr.PermissionDenied, "EDITION_REQUIRED", "support access needs the Enterprise edition")
	ErrInvalid  = pcerr.New(pcerr.InvalidArgument, "INVALID_SUPPORT_REQUEST",
		"a support request needs a task of 1 to 200 characters of plain text, a scope and 1 to 72 hours")
	ErrOrgNotFound     = pcerr.New(pcerr.NotFound, "ORG_NOT_FOUND", "organization not found")
	ErrRequestNotFound = pcerr.New(pcerr.NotFound, "SUPPORT_REQUEST_NOT_FOUND", "support request not found")
	ErrGrantNotFound   = pcerr.New(pcerr.NotFound, "SUPPORT_GRANT_NOT_FOUND", "support grant not found")
	ErrNotPending      = pcerr.New(pcerr.FailedPrecondition, "SUPPORT_REQUEST_NOT_PENDING",
		"the support request was already decided or has expired")
	// ErrSelfApproval: the deciding person's account asked (HR-386).
	ErrSelfApproval = pcerr.New(pcerr.PermissionDenied, "SELF_APPROVAL", "nobody decides their own support request")
	ErrNoGrant      = pcerr.New(pcerr.FailedPrecondition, "NO_SUPPORT_GRANT",
		"there is no approved, unexpired, unrevoked grant for this request")
	ErrHuman = pcerr.New(pcerr.PermissionDenied, "PERSON_REQUIRED", "only a person may decide a support request")
	// ErrNotSupportSession: the caller is not a support session.
	ErrNotSupportSession = pcerr.New(pcerr.FailedPrecondition, "NOT_A_SUPPORT_SESSION", "this is not a support session")
	// ErrUnauthenticated: a support session cookie that does not
	// authenticate; the reason is logged only.
	ErrUnauthenticated = pcerr.New(pcerr.Unauthenticated, "UNAUTHENTICATED", "authentication required")
)

// Identity is a hosted account's identity on the staff list.
type Identity struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

// Config is the support staff configuration (support.*).
type Config struct {
	// StaffOrg is the operator's staff org; zero turns support access off.
	StaffOrg ids.OrgID
	// Staff are the accounts of the support staff; empty turns it off.
	Staff []Identity
}

// Enabled reports whether support access is configured.
func (c Config) Enabled() bool { return !c.StaffOrg.IsZero() && len(c.Staff) > 0 }

func (c Config) listed(issuer, subject string) bool {
	return slices.Contains(c.Staff, Identity{Issuer: issuer, Subject: subject})
}

// Plans resolves org plans (entitlements.Service).
type Plans interface {
	Mode() entitlements.Mode
	For(ctx context.Context, org ids.OrgID) (billing.Entitlements, error)
}

// Notifier enqueues notifications in a transaction (notifications.Service).
type Notifier interface {
	Enqueue(ctx context.Context, tx db.TenantTx, m napp.Message) (napp.Enqueued, error)
}

// Service is the support access use cases.
type Service struct {
	pool   *db.Pool
	cfg    Config
	plans  Plans
	notify Notifier
	clock  clock.Clock
	log    *slog.Logger
}

// New returns the service. notify may be nil (no notifications).
func New(pool *db.Pool, cfg Config, plans Plans, notify Notifier, log *slog.Logger) *Service {
	if log == nil {
		log = pclog.Discard()
	}
	return &Service{pool: pool, cfg: cfg, plans: plans, notify: notify, clock: clock.System{}, log: log}
}

// Enabled reports whether support access is configured.
func (s *Service) Enabled() bool { return s != nil && s.cfg.Enabled() }

// StaffOrg is the staff org.
func (s *Service) StaffOrg() ids.OrgID { return s.cfg.StaffOrg }

// available refuses unless support access is on, the server is hosted,
// and org's plan is Enterprise.
func (s *Service) available(ctx context.Context, org ids.OrgID) error {
	if !s.Enabled() {
		return ErrOff
	}
	if s.plans == nil || s.plans.Mode() == entitlements.ModeLicence {
		return ErrNeedsHosted
	}
	e, err := s.plans.For(ctx, org)
	if err != nil {
		return err
	}
	if e.Edition != billing.Enterprise {
		return ErrEdition
	}
	return nil
}

// Staff is a staff member's browser session in the staff org with its
// last step-up, as the page saw it.
type Staff struct {
	Caller tapp.Caller
	StepUp *stepup.StepUp
	// UserAgent and IP are what the server observed (untrusted).
	UserAgent, IP string
}

// staffMember is a verified member of the support staff.
type staffMember struct {
	Account          ids.UUID
	Issuer, Subject  string
	Email, Name      string
	User, Credential ids.UUID
	StaffOrg         ids.OrgID
}

// IsStaff reports whether c is a member of the support staff (a person of
// the staff org whose linked account is listed), without a step-up: the
// API answers STEP_UP_REQUIRED to them and PERMISSION_DENIED to others.
func (s *Service) IsStaff(ctx context.Context, c tapp.Caller) (bool, error) {
	if !s.Enabled() || c.Org != s.cfg.StaffOrg || !c.Human() {
		return false, nil
	}
	ok := false
	err := s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		u, err := dbq.New(tx).UserIdentityForSupport(ctx, c.Org, c.Principal.ID)
		if db.IsNoRows(err) {
			return nil
		} else if err != nil {
			return err
		}
		ok = td.AccountState(u.State) == td.Enabled && u.AccountID != nil && s.cfg.listed(u.Issuer, u.Subject)
		return nil
	}, db.ReadOnly())
	return ok, err
}

// staff verifies a staff member and their step-up (D38): a person of the
// staff org, enabled, linked to a listed account, whose browser session
// stepped up within five minutes with one of their own active keys.
func (s *Service) staff(ctx context.Context, st Staff) (staffMember, error) {
	if !s.Enabled() {
		return staffMember{}, ErrOff
	}
	c := st.Caller
	if c.Org != s.cfg.StaffOrg || !c.Human() || c.Credential != tapp.CredBrowserSession {
		return staffMember{}, ErrNotStaff
	}
	var out staffMember
	err := s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		u, err := q.UserIdentityForSupport(ctx, c.Org, c.Principal.ID)
		if db.IsNoRows(err) {
			return ErrNotStaff
		} else if err != nil {
			return err
		}
		if td.AccountState(u.State) != td.Enabled || u.AccountID == nil || !s.cfg.listed(u.Issuer, u.Subject) {
			return ErrNotStaff
		}
		if st.StepUp == nil {
			return stepup.ErrStepUp
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		if err := stepup.Check(ctx, tx, c, *st.StepUp, now); err != nil {
			return err
		}
		out = staffMember{
			Account: *u.AccountID, Issuer: u.Issuer, Subject: u.Subject, Email: u.Email, Name: u.DisplayName,
			User: u.ID, Credential: st.StepUp.Credential, StaffOrg: c.Org,
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// RequestInput is a staff member's request.
type RequestInput struct {
	Org   ids.OrgID
	Task  string
	Scope string
	Hours int
}

// cleanTask trims a task and checks it is 1..200 characters of plain text.
func cleanTask(t string) (string, bool) {
	t = strings.TrimSpace(t)
	if t == "" || !utf8.ValidString(t) || utf8.RuneCountInString(t) > MaxTaskRunes {
		return "", false
	}
	for _, r := range t {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029 {
			return "", false
		}
	}
	return t, true
}

// Request records a staff member's request in the customer org, audits
// it there and notifies its org admins.
func (s *Service) Request(ctx context.Context, st Staff, in RequestInput) (Request, error) {
	if in.Scope == "" {
		in.Scope = tapp.SupportScopeReadOnly
	}
	task, ok := cleanTask(in.Task)
	switch {
	case !ok, in.Scope != tapp.SupportScopeReadOnly && in.Scope != tapp.SupportScopeReadPlusEvidence,
		in.Hours < 1 || in.Hours > MaxHours, in.Org.IsZero(), in.Org == ids.PlatformOrg:
		return Request{}, ErrInvalid
	}
	m, err := s.staff(ctx, st)
	if err != nil {
		return Request{}, err
	}
	if in.Org == m.StaffOrg {
		return Request{}, ErrInvalid
	}
	if err := s.available(ctx, in.Org); err != nil {
		return Request{}, err
	}
	var out Request
	err = s.pool.InTenantTx(ctx, in.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if state, err := q.OrgState(ctx, in.Org); db.IsNoRows(err) || (err == nil && state != "ACTIVE") {
			return ErrOrgNotFound
		} else if err != nil {
			return err
		}
		r, err := q.InsertSupportRequest(ctx, dbq.InsertSupportRequestParams{
			OrgID: in.Org, ID: ids.NewV7(), RequesterAccount: m.Account, RequesterIssuer: m.Issuer,
			RequesterSubject: m.Subject, RequesterEmail: trim(m.Email, 320), RequesterName: trim(m.Name, 200),
			StaffOrg: m.StaffOrg.UUID(), StaffUser: m.User, StaffCredential: m.Credential, Task: task, Scope: in.Scope,
			DurationHours: int32(in.Hours), PendingSeconds: int32(PendingFor / time.Second), //nolint:gosec // G115: 1..72
		})
		if err != nil {
			return err
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "support.access_requested", Actor: staffActor(m.Account), Outcome: audit.Success,
			Object: &audit.Object{Type: "support_request", ID: r.ID.String()},
			Details: map[string]string{
				"task": task, "scope": in.Scope, "hours": strconv.Itoa(in.Hours), "staff_org": m.StaffOrg.String(),
				"staff_user": m.User.String(), "webauthn_key": m.Credential.String(),
			},
		}); err != nil {
			return err
		}
		staffName := m.Email
		if staffName == "" {
			staffName = "A staff member"
		}
		if err := s.tellAdmins(ctx, tx, q, in.Org, "support.access_requested", map[string]string{
			"request": r.ID.String(), "staff": trim(staffName, 200), "scope": in.Scope, "hours": strconv.Itoa(in.Hours),
			"expires": r.ExpiresAt.UTC().Format(time.RFC3339),
		}); err != nil {
			return err
		}
		out = requestOf(r, false, nil)
		return nil
	})
	return out, err
}

// staffActor is a support staff member's audit actor (D32:
// support/<account id>).
func staffActor(account ids.UUID) evdomain.Actor {
	return evdomain.Actor{Type: string(td.KindSupport), ID: account.String()}
}

// tellAdmins notifies the org's admins.
func (s *Service) tellAdmins(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, typ string, params map[string]string) error {
	if s.notify == nil {
		return nil
	}
	admins, err := q.OrgUsersWithRoles(ctx, org, []string{string(td.RoleOrgAdmin)})
	if err != nil {
		return err
	}
	_, err = s.notify.Enqueue(ctx, tx, napp.Message{Org: org, Type: typ, Params: params, Personal: admins})
	return err
}

func trim(s string, n int) string {
	for len(s) > n || !utf8.ValidString(s) {
		s = s[:min(len(s), n)]
		for !utf8.ValidString(s) && s != "" {
			s = s[:len(s)-1]
		}
	}
	return s
}

// caller returns the caller holding perm at the org.
func caller(ctx context.Context, perm td.Permission) (tapp.Caller, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return tapp.Caller{}, err
	}
	return c, c.Require(perm, td.OrgPath(c.Org))
}

// Decide approves or denies a pending request (HR-386): a person holding
// support.manage, with a fresh step-up of one of their own keys (su is nil
// over the API, which refuses), whose linked account did not ask.
func (s *Service) Decide(ctx context.Context, id ids.UUID, approve bool, su *stepup.StepUp) (Request, *Grant, error) {
	c, err := caller(ctx, td.PermSupportManage)
	if err != nil {
		return Request{}, nil, err
	}
	if !c.Human() {
		return Request{}, nil, ErrHuman
	}
	if su == nil {
		return Request{}, nil, stepup.ErrStepUp
	}
	if approve {
		if err := s.available(ctx, c.Org); err != nil {
			return Request{}, nil, err
		}
	}
	var out Request
	var grant *Grant
	var refused error
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		if err := stepup.Check(ctx, tx, c, *su, now); err != nil {
			return err
		}
		r, err := q.LockSupportRequest(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrRequestNotFound
		} else if err != nil {
			return err
		}
		if r.State != "PENDING" || r.PastExpiry {
			return ErrNotPending
		}
		u, err := q.GetUser(ctx, c.Org, c.Principal.ID)
		if err != nil {
			return err
		}
		if u.AccountID != nil && *u.AccountID == r.RequesterAccount {
			// Recorded, then refused (T-174).
			refused = ErrSelfApproval
			_, err := audit.Record(ctx, tx, audit.Event{
				Name: "support.self_decision_refused", Actor: c.Actor(), Outcome: audit.Denied, ReasonCode: "SELF_APPROVAL",
				Object: &audit.Object{Type: "support_request", ID: r.ID.String()},
			})
			return err
		}
		state, event := "DENIED", "support.access_denied"
		if approve {
			state, event = "APPROVED", "support.access_approved"
		}
		key := su.Credential
		n, err := q.DecideSupportRequest(ctx, dbq.DecideSupportRequestParams{
			State: state, DecidedBy: &c.Principal.ID, DecidedCredential: &key, OrgID: c.Org, ID: r.ID,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotPending
		}
		details := map[string]string{"webauthn_key": key.String(), "requester": r.RequesterAccount.String()}
		params := map[string]string{"request": r.ID.String()}
		var gid *ids.UUID
		if approve {
			g, err := q.InsertSupportGrant(ctx, dbq.InsertSupportGrantParams{
				OrgID: c.Org, ID: ids.NewV7(), RequestID: r.ID, AccountID: r.RequesterAccount, Scope: r.Scope,
				ApprovedBy: c.Principal.ID, ApprovedCredential: key, DurationHours: r.DurationHours,
			})
			if err != nil {
				return err
			}
			gid = &g.ID
			details["grant"], details["until"], details["scope"] = g.ID.String(), g.ExpiresAt.UTC().Format(time.RFC3339), g.Scope
			params["grant"], params["until"] = g.ID.String(), g.ExpiresAt.UTC().Format(time.RFC3339)
			v := grantOf(g, r.RequesterEmail, r.RequesterName, r.Task, 0, false)
			grant = &v
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: event, Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "support_request", ID: r.ID.String()}, Details: details,
		}); err != nil {
			return err
		}
		if err := s.tellAdmins(ctx, tx, q, c.Org, event, params); err != nil {
			return err
		}
		got, err := q.GetSupportRequest(ctx, c.Org, r.ID)
		if err != nil {
			return err
		}
		out = requestOf(requestRow(got), got.Expired, gid)
		return nil
	})
	if err == nil {
		err = refused
	}
	if err != nil {
		return Request{}, nil, err
	}
	return out, grant, nil
}

// Revoke ends a grant now and every support session under it. Revoking
// only removes access: no step-up, and any holder of support.manage may.
func (s *Service) Revoke(ctx context.Context, id ids.UUID) (Grant, error) {
	c, err := caller(ctx, td.PermSupportManage)
	if err != nil {
		return Grant{}, err
	}
	var out Grant
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		g, err := q.GetSupportGrant(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrGrantNotFound
		} else if err != nil {
			return err
		}
		if g.RevokedAt == nil {
			typ, actor := string(c.Principal.Kind), c.Principal.ID.String()
			if _, err := q.RevokeSupportGrant(ctx, dbq.RevokeSupportGrantParams{
				RevokedByType: &typ, RevokedByID: &actor, OrgID: c.Org, ID: id,
			}); err != nil {
				return err
			}
			reason := "REVOKED"
			ended, err := q.EndSupportSessionsOfGrant(ctx, &reason, c.Org, id)
			if err != nil {
				return err
			}
			if _, err := audit.Record(ctx, tx, audit.Event{
				Name: "support.grant_revoked", Actor: c.Actor(), Outcome: audit.Success,
				Object:  &audit.Object{Type: "support_grant", ID: id.String()},
				Details: map[string]string{"sessions_ended": strconv.FormatInt(ended, 10), "staff": g.AccountID.String()},
			}); err != nil {
				return err
			}
			if err := s.tellAdmins(ctx, tx, q, c.Org, "support.grant_revoked", map[string]string{"grant": id.String()}); err != nil {
				return err
			}
			if g, err = q.GetSupportGrant(ctx, c.Org, id); err != nil {
				return err
			}
		}
		out = grantOf(grantRow(g), g.RequesterEmail, g.RequesterName, g.Task, g.SessionsOpened, g.Expired)
		return nil
	})
	return out, err
}
