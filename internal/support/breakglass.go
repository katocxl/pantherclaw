// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package support

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

var (
	ErrBreakGlassEdition  = pcerr.New(pcerr.PermissionDenied, "EDITION_REQUIRED", "break-glass needs Business or Enterprise")
	ErrDesignation        = pcerr.New(pcerr.InvalidArgument, "INVALID_BREAKGLASS_HOLDERS", "designate at most three distinct active members with an organization role other than org admin")
	ErrNotHolder          = pcerr.New(pcerr.PermissionDenied, "NOT_BREAKGLASS_HOLDER", "only a designated break-glass holder can activate")
	ErrActivation         = pcerr.New(pcerr.InvalidArgument, "INVALID_BREAKGLASS_ACTIVATION", "a plain-text reason of 1 to 500 characters and 1 to 60 minutes are required")
	ErrAlreadyActive      = pcerr.New(pcerr.FailedPrecondition, "BREAKGLASS_ACTIVE", "break-glass is already active")
	ErrActivationNotFound = pcerr.New(pcerr.NotFound, "BREAKGLASS_NOT_FOUND", "break-glass activation not found")
)

// Designation pre-designates a member's emergency role (D33).
type Designation struct {
	User ids.UUID
	Role td.RoleName
}

// Holder is an organization's pre-designated holder.
type Holder struct {
	User, DesignatedBy ids.UUID
	Role               td.RoleName
	DesignatedAt       time.Time
}

// Activation is separately audited emergency access, bounded to an hour.
type Activation struct {
	ID, User             ids.UUID
	Role                 td.RoleName
	Reason               string
	StartedAt, ExpiresAt time.Time
	EndedAt              *time.Time
	EndedBy              string
	Active               bool
}

func holderOf(h dbq.PcBreakglassHolder) Holder {
	return Holder{User: h.UserID, Role: td.RoleName(h.Role), DesignatedBy: h.DesignatedBy, DesignatedAt: h.DesignatedAt}
}

func activationOf(a dbq.PcBreakglassActivation, active bool) Activation {
	out := Activation{
		ID: a.ID, User: a.UserID, Role: td.RoleName(a.Role), Reason: a.Reason,
		StartedAt: a.StartedAt, ExpiresAt: a.ExpiresAt, EndedAt: a.EndedAt, Active: active,
	}
	if a.EndedByType != nil && a.EndedByID != nil {
		out.EndedBy = *a.EndedByType + ":" + *a.EndedByID
	}
	return out
}

func (s *Service) breakGlassAvailable(ctx context.Context, org ids.OrgID) error {
	if s == nil || s.plans == nil {
		return ErrBreakGlassEdition
	}
	e, err := s.plans.For(ctx, org)
	if err != nil {
		return err
	}
	if e.Edition != billing.Business && e.Edition != billing.Enterprise {
		return ErrBreakGlassEdition
	}
	return nil
}

// ListHolders lists the pre-designated members in the caller's org.
func (s *Service) ListHolders(ctx context.Context) ([]Holder, error) {
	c, err := caller(ctx, td.PermBreakGlassRead)
	if err != nil {
		return nil, err
	}
	var out []Holder
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListBreakGlassHolders(ctx, c.Org)
		for _, r := range rows {
			out = append(out, holderOf(r))
		}
		return err
	}, db.ReadOnly())
	return out, err
}

// SetHolders atomically replaces the holders; removing or changing a
// holder's role ends their activation in the same audited transaction.
func (s *Service) SetHolders(ctx context.Context, in []Designation) ([]Holder, error) {
	c, err := caller(ctx, td.PermBreakGlassManage)
	if err != nil {
		return nil, err
	}
	if !c.Human() {
		return nil, ErrHuman
	}
	if err := s.breakGlassAvailable(ctx, c.Org); err != nil {
		return nil, err
	}
	if len(in) > 3 {
		return nil, ErrDesignation
	}
	want := make(map[ids.UUID]td.RoleName, len(in))
	for _, h := range in {
		if h.User.IsZero() || !td.BreakGlassRoleAllowed(h.Role) {
			return nil, ErrDesignation
		}
		if _, exists := want[h.User]; exists {
			return nil, ErrDesignation
		}
		want[h.User] = h.Role
	}
	var out []Holder
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.LockOrgAdmins(ctx, c.Org); err != nil {
			return err
		}
		old, err := q.ListBreakGlassHolders(ctx, c.Org)
		if err != nil {
			return err
		}
		for _, h := range old {
			if want[h.UserID] == td.RoleName(h.Role) {
				continue
			}
			if err := s.endHolder(ctx, tx, c, h.UserID); err != nil {
				return err
			}
			if _, err := q.DeleteBreakGlassHolder(ctx, c.Org, h.UserID); err != nil {
				return err
			}
		}
		for _, h := range in {
			active, err := q.UserActiveInOrg(ctx, c.Org, h.User)
			if db.IsNoRows(err) || (err == nil && !active) {
				return ErrDesignation
			}
			if err != nil {
				return err
			}
			if err := q.PutBreakGlassHolder(ctx, dbq.PutBreakGlassHolderParams{OrgID: c.Org, UserID: h.User, Role: string(h.Role), DesignatedBy: c.Principal.ID}); err != nil {
				return err
			}
		}
		if _, err := audit.Record(ctx, tx, audit.Event{Name: "breakglass.holders_changed", Actor: c.Actor(), Outcome: audit.Success}); err != nil {
			return err
		}
		rows, err := q.ListBreakGlassHolders(ctx, c.Org)
		for _, r := range rows {
			out = append(out, holderOf(r))
		}
		return err
	})
	return out, err
}

func (s *Service) endHolder(ctx context.Context, tx db.TenantTx, c tapp.Caller, user ids.UUID) error {
	typ, id := string(c.Principal.Kind), c.Principal.ID.String()
	reason := "HOLDER_REMOVED"
	ended, err := dbq.New(tx).EndBreakGlassOfUser(ctx, dbq.EndBreakGlassOfUserParams{
		OrgID: c.Org, UserID: user, EndReason: &reason, EndedByType: &typ, EndedByID: &id,
	})
	if err != nil {
		return err
	}
	for _, a := range ended {
		if err := endedAudit(ctx, tx, c.Actor(), a, "HOLDER_REMOVED"); err != nil {
			return err
		}
	}
	return nil
}

func cleanReason(reason string) (string, bool) {
	reason = strings.TrimSpace(reason)
	if reason == "" || !utf8.ValidString(reason) || utf8.RuneCountInString(reason) > 500 {
		return "", false
	}
	for _, r := range reason {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029 {
			return "", false
		}
	}
	return reason, true
}

// ActivateBreakGlass needs the holder's own browser session and recent
// security key. It adds only the pre-designated role, never an exemption.
func (s *Service) ActivateBreakGlass(ctx context.Context, reason string, minutes int, su *stepup.StepUp) (Activation, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return Activation{}, err
	}
	if !c.Human() || c.Credential != tapp.CredBrowserSession {
		return Activation{}, ErrNotHolder
	}
	if err := s.breakGlassAvailable(ctx, c.Org); err != nil {
		return Activation{}, err
	}
	if minutes == 0 {
		minutes = 60
	}
	reason, ok := cleanReason(reason)
	if !ok || minutes < 1 || minutes > 60 {
		return Activation{}, ErrActivation
	}
	var out Activation
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.LockOrgAdmins(ctx, c.Org); err != nil {
			return err
		}
		h, err := q.GetBreakGlassHolder(ctx, c.Org, c.Principal.ID)
		if db.IsNoRows(err) {
			return ErrNotHolder
		}
		if err != nil {
			return err
		}
		active, err := q.UserActiveInOrg(ctx, c.Org, c.Principal.ID)
		if err != nil {
			return err
		}
		if !active || !td.BreakGlassRoleAllowed(td.RoleName(h.Role)) {
			return ErrNotHolder
		}
		if su == nil {
			return stepup.ErrStepUp
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		if err := stepup.Check(ctx, tx, c, *su, now); err != nil {
			return err
		}
		if err := expireBreakGlass(ctx, tx); err != nil {
			return err
		}
		if _, err := q.LiveBreakGlassOfUser(ctx, c.Org, c.Principal.ID); err == nil {
			return ErrAlreadyActive
		} else if !db.IsNoRows(err) {
			return err
		}
		a, err := q.InsertBreakGlassActivation(ctx, dbq.InsertBreakGlassActivationParams{
			OrgID: c.Org, ID: ids.NewV7(), UserID: c.Principal.ID, Role: h.Role, Reason: reason, Credential: su.Credential, Minutes: int32(minutes), //nolint:gosec // bounded above
		})
		if db.IsUniqueViolation(err) {
			return ErrAlreadyActive
		}
		if err != nil {
			return err
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "breakglass.activated", Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "breakglass_activation", ID: a.ID.String()}, Details: map[string]string{"role": h.Role, "reason": trim(reason, 512), "until": a.ExpiresAt.UTC().Format(time.RFC3339), "webauthn_key": su.Credential.String()},
		}); err != nil {
			return err
		}
		if s.notify != nil {
			admins, err := q.OrgUsersWithRoles(ctx, c.Org, []string{string(td.RoleOrgAdmin)})
			if err != nil {
				return err
			}
			others := admins[:0]
			for _, u := range admins {
				if u != c.Principal.ID {
					others = append(others, u)
				}
			}
			if len(others) > 0 {
				if _, err := s.notify.Enqueue(ctx, tx, napp.Message{
					Org: c.Org, Type: "breakglass.activated", Personal: others,
					Params: map[string]string{"activation": a.ID.String(), "user": c.Principal.ID.String(), "role": h.Role, "until": a.ExpiresAt.UTC().Format(time.RFC3339)},
				}); err != nil {
					return err
				}
			}
		}
		out = activationOf(a, true)
		return nil
	})
	return out, err
}

// MyBreakGlass describes the caller's designation and current activation.
func (s *Service) MyBreakGlass(ctx context.Context) (*Holder, *Activation, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return nil, nil, err
	}
	if !c.Human() {
		return nil, nil, nil
	}
	var holder *Holder
	var active *Activation
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		h, err := q.GetBreakGlassHolder(ctx, c.Org, c.Principal.ID)
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		v := holderOf(h)
		holder = &v
		a, err := q.LiveBreakGlassOfUser(ctx, c.Org, c.Principal.ID)
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		v2 := activationOf(a, true)
		active = &v2
		return nil
	}, db.ReadOnly())
	return holder, active, err
}

// EndBreakGlass permits the holder to end their own activation, or an org
// admin to end any activation in that org. Ending only removes authority.
func (s *Service) EndBreakGlass(ctx context.Context, id ids.UUID) (Activation, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return Activation{}, err
	}
	var out Activation
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.LockOrgAdmins(ctx, c.Org); err != nil {
			return err
		}
		a, err := q.GetBreakGlassActivation(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrActivationNotFound
		}
		if err != nil {
			return err
		}
		if !c.Can(td.PermBreakGlassManage, td.OrgPath(c.Org)) && (!c.Human() || a.UserID != c.Principal.ID) {
			return ErrActivationNotFound
		}
		if a.EndedAt == nil {
			typ, who := string(c.Principal.Kind), c.Principal.ID.String()
			reason := "ENDED"
			if _, err := q.EndBreakGlassActivation(ctx, dbq.EndBreakGlassActivationParams{OrgID: c.Org, ID: id, EndReason: &reason, EndedByType: &typ, EndedByID: &who}); err != nil {
				return err
			}
			if err := endedAudit(ctx, tx, c.Actor(), id, "ENDED"); err != nil {
				return err
			}
			a, err = q.GetBreakGlassActivation(ctx, c.Org, id)
			if err != nil {
				return err
			}
		}
		out = activationOf(activationRow(a), false)
		return nil
	})
	return out, err
}

func activationRow(a dbq.GetBreakGlassActivationRow) dbq.PcBreakglassActivation {
	return dbq.PcBreakglassActivation{
		OrgID: a.OrgID, ID: a.ID, UserID: a.UserID, Role: a.Role, Reason: a.Reason, Credential: a.Credential,
		StartedAt: a.StartedAt, ExpiresAt: a.ExpiresAt, EndedAt: a.EndedAt, EndReason: a.EndReason, EndedByType: a.EndedByType, EndedByID: a.EndedByID,
	}
}

// ActivationPage is a cursor page of the org's activations.
type ActivationPage struct {
	Items []Activation
	Next  string
}

func (s *Service) ListActivations(ctx context.Context, size int32, token string) (ActivationPage, error) {
	c, err := caller(ctx, td.PermBreakGlassRead)
	if err != nil {
		return ActivationPage{}, err
	}
	pr, err := page.Parse(size, token)
	if err != nil {
		return ActivationPage{}, err
	}
	var before *ids.UUID
	if !pr.After.IsZero() {
		before = &pr.After
	}
	var out ActivationPage
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListBreakGlassActivations(ctx, c.Org, before, pr.Limit())
		if err != nil {
			return err
		}
		rows, out.Next = page.Finish(pr, rows, func(a dbq.ListBreakGlassActivationsRow) ids.UUID { return a.ID })
		for _, a := range rows {
			out.Items = append(out.Items, activationOf(activationRow(dbq.GetBreakGlassActivationRow(a)), a.Active))
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// BreakGlassCall is called before permission checks for every user RPC
// and server page: injects only the designated role and audits the call
// before anything executes. Authenticated identities and normal approval,
// two-person and invariant checks stay unchanged (HR-389).
func (s *Service) BreakGlassCall(ctx context.Context, c tapp.Caller, procedure string) (tapp.Caller, error) {
	c.BreakGlassActivation = ids.UUID{}
	if !c.Human() {
		return c, nil
	}
	if err := s.breakGlassAvailable(ctx, c.Org); err != nil {
		if errors.Is(err, ErrBreakGlassEdition) {
			return c, nil
		}
		return tapp.Caller{}, err
	}
	err := s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		a, err := q.LiveBreakGlassOfUser(ctx, c.Org, c.Principal.ID)
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if !td.BreakGlassRoleAllowed(td.RoleName(a.Role)) {
			return nil
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "breakglass.call", Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "breakglass_activation", ID: a.ID.String()}, Details: map[string]string{"activation": a.ID.String(), "procedure": trim(procedure, 200)},
		}); err != nil {
			return err
		}
		c.Bindings = append(c.Bindings, td.Binding{Role: td.RoleName(a.Role), Scope: td.Scope{Type: td.ScopeOrg, ID: c.Org.UUID()}})
		c.BreakGlassActivation = a.ID
		return nil
	})
	return c, err
}
