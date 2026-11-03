// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/idps"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/provisioning/domain"
	"github.com/katocxl/pantherclaw/internal/provisioning/ports"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// memberLimit checks the plan's member limit (HR-360) for one more active
// member: ErrPlanLimit when it is reached, any other error as it is.
func (s *Service) memberLimit(ctx context.Context, q *dbq.Queries, org ids.OrgID) error {
	err := tenancy.CheckMemberLimit(ctx, s.Editions, q, org)
	if errors.Is(err, billing.ErrLimitReached) {
		return ports.ErrPlanLimit
	}
	return err
}

// MaxPage bounds one page of a SCIM list.
const MaxPage = 100

// maxAttr bounds a userName, externalId or group name (the columns' bound).
const maxAttr = 256

// sessionReason is why deprovisioning ended a user's sessions.
const (
	cliReason     = "USER_DEPROVISIONED"
	browserReason = "REVOKED"
)

// token is a SCIM token as the core looked it up, in the core's types.
type token struct {
	org ids.OrgID
	id  ids.UUID
	// Issuer is the one issuer whose users and groups the token sees.
	Issuer string
	// SubjectAttribute is "userName" or "externalId" (HR-629).
	SubjectAttribute string
}

func (t token) actor() evdomain.Actor { return evdomain.Actor{Type: "scim_token", ID: t.id.String()} }

// lookUp finds an acting token by its bearer's hash: only an ACTIVE,
// unexpired token of an active org is one. A PENDING token, whose
// activation a second person has not approved, is unknown (D409).
func lookUp(ctx context.Context, q *dbq.Queries, cred credential.Token) (token, error) {
	row, err := q.SCIMTokenByHash(ctx, cred.Org(), cred.Hash())
	if db.IsNoRows(err) {
		return token{}, ports.ErrUnauthenticated
	} else if err != nil {
		return token{}, err
	}
	return token{org: cred.Org(), id: row.ID, Issuer: row.Issuer, SubjectAttribute: row.SubjectAttribute}, nil
}

func parseBearer(pt ports.Token) (credential.Token, error) {
	cred, err := credential.Parse(credential.SCIMToken, pt.Bearer())
	if err != nil {
		return credential.Token{}, ports.ErrUnauthenticated
	}
	return cred, nil
}

// Authenticate resolves a SCIM bearer token (HR-629) and records its use.
// The Token it returns is opaque: every later call looks the token up again
// (D528).
func (s *Service) Authenticate(ctx context.Context, bearer string) (ports.Token, error) {
	pt := ports.NewToken(bearer)
	cred, err := parseBearer(pt)
	if err != nil {
		return ports.Token{}, err
	}
	err = s.Pool.InTenantTx(ctx, cred.Org(), func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		t, err := lookUp(ctx, q, cred)
		if err != nil {
			return err
		}
		return q.TouchSCIMToken(ctx, t.org, t.id)
	})
	if err != nil {
		return ports.Token{}, err
	}
	return pt, nil
}

// inDir runs fn in a transaction of the token's org, with the token looked
// up again inside it: what it provisions is the core's to say, and a token
// revoked a moment ago does nothing (D528).
func (s *Service) inDir(ctx context.Context, pt ports.Token, fn func(ctx context.Context, tx db.TenantTx, q *dbq.Queries, t token) error, opts ...db.TxOption) error {
	cred, err := parseBearer(pt)
	if err != nil {
		return err
	}
	return s.Pool.InTenantTx(ctx, cred.Org(), func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		t, err := lookUp(ctx, q, cred)
		if err != nil {
			return err
		}
		return fn(ctx, tx, q, t)
	}, opts...)
}

// fullEdition reports whether the token's org may add through SCIM. It is
// called inside inDir: the transaction's context names the org, so the
// org's own plan decides, never the deployment's licence (D528).
func (s *Service) fullEdition(ctx context.Context) (bool, error) {
	err := s.entitledSCIM(ctx)
	if errors.Is(err, ports.ErrEdition) {
		return false, nil
	}
	return err == nil, err
}

// dropped records the parts of a request below Enterprise that were not
// applied: only its removals were (D528).
func (s *Service) dropped(ctx context.Context, tx db.TenantTx, t token, objType string, obj ids.UUID, parts []string) error {
	if len(parts) == 0 {
		return nil
	}
	return s.record(ctx, tx, t, "scim.parts_dropped", objType, obj, map[string]string{
		"parts": strings.Join(parts, ","), "reason": "EDITION_REQUIRED",
	})
}

func (s *Service) entitledSCIM(ctx context.Context) error {
	if err := s.entitled(ctx, scim); err != nil {
		if errors.Is(err, ErrEdition) {
			return ports.ErrEdition
		}
		return err
	}
	return nil
}

func clamp(p ports.Page) (offset, limit int32) {
	start, count := p.StartIndex, p.Count
	if start < 1 {
		start = 1
	}
	if count < 0 {
		count = 0
	}
	if count > MaxPage {
		count = MaxPage
	}
	if start > 1<<30 {
		start = 1 << 30
	}
	return int32(start - 1), int32(count)
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// attr checks a userName, externalId or group name: printable, bounded.
func attr(s string, required bool) error {
	if s == "" {
		if required {
			return ports.ErrInvalid
		}
		return nil
	}
	if len(s) > maxAttr || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return ports.ErrInvalid
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return ports.ErrInvalid
		}
	}
	return nil
}

// profile cleans what a provider says of a person, as a sign-in does.
func profile(email, name string) (string, string, error) {
	e := td.NormalizeEmail(td.SanitizeClaim(email, td.MaxEmailLen))
	if email != "" && e == "" {
		return "", "", ports.ErrInvalid
	}
	return e, td.SanitizeClaim(name, td.MaxNameLen), nil
}

// subjectOf is the identity a user signs in with: the token's subject
// attribute (HR-629).
func (t token) subjectOf(userName, externalID string) string {
	if t.SubjectAttribute == domain.SubjectExternalID {
		return externalID
	}
	return userName
}

func userOut(t token, id ids.UUID, subject, email, name, state string, userName, externalID *string, created, updated time.Time) ports.User {
	u := ports.User{
		ID: id.String(), Email: email, DisplayName: name, Active: state == string(td.Enabled),
		UserName: deref(userName), ExternalID: deref(externalID), CreatedAt: created, UpdatedAt: updated,
	}
	if t.SubjectAttribute == domain.SubjectExternalID {
		u.ExternalID = subject
		if u.UserName == "" {
			u.UserName = email
		}
	} else {
		u.UserName = subject
	}
	return u
}

func listedUser(t token, r dbq.ListDirectoryUsersRow) ports.User {
	return userOut(t, r.ID, r.Subject, r.Email, r.DisplayName, r.State, r.UserName, r.ExternalID, r.CreatedAt, r.UpdatedAt)
}

func lockedUser(t token, r dbq.LockDirectoryUserRow) ports.User {
	return userOut(t, r.ID, r.Subject, r.Email, r.DisplayName, r.State, r.UserName, r.ExternalID, r.CreatedAt, r.UpdatedAt)
}

// ListUsers lists the token issuer's users, filtered on one exact value.
func (s *Service) ListUsers(ctx context.Context, pt ports.Token, f ports.UserFilter, p ports.Page) (ports.Users, error) {
	var out ports.Users
	err := s.inDir(ctx, pt, func(ctx context.Context, _ db.TenantTx, q *dbq.Queries, t token) error {
		// userName matches without case (RFC 7643 4.1.1), externalId exactly.
		var subject, subjectCI, userName, externalID *string
		if t.SubjectAttribute == domain.SubjectExternalID {
			subject, userName = optional(f.ExternalID), optional(f.UserName)
		} else {
			subjectCI, externalID = optional(f.UserName), optional(f.ExternalID)
		}
		n, err := q.CountDirectoryUsers(ctx, dbq.CountDirectoryUsersParams{
			OrgID: t.org, Issuer: t.Issuer, Subject: subject, SubjectCi: subjectCI, UserName: userName, ExternalID: externalID,
		})
		if err != nil {
			return err
		}
		out.Total = int(n)
		offset, limit := clamp(p)
		if limit == 0 {
			return nil
		}
		rows, err := q.ListDirectoryUsers(ctx, dbq.ListDirectoryUsersParams{
			OrgID: t.org, Issuer: t.Issuer, Subject: subject, SubjectCi: subjectCI, UserName: userName, ExternalID: externalID,
			PageOffset: offset, PageLimit: limit,
		})
		if err != nil {
			return err
		}
		for _, r := range rows {
			out.Items = append(out.Items, listedUser(t, r))
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// lockUser locks a user of the token's issuer that SCIM has not deleted.
func lockUser(ctx context.Context, q *dbq.Queries, t token, id string) (dbq.LockDirectoryUserRow, error) {
	u, err := ids.ParseUUID(id)
	if err != nil {
		return dbq.LockDirectoryUserRow{}, ports.ErrNotFound
	}
	r, err := q.LockDirectoryUser(ctx, t.org, t.Issuer, u)
	if db.IsNoRows(err) || (err == nil && r.DeletedAt != nil) {
		return dbq.LockDirectoryUserRow{}, ports.ErrNotFound
	}
	return r, err
}

// GetUser returns one user of the token's issuer.
func (s *Service) GetUser(ctx context.Context, pt ports.Token, id string) (ports.User, error) {
	var out ports.User
	err := s.inDir(ctx, pt, func(ctx context.Context, _ db.TenantTx, q *dbq.Queries, t token) error {
		r, err := lockUser(ctx, q, t, id)
		if err != nil {
			return err
		}
		out = lockedUser(t, r)
		return nil
	})
	return out, err
}

// taken reports whether another user of the issuer has this userName or
// externalId (the one that is not the subject; pc.users keeps the subject
// unique).
func taken(ctx context.Context, q *dbq.Queries, t token, self ids.UUID, userName, externalID string) error {
	var arg dbq.CountDirectoryUsersParams
	switch {
	case t.SubjectAttribute == domain.SubjectExternalID && userName != "":
		arg = dbq.CountDirectoryUsersParams{OrgID: t.org, Issuer: t.Issuer, UserName: &userName}
	case t.SubjectAttribute == domain.SubjectUserName && externalID != "":
		arg = dbq.CountDirectoryUsersParams{OrgID: t.org, Issuer: t.Issuer, ExternalID: &externalID}
	default:
		return nil
	}
	rows, err := q.ListDirectoryUsers(ctx, dbq.ListDirectoryUsersParams{
		OrgID: arg.OrgID, Issuer: arg.Issuer, UserName: arg.UserName, ExternalID: arg.ExternalID, PageLimit: 2,
	})
	if err != nil {
		return err
	}
	for _, r := range rows {
		if r.ID != self {
			return ports.ErrConflict
		}
	}
	return nil
}

// CreateUser provisions a user of the token's issuer (F918). It needs the
// Enterprise edition and, when active, room under the plan's member limit.
// A user SCIM deleted comes back as the same user; any other user with the
// identity is a conflict.
func (s *Service) CreateUser(ctx context.Context, pt ports.Token, in ports.UserInput) (ports.User, error) {
	var out ports.User
	active := in.Active == nil || *in.Active
	err := s.inDir(ctx, pt, func(ctx context.Context, tx db.TenantTx, q *dbq.Queries, t token) error {
		if err := s.entitledSCIM(ctx); err != nil { // the org's plan: ctx names the org
			return err
		}
		if err := attr(in.UserName, true); err != nil {
			return err
		}
		if err := attr(in.ExternalID, t.SubjectAttribute == domain.SubjectExternalID); err != nil {
			return err
		}
		email, name, err := profile(in.Email, in.DisplayName)
		if err != nil {
			return err
		}
		subject := t.subjectOf(in.UserName, in.ExternalID)
		if err := taken(ctx, q, t, ids.UUID{}, in.UserName, in.ExternalID); err != nil {
			return err
		}
		state := td.Disabled
		if active {
			state = td.Enabled
			if err := s.memberLimit(ctx, q, t.org); err != nil {
				return err
			}
		}
		var id ids.UUID
		scimDisabled, deprovision := !active, false
		prior, err := q.DirectoryUserBySubject(ctx, t.org, t.Issuer, subject)
		switch {
		case db.IsNoRows(err):
			u, err := q.InsertProvisionedUser(ctx, dbq.InsertProvisionedUserParams{
				OrgID: t.org, ID: ids.NewV7(), Issuer: t.Issuer, Subject: subject, Email: email, DisplayName: name, State: string(state),
			})
			if db.IsUniqueViolation(err) {
				return ports.ErrConflict // a concurrent create of the same identity
			} else if err != nil {
				return err
			}
			id = u.ID
		case err != nil:
			return err
		case prior.DeletedAt == nil:
			return ports.ErrConflict
		default:
			// Deleted by SCIM before: it comes back, but a person's decision
			// to disable it stays (HR-632).
			id = prior.ID
			r, err := q.LockDirectoryUser(ctx, t.org, t.Issuer, id)
			if err != nil {
				return err
			}
			if err := q.SetProvisionedProfile(ctx, dbq.SetProvisionedProfileParams{Email: email, DisplayName: name, OrgID: t.org, ID: id}); err != nil {
				return err
			}
			enabled := r.State == string(td.Enabled)
			switch {
			case active && !enabled:
				if !r.DisabledByScim {
					return ports.ErrDisabledHere
				}
				if _, err := q.SetUserState(ctx, string(td.Enabled), t.org, id); err != nil {
					return err
				}
			case !active && enabled:
				deprovision = true
			case !active:
				scimDisabled = r.DisabledByScim // a person's decision stays theirs
			}
		}
		if deprovision {
			if err := s.deprovision(ctx, tx, q, t, id); err != nil {
				return err
			}
		}
		if err := q.PutSCIMUser(ctx, dbq.PutSCIMUserParams{
			OrgID: t.org, UserID: id, UserName: optional(in.UserName), ExternalID: optional(in.ExternalID), DisabledByScim: scimDisabled,
		}); err != nil {
			return err
		}
		if err := s.record(ctx, tx, t, "scim.user_created", "user", id, map[string]string{"active": strconv.FormatBool(active)}); err != nil {
			return err
		}
		r, err := q.LockDirectoryUser(ctx, t.org, t.Issuer, id)
		if err != nil {
			return err
		}
		out = lockedUser(t, r)
		return nil
	})
	return out, s.refused(ctx, pt, err)
}

// ReplaceUser sets every field (PUT).
func (s *Service) ReplaceUser(ctx context.Context, pt ports.Token, id string, in ports.UserInput) (ports.User, error) {
	return s.ChangeUser(ctx, pt, id, ports.UserChange{
		UserName: &in.UserName, ExternalID: &in.ExternalID, Email: &in.Email, DisplayName: &in.DisplayName, Active: in.Active,
	})
}

// ChangeUser applies a partial change (PATCH). The subject never changes
// (ErrImmutable). Active false deprovisions (HR-632); active true re-enables
// only a user SCIM disabled, never one a person disabled (ErrDisabledHere).
// Removing (active false) works in every edition. Below Enterprise a
// request that removes applies its removal only, records the parts it
// dropped and returns the stored user; one that does not remove is
// ErrEdition (D528).
func (s *Service) ChangeUser(ctx context.Context, pt ports.Token, id string, c ports.UserChange) (ports.User, error) {
	var out ports.User
	err := s.inDir(ctx, pt, func(ctx context.Context, tx db.TenantTx, q *dbq.Queries, t token) error {
		full, err := s.fullEdition(ctx)
		if err != nil {
			return err
		}
		removal := c.Active != nil && !*c.Active
		if !full && !removal {
			return ports.ErrEdition
		}
		r, err := lockUser(ctx, q, t, id)
		if err != nil {
			return err
		}
		cur := lockedUser(t, r)
		if !full {
			return s.removeOnly(ctx, tx, q, t, r, cur, c, &out)
		}
		userName, externalID := cur.UserName, cur.ExternalID
		if t.SubjectAttribute == domain.SubjectExternalID && r.UserName == nil {
			userName = "" // shown as the email, not stored
		}
		if c.UserName != nil {
			userName = *c.UserName
		}
		if c.ExternalID != nil {
			externalID = *c.ExternalID
		}
		if err := attr(userName, t.SubjectAttribute == domain.SubjectUserName); err != nil {
			return err
		}
		if err := attr(externalID, t.SubjectAttribute == domain.SubjectExternalID); err != nil {
			return err
		}
		if t.subjectOf(userName, externalID) != r.Subject {
			return ports.ErrImmutable
		}
		if err := taken(ctx, q, t, r.ID, userName, externalID); err != nil {
			return err
		}
		details := map[string]string{}
		if c.Email != nil || c.DisplayName != nil {
			email, name := r.Email, r.DisplayName
			if c.Email != nil {
				email = *c.Email
			}
			if c.DisplayName != nil {
				name = *c.DisplayName
			}
			if email, name, err = profile(email, name); err != nil {
				return err
			}
			if err := q.SetProvisionedProfile(ctx, dbq.SetProvisionedProfileParams{Email: email, DisplayName: name, OrgID: t.org, ID: r.ID}); err != nil {
				return err
			}
			details["profile"] = "changed"
		}
		disabledByScim := r.DisabledByScim
		if c.Active != nil {
			switch enabled := r.State == string(td.Enabled); {
			case *c.Active && !enabled:
				if !r.DisabledByScim {
					return ports.ErrDisabledHere
				}
				if err := s.memberLimit(ctx, q, t.org); err != nil {
					return err
				}
				if _, err := q.SetUserState(ctx, string(td.Enabled), t.org, r.ID); err != nil {
					return err
				}
				disabledByScim, details["active"] = false, "true"
			case !*c.Active && enabled:
				if err := s.deprovision(ctx, tx, q, t, r.ID); err != nil {
					return err
				}
				disabledByScim, details["active"] = true, "false"
			}
		}
		if err := q.PutSCIMUser(ctx, dbq.PutSCIMUserParams{
			OrgID: t.org, UserID: r.ID, UserName: optional(userName), ExternalID: optional(externalID), DisabledByScim: disabledByScim,
		}); err != nil {
			return err
		}
		if err := s.record(ctx, tx, t, "scim.user_changed", "user", r.ID, details); err != nil {
			return err
		}
		r, err = q.LockDirectoryUser(ctx, t.org, t.Issuer, r.ID)
		if err != nil {
			return err
		}
		out = lockedUser(t, r)
		return nil
	})
	return out, s.refused(ctx, pt, err)
}

// removeOnly applies the one removal a request below Enterprise may make,
// deprovisioning, and records what else it asked for (D528).
func (s *Service) removeOnly(ctx context.Context, tx db.TenantTx, q *dbq.Queries, t token, r dbq.LockDirectoryUserRow, cur ports.User, c ports.UserChange, out *ports.User) error {
	var parts []string
	differs := func(p *string, v string) bool { return p != nil && *p != v }
	if differs(c.UserName, cur.UserName) {
		parts = append(parts, "userName")
	}
	if differs(c.ExternalID, cur.ExternalID) {
		parts = append(parts, "externalId")
	}
	if differs(c.Email, cur.Email) {
		parts = append(parts, "email")
	}
	if differs(c.DisplayName, cur.DisplayName) {
		parts = append(parts, "displayName")
	}
	if r.State == string(td.Enabled) {
		if err := s.deprovision(ctx, tx, q, t, r.ID); err != nil {
			return err
		}
		if err := q.PutSCIMUser(ctx, dbq.PutSCIMUserParams{
			OrgID: t.org, UserID: r.ID, UserName: r.UserName, ExternalID: r.ExternalID, DisabledByScim: true,
		}); err != nil {
			return err
		}
		if err := s.record(ctx, tx, t, "scim.user_changed", "user", r.ID, map[string]string{"active": "false"}); err != nil {
			return err
		}
	}
	if err := s.dropped(ctx, tx, t, "user", r.ID, parts); err != nil {
		return err
	}
	u, err := q.LockDirectoryUser(ctx, t.org, t.Issuer, r.ID)
	if err != nil {
		return err
	}
	*out = lockedUser(t, u)
	return nil
}

// DeleteUser deprovisions the user, drops their group memberships (and so
// the bindings those gave) and hides them from SCIM. Works in every edition.
func (s *Service) DeleteUser(ctx context.Context, pt ports.Token, id string) error {
	err := s.inDir(ctx, pt, func(ctx context.Context, tx db.TenantTx, q *dbq.Queries, t token) error {
		r, err := lockUser(ctx, q, t, id)
		if err != nil {
			return err
		}
		disabledByScim := r.DisabledByScim
		if r.State == string(td.Enabled) {
			if err := s.deprovision(ctx, tx, q, t, r.ID); err != nil {
				return err
			}
			disabledByScim = true
		}
		groups, err := q.GroupsOfUser(ctx, t.org, r.ID)
		if err != nil {
			return err
		}
		for _, g := range groups {
			if err := q.RemoveGroupMember(ctx, t.org, g, r.ID); err != nil {
				return err
			}
		}
		if _, _, err := reconcile(ctx, q, t.org, r.ID); err != nil {
			return err
		}
		now := s.now().Now()
		if err := q.PutSCIMUser(ctx, dbq.PutSCIMUserParams{
			OrgID: t.org, UserID: r.ID, UserName: r.UserName, ExternalID: r.ExternalID, DisabledByScim: disabledByScim, DeletedAt: &now,
		}); err != nil {
			return err
		}
		return s.record(ctx, tx, t, "scim.user_deleted", "user", r.ID, map[string]string{"groups_left": strconv.Itoa(len(groups))})
	})
	return s.refused(ctx, pt, err)
}

// deprovision disables an enabled user and ends their sessions at once
// (HR-632). Their API keys stay active: the posture queue lists them for a
// person to rotate (D409). It is ErrLastAdmin when no active Org Admin would
// be left, or none with a way to sign in (HR-484).
func (s *Service) deprovision(ctx context.Context, tx db.TenantTx, q *dbq.Queries, t token, user ids.UUID) error {
	guard, err := tenancy.GuardAdmins(ctx, q, t.org)
	if err != nil {
		return err
	}
	if _, err := q.SetUserState(ctx, string(td.Disabled), t.org, user); err != nil {
		return err
	}
	if err := q.MarkSCIMDeprovisioned(ctx, t.org, user); err != nil {
		return err
	}
	cliReason, browserReason := cliReason, browserReason
	cli, err := q.RevokeUserSessions(ctx, &cliReason, t.org, user)
	if err != nil {
		return err
	}
	browser, err := q.EndAllUserBrowserSessions(ctx, &browserReason, t.org, user)
	if err != nil {
		return err
	}
	if err := guard(ctx); err != nil {
		if errors.Is(err, td.ErrLastOrgAdmin) {
			return ports.ErrLastAdmin
		}
		return err
	}
	if s.IdPs != nil {
		if err := s.IdPs.CheckSignInPath(ctx, tx); err != nil {
			if errors.Is(err, idps.ErrLockOut) {
				return ports.ErrLastAdmin
			}
			return err
		}
	}
	keys, err := q.CountActiveKeysOfUser(ctx, t.org, td.PrincipalRef{Kind: td.KindUser, ID: user}.String())
	if err != nil {
		return err
	}
	return s.record(ctx, tx, t, "scim.user_deprovisioned", "user", user, map[string]string{
		"cli_sessions_revoked": strconv.FormatInt(cli, 10), "browser_sessions_ended": strconv.FormatInt(browser, 10),
		"api_keys_left_active": strconv.FormatInt(keys, 10),
	})
}

// record writes a directory change into the org's evidence ledger.
func (s *Service) record(ctx context.Context, tx db.TenantTx, t token, name, objType string, obj ids.UUID, details map[string]string) error {
	if details == nil {
		details = map[string]string{}
	}
	details["issuer"] = trimDetail(t.Issuer)
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: t.actor(), Outcome: audit.Success, Object: &audit.Object{Type: objType, ID: obj.String()}, Details: details,
	})
	return err
}

func trimDetail(s string) string {
	if len(s) > 500 {
		return s[:500]
	}
	return s
}

// refused records a deprovisioning the last-admin guard refused, in its own
// transaction: the refused one rolled back, and the refusal is an owned
// failure a person must see (HR-632).
func (s *Service) refused(ctx context.Context, pt ports.Token, err error) error {
	if !errors.Is(err, ports.ErrLastAdmin) {
		return err
	}
	cred, perr := parseBearer(pt)
	if perr != nil {
		return err
	}
	rerr := s.Pool.InTenantTx(ctx, cred.Org(), func(ctx context.Context, tx db.TenantTx) error {
		t, err := lookUp(ctx, dbq.New(tx), cred)
		if err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "scim.user_deprovision_refused", Actor: t.actor(), Outcome: audit.Denied, ReasonCode: "LAST_ORG_ADMIN",
			Object: &audit.Object{Type: "scim_token", ID: t.id.String()}, Details: map[string]string{"issuer": trimDetail(t.Issuer)},
		})
		return err
	})
	if rerr != nil {
		s.log().ErrorContext(ctx, "provisioning: recording a refused deprovisioning failed", "err", rerr)
	}
	return err
}
