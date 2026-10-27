// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package support

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// StaffRequest returns a staff member's own request in org, for the
// staff's request page; another account's request reads as not found. It
// needs no step-up: it only shows what the staff member asked.
func (s *Service) StaffRequest(ctx context.Context, staff tapp.Caller, org, id ids.UUID) (Request, error) {
	ok, err := s.IsStaff(ctx, staff)
	if err != nil {
		return Request{}, err
	}
	if !ok {
		return Request{}, ErrNotStaff
	}
	account, err := s.accountOf(ctx, staff)
	if err != nil {
		return Request{}, err
	}
	o, err := ids.FromUUID[ids.Org](org)
	if err != nil || o == s.cfg.StaffOrg {
		return Request{}, ErrRequestNotFound
	}
	var out Request
	err = s.pool.InTenantTx(ctx, o, func(ctx context.Context, tx db.TenantTx) error {
		r, err := dbq.New(tx).GetSupportRequest(ctx, o, id)
		if db.IsNoRows(err) || (err == nil && r.RequesterAccount != account) {
			return ErrRequestNotFound
		} else if err != nil {
			return err
		}
		out = requestOf(requestRow(r), r.Expired, r.GrantID)
		return nil
	}, db.ReadOnly())
	return out, err
}

// accountOf is a staff user's linked account.
func (s *Service) accountOf(ctx context.Context, c tapp.Caller) (ids.UUID, error) {
	var out ids.UUID
	err := s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		u, err := dbq.New(tx).UserIdentityForSupport(ctx, c.Org, c.Principal.ID)
		if err != nil || u.AccountID == nil {
			return errors.Join(err, ErrNotStaff)
		}
		out = *u.AccountID
		return nil
	}, db.ReadOnly())
	return out, err
}

// Opened is a new support session: its id and the cookie secret, which is
// shown once and stored only as a hash.
type Opened struct {
	Org       ids.OrgID
	Session   ids.UUID
	Grant     ids.UUID
	Secret    string
	ExpiresAt time.Time
}

// Open opens a support session in org under the approved grant of
// request (HR-385): the staff member stepped up in the staff org, the
// grant is theirs and in force, and the org is on Enterprise. The session
// ends at the grant's expiry at the latest, and after 12 hours.
func (s *Service) Open(ctx context.Context, st Staff, org ids.OrgID, request ids.UUID) (Opened, error) {
	m, err := s.staff(ctx, st)
	if err != nil {
		return Opened{}, err
	}
	if org == m.StaffOrg {
		return Opened{}, ErrNoGrant
	}
	if err := s.available(ctx, org); err != nil {
		return Opened{}, err
	}
	secret, err := credential.New(credential.SupportSession, "", org)
	if err != nil {
		return Opened{}, err
	}
	out := Opened{Org: org, Secret: secret.Reveal()}
	err = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if state, err := q.OrgState(ctx, org); db.IsNoRows(err) || (err == nil && state != "ACTIVE") {
			return ErrNoGrant
		} else if err != nil {
			return err
		}
		g, err := q.LiveSupportGrantOfRequest(ctx, org, request, m.Account)
		if db.IsNoRows(err) {
			return ErrNoGrant
		} else if err != nil {
			return err
		}
		if !s.cfg.listed(g.RequesterIssuer, g.RequesterSubject) {
			return ErrNotStaff
		}
		sess, err := q.InsertSupportSession(ctx, dbq.InsertSupportSessionParams{
			OrgID: org, ID: ids.NewV7(), GrantID: g.ID, AccountID: m.Account, StaffCredential: m.Credential,
			SecretHash: secret.Hash(), UserAgent: trim(st.UserAgent, 256), ClientIp: trim(st.IP, 64),
			GrantExpiresAt: g.ExpiresAt, MaxSeconds: int32(SessionMaxAge / time.Second),
		})
		if err != nil {
			return err
		}
		out.Session, out.Grant, out.ExpiresAt = sess.ID, g.ID, sess.ExpiresAt
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "support.session_opened", Actor: staffActor(m.Account), Outcome: audit.Success,
			Object: &audit.Object{Type: "support_session", ID: sess.ID.String()},
			Details: map[string]string{
				"grant": g.ID.String(), "request": request.String(), "scope": g.Scope, "staff_org": m.StaffOrg.String(),
				"staff_user": m.User.String(), "webauthn_key": m.Credential.String(),
				"until": sess.ExpiresAt.UTC().Format(time.RFC3339),
			},
		})
		return err
	})
	if err != nil {
		return Opened{}, err
	}
	return out, nil
}

// IsSessionCookie reports whether v has the support session's form (the
// API then authenticates it as one, never as a browser session).
func IsSessionCookie(v string) bool {
	_, err := credential.Parse(credential.SupportSession, v)
	return err == nil
}

// Authenticate resolves a support session cookie for a call to procedure
// (HR-385, HR-388). In one transaction of the session's org it checks the
// org, the session's state and its lifetime and idle limits, and the
// grant (approved, unexpired, unrevoked) by the database clock, and that
// the staff member is still on the staff list; a session that fails one
// of them is ended. The call itself is recorded in the org's audit ledger
// with the staff member's account, the grant and the session, before
// anything runs. The org's plan must still be Enterprise. Every failure
// is ErrUnauthenticated; the reason is logged.
func (s *Service) Authenticate(ctx context.Context, cookie, procedure string) (tapp.Caller, error) {
	if !s.Enabled() {
		return tapp.Caller{}, ErrUnauthenticated
	}
	tok, err := credential.Parse(credential.SupportSession, cookie)
	if err != nil {
		return s.rejected(ctx, "session_malformed")
	}
	org := tok.Org()
	if err := s.available(ctx, org); err != nil {
		return s.rejected(ctx, "unavailable")
	}
	var out tapp.Caller
	reason := ""
	err = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if state, err := q.OrgState(ctx, org); db.IsNoRows(err) || (err == nil && state != "ACTIVE") {
			reason = "org_inactive"
			return nil
		} else if err != nil {
			return err
		}
		r, err := q.SupportSessionBySecret(ctx, int32(SessionIdle/time.Second), org, tok.Hash())
		switch {
		case db.IsNoRows(err):
			reason = "session_unknown"
			return nil
		case err != nil:
			return err
		case r.State != "ACTIVE":
			reason = "session_ended"
			return nil
		}
		end := func(code, why string) error {
			reason = why
			_, err := q.EndSupportSession(ctx, &code, org, r.ID)
			return err
		}
		switch {
		case !r.GrantLive:
			return end("GRANT_ENDED", "grant_ended")
		case !r.WithinLifetime:
			return end("EXPIRED", "session_expired")
		case !r.WithinIdle:
			return end("IDLE", "session_idle")
		case !s.cfg.listed(r.RequesterIssuer, r.RequesterSubject):
			return end("REVOKED", "staff_unlisted")
		}
		p := td.PrincipalRef{Kind: td.KindSupport, ID: r.AccountID}
		out = tapp.Caller{
			Subject:    td.Subject{Org: org, Principal: p, Bindings: tapp.SupportScopeBindings(org, r.Scope)},
			Credential: tapp.CredSupportSession, Session: r.ID, SupportGrant: r.GrantID,
		}
		if _, err := audit.Record(audit.WithAuthKind(ctx, string(tapp.CredSupportSession)), tx, audit.Event{
			Name: "support.call", Actor: staffActor(r.AccountID), Outcome: audit.Success,
			Object:  &audit.Object{Type: "support_session", ID: r.ID.String()},
			Details: map[string]string{"procedure": trim(procedure, 200), "grant": r.GrantID.String()},
		}); err != nil {
			return err
		}
		if r.Touch {
			return q.TouchSupportSession(ctx, org, r.ID)
		}
		return nil
	})
	if err != nil {
		return tapp.Caller{}, err
	}
	if reason != "" {
		return s.rejected(ctx, reason)
	}
	return out, nil
}

func (s *Service) rejected(ctx context.Context, reason string) (tapp.Caller, error) {
	s.log.WarnContext(ctx, "support.session_rejected", slog.String(pclog.KeyOutcome, "rejected"), slog.String("reason", reason))
	return tapp.Caller{}, ErrUnauthenticated
}

// Current describes the caller's support session (the console's banner).
func (s *Service) Current(ctx context.Context) (ids.UUID, Grant, time.Time, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return ids.UUID{}, Grant{}, time.Time{}, err
	}
	if c.Credential != tapp.CredSupportSession || !c.Support() {
		return ids.UUID{}, Grant{}, time.Time{}, ErrNotSupportSession
	}
	var g Grant
	var until time.Time
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		sess, err := q.GetSupportSession(ctx, c.Org, c.Session)
		if err != nil {
			return err
		}
		row, err := q.GetSupportGrant(ctx, c.Org, sess.GrantID)
		if err != nil {
			return err
		}
		g = grantOf(grantRow(row), row.RequesterEmail, row.RequesterName, row.Task, row.SessionsOpened, row.Expired)
		until = sess.ExpiresAt
		return nil
	}, db.ReadOnly())
	return c.Session, g, until, err
}

// Logout ends the support session of a cookie; an unknown or ended one is
// not an error.
func (s *Service) Logout(ctx context.Context, cookie string) error {
	tok, err := credential.Parse(credential.SupportSession, cookie)
	if err != nil || !s.Enabled() {
		return nil //nolint:nilerr // signed out either way
	}
	org := tok.Org()
	return s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.SupportSessionBySecret(ctx, int32(SessionIdle/time.Second), org, tok.Hash())
		if db.IsNoRows(err) {
			return nil
		} else if err != nil {
			return err
		}
		code := "LOGOUT"
		n, err := q.EndSupportSession(ctx, &code, org, r.ID)
		if err != nil || n == 0 {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "support.session_ended", Actor: staffActor(r.AccountID), Outcome: audit.Success, ReasonCode: code,
			Object: &audit.Object{Type: "support_session", ID: r.ID.String()}, Details: map[string]string{"grant": r.GrantID.String()},
		})
		return err
	})
}
