// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package partners

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Operator is a partner person's browser session in the partner org with
// its last step-up, as the open page saw it.
type Operator struct {
	Caller tapp.Caller
	StepUp *stepup.StepUp
	// UserAgent and IP are what the server observed (untrusted).
	UserAgent, IP string
}

// Opened is a new partner session: its id and the cookie secret, which is
// shown once and stored only as a hash.
type Opened struct {
	Customer  ids.OrgID
	Session   ids.UUID
	Link      ids.UUID
	Secret    string
	ExpiresAt time.Time
}

// LiveLink returns the partner's ACTIVE link with customer, for the open
// page (partner.operate, a person).
func (s *Service) LiveLink(ctx context.Context, customer ids.UUID) (Link, error) {
	c, err := person(ctx, PermOperate)
	if err != nil {
		return Link{}, err
	}
	var out Link
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		l, err := q.LivePartnerLink(ctx, c.Org.UUID(), customer)
		if db.IsNoRows(err) {
			return ErrNoLink
		} else if err != nil {
			return err
		}
		r, err := q.GetPartnerLink(ctx, l.ID, c.Org.UUID())
		if err != nil {
			return err
		}
		out = linkOf(r)
		return nil
	}, db.ReadOnly())
	return out, err
}

// Open opens a partner session in customer under the partner's ACTIVE link
// (D1101, D1100a): a partner person holding partner.operate who stepped up
// in the partner org within five minutes, the partner org on Enterprise.
// The session ends at the link's end at the latest, and after 12 hours.
// It is recorded in both orgs.
func (s *Service) Open(ctx context.Context, op Operator, customer ids.OrgID) (Opened, error) {
	ctx = tapp.WithCaller(ctx, op.Caller)
	c, err := person(ctx, PermOperate)
	if err != nil {
		return Opened{}, err
	}
	if customer == c.Org {
		return Opened{}, ErrNoLink
	}
	if op.StepUp == nil {
		return Opened{}, stepup.ErrStepUp
	}
	if err := stepup.Verify(ctx, s.pool, c, *op.StepUp); err != nil {
		return Opened{}, err
	}
	if err := s.partnerAccess(ctx, c.Org); err != nil {
		return Opened{}, err
	}
	secret, err := credential.New(credential.PartnerSession, "", customer)
	if err != nil {
		return Opened{}, err
	}
	actor := partnerActor(c.Org.UUID(), c.Principal.ID)
	out := Opened{Customer: customer, Secret: secret.Reveal()}
	details := map[string]string{"partner_org": c.Org.String(), "webauthn_key": op.StepUp.Credential.String()}
	err = s.pool.InTenantTx(ctx, customer, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if state, err := q.OrgState(ctx, customer); db.IsNoRows(err) || (err == nil && state != "ACTIVE") {
			return ErrNoLink
		} else if err != nil {
			return err
		}
		l, err := q.LivePartnerLink(ctx, c.Org.UUID(), customer.UUID())
		if db.IsNoRows(err) {
			return ErrNoLink
		} else if err != nil {
			return err
		}
		if l.EndsAt == nil {
			return ErrNoLink
		}
		sess, err := q.InsertPartnerSession(ctx, dbq.InsertPartnerSessionParams{
			OrgID: customer, ID: ids.NewV7(), LinkID: l.ID, PartnerOrg: c.Org.UUID(), PartnerUser: c.Principal.ID,
			PartnerCredential: op.StepUp.Credential, SecretHash: secret.Hash(), UserAgent: trim(op.UserAgent, 256),
			ClientIp: trim(op.IP, 64), LinkEndsAt: *l.EndsAt, MaxSeconds: int32(SessionMaxAge / time.Second),
		})
		if err != nil {
			return err
		}
		out.Session, out.Link, out.ExpiresAt = sess.ID, l.ID, sess.ExpiresAt
		details["link"] = l.ID.String()
		details["until"] = sess.ExpiresAt.UTC().Format(time.RFC3339)
		return record(ctx, tx, actor, auditkind.PartnerSessionOpened, "partner_session", sess.ID, details)
	})
	if err != nil {
		return Opened{}, err
	}
	return out, s.mirror(ctx, c.Org.UUID(), actor, auditkind.PartnerSessionOpened, "partner_session", out.Session, details)
}

// IsSessionCookie reports whether v has the partner session's form (the
// API then authenticates it as one, never as a browser session).
func IsSessionCookie(v string) bool {
	_, err := credential.Parse(credential.PartnerSession, v)
	return err == nil
}

// sessionRow is what Authenticate learned of a session in the customer org.
type sessionRow struct {
	id, link, partnerOrg, user ids.UUID
	touch                      bool
}

// Authenticate resolves a partner session cookie for a call to procedure
// (HR-811, HR-813). It checks, every call:
//
//   - in the customer org, by the database clock: the org is active, the
//     session is ACTIVE within its lifetime and idle limit, and its link is
//     ACTIVE, of this customer and partner, inside its window;
//   - the partner org is still on Enterprise (PartnerAccess);
//   - in the partner org: the partner person is still enabled and still
//     holds partner.operate.
//
// A session that fails one of them is ended. The call is then recorded in
// the customer's audit log as partner.call, with actor
// partner/<partner org>/<user>, before anything runs. Every failure is
// ErrUnauthenticated; the reason is logged.
func (s *Service) Authenticate(ctx context.Context, cookie, procedure string) (tapp.Caller, error) {
	tok, err := credential.Parse(credential.PartnerSession, cookie)
	if err != nil {
		return s.rejected(ctx, "session_malformed")
	}
	org := tok.Org()
	var row sessionRow
	reason := ""
	err = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if state, err := q.OrgState(ctx, org); db.IsNoRows(err) || (err == nil && state != "ACTIVE") {
			reason = "org_inactive"
			return nil
		} else if err != nil {
			return err
		}
		r, err := q.PartnerSessionBySecret(ctx, int32(SessionIdle/time.Second), org, tok.Hash())
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
			_, err := q.EndPartnerSession(ctx, &code, org, r.ID)
			return err
		}
		switch {
		case !r.LinkLive:
			return end("LINK_ENDED", "link_ended")
		case !r.WithinLifetime:
			return end("EXPIRED", "session_expired")
		case !r.WithinIdle:
			return end("IDLE", "session_idle")
		}
		row = sessionRow{id: r.ID, link: r.LinkID, partnerOrg: r.PartnerOrg, user: r.PartnerUser, touch: r.Touch}
		return nil
	})
	if err != nil {
		return tapp.Caller{}, err
	}
	if reason != "" {
		return s.rejected(ctx, reason)
	}
	if why, err := s.partnerStillAllowed(ctx, row); err != nil {
		return tapp.Caller{}, err
	} else if why != "" {
		if err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			code := "PARTNER_REMOVED"
			_, err := dbq.New(tx).EndPartnerSession(ctx, &code, org, row.id)
			return err
		}); err != nil {
			return tapp.Caller{}, err
		}
		return s.rejected(ctx, why)
	}
	p := td.PrincipalRef{Kind: td.KindPartner, ID: row.user}
	out := tapp.Caller{
		Subject:    td.Subject{Org: org, Principal: p, Bindings: tapp.PartnerSessionBindings(org)},
		Credential: tapp.CredPartnerSession, Session: row.id,
	}
	err = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := audit.Record(audit.WithAuthKind(ctx, string(tapp.CredPartnerSession)), tx, audit.Event{
			Name: auditkind.PartnerCall, Actor: partnerActor(row.partnerOrg, row.user), Outcome: audit.Success,
			Object: &audit.Object{Type: "partner_session", ID: row.id.String()},
			Details: map[string]string{
				"procedure": trim(procedure, 200), "link": row.link.String(), "partner_org": row.partnerOrg.String(),
			},
		}); err != nil {
			return err
		}
		if row.touch {
			return dbq.New(tx).TouchPartnerSession(ctx, org, row.id)
		}
		return nil
	})
	if err != nil {
		return tapp.Caller{}, err
	}
	return out, nil
}

// partnerStillAllowed checks the partner side of a session: the partner
// org's edition and its person. It returns a reason when the session must
// end.
func (s *Service) partnerStillAllowed(ctx context.Context, row sessionRow) (string, error) {
	partner, err := ids.FromUUID[ids.Org](row.partnerOrg)
	if err != nil {
		return "partner_invalid", nil //nolint:nilerr // a stored id that does not parse ends the session
	}
	if err := s.partnerAccess(ctx, partner); errors.Is(err, ErrEdition) {
		return "partner_edition", nil
	} else if err != nil {
		return "", err
	}
	why := ""
	err = s.pool.InTenantTx(ctx, partner, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if state, err := q.OrgState(ctx, partner); db.IsNoRows(err) || (err == nil && state != "ACTIVE") {
			why = "partner_inactive"
			return nil
		} else if err != nil {
			return err
		}
		u, err := q.UserIdentityForSupport(ctx, partner, row.user)
		if db.IsNoRows(err) {
			why = "partner_person_removed"
			return nil
		} else if err != nil {
			return err
		}
		if td.AccountState(u.State) != td.Enabled {
			why = "partner_person_disabled"
			return nil
		}
		p := td.PrincipalRef{Kind: td.KindUser, ID: row.user}
		bindings, err := tapp.Bindings(ctx, q, partner, p)
		if err != nil {
			return err
		}
		if !(td.Subject{Org: partner, Principal: p, Bindings: bindings}).Can(PermOperate, td.OrgPath(partner)) {
			why = "partner_person_unauthorized"
		}
		return nil
	}, db.ReadOnly())
	return why, err
}

func (s *Service) rejected(ctx context.Context, reason string) (tapp.Caller, error) {
	s.log.WarnContext(ctx, "partners.session_rejected", slog.String(pclog.KeyOutcome, "rejected"), slog.String("reason", reason))
	return tapp.Caller{}, ErrUnauthenticated
}

// Current describes the caller's partner session (the console's banner).
type Current struct {
	Session    ids.UUID
	Link       ids.UUID
	PartnerOrg ids.UUID
	User       ids.UUID
	Scopes     []string
	ExpiresAt  time.Time
}

// CurrentSession describes the caller's partner session.
func (s *Service) CurrentSession(ctx context.Context) (Current, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return Current{}, err
	}
	if !c.PartnerSession() {
		return Current{}, ErrNotSession
	}
	var out Current
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		r, err := dbq.New(tx).GetPartnerSession(ctx, c.Org, c.Session)
		if err != nil {
			return err
		}
		out = Current{Session: r.ID, Link: r.LinkID, PartnerOrg: r.PartnerOrg, User: r.PartnerUser, Scopes: r.Scopes, ExpiresAt: r.ExpiresAt}
		return nil
	}, db.ReadOnly())
	return out, err
}

// Logout ends the partner session of a cookie; an unknown or ended one is
// not an error.
func (s *Service) Logout(ctx context.Context, cookie string) error {
	tok, err := credential.Parse(credential.PartnerSession, cookie)
	if err != nil {
		return nil //nolint:nilerr // signed out either way
	}
	org := tok.Org()
	return s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.PartnerSessionBySecret(ctx, int32(SessionIdle/time.Second), org, tok.Hash())
		if db.IsNoRows(err) {
			return nil
		} else if err != nil {
			return err
		}
		code := "LOGOUT"
		n, err := q.EndPartnerSession(ctx, &code, org, r.ID)
		if err != nil || n == 0 {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: auditkind.PartnerSessionEnded, Actor: partnerActor(r.PartnerOrg, r.PartnerUser), Outcome: audit.Success,
			ReasonCode: code, Object: &audit.Object{Type: "partner_session", ID: r.ID.String()},
			Details: map[string]string{"link": r.LinkID.String()},
		})
		return err
	})
}

// OpenOverAPI refuses to open a partner session over the API: a partner
// person holding partner.operate gets STEP_UP_REQUIRED (the open page is
// the only way, D1100a), anyone else their permission error.
func (s *Service) OpenOverAPI(ctx context.Context) error {
	if _, err := person(ctx, PermOperate); err != nil {
		return err
	}
	return stepup.ErrStepUp
}
