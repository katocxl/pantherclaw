// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"sync"
	"time"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/provisioning/domain"
	"github.com/katocxl/pantherclaw/internal/provisioning/ports"
)

// Web is the core's browser sign-in page: only it sets a session cookie.
type Web interface {
	FinishExternalSignIn(w http.ResponseWriter, r *http.Request, out authnapp.BrowserSignIn, err error)
	ClientMeta(r *http.Request) authnapp.ClientMeta
}

// SignIn is the core's side of SAML sign-in (F922, HR-634): connections,
// single-use sign-in requests, the assertion replay record, and the
// session. It signs in existing users only (D409 point 8).
type SignIn struct {
	Pool    *db.Pool
	Browser *authnapp.Browser
	Web     Web
	Clock   interface{ Now() time.Time }
}

var _ ports.SignIn = (*SignIn)(nil)

// maxReplayWindow bounds how long an assertion id is remembered.
const maxReplayWindow = 24 * time.Hour

func parseConn(orgID, connectionID string) (ids.OrgID, ids.UUID, error) {
	org, err := ids.Parse[ids.Org](orgID)
	if err != nil || org == ids.PlatformOrg {
		return ids.OrgID{}, ids.UUID{}, ports.ErrSignInUnavailable
	}
	id, err := ids.ParseUUID(connectionID)
	if err != nil {
		return ids.OrgID{}, ids.UUID{}, ports.ErrSignInUnavailable
	}
	return org, id, nil
}

// active is an ACTIVE connection of an active org.
func (s *SignIn) active(ctx context.Context, org ids.OrgID, id ids.UUID) (dbq.PcSamlConnection, error) {
	var r dbq.PcSamlConnection
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		state, err := q.OrgState(ctx, org)
		if err != nil || state != "ACTIVE" {
			return ports.ErrSignInUnavailable
		}
		r, err = q.GetSAMLConnection(ctx, org, id)
		if db.IsNoRows(err) {
			return ports.ErrSignInUnavailable
		} else if err != nil {
			return err
		}
		if r.State != domain.StateActive || r.Issuer == nil {
			return ports.ErrSignInUnavailable
		}
		return nil
	}, db.ReadOnly())
	return r, err
}

// Connection returns an ACTIVE connection with its stored certificates.
func (s *SignIn) Connection(ctx context.Context, orgID, connectionID string) (ports.Connection, error) {
	org, id, err := parseConn(orgID, connectionID)
	if err != nil {
		return ports.Connection{}, err
	}
	r, err := s.active(ctx, org, id)
	if err != nil {
		return ports.Connection{}, err
	}
	out := ports.Connection{ID: r.ID.String(), OrgID: org.String(), Name: r.Name, IdPEntityID: r.IdpEntityID, SSOURL: r.SsoUrl}
	for _, c := range r.Certificates {
		der, err := base64.StdEncoding.DecodeString(c)
		if err != nil {
			return ports.Connection{}, ports.ErrSignInUnavailable
		}
		out.Certificates = append(out.Certificates, der)
	}
	return out, nil
}

func provider(r dbq.PcSamlConnection) string { return domain.ProviderPrefix + r.Name }

func validRequestID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range []byte(id) {
		if c <= 0x20 || c >= 0x7f {
			return false
		}
	}
	return true
}

// StartSignIn stores a sign-in for AuthnRequest requestID.
func (s *SignIn) StartSignIn(ctx context.Context, orgID, connectionID, requestID, next, clientIP string) (ports.Started, error) {
	org, id, err := parseConn(orgID, connectionID)
	if err != nil || !validRequestID(requestID) {
		return ports.Started{}, ports.ErrSignInUnavailable
	}
	r, err := s.active(ctx, org, id)
	if err != nil {
		return ports.Started{}, err
	}
	st, err := s.Browser.StartExternal(ctx, org, provider(r), requestID, next, clientIP)
	if errors.Is(err, authnapp.ErrSignInUnavailable) {
		return ports.Started{}, ports.ErrSignInUnavailable
	} else if err != nil {
		return ports.Started{}, err
	}
	return ports.Started{RelayState: st.State, Binding: st.Binding, Expires: st.Expires}, nil
}

// ConsumeSignIn takes a stored sign-in once.
func (s *SignIn) ConsumeSignIn(ctx context.Context, orgID, connectionID, relayState, binding string) (ports.Pending, error) {
	org, id, err := parseConn(orgID, connectionID)
	if err != nil {
		return ports.Pending{}, err
	}
	r, err := s.active(ctx, org, id)
	if err != nil {
		return ports.Pending{}, err
	}
	requestID, next, err := s.Browser.ConsumeExternal(ctx, org, provider(r), relayState, binding)
	if errors.Is(err, authnapp.ErrBadCallback) {
		return ports.Pending{}, ports.ErrSignInUnavailable
	} else if err != nil {
		return ports.Pending{}, err
	}
	return ports.Pending{RequestID: requestID, Handle: &pending{org: org, conn: id, next: next}}, nil
}

// pending is the core's record of one consumed sign-in (D528): only this
// package makes one, RecordAssertion marks its assertion accepted, and
// FinishSignIn takes it once after that.
type pending struct {
	org      ids.OrgID
	conn     ids.UUID
	next     string
	mu       sync.Mutex
	recorded bool
	finished bool
}

func (*pending) SignInHandle() {}

// handleOf is the core's own handle, or nil for anything else.
func handleOf(h ports.SignInHandle) *pending {
	p, _ := h.(*pending)
	return p
}

func hashed(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// RecordAssertion accepts an assertion id of the handle's connection once.
func (s *SignIn) RecordAssertion(ctx context.Context, h ports.SignInHandle, assertionID string, notOnOrAfter time.Time) error {
	p := handleOf(h)
	if p == nil {
		return ports.ErrSignInUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.recorded || p.finished {
		return ports.ErrReplayed // one assertion per sign-in
	}
	org, id := p.org, p.conn
	if assertionID == "" || len(assertionID) > 256 {
		return ports.ErrReplayed
	}
	now := s.now()
	if !notOnOrAfter.After(now) {
		return ports.ErrReplayed // no longer within its time
	}
	if notOnOrAfter.After(now.Add(maxReplayWindow)) {
		notOnOrAfter = now.Add(maxReplayWindow)
	}
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.GetSAMLConnection(ctx, org, id)
		if db.IsNoRows(err) {
			return ports.ErrSignInUnavailable
		} else if err != nil {
			return err
		}
		n, err := q.InsertAuthReplay(ctx, dbq.InsertAuthReplayParams{
			OrgID: org, Issuer: "saml:" + hashed(r.IdpEntityID), Jti: hashed(assertionID), ExpiresAt: notOnOrAfter,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return ports.ErrReplayed
		}
		return nil
	})
	if err == nil {
		p.recorded = true
	}
	return err
}

// maxAuthnAhead is how far ahead an AuthnInstant may be, as for an OpenID
// auth_time; one within it counts as now (D528).
const maxAuthnAhead = 5 * time.Minute

func (s *SignIn) now() time.Time {
	if s.Clock == nil {
		return time.Now()
	}
	return s.Clock.Now()
}

// FinishSignIn opens a session for a verified identity of an ACTIVE
// connection: the identity's issuer is the connection's, so an assertion
// signs in only users of that connection.
func (s *SignIn) FinishSignIn(w http.ResponseWriter, r *http.Request, h ports.SignInHandle, v ports.Verified) {
	ctx := r.Context()
	p := handleOf(h)
	if p == nil {
		s.Web.FinishExternalSignIn(w, r, authnapp.BrowserSignIn{}, authnapp.ErrSignInUnavailable)
		return
	}
	p.mu.Lock()
	ok := p.recorded && !p.finished
	p.finished = true
	p.mu.Unlock()
	if !ok {
		s.Web.FinishExternalSignIn(w, r, authnapp.BrowserSignIn{}, authnapp.ErrSignInUnavailable)
		return
	}
	now := s.now()
	authTime := v.AuthenticatedAt
	if authTime.After(now.Add(maxAuthnAhead)) {
		s.Web.FinishExternalSignIn(w, r, authnapp.BrowserSignIn{}, authnapp.ErrSignInUnavailable)
		return
	}
	if authTime.After(now) {
		authTime = now
	}
	conn, err := s.active(ctx, p.org, p.conn)
	if err != nil {
		s.Web.FinishExternalSignIn(w, r, authnapp.BrowserSignIn{}, authnapp.ErrSignInUnavailable)
		return
	}
	claims := authnapp.IDClaims{
		Issuer: *conn.Issuer, Subject: v.Subject, Email: v.Email, Name: v.DisplayName, AuthTime: authTime,
	}
	if claims.Email == "" || claims.Name == "" {
		s.fillProfile(ctx, p.org, &claims)
	}
	out, err := s.Browser.FinishExternal(ctx, p.org, provider(conn), claims, p.next, s.Web.ClientMeta(r))
	s.Web.FinishExternalSignIn(w, r, out, err)
}

// fillProfile keeps the stored email and name an assertion did not carry:
// a sign-in records what the provider says.
func (s *SignIn) fillProfile(ctx context.Context, org ids.OrgID, c *authnapp.IDClaims) {
	_ = s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListDirectoryUsers(ctx, dbq.ListDirectoryUsersParams{
			OrgID: org, Issuer: c.Issuer, Subject: &c.Subject, PageLimit: 1,
		})
		if err != nil || len(rows) == 0 {
			return err
		}
		if c.Email == "" {
			c.Email = rows[0].Email
		}
		if c.Name == "" {
			c.Name = rows[0].DisplayName
		}
		return nil
	}, db.ReadOnly())
}
