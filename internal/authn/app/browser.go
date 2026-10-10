// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Browser sign-in and session parameters (SB-2, G0 M5 part 1, HR-150).
const (
	BrowserSessionIdle     = 30 * time.Minute
	BrowserSessionLifetime = 12 * time.Hour
	// RotationGrace is how long a replaced session secret still works, for
	// requests that were already in flight when it rotated.
	RotationGrace = 60 * time.Second
	// MaxBrowserSessions is the most active browser sessions one user has.
	MaxBrowserSessions = 10
	LoginRequestTTL    = 10 * time.Minute
	// RecentSignIn is how fresh a provider sign-in must be for sensitive
	// account changes (HR-155); it is sent as max_age.
	RecentSignIn = 5 * time.Minute
	// maxOpenLoginRequests caps the pending sign-ins of one org: anyone can
	// start a sign-in, so their rows must be bounded.
	maxOpenLoginRequests = 10_000

	LoginPath   = "/login"
	LogoutPath  = "/logout"
	AccountPath = "/account"
	// ContainmentPath is the emergency-stop page (G0 M6, response/app).
	ContainmentPath = "/containment"
)

// CredBrowserSession marks a caller authenticated by a browser session.
const CredBrowserSession = tapp.CredBrowserSession

// Browser sign-in errors.
var (
	// ErrSignInUnavailable: unknown or inactive org, unknown provider, or a
	// return path that is not on the list.
	ErrSignInUnavailable = errors.New("authn: sign-in is not available")
	// ErrSignInBusy: too many sign-ins in progress for the org.
	ErrSignInBusy = errors.New("authn: too many sign-ins in progress")
)

// ApprovalsPath is the approval page (G0 M5 part 2): /approvals lists the
// requests waiting for the person, /approvals/{id} shows one.
const ApprovalsPath = "/approvals"

// returnPaths are the pages a sign-in may return to (HR-152).
var returnPaths = []string{AccountPath, ContainmentPath, ApprovalsPath}

// approvalPath is one approval request's page, matched exactly: the
// request id in its canonical lower-case form and nothing else.
var approvalPath = regexp.MustCompile(`^/approvals/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ValidReturnPath reports whether p is a page a sign-in may return to: one
// on the fixed list or one approval request's page, matched exactly.
func ValidReturnPath(p string) bool {
	return slices.Contains(returnPaths, p) || approvalPath.MatchString(p)
}

// Browser implements browser sign-in (OIDC authorization code with PKCE)
// and browser sessions.
type Browser struct {
	pool   *db.Pool
	issuer string
	idps   map[string]IdP
	clock  clock.Clock
	log    *slog.Logger
}

// NewBrowser returns the browser sign-in use cases. issuer is the server's
// public URL; the callback is the device flow's, told apart by state prefix.
func NewBrowser(pool *db.Pool, issuer string, idps []IdP, clk clock.Clock, log *slog.Logger) *Browser {
	if log == nil {
		log = pclog.Discard()
	}
	m := map[string]IdP{}
	for _, p := range idps {
		m[p.Name()] = p
	}
	return &Browser{pool: pool, issuer: issuer, idps: m, clock: clk, log: log}
}

func (b *Browser) provider(name string) (IdP, bool) {
	if name == "" && len(b.idps) == 1 {
		for _, p := range b.idps {
			return p, true
		}
	}
	p, ok := b.idps[name]
	return p, ok
}

func (b *Browser) redirectURI(provider string) string { return b.issuer + CallbackPath + provider }

// BrowserStart starts a browser sign-in. Recent asks the provider for a
// sign-in at most RecentSignIn old (max_age), for sensitive changes.
type BrowserStart struct {
	Org, Provider, Next string
	Recent              bool
	ClientIP            string
}

// Start records a pending sign-in and returns the provider URL and the
// browser binding, which the caller sets as an HttpOnly cookie.
func (b *Browser) Start(ctx context.Context, in BrowserStart) (Redirect, error) {
	org, err := ids.Parse[ids.Org](in.Org)
	if err != nil {
		return Redirect{}, ErrSignInUnavailable
	}
	idp, ok := b.provider(in.Provider)
	if !ok {
		return Redirect{}, ErrSignInUnavailable
	}
	next := in.Next
	if next == "" {
		next = AccountPath
	}
	if !ValidReturnPath(next) {
		return Redirect{}, ErrSignInUnavailable
	}
	state, err := credential.New(credential.LoginState, "", org)
	if err != nil {
		return Redirect{}, err
	}
	nonce, err1 := credential.Secret()
	verifier, err2 := credential.Secret()
	binding, err3 := credential.Secret()
	if err := errors.Join(err1, err2, err3); err != nil {
		return Redirect{}, err
	}
	req := AuthRequest{State: state.Reveal(), Nonce: nonce, Verifier: verifier, RedirectURI: b.redirectURI(idp.Name())}
	var maxAge *int32
	if in.Recent {
		req.MaxAge = RecentSignIn
		s := int32(RecentSignIn / time.Second)
		maxAge = &s
	}
	err = b.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := orgActive(ctx, q, org); err != nil {
			return ErrSignInUnavailable // no org-existence oracle beyond "not available"
		}
		n, err := q.InsertLoginRequest(ctx, dbq.InsertLoginRequestParams{
			OrgID: org.UUID(), ID: ids.NewV7(), StateHash: state.Hash(), BindingHash: credential.HashString(binding),
			Nonce: nonce, PkceVerifier: verifier, Provider: idp.Name(), NextPath: next, MaxAge: maxAge,
			RequestedIp: trim(in.ClientIP, 64), TtlSeconds: int32(LoginRequestTTL / time.Second), MaxOpen: maxOpenLoginRequests,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrSignInBusy
		}
		return nil
	})
	if err != nil {
		return Redirect{}, err
	}
	u, err := idp.AuthCodeURL(ctx, req)
	if err != nil {
		return Redirect{}, err
	}
	return Redirect{URL: u, Binding: binding}, nil
}

// ClientMeta is what the server observed about the browser; it is stored
// and shown as untrusted.
type ClientMeta struct {
	UserAgent, IP string
}

// BrowserSignIn is the result of a browser callback. When Reason is set the
// sign-in was refused (NOT_A_MEMBER, USER_DISABLED, IDP_ERROR,
// LOGIN_FAILED); otherwise Secret is the new session cookie value.
type BrowserSignIn struct {
	Org     ids.OrgID
	Session ids.UUID
	Secret  string
	Next    string
	Reason  string
}

// Callback completes a browser sign-in. The state is consumed first (single
// use); then the callback is verified (verifySignIn), the identity must be
// an enabled user of the org, and a new session is created with a secret
// that did not exist before this moment (no fixation, HR-150).
func (b *Browser) Callback(ctx context.Context, providerName string, params url.Values, binding string, meta ClientMeta) (BrowserSignIn, error) {
	idp, ok := b.idps[providerName]
	if !ok {
		return BrowserSignIn{}, ErrBadCallback
	}
	state, err := credential.Parse(credential.LoginState, params.Get("state"))
	if err != nil {
		return BrowserSignIn{}, ErrBadCallback
	}
	org := state.Org()
	var row dbq.ConsumeLoginStateRow
	err = b.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		row, err = dbq.New(tx).ConsumeLoginState(ctx, org, state.Hash())
		return notFoundAs(err, ErrBadCallback)
	})
	if err != nil {
		return BrowserSignIn{}, err
	}
	refuse := func(reason, detail string, err error) (BrowserSignIn, error) {
		attrs := []slog.Attr{slog.String("reason", reason), slog.String("org", org.String()), slog.String("provider", providerName)}
		if detail != "" {
			attrs = append(attrs, slog.String("detail", detail))
		}
		if err != nil {
			attrs = append(attrs, pclog.Err(err))
		}
		b.log.LogAttrs(ctx, slog.LevelWarn, "authn.browser_login_denied", attrs...)
		return BrowserSignIn{Org: org, Reason: reason}, nil
	}
	pending := pendingSignIn{provider: row.Provider, bindingHash: row.BindingHash, nonce: row.Nonce, verifier: row.PkceVerifier}
	if row.MaxAge != nil {
		pending.maxAge = time.Duration(*row.MaxAge) * time.Second
	}
	claims, failed := verifySignIn(ctx, idp, b.redirectURI(providerName), providerName, params, binding, pending, b.clock.Now())
	if failed != nil {
		return refuse(failed.reason, failed.detail, failed.err)
	}
	secret, err := credential.New(credential.BrowserSession, "", org)
	if err != nil {
		return BrowserSignIn{}, err
	}
	out := BrowserSignIn{Org: org, Next: row.NextPath}
	err = b.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		u, err := q.UserByIdentity(ctx, org, claims.Issuer, claims.Subject)
		switch {
		case db.IsNoRows(err):
			out.Reason = "NOT_A_MEMBER"
			return nil
		case err != nil:
			return err
		case td.AccountState(u.State) != td.Enabled:
			out.Reason = "USER_DISABLED"
			return nil
		}
		email := td.NormalizeEmail(td.SanitizeClaim(claims.Email, td.MaxEmailLen))
		if err := q.RecordLogin(ctx, dbq.RecordLoginParams{
			OrgID: org, ID: u.ID, Email: email, DisplayName: td.SanitizeClaim(claims.Name, td.MaxNameLen),
		}); err != nil {
			return err
		}
		bs, err := tapp.Bindings(ctx, q, org, td.PrincipalRef{Kind: td.KindUser, ID: u.ID})
		if err != nil {
			return err
		}
		if err := q.EndDeadBrowserSessions(ctx, org, u.ID, int32(BrowserSessionIdle/time.Second)); err != nil {
			return err
		}
		if _, err := q.EndExcessBrowserSessions(ctx, org, u.ID, MaxBrowserSessions-1); err != nil {
			return err
		}
		var authTime *time.Time
		if !claims.AuthTime.IsZero() {
			authTime = &claims.AuthTime
		}
		out.Session = ids.NewV7()
		if _, err := q.InsertBrowserSession(ctx, dbq.InsertBrowserSessionParams{
			OrgID: org, ID: out.Session, UserID: u.ID, SecretHash: secret.Hash(), Provider: providerName, AuthTime: authTime,
			RolesDigest: rolesDigest(bs), UserAgent: td.SanitizeClaim(meta.UserAgent, 256), ClientIp: trim(meta.IP, 64),
			TtlSeconds: int32(BrowserSessionLifetime / time.Second),
		}); err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "authn.login", Actor: evdomain.Actor{Type: string(td.KindUser), ID: u.ID.String()}, Outcome: audit.Success,
			Object:  &audit.Object{Type: "browser_session", ID: out.Session.String()},
			Details: map[string]string{"method": "browser", "provider": providerName, "recent": boolString(row.MaxAge != nil)},
		})
		return err
	})
	if err != nil {
		return BrowserSignIn{}, err
	}
	if out.Reason != "" {
		return refuse(out.Reason, "", nil)
	}
	out.Secret = secret.Reveal()
	return out, nil
}

// BrowserSession is a caller authenticated by a browser session cookie.
type BrowserSession struct {
	tapp.Caller
	ID ids.UUID
	// AuthTime is when the provider last authenticated the person (zero when
	// the provider did not say); StepUpAt and StepUpCredential record the
	// last WebAuthn step-up on this session.
	AuthTime         time.Time
	StepUpAt         time.Time
	StepUpCredential ids.UUID
	// Now is the database clock at authentication, for age checks.
	Now time.Time
	// Rotated is set when this request rotated the session secret: the
	// caller must replace the cookie with it.
	Rotated string
	// secretHash is the hash of the presented secret when it is the
	// current one (empty inside the rotation grace).
	secretHash []byte
}

// SignedInWithin reports whether the provider authenticated the person no
// longer than d ago (by the database clock).
func (s BrowserSession) SignedInWithin(d time.Duration) bool {
	return !s.AuthTime.IsZero() && !s.AuthTime.Before(s.Now.Add(-d))
}

// SteppedUpWithin reports whether this session stepped up no longer than d
// ago (by the database clock).
func (s BrowserSession) SteppedUpWithin(d time.Duration) bool {
	return !s.StepUpAt.IsZero() && !s.StepUpAt.Before(s.Now.Add(-d))
}

// User is the session's user id.
func (s BrowserSession) User() ids.UUID { return s.Principal.ID }

// Authenticate resolves a session cookie (HR-150). In one tenant
// transaction it checks the org, the user, the session state, the idle and
// absolute limits by the database clock and, for a replaced secret, the
// rotation grace: a replaced secret presented after the grace ends the
// session (theft signal). A session whose user's role bindings changed is
// rotated. Every failure returns ErrUnauthenticated; the reason is logged.
func (b *Browser) Authenticate(ctx context.Context, cookie string) (BrowserSession, error) {
	tok, err := credential.Parse(credential.BrowserSession, cookie)
	if err != nil {
		return b.authFailed(ctx, reject("session_malformed"))
	}
	org := tok.Org()
	var out BrowserSession
	var fail error
	err = b.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := orgActive(ctx, q, org); err != nil {
			return err
		}
		s, err := q.BrowserSessionBySecret(ctx, dbq.BrowserSessionBySecretParams{
			OrgID: org, SecretHash: tok.Hash(), GraceSeconds: int32(RotationGrace / time.Second),
			IdleSeconds: int32(BrowserSessionIdle / time.Second),
		})
		switch {
		case db.IsNoRows(err):
			return reject("session_unknown")
		case err != nil:
			return err
		case s.State != "ACTIVE":
			return reject("session_ended")
		}
		end := func(reason, why string) error {
			if _, err := q.EndBrowserSession(ctx, &reason, org, s.ID); err != nil {
				return err
			}
			if reason == "REUSE" {
				if _, err := audit.Record(ctx, tx, audit.Event{
					Name: "authn.session_reuse", Actor: evdomain.Actor{Type: "system", ID: "session-reuse-detector"},
					Outcome: audit.Success, ReasonCode: reason, Object: &audit.Object{Type: "browser_session", ID: s.ID.String()},
					Details: map[string]string{"user": s.UserID.String()},
				}); err != nil {
					return err
				}
			}
			fail = reject(why) // commit the end, then refuse
			return nil
		}
		switch {
		case !s.Current && !s.WithinGrace:
			return end("REUSE", "session_secret_reused")
		case !s.WithinLifetime:
			return end("EXPIRED", "session_expired")
		case !s.WithinIdle:
			return end("IDLE", "session_idle")
		case td.AccountState(s.UserState) != td.Enabled:
			return reject("user_disabled")
		}
		p := td.PrincipalRef{Kind: td.KindUser, ID: s.UserID}
		bs, err := tapp.Bindings(ctx, q, org, p)
		if err != nil {
			return err
		}
		out = BrowserSession{
			Caller: tapp.Caller{
				Subject: td.Subject{Org: org, Principal: p, Bindings: bs}, Credential: CredBrowserSession, Session: s.ID,
			},
			ID: s.ID, Now: s.DbNow,
		}
		if s.AuthTime != nil {
			out.AuthTime = *s.AuthTime
		}
		if s.Current {
			out.secretHash = tok.Hash()
		}
		if s.StepUpAt != nil && s.StepUpCredentialID != nil {
			out.StepUpAt, out.StepUpCredential = *s.StepUpAt, *s.StepUpCredentialID
		}
		// A role change rotates the secret (SB-2). A request carrying the
		// previous secret inside the grace never rotates again.
		if digest := rolesDigest(bs); s.Current && string(digest) != string(s.RolesDigest) {
			secret, err := rotateSession(ctx, q, org, s.ID, tok.Hash(), digest)
			if err != nil {
				return err
			}
			out.Rotated = secret
			if secret != "" {
				out.secretHash = credential.HashString(secret)
			}
			return nil
		}
		if s.Touch {
			return q.TouchBrowserSession(ctx, org, s.ID)
		}
		return nil
	})
	if err == nil {
		err = fail
	}
	if err != nil {
		return b.authFailed(ctx, err)
	}
	return out, nil
}

// rotateSession replaces a session's secret, keeping the old one for the
// grace period. A lost race (another request rotated first) returns "": the
// caller keeps its cookie, which is now inside the grace.
func rotateSession(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID, oldHash, digest []byte) (string, error) {
	next, err := credential.New(credential.BrowserSession, "", org)
	if err != nil {
		return "", err
	}
	n, err := q.RotateBrowserSession(ctx, dbq.RotateBrowserSessionParams{
		OrgID: org, ID: id, NewHash: next.Hash(), OldHash: oldHash, RolesDigest: digest,
	})
	if err != nil || n == 0 {
		return "", err
	}
	return next.Reveal(), nil
}

func (b *Browser) authFailed(ctx context.Context, err error) (BrowserSession, error) {
	var f failure
	if errors.As(err, &f) {
		b.log.WarnContext(ctx, "authn.browser_session_rejected", slog.String(pclog.KeyOutcome, "rejected"), slog.String("reason", f.reason))
		return BrowserSession{}, ErrUnauthenticated
	}
	return BrowserSession{}, err
}

// Logout ends the session of a cookie. An unknown or ended cookie is not an
// error: the result is the same, signed out.
func (b *Browser) Logout(ctx context.Context, cookie string) error {
	s, err := b.Authenticate(ctx, cookie)
	if errors.Is(err, ErrUnauthenticated) {
		return nil
	}
	if err != nil {
		return err
	}
	return b.end(ctx, s, s.ID, "LOGOUT")
}

// SessionInfo describes one browser session to its user.
type SessionInfo struct {
	ID                  ids.UUID
	Provider            string
	UserAgent, ClientIP string // untrusted, as observed
	Live, Current       bool
	State, EndReason    string
	CreatedAt, LastSeen time.Time
	ExpiresAt           time.Time
	AuthTime, StepUpAt  *time.Time
	EndedAt             *time.Time
}

// ListSessions lists the caller's own browser sessions, newest first.
func (b *Browser) ListSessions(ctx context.Context, s BrowserSession) ([]SessionInfo, error) {
	var out []SessionInfo
	err := b.pool.InTenantTx(ctx, s.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListUserBrowserSessions(ctx, int32(BrowserSessionIdle/time.Second), s.Org, s.User())
		if err != nil {
			return err
		}
		out = make([]SessionInfo, len(rows))
		for i, r := range rows {
			out[i] = SessionInfo{
				ID: r.ID, Provider: r.Provider, UserAgent: r.UserAgent, ClientIP: r.ClientIp, Live: r.Live, Current: r.ID == s.ID,
				State: r.State, EndReason: deref(r.EndReason), CreatedAt: r.CreatedAt, LastSeen: r.LastSeenAt,
				ExpiresAt: r.ExpiresAt, AuthTime: r.AuthTime, StepUpAt: r.StepUpAt, EndedAt: r.EndedAt,
			}
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// ErrSessionNotFound is returned for a session id that is not the caller's.
var ErrSessionNotFound = errors.New("authn: no such session")

// RevokeSession ends one of the caller's own sessions.
func (b *Browser) RevokeSession(ctx context.Context, s BrowserSession, id ids.UUID) error {
	return b.end(ctx, s, id, "REVOKED")
}

func (b *Browser) end(ctx context.Context, s BrowserSession, id ids.UUID, reason string) error {
	return b.pool.InTenantTx(ctx, s.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		n, err := q.EndUserBrowserSession(ctx, dbq.EndUserBrowserSessionParams{Reason: &reason, OrgID: s.Org, ID: id, UserID: s.User()})
		if err != nil {
			return err
		}
		if n == 0 {
			exists, err := q.UserBrowserSessionExists(ctx, s.Org, id, s.User())
			if err != nil {
				return err
			}
			if !exists {
				return ErrSessionNotFound // another user's or org's id: indistinguishable from none
			}
			return nil // already ended
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "authn.session_ended", Actor: s.Actor(), Outcome: audit.Success, ReasonCode: reason,
			Object: &audit.Object{Type: "browser_session", ID: id.String()},
		})
		return err
	})
}

// rolesDigest summarizes role bindings so a change can be detected: the
// SHA-256 of the sorted "role scope-type scope-id" lines.
func rolesDigest(bs []td.Binding) []byte {
	lines := make([]string, len(bs))
	for i, b := range bs {
		lines[i] = string(b.Role) + " " + string(b.Scope.Type) + " " + b.Scope.ID.String()
	}
	slices.Sort(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return sum[:]
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// Profile is what the account page shows about its user.
type Profile struct {
	Org         ids.OrgID
	User        ids.UUID
	Email, Name string
}

// Profile returns the caller's own profile.
func (b *Browser) Profile(ctx context.Context, s BrowserSession) (Profile, error) {
	var out Profile
	err := b.pool.InTenantTx(ctx, s.Org, func(ctx context.Context, tx db.TenantTx) error {
		u, err := dbq.New(tx).GetUser(ctx, s.Org, s.User())
		if err != nil {
			return err
		}
		out = Profile{Org: s.Org, User: u.ID, Email: u.Email, Name: u.DisplayName}
		return nil
	}, db.ReadOnly())
	return out, err
}
