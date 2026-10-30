// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/assertion"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/authn/token"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Device-flow parameters (G0 brief items 7 and 8).
const (
	DeviceCodeTTL        = 10 * time.Minute
	PollInterval         = 5 * time.Second
	SessionTTL           = 8 * time.Hour
	MaxAuthorizeAttempts = 5
	// CLIClientID is the client id of pclaw; each CLI proves possession of
	// its own device key, so the shared id grants nothing by itself.
	CLIClientID = "pclaw"
	// DevicePath is the browser page where a person confirms a code.
	DevicePath = "/device"
	// CallbackPath is the per-provider OIDC redirect path prefix.
	CallbackPath = "/oauth2/callback/"
)

// Device-flow OAuth errors (RFC 8628 §3.5).
var (
	ErrAuthorizationPending = &OAuthError{Code: "authorization_pending", Description: "the user has not finished signing in", Status: 400}
	ErrAccessDenied         = &OAuthError{Code: "access_denied", Description: "the sign-in was denied", Status: 400}
	ErrExpiredToken         = &OAuthError{Code: "expired_token", Description: "the device code expired", Status: 400}
)

// IDClaims are the verified claims of an ID token. AuthTime is the zero
// time when the provider did not send auth_time.
type IDClaims struct {
	Issuer, Subject string
	Email           string
	EmailVerified   bool
	Name            string
	Nonce           string
	AuthTime        time.Time
}

// AuthRequest is one authorization request to a provider: state, nonce and
// PKCE verifier are fresh per request. MaxAge, when positive, asks the
// provider to re-authenticate a person who signed in longer ago (OIDC Core
// 3.1.2.1); the ID token must then carry auth_time.
type AuthRequest struct {
	State, Nonce, Verifier, RedirectURI string
	MaxAge                              time.Duration
	// ForceLogin asks for prompt=login and explicit max_age=0.
	ForceLogin bool
}

// SubjectClaims are the verified claims of an RFC 8693 subject token
// (HR-145): who it proves, and what makes it single use.
type SubjectClaims struct {
	Issuer, Subject string
	// JTI is empty when the token has none.
	JTI       string
	ExpiresAt time.Time
}

// IdP is an OpenID provider PantherClaw is a relying party of
// (adapters/oidc). Exchange verifies the ID token's signature (RS256, ES256
// or EdDSA), iss, aud, azp and expiry; the caller checks the nonce.
type IdP interface {
	Name() string
	Issuer() string
	// RequireIssParam reports whether the provider advertises RFC 9207: the
	// authorization response must then carry its iss.
	RequireIssParam(ctx context.Context) (bool, error)
	// TrustEmail reports whether the provider's email claim is trusted even
	// without email_verified (an IdP-managed directory).
	TrustEmail() bool
	AuthCodeURL(ctx context.Context, req AuthRequest) (string, error)
	Exchange(ctx context.Context, code, verifier, redirectURI string) (IDClaims, error)
}

// Device implements the CLI device login (ADR-0016): device authorization,
// the browser confirmation and OIDC callback, the device-code and refresh
// grants, and revocation.
type Device struct {
	pool      *db.Pool
	tokens    *token.Service
	issuer    string
	audiences []string
	idps      providers
	clock     clock.Clock
	log       *slog.Logger
}

// NewDevice returns the device-flow use cases for the given providers.
func NewDevice(pool *db.Pool, tokens *token.Service, issuer string, idps []IdP, clk clock.Clock, log *slog.Logger) *Device {
	if log == nil {
		log = pclog.Discard()
	}
	return &Device{
		pool: pool, tokens: tokens, issuer: issuer, audiences: []string{issuer, issuer + TokenPath},
		idps: newProviders(idps), clock: clk, log: log,
	}
}

// WithOrgProviders resolves organizations' own providers on each step of
// a device login (G0 M18 D155).
func (d *Device) WithOrgProviders(r OrgIdPs) *Device {
	d.idps.orgs = r
	return d
}

// RedirectURI is the callback URL registered at the provider.
func (d *Device) RedirectURI(provider string) string { return d.issuer + CallbackPath + provider }

// DeviceStart is a device authorization request from the CLI.
type DeviceStart struct {
	Org        string
	DeviceJWK  string
	DeviceName string
	Invitation string
	Provider   string
	ClientIP   string
}

// DeviceAuthorization is the RFC 8628 §3.2 response.
type DeviceAuthorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// Start begins a device login for an org. The device key must be an
// Ed25519 public JWK: every later step proves possession of it.
func (d *Device) Start(ctx context.Context, in DeviceStart) (DeviceAuthorization, error) {
	if in.Org == "" || !d.idps.any() {
		return DeviceAuthorization{}, ErrInvalidRequest
	}
	org, err := ids.Parse[ids.Org](in.Org)
	if err != nil {
		return DeviceAuthorization{}, ErrInvalidRequest
	}
	idp, ok, err := d.idps.forOrg(ctx, org, in.Provider)
	if err != nil {
		return DeviceAuthorization{}, err
	}
	if !ok {
		return DeviceAuthorization{}, ErrInvalidRequest
	}
	key, err := assertion.ParsePublicJWK(assertion.EdDSA, []byte(in.DeviceJWK))
	if err != nil {
		return DeviceAuthorization{}, ErrInvalidRequest
	}
	code, err := credential.New(credential.DeviceCode, "", org)
	if err != nil {
		return DeviceAuthorization{}, err
	}
	var out DeviceAuthorization
	err = d.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := orgActive(ctx, q, org); err != nil {
			return ErrInvalidRequest // no org-existence oracle beyond "invalid request"
		}
		var invitation *ids.UUID
		if in.Invitation != "" {
			tok, err := credential.Parse(credential.Invitation, in.Invitation)
			if err != nil || tok.Org() != org {
				return ErrInvalidGrant
			}
			id, err := q.PendingInvitationByHash(ctx, org, tok.Hash())
			if err != nil {
				return notFoundAs(err, ErrInvalidGrant)
			}
			invitation = &id
		}
		for range 5 {
			uc, err := credential.NewUserCode()
			if err != nil {
				return err
			}
			_, err = q.InsertDeviceCode(ctx, dbq.InsertDeviceCodeParams{
				OrgID: org, ID: ids.NewV7(), CodeHash: code.Hash(), UserCode: uc, DeviceJkt: key.Thumbprint,
				DeviceJwk: key.Canonical, DeviceName: td.SanitizeClaim(in.DeviceName, 64), RequestedIp: trim(in.ClientIP, 64),
				InvitationID: invitation, Provider: ptr(idp.Name()), TtlSeconds: int32(DeviceCodeTTL.Seconds()),
			})
			if db.IsNoRows(err) {
				continue // ON CONFLICT DO NOTHING skipped a user-code collision: draw again
			}
			if err != nil {
				return err
			}
			verify := d.issuer + DevicePath + "?org=" + url.QueryEscape(org.String())
			out = DeviceAuthorization{
				DeviceCode: code.Reveal(), UserCode: credential.FormatUserCode(uc),
				VerificationURI: verify, VerificationURIComplete: verify + "&user_code=" + credential.FormatUserCode(uc),
				ExpiresIn: int(DeviceCodeTTL.Seconds()), Interval: int(PollInterval.Seconds()),
			}
			return nil
		}
		return errors.New("authn: could not allocate a user code")
	})
	return out, err
}

// DevicePrompt is what the confirmation page shows (RFC 8628 §5.4).
type DevicePrompt struct {
	Org                    ids.OrgID
	UserCode               string
	DeviceName, IP         string
	Provider               string
	RequestedAt, ExpiresAt time.Time
	Invited                bool
}

// ErrUnknownCode is shown when a user code is wrong or expired.
var ErrUnknownCode = errors.New("authn: unknown or expired code")

// Prompt looks up an open device code by the code the person typed.
func (d *Device) Prompt(ctx context.Context, orgParam, userCode string) (DevicePrompt, error) {
	org, err := ids.Parse[ids.Org](orgParam)
	if err != nil {
		return DevicePrompt{}, ErrUnknownCode
	}
	uc, ok := credential.NormalizeUserCode(userCode)
	if !ok {
		return DevicePrompt{}, ErrUnknownCode
	}
	var out DevicePrompt
	err = d.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		r, err := dbq.New(tx).OpenDeviceCodeByUserCode(ctx, org, uc)
		if err != nil {
			return notFoundAs(err, ErrUnknownCode)
		}
		out = DevicePrompt{
			Org: org, UserCode: credential.FormatUserCode(uc), DeviceName: r.DeviceName, IP: r.RequestedIp,
			Provider: deref(r.Provider), RequestedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, Invited: r.InvitationID != nil,
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// Redirect sends the browser to the provider; Binding must be set as an
// HttpOnly cookie and presented at the callback.
type Redirect struct {
	URL     string
	Binding string
}

// Confirm starts the provider login for a confirmed code: a fresh OAuth
// state, nonce, PKCE verifier and browser binding are stored (hashed where
// they are compared) and the code moves to AUTHORIZING.
func (d *Device) Confirm(ctx context.Context, orgParam, userCode string) (Redirect, error) {
	p, err := d.Prompt(ctx, orgParam, userCode)
	if err != nil {
		return Redirect{}, err
	}
	idp, ok, err := d.idps.forOrg(ctx, p.Org, p.Provider)
	if err != nil {
		return Redirect{}, err
	}
	if !ok || p.Provider == "" {
		return Redirect{}, ErrUnknownCode
	}
	state, err := credential.New(credential.OAuthState, "", p.Org)
	if err != nil {
		return Redirect{}, err
	}
	nonce, err1 := credential.Secret()
	verifier, err2 := credential.Secret()
	binding, err3 := credential.Secret()
	if err := errors.Join(err1, err2, err3); err != nil {
		return Redirect{}, err
	}
	uc, _ := credential.NormalizeUserCode(p.UserCode)
	err = d.pool.InTenantTx(ctx, p.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.OpenDeviceCodeByUserCode(ctx, p.Org, uc)
		if err != nil {
			return notFoundAs(err, ErrUnknownCode)
		}
		n, err := q.AuthorizeDeviceCode(ctx, dbq.AuthorizeDeviceCodeParams{
			OrgID: p.Org, ID: r.ID, OauthStateHash: state.Hash(), BindingHash: credential.HashString(binding),
			Nonce: &nonce, PkceVerifier: &verifier,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrUnknownCode // expired, closed or too many attempts
		}
		return nil
	})
	if err != nil {
		return Redirect{}, err
	}
	u, err := idp.AuthCodeURL(ctx, AuthRequest{State: state.Reveal(), Nonce: nonce, Verifier: verifier, RedirectURI: d.RedirectURI(idp.Name())})
	if err != nil {
		return Redirect{}, err
	}
	return Redirect{URL: u, Binding: binding}, nil
}

// Outcome of the browser leg, for the result page.
type Outcome struct {
	Approved bool
	// Reason is a stable code: NOT_A_MEMBER, USER_DISABLED,
	// INVITATION_INVALID, EMAIL_MISMATCH, IDP_ERROR, LOGIN_FAILED.
	Reason string
	Email  string
}

// ErrBadCallback is returned when a callback cannot be tied to an open
// device login (unknown, reused or expired state).
var ErrBadCallback = errors.New("authn: invalid or expired sign-in response")

// Callback completes the provider login. The state is consumed first (single
// use); then the browser binding, the RFC 9207 iss parameter, the code
// exchange with PKCE, the ID token and its nonce are checked; finally the
// identity is mapped to a user of the org (or an invitation is accepted)
// and the device code is approved. After the state is consumed every
// failure denies the device code.
func (d *Device) Callback(ctx context.Context, providerName string, params url.Values, binding string) (Outcome, error) {
	state, err := credential.Parse(credential.OAuthState, params.Get("state"))
	if err != nil {
		return Outcome{}, ErrBadCallback
	}
	org := state.Org()
	// The org's providers now: one disabled since the login started no
	// longer completes it (D155).
	idp, ok, err := d.idps.forOrg(ctx, org, providerName)
	if err != nil {
		return Outcome{}, err
	}
	if !ok || providerName == "" {
		return Outcome{}, ErrBadCallback
	}
	var row dbq.ConsumeDeviceStateRow
	err = d.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		row, err = dbq.New(tx).ConsumeDeviceState(ctx, org, state.Hash())
		return notFoundAs(err, ErrBadCallback)
	})
	if err != nil {
		return Outcome{}, err
	}
	deny := func(reason string, attrs ...slog.Attr) (Outcome, error) {
		d.log.LogAttrs(ctx, slog.LevelWarn, "authn.device_login_denied",
			append([]slog.Attr{slog.String("reason", reason), slog.String("org", org.String()), slog.String("provider", providerName)}, attrs...)...)
		err := d.pool.InTenantTx(context.WithoutCancel(ctx), org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := dbq.New(tx).DenyDeviceCode(ctx, &reason, org, row.ID)
			return err
		})
		return Outcome{Reason: reason}, err
	}
	claims, failed := verifySignIn(ctx, idp, d.RedirectURI(providerName), providerName, params, binding, pendingSignIn{
		provider: deref(row.Provider), bindingHash: row.BindingHash, nonce: row.Nonce, verifier: row.PkceVerifier,
	}, d.clock.Now())
	if failed != nil {
		attrs := []slog.Attr{slog.String("detail", failed.detail)}
		if failed.err != nil {
			attrs = append(attrs, pclog.Err(failed.err))
		}
		return deny(failed.reason, attrs...)
	}
	var out Outcome
	err = d.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = d.approve(ctx, tx, org, idp, row, claims)
		return err
	})
	if err != nil {
		return Outcome{}, err
	}
	if !out.Approved {
		return deny(out.Reason)
	}
	return out, nil
}

// approve maps the identity to a user (accepting the device code's
// invitation for a new user) and approves the device code.
func (d *Device) approve(ctx context.Context, tx db.TenantTx, org ids.OrgID, idp IdP, row dbq.ConsumeDeviceStateRow, c IDClaims) (Outcome, error) {
	q := dbq.New(tx)
	email := td.NormalizeEmail(td.SanitizeClaim(c.Email, td.MaxEmailLen))
	name := td.SanitizeClaim(c.Name, td.MaxNameLen)
	u, err := q.UserByIdentity(ctx, org, c.Issuer, c.Subject)
	switch {
	case err == nil:
		if td.AccountState(u.State) != td.Enabled {
			return Outcome{Reason: "USER_DISABLED"}, nil
		}
		if err := q.RecordLogin(ctx, dbq.RecordLoginParams{OrgID: org, ID: u.ID, Email: email, DisplayName: name}); err != nil {
			return Outcome{}, err
		}
	case !db.IsNoRows(err):
		return Outcome{}, err
	case row.InvitationID == nil:
		return Outcome{Reason: "NOT_A_MEMBER"}, nil
	default:
		var reason string
		u, reason, err = d.acceptInvitation(ctx, q, tx, org, idp, *row.InvitationID, c, email, name)
		if err != nil || reason != "" {
			return Outcome{Reason: reason}, err
		}
	}
	n, err := q.ApproveDeviceCode(ctx, &u.ID, org, row.ID)
	if err != nil {
		return Outcome{}, err
	}
	if n == 0 {
		return Outcome{Reason: "LOGIN_FAILED"}, nil
	}
	_, err = audit.Record(ctx, tx, audit.Event{
		Name: "authn.login", Actor: evdomain.Actor{Type: string(td.KindUser), ID: u.ID.String()}, Outcome: audit.Success,
		Object:  &audit.Object{Type: "user", ID: u.ID.String()},
		Details: map[string]string{"method": "device_code", "provider": idp.Name(), "device_code": row.ID.String()},
	})
	return Outcome{Approved: true, Email: email}, err
}

// acceptInvitation creates the user for a pending invitation, grants its
// org-scope roles and marks it accepted. A MEMBER invitation (and a
// BOOTSTRAP one that names an email) requires the provider to assert that
// email, verified or from a trusted directory.
func (d *Device) acceptInvitation(ctx context.Context, q *dbq.Queries, tx db.TenantTx, org ids.OrgID, idp IdP,
	invID ids.UUID, c IDClaims, email, name string,
) (dbq.PcUser, string, error) {
	inv, err := q.LockInvitation(ctx, org, invID)
	if err != nil {
		return dbq.PcUser{}, "", err
	}
	if inv.State != "PENDING" || !inv.Live {
		return dbq.PcUser{}, "INVITATION_INVALID", nil
	}
	if inv.Email != "" && (email != inv.Email || (!c.EmailVerified && !idp.TrustEmail())) {
		return dbq.PcUser{}, "EMAIL_MISMATCH", nil
	}
	u, err := q.InsertUser(ctx, dbq.InsertUserParams{
		OrgID: org, ID: ids.NewV7(), Issuer: c.Issuer, Subject: c.Subject, Email: email, DisplayName: name,
	})
	if err != nil {
		return dbq.PcUser{}, "", err
	}
	for _, r := range inv.Roles {
		if _, err := td.CheckBindable(td.RoleName(r), td.KindUser, td.ScopeOrg); err != nil {
			return dbq.PcUser{}, "", err
		}
		if _, err := q.InsertRoleBinding(ctx, dbq.InsertRoleBindingParams{
			OrgID: org, ID: ids.NewV7(), Role: r, UserID: &u.ID, ScopeType: string(td.ScopeOrg), CreatedBy: "invitation:" + inv.ID.String(),
		}); err != nil {
			return dbq.PcUser{}, "", err
		}
	}
	if n, err := q.AcceptInvitation(ctx, &u.ID, org, inv.ID); err != nil || n == 0 {
		return dbq.PcUser{}, "INVITATION_INVALID", err
	}
	actor := evdomain.Actor{Type: string(td.KindUser), ID: u.ID.String()}
	for _, ev := range []audit.Event{
		{Name: "access.user_created", Object: &audit.Object{Type: "user", ID: u.ID.String()}, Details: map[string]string{"provider": idp.Name()}},
		{
			Name: "access.invitation_accepted", Object: &audit.Object{Type: "invitation", ID: inv.ID.String()},
			Details: map[string]string{"kind": inv.Kind, "roles": joinStrings(inv.Roles)},
		},
	} {
		ev.Actor, ev.Outcome = actor, audit.Success
		if _, err := audit.Record(ctx, tx, ev); err != nil {
			return dbq.PcUser{}, "", err
		}
	}
	return u, "", nil
}

// deviceProof verifies the CLI's client assertion, signed with the device
// key registered at Start, and records its jti.
func (d *Device) deviceProof(ctx context.Context, q *dbq.Queries, org ids.OrgID, jwk []byte, form url.Values) error {
	if form.Get("client_id") != CLIClientID || form.Get("client_assertion_type") != AssertionType {
		return reject("device_assertion_missing")
	}
	pk, err := assertion.ParsePublicJWK(assertion.EdDSA, jwk)
	if err != nil {
		return err
	}
	v, err := assertion.Verify(form.Get("client_assertion"), pk, assertion.Expect{
		ClientID: CLIClientID, Audiences: d.audiences, Now: d.clock.Now(),
	})
	if err != nil {
		return reject("device_assertion_invalid")
	}
	n, err := q.InsertAuthReplay(ctx, dbq.InsertAuthReplayParams{OrgID: org, Issuer: "device:" + pk.Thumbprint, Jti: v.JTI, ExpiresAt: v.ExpiresAt})
	if err != nil {
		return err
	}
	if n == 0 {
		return reject("device_assertion_replayed")
	}
	return nil
}

// DeviceCodeGrant exchanges an approved device code for a CLI session: an
// access token and a refresh token, both usable only with the device key.
func (d *Device) DeviceCodeGrant(ctx context.Context, form url.Values) (TokenResponse, error) {
	code, err := credential.Parse(credential.DeviceCode, form.Get("device_code"))
	if err != nil {
		return TokenResponse{}, ErrInvalidGrant
	}
	org := code.Org()
	var out TokenResponse
	var oauthErr error
	err = d.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		p, err := q.PollDeviceCode(ctx, org, int32(PollInterval.Seconds()), code.Hash())
		if err != nil {
			return notFoundAs(err, ErrInvalidGrant)
		}
		switch {
		case p.TooFast:
			oauthErr = ErrSlowDown // commit last_polled_at
			return nil
		case !p.Live && p.State != "CONSUMED":
			return ErrExpiredToken
		case p.State == "PENDING" || p.State == "AUTHORIZING":
			oauthErr = ErrAuthorizationPending
			return nil
		case p.State == "DENIED":
			return ErrAccessDenied
		case p.State != "APPROVED" || p.UserID == nil:
			return ErrInvalidGrant
		}
		if err := d.deviceProof(ctx, q, org, p.DeviceJwk, form); err != nil {
			return err
		}
		if n, err := q.ConsumeDeviceCode(ctx, org, p.ID); err != nil {
			return err
		} else if n == 0 {
			return ErrInvalidGrant
		}
		u, err := q.GetUser(ctx, org, *p.UserID)
		if err != nil || td.AccountState(u.State) != td.Enabled {
			return errors.Join(err, ErrAccessDenied)
		}
		out, err = d.newSession(ctx, tx, q, org, u.ID, p.DeviceJkt, p.DeviceJwk, p.DeviceName)
		return err
	})
	if err == nil {
		err = oauthErr
	}
	return out, d.oauthResult(ctx, err)
}

// oauthResult logs rejected credentials and maps them to invalid_grant.
func (d *Device) oauthResult(ctx context.Context, err error) error {
	var f failure
	if errors.As(err, &f) {
		d.log.WarnContext(ctx, "authn.token_failed", slog.String("error", "invalid_grant"), slog.String("reason", f.reason))
		return ErrInvalidGrant
	}
	return err
}

func (d *Device) newSession(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, user ids.UUID, jkt string, jwk []byte, name string) (TokenResponse, error) {
	refresh, err := credential.New(credential.RefreshToken, "", org)
	if err != nil {
		return TokenResponse{}, err
	}
	sid := ids.NewV7()
	if _, err := q.InsertCLISession(ctx, dbq.InsertCLISessionParams{
		OrgID: org, ID: sid, UserID: user, DeviceJkt: jkt, DeviceJwk: jwk, DeviceName: name,
		RefreshHash: refresh.Hash(), TtlSeconds: int32(SessionTTL.Seconds()),
	}); err != nil {
		return TokenResponse{}, err
	}
	at, err := d.issue(org, user, sid)
	if err != nil {
		return TokenResponse{}, err
	}
	_, err = audit.Record(ctx, tx, audit.Event{
		Name: "authn.session_created", Actor: evdomain.Actor{Type: string(td.KindUser), ID: user.String()}, Outcome: audit.Success,
		Object: &audit.Object{Type: "cli_session", ID: sid.String()}, Details: map[string]string{"device_jkt": jkt},
	})
	at.RefreshToken = refresh.Reveal()
	return at, err
}

func (d *Device) issue(org ids.OrgID, user, session ids.UUID) (TokenResponse, error) {
	tok, _, err := d.tokens.Issue(token.Grant{
		Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user}, Session: session, ClientID: CLIClientID,
	}, d.clock.Now())
	if err != nil {
		return TokenResponse{}, err
	}
	return TokenResponse{AccessToken: tok, TokenType: "Bearer", ExpiresIn: int(token.TTL.Seconds())}, nil
}

// RefreshGrant rotates a CLI session's refresh token. The request must be
// signed with the session's device key. Presenting a refresh token that was
// already rotated is treated as theft: the session is revoked.
func (d *Device) RefreshGrant(ctx context.Context, form url.Values) (TokenResponse, error) {
	old, err := credential.Parse(credential.RefreshToken, form.Get("refresh_token"))
	if err != nil {
		return TokenResponse{}, ErrInvalidGrant
	}
	org := old.Org()
	var out TokenResponse
	var reuse bool
	err = d.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		s, err := q.SessionByRefresh(ctx, org, old.Hash())
		if db.IsNoRows(err) {
			prev, err := q.SessionByPreviousRefresh(ctx, org, old.Hash())
			if err != nil {
				return notFoundAs(err, ErrInvalidGrant)
			}
			reason := "REFRESH_REUSE"
			if _, err := q.RevokeSession(ctx, &reason, org, prev.ID); err != nil {
				return err
			}
			reuse = true
			_, err = audit.Record(ctx, tx, audit.Event{
				Name: "authn.session_revoked", Actor: evdomain.Actor{Type: "system", ID: "refresh-reuse-detector"},
				Outcome: audit.Success, ReasonCode: reason, Object: &audit.Object{Type: "cli_session", ID: prev.ID.String()},
				Details: map[string]string{"user": prev.UserID.String()},
			})
			return err // commit the revocation
		} else if err != nil {
			return err
		}
		if s.State != "ACTIVE" || !s.Live || td.AccountState(s.UserState) != td.Enabled {
			return ErrInvalidGrant
		}
		if err := d.deviceProof(ctx, q, org, s.DeviceJwk, form); err != nil {
			return err
		}
		next, err := credential.New(credential.RefreshToken, "", org)
		if err != nil {
			return err
		}
		n, err := q.RotateRefresh(ctx, dbq.RotateRefreshParams{OrgID: org, ID: s.ID, NewHash: next.Hash(), OldHash: old.Hash()})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrInvalidGrant
		}
		if out, err = d.issue(org, s.UserID, s.ID); err != nil {
			return err
		}
		out.RefreshToken = next.Reveal()
		return nil
	})
	if reuse {
		d.log.WarnContext(ctx, "authn.refresh_reuse", slog.String("org", org.String()))
		return TokenResponse{}, ErrInvalidGrant
	}
	return out, d.oauthResult(ctx, err)
}

// Revoke ends the CLI session of a refresh token (RFC 7009: the response is
// the same whether or not the token was valid).
func (d *Device) Revoke(ctx context.Context, refresh string) error {
	tok, err := credential.Parse(credential.RefreshToken, refresh)
	if err != nil {
		return nil //nolint:nilerr // RFC 7009: an unparsable token is answered like a valid one
	}
	return d.pool.InTenantTx(ctx, tok.Org(), func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		s, err := q.SessionByRefresh(ctx, tok.Org(), tok.Hash())
		if db.IsNoRows(err) {
			return nil
		} else if err != nil {
			return err
		}
		reason := "LOGOUT"
		if n, err := q.RevokeSession(ctx, &reason, tok.Org(), s.ID); err != nil || n == 0 {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "authn.session_revoked", Actor: evdomain.Actor{Type: string(td.KindUser), ID: s.UserID.String()},
			Outcome: audit.Success, ReasonCode: reason, Object: &audit.Object{Type: "cli_session", ID: s.ID.String()},
		})
		return err
	})
}

func notFoundAs(err, as error) error {
	if db.IsNoRows(err) {
		return as
	}
	return err
}

func ptr(s string) *string { return &s }

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func trim(s string, n int) string { //nolint:unparam // one bound today, a helper for every stored observed value
	if len(s) > n {
		return s[:n]
	}
	return s
}

func joinStrings(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}
