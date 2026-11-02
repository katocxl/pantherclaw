// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"time"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/idaccess/domain"
	"github.com/katocxl/pantherclaw/internal/idaccess/ports"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	runs "github.com/katocxl/pantherclaw/internal/runs/app"
)

// GrantAuthorizationCode is the grant a code is redeemed with.
const GrantAuthorizationCode = "authorization_code"

// Prefixes of the codes and refresh tokens this flow issues: the org they
// belong to follows, so the token endpoint finds the tenant before it hashes
// the secret.
const (
	CodePrefix    = "pcmc_"
	RefreshPrefix = "pcmr_"
)

var errInvalidScope = &authnapp.OAuthError{Code: "invalid_scope", Description: "a refresh keeps the run's scope", Status: 400}

// CodeTTL is how long an authorization code is redeemable (HR-628).
const CodeTTL = 60 * time.Second

// AuthorizeError is a refused authorization request. With Redirect it goes
// back to the client's redirect URI (RFC 6749 §4.1.2.1); without, the
// client or its redirect URI could not be trusted and the person sees it.
type AuthorizeError struct {
	Code, Description string
	Redirect          bool
}

func (e *AuthorizeError) Error() string { return e.Code + ": " + e.Description }

func pageError(desc string) *AuthorizeError {
	return &AuthorizeError{Code: "invalid_request", Description: desc}
}

func redirectError(code, desc string) *AuthorizeError {
	return &AuthorizeError{Code: code, Description: desc, Redirect: true}
}

// AuthorizeRequest is an authorization request's parameters (RFC 6749
// §4.1.1, RFC 7636, RFC 8707).
type AuthorizeRequest struct {
	ClientID, RedirectURI, State, CodeChallenge, Resource, Scope string
	HasScope                                                     bool
}

// AuthorizeParams are the parameters an authorization request carries;
// any other is ignored (RFC 6749 §3.1).
var AuthorizeParams = []string{"response_type", "client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "resource", "scope"}

// Consent is what the consent page states (D408.4, HR-628): the client by
// its URL and host and its UNTRUSTED name, the agent it acts as, the server
// it asks for, and that consenting creates no access.
type Consent struct {
	Request    AuthorizeRequest
	ClientURL  string
	ClientHost string
	// ClientName is the document's UNTRUSTED name; it is shown as such.
	ClientName string
	Agent      ids.UUID
	AgentName  string
	Connection string
	Resource   string
}

// CodeFlow is the authorization code flow for allow-listed MCP clients (G0
// M26 D402, D408.4; HR-628): PKCE S256 only, an exact redirect URI from the
// client's validated metadata document, a client the org allow-listed, a
// signed-in person and their consent. The person is the run's launcher; the
// run uses one of the grants that person already gave the client's agent,
// and nothing is created besides the run. Codes are single use and live 60
// seconds. Refresh tokens are stored as hashes, rotated on every use, bound
// to client, run and resource, and end with the run; reusing a rotated one
// kills its family and raises an audited event.
type CodeFlow struct {
	Pool      *db.Pool
	Documents ports.ClientDocuments
	Runs      RunStarter
	Tokens    ports.Minter
	// Notify tells the org's admins of a refresh token reuse; nil sends
	// nothing.
	Notify    Notifier
	PublicURL string
	Clock     clock.Clock
	Log       *slog.Logger
}

func (f *CodeFlow) log() *slog.Logger {
	if f.Log == nil {
		return pclog.Discard()
	}
	return f.Log
}

// ParseAuthorize reads an authorization request's parameters.
func ParseAuthorize(q url.Values) (AuthorizeRequest, *AuthorizeError) {
	for _, k := range AuthorizeParams {
		if len(q[k]) > 1 {
			return AuthorizeRequest{}, pageError("a parameter is repeated")
		}
	}
	r := AuthorizeRequest{
		ClientID: q.Get("client_id"), RedirectURI: q.Get("redirect_uri"), State: q.Get("state"),
		CodeChallenge: q.Get("code_challenge"), Resource: q.Get("resource"), Scope: q.Get("scope"),
	}
	_, r.HasScope = q["scope"]
	if r.ClientID == "" || r.RedirectURI == "" {
		return r, pageError("client_id and redirect_uri are required")
	}
	if len(r.State) > 512 || len(r.Scope) > 2048 {
		return r, pageError("a parameter is too long")
	}
	return r, nil
}

// checkRest checks what is redirected back when wrong, once the client and
// its redirect URI are trusted.
func checkRest(q url.Values, r AuthorizeRequest) *AuthorizeError {
	switch {
	case q.Get("response_type") != "code":
		return redirectError("unsupported_response_type", "only the code flow is supported")
	case q.Get("code_challenge_method") != "S256" || !validChallenge(r.CodeChallenge):
		return redirectError("invalid_request", "PKCE with S256 is required")
	case r.Resource == "":
		return redirectError("invalid_target", "the resource parameter is required")
	}
	return nil
}

func validChallenge(s string) bool {
	if len(s) != 43 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil
}

// Prepare checks an authorization request for org on behalf of a signed-in
// person, and returns what the consent page states.
func (f *CodeFlow) Prepare(ctx context.Context, org ids.OrgID, q url.Values) (Consent, error) {
	r, aerr := ParseAuthorize(q)
	if aerr != nil {
		return Consent{}, aerr
	}
	if !ValidClientURL(r.ClientID) {
		return Consent{}, pageError("the client is not identified by a metadata document URL")
	}
	var c Consent
	var client dbq.PcMcpClient
	var gatewayURL *string
	err := f.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		client, err = q.ActiveMcpClientByURL(ctx, org, r.ClientID)
		if db.IsNoRows(err) {
			return pageError("this organization has not allowed this client")
		} else if err != nil {
			return err
		}
		a, err := q.GetAgent(ctx, org, client.AgentID)
		if err != nil {
			return err
		}
		c.Agent, c.AgentName = a.ID, a.Name
		access, err := q.GetOrgMcpAccess(ctx, org)
		if err == nil && access.Enabled {
			gatewayURL = access.GatewayUrl
		} else if err != nil && !db.IsNoRows(err) {
			return err
		}
		return nil
	}, db.ReadOnly())
	if err != nil {
		return Consent{}, err
	}
	md, err := f.Documents.Fetch(ctx, r.ClientID)
	if err != nil {
		f.log().WarnContext(ctx, "idaccess.client_document_refused", slog.String("org", org.String()), slog.String("detail", err.Error()))
		return Consent{}, pageError("the client's metadata document could not be read or is not acceptable")
	}
	if !slices.Contains(md.RedirectURIs, r.RedirectURI) {
		return Consent{}, pageError("the redirect URI is not one the client's metadata document registers")
	}
	if aerr := checkRest(q, r); aerr != nil {
		return Consent{}, aerr
	}
	if gatewayURL == nil {
		return Consent{}, redirectError("access_denied", "MCP authorization is off for this organization")
	}
	conn, ok := domain.ConnectionOf(*gatewayURL, r.Resource)
	if !ok {
		return Consent{}, redirectError("invalid_target", "the resource is not a server of this organization's gateway")
	}
	u, _ := url.Parse(r.ClientID)
	c.Request, c.ClientURL, c.ClientHost, c.ClientName = r, r.ClientID, u.Host, md.Name
	c.Connection, c.Resource = conn, r.Resource
	return c, nil
}

// Issuer is the org's authorization server identifier, the iss parameter
// of every response (RFC 9207).
func (f *CodeFlow) Issuer(org ids.OrgID) string { return domain.IssuerID(f.PublicURL, org) }

// ErrorRedirect is where a redirectable refusal sends the browser.
func (f *CodeFlow) ErrorRedirect(org ids.OrgID, r AuthorizeRequest, e *AuthorizeError) string {
	v := url.Values{"error": {e.Code}, "error_description": {e.Description}, "iss": {f.Issuer(org)}}
	if r.State != "" {
		v.Set("state", r.State)
	}
	return withQuery(r.RedirectURI, v)
}

func withQuery(redirect string, v url.Values) string {
	u, err := url.Parse(redirect)
	if err != nil {
		return redirect
	}
	q := u.Query()
	for k, vs := range v {
		q[k] = vs
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func secret(prefix string, org ids.OrgID) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return prefix + org.String() + "_" + base64.RawURLEncoding.EncodeToString(b)
}

// orgOfSecret reads the org a code or refresh token names.
func orgOfSecret(prefix, s string) (ids.OrgID, bool) {
	rest, ok := strings.CutPrefix(s, prefix)
	if !ok || len(s) > 256 {
		return ids.OrgID{}, false
	}
	o, _, ok := strings.Cut(rest, "_")
	if !ok {
		return ids.OrgID{}, false
	}
	org, err := ids.Parse[ids.Org](o)
	return org, err == nil
}

func digest(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// Approve records the person's consent: the request is checked again, a
// code is stored by its hash and the redirect carries code, state and iss
// (RFC 9207). Deny sends access_denied back instead.
func (f *CodeFlow) Approve(ctx context.Context, o ids.OrgID, user ids.UUID, q url.Values) (string, error) {
	c, err := f.Prepare(ctx, o, q)
	if err != nil {
		return "", err
	}
	var scopeOps []string
	if c.Request.HasScope {
		if !scopeValid(c.Request.Scope) {
			return f.ErrorRedirect(o, c.Request, redirectError("invalid_scope", "the scope is not valid")), nil
		}
		// The raw values are kept; the token request resolves them against
		// the person's grants. An empty scope is none.
		scopeOps = strings.Fields(c.Request.Scope)
	}
	code := secret(CodePrefix, o)
	err = f.Pool.InTenantTx(ctx, o, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		client, err := q.ActiveMcpClientByURL(ctx, o, c.ClientURL)
		if err != nil {
			return err
		}
		if err := q.InsertMcpAuthorizationCode(ctx, dbq.InsertMcpAuthorizationCodeParams{
			OrgID: o, CodeHash: digest(code), ClientID: client.ID, UserID: user, RedirectUri: c.Request.RedirectURI,
			CodeChallenge: c.Request.CodeChallenge, Resource: c.Resource, ScopeOperations: scopeOps,
		}); err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "idaccess.consent_given", Actor: evdomain.Actor{Type: "user", ID: user.String()}, Outcome: audit.Success,
			Object:  &audit.Object{Type: "mcp_client", ID: client.ID.String()},
			Details: map[string]string{"client_url": c.ClientURL, "agent": c.Agent.String(), "resource": c.Resource},
		})
		return err
	})
	if err != nil {
		return "", err
	}
	v := url.Values{"code": {code}, "iss": {f.Issuer(o)}}
	if c.Request.State != "" {
		v.Set("state", c.Request.State)
	}
	return withQuery(c.Request.RedirectURI, v), nil
}

// Deny sends the person's refusal back to the client.
func (f *CodeFlow) Deny(ctx context.Context, o ids.OrgID, q url.Values) (string, error) {
	c, err := f.Prepare(ctx, o, q)
	if err != nil {
		return "", err
	}
	return f.ErrorRedirect(o, c.Request, redirectError("access_denied", "the person declined")), nil
}

// scopeValid reports whether a requested scope parses.
func scopeValid(scope string) bool {
	_, err := domain.ParseScope(scope, true)
	return err == nil
}

// verifierMatches checks a PKCE code verifier against its S256 challenge (RFC
// 7636 §4.6).
func verifierMatches(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for _, r := range verifier {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') && !strings.ContainsRune("-._~", r) {
			return false
		}
	}
	h := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(h[:])), []byte(challenge)) == 1
}

func (f *CodeFlow) fail(ctx context.Context, oe *authnapp.OAuthError, reason string, attrs ...slog.Attr) error {
	f.log().LogAttrs(ctx, slog.LevelWarn, "idaccess.token_failed",
		append([]slog.Attr{slog.String("error", oe.Code), slog.String("reason", reason)}, attrs...)...)
	return oe
}

// AuthorizationCode is the token endpoint's authorization_code grant.
func (f *CodeFlow) AuthorizationCode(ctx context.Context, form url.Values) (authnapp.TokenResponse, error) {
	if form.Get("client_assertion") != "" {
		// Clients are public: a key from a metadata document is never trusted (D408.2).
		return authnapp.TokenResponse{}, f.fail(ctx, authnapp.ErrInvalidClient, "client_authentication_unsupported")
	}
	code, clientURL := form.Get("code"), form.Get("client_id")
	org, ok := orgOfSecret(CodePrefix, code)
	if !ok || clientURL == "" {
		return authnapp.TokenResponse{}, f.fail(ctx, authnapp.ErrInvalidGrant, "code_malformed")
	}
	now := f.Clock.Now()
	var out authnapp.TokenResponse
	err := f.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		// The code is spent by the first request naming it, right or wrong.
		row, err := q.SpendMcpAuthorizationCode(ctx, org, digest(code))
		if db.IsNoRows(err) {
			return refuse(authnapp.ErrInvalidGrant, "code_unknown_used_or_expired")
		} else if err != nil {
			return err
		}
		client, err := q.GetMcpClient(ctx, org, row.ClientID)
		if err != nil {
			return err
		}
		switch {
		case client.ClientUrl != clientURL:
			return refuse(authnapp.ErrInvalidGrant, "client_mismatch")
		case client.State != "ACTIVE":
			return refuse(authnapp.ErrInvalidGrant, "client_removed")
		case form.Get("redirect_uri") != row.RedirectUri:
			return refuse(authnapp.ErrInvalidGrant, "redirect_uri_mismatch")
		case !verifierMatches(form.Get("code_verifier"), row.CodeChallenge):
			return refuse(authnapp.ErrInvalidGrant, "pkce")
		case form.Get("resource") != "" && form.Get("resource") != row.Resource:
			return refuse(authnapp.ErrInvalidGrant, "resource_mismatch")
		}
		scope, err := domain.ParseScope(strings.Join(row.ScopeOperations, " "), len(row.ScopeOperations) > 0)
		if err != nil {
			return refuse(authnapp.ErrInvalidGrant, "scope")
		}
		conn, err := f.liveResource(ctx, q, org, row.Resource)
		if err != nil {
			return err
		}
		agent, err := q.GetAgent(ctx, org, client.AgentID)
		if err != nil || agent.EnvironmentID == nil {
			return refuse(accessDenied(ReasonNoGrant, "no grant covers this agent"), "agent_unusable")
		}
		choice, err := chooseGrant(ctx, q, org, agent.ID, *agent.EnvironmentID, row.UserID, client.InstanceID, scope)
		if err != nil {
			return err
		}
		run, err := f.Runs.StartForIdentityTx(ctx, tx, runs.IdentityRunInput{
			Org: org, Agent: agent.ID, Instance: client.InstanceID, User: row.UserID,
			Grant: choice.Grant, Operations: choice.Operations, TaskRef: "mcp " + conn,
		})
		if err != nil {
			return refuse(accessDenied(ReasonNoGrant, "the grant can't be used"), "run_refused: "+err.Error())
		}
		out, err = f.issue(ctx, q, org, client, run.ID, run.EnvironmentID, run.ExpiresAt, conn, row.Resource, choice.Operations, ids.NewV7(), now)
		if err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "idaccess.token_issued", Actor: evdomain.Actor{Type: "user", ID: row.UserID.String()}, Outcome: audit.Success,
			Object: &audit.Object{Type: "run", ID: run.ID.String()},
			Details: map[string]string{
				"grant": "authorization_code", "client": client.ID.String(), "resource": row.Resource, "grant_id": choice.Grant.String(),
			},
		})
		return err
	})
	var r refusal
	if errors.As(err, &r) {
		return authnapp.TokenResponse{}, f.fail(ctx, r.oe, r.reason, slog.String("org", org.String()))
	}
	return out, err
}

// liveResource checks the org's MCP authorization is still on and the
// resource still one of its gateway's servers.
func (f *CodeFlow) liveResource(ctx context.Context, q *dbq.Queries, org ids.OrgID, resource string) (string, error) {
	access, err := q.GetOrgMcpAccess(ctx, org)
	if db.IsNoRows(err) || (err == nil && (!access.Enabled || access.GatewayUrl == nil)) {
		return "", refuse(accessDenied(ReasonMcpAccessOff, "MCP authorization is off for this organization"), "mcp_access_off")
	} else if err != nil {
		return "", err
	}
	conn, ok := domain.ConnectionOf(*access.GatewayUrl, resource)
	if !ok {
		return "", refuse(authnapp.ErrInvalidGrant, "resource_unknown")
	}
	return conn, nil
}

// issue mints an access token and a refresh token of family for the run.
func (f *CodeFlow) issue(ctx context.Context, q *dbq.Queries, org ids.OrgID, client dbq.PcMcpClient, run, env ids.UUID,
	runExpires time.Time, conn, resource string, ops []string, family ids.UUID, now time.Time,
) (authnapp.TokenResponse, error) {
	tok, exp, err := f.Tokens.Mint(ctx, ports.AccessClaims{
		Org: org, Environment: env, Agent: client.AgentID, Instance: client.InstanceID, Run: run, Connection: conn,
		Resource: resource, ClientKind: ports.ClientMcp, Client: client.ID, Scope: ops,
	}, now)
	if err != nil {
		return authnapp.TokenResponse{}, err
	}
	refresh := secret(RefreshPrefix, org)
	if err := q.InsertMcpRefreshToken(ctx, dbq.InsertMcpRefreshTokenParams{
		OrgID: org, ID: ids.NewV7(), FamilyID: family, TokenHash: digest(refresh), ClientID: client.ID, RunID: run,
		Resource: resource, ExpiresAt: runExpires,
	}); err != nil {
		return authnapp.TokenResponse{}, err
	}
	return authnapp.TokenResponse{
		AccessToken: tok, TokenType: "Bearer", ExpiresIn: int(exp.Sub(now).Seconds()), RefreshToken: refresh,
		Scope: strings.Join(ops, " "), RunID: run.String(),
	}, nil
}

// IsRefresh reports whether a token request's refresh token is one of
// this flow's.
func IsRefresh(form url.Values) bool {
	return strings.HasPrefix(form.Get("refresh_token"), RefreshPrefix)
}

// errReuse carries a refresh token reuse out of the transaction that
// killed its family, so that the kill commits.
type errReuse struct{ family, client, run ids.UUID }

// Refresh is the token endpoint's refresh_token grant for this flow's
// tokens. The token is rotated; a rotated or killed one is refused, and a
// rotated one presented again kills the whole family and raises an audited
// event (HR-628).
func (f *CodeFlow) Refresh(ctx context.Context, form url.Values) (authnapp.TokenResponse, error) {
	if form.Get("client_assertion") != "" {
		return authnapp.TokenResponse{}, f.fail(ctx, authnapp.ErrInvalidClient, "client_authentication_unsupported")
	}
	token, clientURL := form.Get("refresh_token"), form.Get("client_id")
	org, ok := orgOfSecret(RefreshPrefix, token)
	if !ok || clientURL == "" {
		return authnapp.TokenResponse{}, f.fail(ctx, authnapp.ErrInvalidGrant, "refresh_malformed")
	}
	if _, asked := form["scope"]; asked {
		return authnapp.TokenResponse{}, f.fail(ctx, errInvalidScope, "scope_on_refresh")
	}
	now := f.Clock.Now()
	var out authnapp.TokenResponse
	var reuse errReuse
	err := f.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.LockMcpRefreshToken(ctx, org, digest(token))
		if db.IsNoRows(err) {
			return refuse(authnapp.ErrInvalidGrant, "refresh_unknown")
		} else if err != nil {
			return err
		}
		client, err := q.GetMcpClient(ctx, org, row.ClientID)
		if err != nil {
			return err
		}
		if client.ClientUrl != clientURL {
			return refuse(authnapp.ErrInvalidGrant, "client_mismatch")
		}
		switch row.State {
		case "ROTATED":
			if _, err := q.KillMcpRefreshFamily(ctx, org, row.FamilyID); err != nil {
				return err
			}
			if _, err := audit.Record(ctx, tx, audit.Event{
				Name: "idaccess.refresh_reuse", Actor: evdomain.Actor{Type: "system", ID: "pantherclaw"}, Outcome: audit.Failure,
				ReasonCode: "REFRESH_TOKEN_REUSED", Object: &audit.Object{Type: "run", ID: row.RunID.String()},
				Details: map[string]string{"client": client.ID.String(), "family": row.FamilyID.String()},
			}); err != nil {
				return err
			}
			if err := (&Admin{Notify: f.Notify}).tellAdmins(ctx, tx, "idaccess.refresh_reuse", map[string]string{
				"client": client.ClientUrl, "run": row.RunID.String(),
			}); err != nil {
				return err
			}
			reuse = errReuse{family: row.FamilyID, client: client.ID, run: row.RunID}
			return nil
		case "KILLED":
			return refuse(authnapp.ErrInvalidGrant, "refresh_killed")
		}
		switch {
		case !row.ExpiresAt.After(now):
			return refuse(authnapp.ErrInvalidGrant, "refresh_expired")
		case client.State != "ACTIVE":
			return refuse(authnapp.ErrInvalidGrant, "client_removed")
		case form.Get("resource") != "" && form.Get("resource") != row.Resource:
			return refuse(authnapp.ErrInvalidGrant, "resource_mismatch")
		}
		run, err := q.SubjectRun(ctx, org, row.RunID)
		if err != nil {
			return err
		}
		if !run.Live {
			// The refresh token ends with its run (D408.4).
			return refuse(authnapp.ErrInvalidGrant, "run_ended")
		}
		conn, err := f.liveResource(ctx, q, org, row.Resource)
		if err != nil {
			return err
		}
		if n, err := q.RotateMcpRefreshToken(ctx, org, row.ID); err != nil {
			return err
		} else if n != 1 {
			return refuse(authnapp.ErrInvalidGrant, "refresh_raced")
		}
		out, err = f.issue(ctx, q, org, client, row.RunID, run.EnvironmentID, run.ExpiresAt, conn, row.Resource, run.ScopeOperations, row.FamilyID, now)
		return err
	})
	var r refusal
	switch {
	case errors.As(err, &r):
		return authnapp.TokenResponse{}, f.fail(ctx, r.oe, r.reason, slog.String("org", org.String()))
	case err != nil:
		return authnapp.TokenResponse{}, err
	case !reuse.family.IsZero():
		f.log().LogAttrs(ctx, slog.LevelWarn, "security.refresh_token_reused", slog.String("org", org.String()),
			slog.String("client", reuse.client.String()), slog.String("run", reuse.run.String()))
		return authnapp.TokenResponse{}, f.fail(ctx, authnapp.ErrInvalidGrant, "refresh_reused")
	}
	return out, nil
}

// AuthorizePath is the org's authorization endpoint, under its issuer: the
// consent page (webhttp).
func AuthorizePath(org ids.OrgID) string { return "/orgs/" + org.String() + "/mcp/authorize" }

// Metadata is the org's RFC 8414 authorization server metadata, served at
// /.well-known/oauth-authorization-server/orgs/<org> (path insertion). An
// org with neither MCP authorization on nor an active assertion issuer has
// none, so the metadata says nothing about orgs that don't use it.
func (f *CodeFlow) Metadata(ctx context.Context, org ids.OrgID) (map[string]any, bool, error) {
	var on bool
	err := f.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		access, err := q.GetOrgMcpAccess(ctx, org)
		if err == nil && access.Enabled {
			on = true
			return nil
		} else if err != nil && !db.IsNoRows(err) {
			return err
		}
		rows, err := q.ListAssertionIssuers(ctx, org)
		if err != nil {
			return err
		}
		on = slices.ContainsFunc(rows, func(r dbq.PcOrgAssertionIssuer) bool { return r.State == "ACTIVE" })
		return nil
	}, db.ReadOnly())
	if err != nil || !on {
		return nil, false, err
	}
	base := strings.TrimSuffix(f.PublicURL, "/")
	return map[string]any{
		"issuer":                                           f.Issuer(org),
		"authorization_endpoint":                           base + AuthorizePath(org),
		"token_endpoint":                                   base + authnapp.TokenPath,
		"response_types_supported":                         []string{"code"},
		"response_modes_supported":                         []string{"query"},
		"grant_types_supported":                            []string{GrantAuthorizationCode, "refresh_token", GrantJWTBearer},
		"code_challenge_methods_supported":                 []string{"S256"},
		"token_endpoint_auth_methods_supported":            []string{"none", "private_key_jwt"},
		"token_endpoint_auth_signing_alg_values_supported": []string{"EdDSA"},
		"client_id_metadata_document_supported":            true,
		"authorization_response_iss_parameter_supported":   true,
		"authorization_grant_profiles_supported":           []string{GrantProfileIDJAG},
	}, true, nil
}
