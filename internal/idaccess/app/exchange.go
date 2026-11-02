// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"log/slog"
	"net/url"
	"slices"
	"strings"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/authn/assertion"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/idaccess/domain"
	"github.com/katocxl/pantherclaw/internal/idaccess/ports"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	runs "github.com/katocxl/pantherclaw/internal/runs/app"
)

// GrantJWTBearer is the RFC 7523 grant type an ID-JAG is presented with
// (draft -06 §4.4).
const GrantJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// GrantProfileIDJAG is advertised in the authorization server metadata
// (draft -06 §7.2).
const GrantProfileIDJAG = "urn:ietf:params:oauth:grant-profile:id-jag"

// Reasons in an access_denied description: a valid assertion that no
// existing grant covers (draft -06 §4.4.3).
const (
	ReasonNoGrant        = "NO_GRANT"
	ReasonAmbiguousGrant = "AMBIGUOUS_GRANT"
	ReasonMcpAccessOff   = "MCP_ACCESS_OFF"
)

func accessDenied(reason, text string) *authnapp.OAuthError {
	return &authnapp.OAuthError{Code: "access_denied", Description: reason + ": " + text, Status: 400}
}

// RunStarter starts the run a token uses (runs.Service).
type RunStarter interface {
	StartForIdentityTx(ctx context.Context, tx db.TenantTx, in runs.IdentityRunInput) (runs.Run, error)
}

// Exchange implements the jwt-bearer grant for ID-JAGs (G0 M26 D400, D408;
// HR-620-622, HR-624): the assertion is verified against the org's ACTIVE
// issuer, the client authenticates with private_key_jwt signed by an
// admitted instance of the agent its client id is pinned to, the person is
// the active user the assertion's (iss, sub) is linked to, and the run uses
// or narrows one existing root grant. No grant row is written, and no
// refresh token is issued (draft -06 §4.4.4).
type Exchange struct {
	Pool     *db.Pool
	Verifier ports.AssertionVerifier
	Runs     RunStarter
	Tokens   ports.Minter
	// PublicURL is the server's public URL.
	PublicURL string
	Clock     clock.Clock
	Log       *slog.Logger
}

func (e *Exchange) fail(ctx context.Context, oe *authnapp.OAuthError, reason string, attrs ...slog.Attr) error {
	log := e.Log
	if log == nil {
		log = pclog.Discard()
	}
	log.LogAttrs(ctx, slog.LevelWarn, "idaccess.token_failed",
		append([]slog.Attr{slog.String("error", oe.Code), slog.String("reason", reason)}, attrs...)...)
	return oe
}

// refusal carries an OAuth error out of a transaction with its log reason.
type refusal struct {
	oe     *authnapp.OAuthError
	reason string
}

func (r refusal) Error() string { return r.reason }

func refuse(oe *authnapp.OAuthError, reason string) error { return refusal{oe: oe, reason: reason} }

// peeked are claims read before verification, only to choose the org and
// the issuer entry that then verify everything.
type peeked struct {
	Iss    string         `json:"iss"`
	Aud    jsontext.Value `json:"aud"`
	Tenant string         `json:"tenant"`
}

func peek(raw string) (peeked, string, bool) {
	var p peeked
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || len(raw) > domain.MaxAssertionBytes {
		return p, "", false
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(b, &p) != nil {
		return p, "", false
	}
	var aud string
	if json.Unmarshal(p.Aud, &aud) != nil {
		var auds []string
		if json.Unmarshal(p.Aud, &auds) != nil || len(auds) != 1 {
			return p, "", false
		}
		aud = auds[0]
	}
	return p, aud, true
}

// pickIssuer chooses the entry an assertion names: the one pinning its
// tenant, else the one with no tenant.
func pickIssuer(rows []dbq.PcOrgAssertionIssuer, tenant string) (dbq.PcOrgAssertionIssuer, bool) {
	for _, r := range rows {
		if r.Tenant != nil && *r.Tenant == tenant {
			return r, true
		}
	}
	for _, r := range rows {
		if r.Tenant == nil {
			return r, true
		}
	}
	return dbq.PcOrgAssertionIssuer{}, false
}

// JWTBearer is the token endpoint's jwt-bearer grant.
func (e *Exchange) JWTBearer(ctx context.Context, form url.Values) (authnapp.TokenResponse, error) {
	raw, clientAssertion := form.Get("assertion"), form.Get("client_assertion")
	if form.Get("client_assertion_type") != authnapp.AssertionType || clientAssertion == "" {
		return authnapp.TokenResponse{}, e.fail(ctx, authnapp.ErrInvalidClient, "client_authentication_missing")
	}
	if raw == "" {
		return authnapp.TokenResponse{}, e.fail(ctx, authnapp.ErrInvalidRequest, "assertion_missing")
	}
	p, aud, ok := peek(raw)
	if !ok {
		return authnapp.TokenResponse{}, e.fail(ctx, authnapp.ErrInvalidGrant, "assertion_malformed")
	}
	org, ok := domain.OrgOf(e.PublicURL, aud)
	if !ok {
		return authnapp.TokenResponse{}, e.fail(ctx, authnapp.ErrInvalidGrant, "audience")
	}
	kid, err := assertion.KeyID(clientAssertion)
	if err != nil {
		return authnapp.TokenResponse{}, e.fail(ctx, authnapp.ErrInvalidClient, "client_assertion_malformed")
	}
	var rows []dbq.PcOrgAssertionIssuer
	if err := e.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		rows, err = dbq.New(tx).ActiveAssertionIssuers(ctx, org, p.Iss)
		return err
	}, db.ReadOnly()); err != nil {
		return authnapp.TokenResponse{}, err
	}
	row, ok := pickIssuer(rows, p.Tenant)
	if !ok {
		return authnapp.TokenResponse{}, e.fail(ctx, authnapp.ErrInvalidGrant, "issuer_unknown", slog.String("org", org.String()))
	}
	iss := domain.Issuer{
		ID: row.ID, URL: row.Issuer, Audience: row.Audience, Tenant: deref(row.Tenant), AudTenant: org.String(), Algorithms: row.Algorithms,
	}
	now := e.Clock.Now()
	a, err := e.Verifier.Verify(ctx, raw, iss, now)
	if err != nil {
		return authnapp.TokenResponse{}, e.fail(ctx, authnapp.ErrInvalidGrant, "assertion_invalid", slog.String("detail", err.Error()))
	}
	resource, err := chooseResource(a.Resources, form)
	if err != nil {
		return authnapp.TokenResponse{}, e.fail(ctx, authnapp.ErrInvalidGrant, "resource")
	}
	scope, err := chooseScope(a, form)
	if err != nil {
		return authnapp.TokenResponse{}, e.fail(ctx, authnapp.ErrInvalidGrant, "scope")
	}
	var out authnapp.TokenResponse
	err = e.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		binding, err := q.ActiveAssertionClient(ctx, org, row.ID, a.ClientID)
		if db.IsNoRows(err) {
			return refuse(authnapp.ErrInvalidClient, "client_unbound")
		} else if err != nil {
			return err
		}
		if c := form.Get("client_id"); c != "" && c != a.ClientID {
			return refuse(authnapp.ErrInvalidClient, "client_id_mismatch")
		}
		inst, err := q.AdmittedInstanceByKey(ctx, org, binding.AgentID, kid)
		if db.IsNoRows(err) {
			return refuse(authnapp.ErrInvalidClient, "client_key_unknown")
		} else if err != nil {
			return err
		}
		pk, err := assertion.ParsePublicJWK(assertion.EdDSA, inst.PublicJwk)
		if err != nil {
			return refuse(authnapp.ErrInvalidClient, "client_key_unusable")
		}
		issuerID := domain.IssuerID(e.PublicURL, org)
		v, err := assertion.Verify(clientAssertion, pk, assertion.Expect{
			ClientID: a.ClientID, Audiences: []string{issuerID, strings.TrimSuffix(e.PublicURL, "/") + authnapp.TokenPath}, Now: now,
		})
		if err != nil {
			return refuse(authnapp.ErrInvalidClient, "client_assertion_invalid")
		}
		if n, err := q.InsertAuthReplay(ctx, dbq.InsertAuthReplayParams{
			OrgID: org, Issuer: "instance:" + inst.ID.String(), Jti: v.JTI, ExpiresAt: v.ExpiresAt,
		}); err != nil {
			return err
		} else if n == 0 {
			return refuse(authnapp.ErrInvalidClient, "client_assertion_replayed")
		}
		if n, err := q.InsertAuthReplay(ctx, dbq.InsertAuthReplayParams{
			OrgID: org, Issuer: "idjag:" + hash(a.Issuer), Jti: hash(a.JTI), ExpiresAt: a.ExpiresAt,
		}); err != nil {
			return err
		} else if n == 0 {
			return refuse(authnapp.ErrInvalidGrant, "assertion_replayed")
		}
		user, err := q.ActiveUserBySubject(ctx, org, a.Issuer, a.Subject)
		if db.IsNoRows(err) {
			return refuse(authnapp.ErrInvalidGrant, "subject_unknown")
		} else if err != nil {
			return err
		}
		access, err := q.GetOrgMcpAccess(ctx, org)
		if db.IsNoRows(err) || (err == nil && (!access.Enabled || access.GatewayUrl == nil)) {
			return refuse(accessDenied(ReasonMcpAccessOff, "MCP authorization is off for this organization"), "mcp_access_off")
		} else if err != nil {
			return err
		}
		conn, ok := domain.ConnectionOf(*access.GatewayUrl, resource)
		if !ok {
			return refuse(authnapp.ErrInvalidGrant, "resource_unknown")
		}
		agent, err := q.GetAgent(ctx, org, binding.AgentID)
		if err != nil || agent.EnvironmentID == nil {
			return refuse(accessDenied(ReasonNoGrant, "no grant covers this agent"), "agent_unusable")
		}
		choice, err := chooseGrant(ctx, q, org, agent.ID, *agent.EnvironmentID, user, inst.ID, scope)
		if err != nil {
			return err
		}
		run, err := e.Runs.StartForIdentityTx(ctx, tx, runs.IdentityRunInput{
			Org: org, Agent: agent.ID, Instance: inst.ID, User: user, Issuer: a.Issuer, Subject: a.Subject,
			Grant: choice.Grant, Operations: choice.Operations, TaskRef: "id-jag " + conn,
		})
		if err != nil {
			return refuse(accessDenied(ReasonNoGrant, "the grant can't be used"), "run_refused: "+err.Error())
		}
		tok, exp, err := e.Tokens.Mint(ctx, ports.AccessClaims{
			Org: org, Environment: run.EnvironmentID, Agent: agent.ID, Instance: inst.ID, Run: run.ID, Connection: conn,
			Resource: resource, ClientKind: ports.ClientAssertion, Client: binding.ID, Scope: choice.Operations,
		}, now)
		if err != nil {
			return err
		}
		out = authnapp.TokenResponse{
			AccessToken: tok, TokenType: "Bearer", ExpiresIn: int(exp.Sub(now).Seconds()),
			Scope: strings.Join(choice.Operations, " "), RunID: run.ID.String(),
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "idaccess.token_issued", Actor: evdomain.Actor{Type: "instance", ID: inst.ID.String()}, Outcome: audit.Success,
			Object: &audit.Object{Type: "run", ID: run.ID.String()},
			Details: map[string]string{
				"grant": "jwt_bearer", "issuer": a.Issuer, "client": binding.ID.String(), "user": user.String(),
				"resource": resource, "grant_id": choice.Grant.String(),
			},
		})
		return err
	})
	var r refusal
	if errors.As(err, &r) {
		return authnapp.TokenResponse{}, e.fail(ctx, r.oe, r.reason, slog.String("org", org.String()))
	}
	return out, err
}

func hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// chooseResource is the one protected resource the token is for: the
// assertion's only one, or the one the request's resource names among them.
// Identifiers compare as exact strings (draft -06 §4.3).
func chooseResource(resources []string, form url.Values) (string, error) {
	want := form.Get("resource")
	switch {
	case want != "" && slices.Contains(resources, want):
		return want, nil
	case want == "" && len(resources) == 1:
		return resources[0], nil
	}
	return "", domain.ErrAssertion
}

// chooseScope is the assertion's scope, or the request's when it only keeps
// some of the assertion's values: a request never widens the assertion.
func chooseScope(a domain.Assertion, form url.Values) (domain.Scope, error) {
	if _, asked := form["scope"]; !asked {
		return domain.ParseScope(a.Scope, a.HasScope)
	}
	have := strings.Fields(a.Scope)
	for _, v := range strings.Fields(form.Get("scope")) {
		if a.HasScope && !slices.Contains(have, v) {
			return domain.Scope{}, domain.ErrAssertion
		}
	}
	return domain.ParseScope(form.Get("scope"), true)
}

// chooseGrant picks the existing grant (HR-620, HR-621).
func chooseGrant(ctx context.Context, q *dbq.Queries, org ids.OrgID, agent, env, user, instance ids.UUID, s domain.Scope) (domain.Choice, error) {
	rows, err := q.UsableRootGrants(ctx, dbq.UsableRootGrantsParams{
		OrgID: org, AgentID: agent, EnvironmentID: env, UserID: &user, InstanceID: &instance,
	})
	if err != nil {
		return domain.Choice{}, err
	}
	cands := make([]domain.Candidate, 0, len(rows))
	for _, r := range rows {
		b, err := gdomain.DecodeBounds(r.Bounds)
		if err != nil {
			return domain.Choice{}, err
		}
		cands = append(cands, domain.Candidate{ID: r.ID, Operations: b.Operations})
	}
	c, err := domain.Choose(cands, s)
	switch {
	case errors.Is(err, domain.ErrNoGrant):
		return c, refuse(accessDenied(ReasonNoGrant, "no existing grant covers this person, agent and scope"), "no_grant")
	case errors.Is(err, domain.ErrAmbiguousGrant):
		return c, refuse(accessDenied(ReasonAmbiguousGrant, "several grants match; name one with pc.grant:<id>"), "ambiguous_grant")
	}
	return c, err
}
