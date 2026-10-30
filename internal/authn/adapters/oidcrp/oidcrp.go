// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package oidcrp makes PantherClaw an OpenID Connect relying party of a
// customer identity provider (SB-2, ADR-0016), using go-oidc for discovery
// and ID token verification and x/oauth2 for the authorization code flow
// with PKCE (S256).
//
// ID tokens are accepted only with RS256, ES256 or EdDSA signatures from
// the provider's published keys, with iss, aud, exp checked by go-oidc and
// azp and iat checked here; the caller compares the nonce. All provider
// endpoints must be HTTPS, except for an explicitly configured loopback
// development issuer. Discovery is lazy and retried after failures, so a
// provider outage does not stop the server.
package oidcrp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// SigningAlgs are the ID token algorithms accepted (SB-2).
var SigningAlgs = []string{oidc.RS256, oidc.ES256, oidc.EdDSA}

var namePattern = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// Config describes one provider.
type Config struct {
	// Name identifies the provider in URLs (/oauth2/callback/<name>).
	Name         string
	Issuer       string
	ClientID     string
	ClientSecret pclog.Secret[[]byte]
	// Scopes requested in addition to openid (default: email, profile).
	Scopes []string
	// TrustEmail accepts the email claim without email_verified, for
	// providers whose emails are administered (an enterprise directory).
	TrustEmail bool
	// SubjectTokenAudience, when set, lets runs present this provider's
	// tokens as RFC 8693 subject tokens whose aud contains it (HR-145).
	SubjectTokenAudience string
	// AllowInsecureLoopback allows an http:// issuer on a loopback host
	// (local Keycloak or a test provider). Never for production.
	AllowInsecureLoopback bool
	// TokenAuth is how the client authenticates at the token endpoint:
	// TokenAuthBasic (empty means basic) or TokenAuthPost.
	TokenAuth string
	// HTTPClient overrides the default client (tests); it must not follow
	// redirects or read proxy variables.
	HTTPClient *http.Client
	// Org marks an organization's own provider (G0 M18 D155, HR-483): its
	// issuer and every discovered endpoint must be HTTPS on a host the
	// egress guard allows, AllowInsecureLoopback and subject tokens are
	// refused, and the default client is the egress client, which also
	// refuses private and loopback addresses at dial time.
	Org bool
}

// Provider is a configured OpenID provider.
type Provider struct {
	cfg    Config
	client *http.Client

	mu   sync.Mutex
	disc *discovered
}

type discovered struct {
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	// subject verifies subject tokens: aud is the subject token audience.
	subject  *oidc.IDTokenVerifier
	endpoint oauth2.Endpoint
	issParam bool
}

// New validates cfg and returns a Provider; discovery happens on first use.
func New(cfg Config) (*Provider, error) {
	var errs []error
	if !namePattern.MatchString(cfg.Name) {
		errs = append(errs, errors.New("name must be 1-32 lowercase letters, digits or hyphens"))
	}
	if err := checkURL(cfg.Issuer, cfg.AllowInsecureLoopback); err != nil {
		errs = append(errs, fmt.Errorf("issuer: %w", err))
	}
	if cfg.Org {
		if cfg.AllowInsecureLoopback || cfg.SubjectTokenAudience != "" {
			errs = append(errs, errors.New("an organization's provider has no insecure loopback issuer and no subject tokens"))
		}
		if err := CheckOrgURL(cfg.Issuer); err != nil {
			errs = append(errs, fmt.Errorf("issuer: %w", err))
		}
	}
	if cfg.ClientID == "" || len(cfg.ClientSecret.Reveal()) == 0 {
		errs = append(errs, errors.New("client_id and a client secret are required"))
	}
	if cfg.TokenAuth != "" && cfg.TokenAuth != TokenAuthBasic && cfg.TokenAuth != TokenAuthPost {
		errs = append(errs, errors.New("token_auth must be basic or post"))
	}
	if len(cfg.SubjectTokenAudience) > 256 {
		errs = append(errs, errors.New("subject_token_audience is at most 256 characters"))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("oidc provider %q: %w", cfg.Name, err)
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"email", "profile"}
	}
	client := cfg.HTTPClient
	if client == nil && cfg.Org {
		// An organization's provider is customer input: the egress client
		// checks the address actually dialed (HR-071, HR-483).
		client = httpx.NewEgressClient(httpx.EgressConfig{Timeout: 10 * time.Second})
	}
	if client == nil {
		// Only the configured issuer and its discovered endpoints are ever
		// contacted: no redirects, no proxy variables (HR-070, HR-072).
		client = httpx.NewControlClient(httpx.ControlConfig{Timeout: 10 * time.Second})
	}
	return &Provider{cfg: cfg, client: client}, nil
}

// checkURL requires https, or http on a loopback host when allowed.
func checkURL(raw string, insecureLoopback bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("must be an absolute URL without userinfo, query or fragment")
	}
	switch {
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && insecureLoopback && isLoopback(u.Hostname()):
		return nil
	}
	return errors.New("must use https (http only for a loopback development issuer)")
}

// CheckOrgURL is checkURL for an organization's provider (HR-483): HTTPS
// only, on a host that is neither localhost nor an address or metadata
// name the egress guard denies. Other names are checked when they are
// dialed.
func CheckOrgURL(raw string) error {
	if err := checkURL(raw, false); err != nil {
		return err
	}
	u, _ := url.Parse(raw)
	h := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") || httpx.DeniedHost(u.Hostname(), nil) {
		return errors.New("must not be a private, loopback or metadata address")
	}
	return nil
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// Name implements authnapp.IdP.
func (p *Provider) Name() string { return p.cfg.Name }

// Issuer implements authnapp.IdP.
func (p *Provider) Issuer() string { return p.cfg.Issuer }

// TrustEmail implements authnapp.IdP.
func (p *Provider) TrustEmail() bool { return p.cfg.TrustEmail }

// load discovers the provider once; a failure is returned and retried on
// the next call.
func (p *Provider) load(ctx context.Context) (*discovered, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.disc != nil {
		return p.disc, nil
	}
	// The key set keeps the context for later key refreshes: it must not be
	// canceled with this request.
	octx := oidc.ClientContext(context.WithoutCancel(ctx), p.client)
	prov, err := oidc.NewProvider(octx, p.cfg.Issuer) // checks that the document's issuer matches
	if err != nil {
		return nil, fmt.Errorf("oidc %s: discovery: %w", p.cfg.Name, err)
	}
	var meta struct {
		AuthURL       string   `json:"authorization_endpoint"`
		TokenURL      string   `json:"token_endpoint"`
		JWKSURL       string   `json:"jwks_uri"`
		IssParam      bool     `json:"authorization_response_iss_parameter_supported"`
		PKCEMethods   []string `json:"code_challenge_methods_supported"`
		ResponseTypes []string `json:"response_types_supported"`
	}
	if err := prov.Claims(&meta); err != nil {
		return nil, fmt.Errorf("oidc %s: metadata: %w", p.cfg.Name, err)
	}
	for _, u := range []string{meta.AuthURL, meta.TokenURL, meta.JWKSURL} {
		if err := checkURL(u, p.cfg.AllowInsecureLoopback); err != nil {
			return nil, fmt.Errorf("oidc %s: endpoint %q: %w", p.cfg.Name, u, err)
		}
		if p.cfg.Org {
			if err := CheckOrgURL(u); err != nil {
				return nil, fmt.Errorf("oidc %s: endpoint %q: %w", p.cfg.Name, u, err)
			}
		}
	}
	if len(meta.PKCEMethods) > 0 && !slices.Contains(meta.PKCEMethods, "S256") {
		return nil, fmt.Errorf("oidc %s: provider does not support PKCE S256", p.cfg.Name)
	}
	// The key set's client drops RSA keys under 2048 bits in FIPS mode (D35).
	kctx := oidc.ClientContext(context.WithoutCancel(ctx), keysClient(p.client))
	p.disc = &discovered{
		provider: prov,
		verifier: prov.VerifierContext(kctx, &oidc.Config{ClientID: p.cfg.ClientID, SupportedSigningAlgs: SigningAlgs}),
		endpoint: oauth2.Endpoint{AuthURL: meta.AuthURL, TokenURL: meta.TokenURL, AuthStyle: p.authStyle()},
		issParam: meta.IssParam,
	}
	if a := p.cfg.SubjectTokenAudience; a != "" {
		p.disc.subject = prov.VerifierContext(kctx, &oidc.Config{ClientID: a, SupportedSigningAlgs: SigningAlgs})
	}
	return p.disc, nil
}

// Token endpoint client authentication methods (G0 UI D32): the two
// standard client-secret methods, nothing else.
const (
	TokenAuthBasic = "basic" // client_secret_basic (default)
	TokenAuthPost  = "post"  // client_secret_post
)

// authStyle is how the client secret goes to the token endpoint.
func (p *Provider) authStyle() oauth2.AuthStyle {
	if p.cfg.TokenAuth == TokenAuthPost {
		return oauth2.AuthStyleInParams
	}
	return oauth2.AuthStyleInHeader
}

func (p *Provider) oauth(d *discovered, redirectURI string) *oauth2.Config {
	return &oauth2.Config{
		ClientID: p.cfg.ClientID, ClientSecret: string(p.cfg.ClientSecret.Reveal()), Endpoint: d.endpoint,
		RedirectURL: redirectURI, Scopes: append([]string{oidc.ScopeOpenID}, p.cfg.Scopes...),
	}
}

// Discover fetches and checks the provider's discovery document now (an
// organization's provider is checked before it is stored).
func (p *Provider) Discover(ctx context.Context) error {
	_, err := p.load(ctx)
	return err
}

// RequireIssParam implements authnapp.IdP (RFC 9207).
func (p *Provider) RequireIssParam(ctx context.Context) (bool, error) {
	d, err := p.load(ctx)
	if err != nil {
		return false, err
	}
	return d.issParam, nil
}

// AuthCodeURL implements authnapp.IdP: authorization code flow with state,
// nonce and PKCE S256, and max_age when the request asks for a recent
// sign-in.
func (p *Provider) AuthCodeURL(ctx context.Context, req authnapp.AuthRequest) (string, error) {
	d, err := p.load(ctx)
	if err != nil {
		return "", err
	}
	opts := []oauth2.AuthCodeOption{oidc.Nonce(req.Nonce), oauth2.S256ChallengeOption(req.Verifier)}
	if req.ForceLogin {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "login"), oauth2.SetAuthURLParam("max_age", "0"))
	} else if req.MaxAge > 0 {
		opts = append(opts, oauth2.SetAuthURLParam("max_age", strconv.Itoa(int(req.MaxAge/time.Second))))
	}
	return p.oauth(d, req.RedirectURI).AuthCodeURL(req.State, opts...), nil
}

// Exchange implements authnapp.IdP.
func (p *Provider) Exchange(ctx context.Context, code, verifier, redirectURI string) (authnapp.IDClaims, error) {
	if code == "" || len(code) > 4096 {
		return authnapp.IDClaims{}, errors.New("oidc: missing or oversized code")
	}
	d, err := p.load(ctx)
	if err != nil {
		return authnapp.IDClaims{}, err
	}
	octx := oidc.ClientContext(ctx, p.client)
	tok, err := p.oauth(d, redirectURI).Exchange(octx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return authnapp.IDClaims{}, fmt.Errorf("oidc: code exchange: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return authnapp.IDClaims{}, errors.New("oidc: token response has no id_token")
	}
	idt, err := d.verifier.Verify(octx, raw)
	if err != nil {
		return authnapp.IDClaims{}, fmt.Errorf("oidc: id_token: %w", err)
	}
	var c struct {
		AZP           string `json:"azp"`
		Email         string `json:"email"`
		EmailVerified any    `json:"email_verified"`
		Name          string `json:"name"`
		Preferred     string `json:"preferred_username"`
		AuthTime      *int64 `json:"auth_time"`
	}
	if err := idt.Claims(&c); err != nil {
		return authnapp.IDClaims{}, fmt.Errorf("oidc: claims: %w", err)
	}
	// azp: required to be the client when there are several audiences, and
	// never another client when present (OIDC Core §3.1.3.7).
	if (len(idt.Audience) > 1 || c.AZP != "") && c.AZP != p.cfg.ClientID {
		return authnapp.IDClaims{}, errors.New("oidc: azp is not this client")
	}
	if idt.IssuedAt.After(time.Now().Add(5 * time.Minute)) {
		return authnapp.IDClaims{}, errors.New("oidc: id_token issued in the future")
	}
	if idt.Subject == "" {
		return authnapp.IDClaims{}, errors.New("oidc: id_token without sub")
	}
	name := c.Name
	if name == "" {
		name = c.Preferred
	}
	var authTime time.Time
	if c.AuthTime != nil {
		if *c.AuthTime <= 0 || time.Unix(*c.AuthTime, 0).After(time.Now().Add(5*time.Minute)) {
			return authnapp.IDClaims{}, errors.New("oidc: auth_time is not a past time")
		}
		authTime = time.Unix(*c.AuthTime, 0)
	}
	return authnapp.IDClaims{
		Issuer: idt.Issuer, Subject: idt.Subject, Email: c.Email, EmailVerified: truthy(c.EmailVerified),
		Name: name, Nonce: idt.Nonce, AuthTime: authTime,
	}, nil
}

// truthy accepts email_verified as a boolean or the string "true" (some
// providers send strings).
func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true")
	}
	return false
}
