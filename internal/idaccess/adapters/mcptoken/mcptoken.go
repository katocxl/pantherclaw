// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package mcptoken signs and verifies pap-mcp+jwt, the bearer access token
// a standard MCP client presents at one gateway server (G0 M26 D402, D408;
// HR-626). It is signed with the mcp_tokens keys only, so it can never pass
// for a workload token (pap-wt+jwt, workload_tokens keys) nor the other way
// round. It lives AccessTokenTTL, names exactly one protected resource as
// its audience, and carries no key confirmation: it is bearer proof, level
// 0, and the Authority re-checks the client, the opt-in and the run on
// every call.
package mcptoken

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/idaccess/domain"
	"github.com/katocxl/pantherclaw/internal/idaccess/ports"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TokenType is the JWS typ of an MCP access token.
const TokenType = "pap-mcp+jwt"

// ProofBearer is the workload.proof a call with this token carries (HR-627).
const ProofBearer = "bearer"

// MaxBytes bounds a token before it is parsed.
const MaxBytes = 8 << 10

// Leeway tolerates clock skew between the server's replicas.
const Leeway = 30 * time.Second

// ErrInvalid is every refusal; the detail is for logs. ErrExpired is the
// one refusal a client can act on (it gets a new token).
var (
	ErrInvalid = errors.New("mcptoken: invalid token")
	ErrExpired = fmt.Errorf("%w: expired", ErrInvalid)
)

func bad(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

type claims struct {
	Issuer    string    `json:"iss"`
	Subject   string    `json:"sub"`
	Audience  string    `json:"aud"`
	IssuedAt  int64     `json:"iat"`
	NotBefore int64     `json:"nbf"`
	Expiry    int64     `json:"exp"`
	ID        string    `json:"jti"`
	Scope     string    `json:"scope,omitzero"`
	PAP       claimsPAP `json:"pap"`
}

type claimsPAP struct {
	V          int      `json:"v"`
	Org        string   `json:"org"`
	Env        string   `json:"env"`
	Run        string   `json:"run"`
	Connection string   `json:"conn"`
	Client     client   `json:"client"`
	Proof      string   `json:"proof"`
	Ops        []string `json:"ops,omitzero"`
}

type client struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// Signer returns the active mcp_tokens signer (keys.Registry).
type Signer interface {
	Signer() (*jws.Signer, error)
}

// SignerFunc adapts a function to Signer.
type SignerFunc func() (*jws.Signer, error)

// Signer implements Signer.
func (f SignerFunc) Signer() (*jws.Signer, error) { return f() }

// Minter implements ports.Minter.
type Minter struct {
	Keys Signer
	// Issuer is the server's public URL.
	Issuer string
}

// Mint signs a token for c, valid from now for domain.AccessTokenTTL.
func (m *Minter) Mint(_ context.Context, c ports.AccessClaims, now time.Time) (string, time.Time, error) {
	switch {
	case c.Org.IsZero() || c.Agent.IsZero() || c.Instance.IsZero() || c.Run.IsZero() || c.Environment.IsZero() || c.Client.IsZero():
		return "", time.Time{}, bad("incomplete claims")
	case c.ClientKind != ports.ClientAssertion && c.ClientKind != ports.ClientMcp:
		return "", time.Time{}, bad("client kind")
	case c.Connection == "" || c.Resource == "":
		return "", time.Time{}, bad("resource")
	}
	signer, err := m.Keys.Signer()
	if err != nil {
		return "", time.Time{}, err
	}
	now = now.Truncate(time.Second)
	exp := now.Add(domain.AccessTokenTTL)
	inst := pap.Instance{Org: c.Org, Agent: c.Agent, Instance: c.Instance}
	payload, err := json.Marshal(claims{
		Issuer: m.Issuer, Subject: inst.String(), Audience: c.Resource,
		IssuedAt: now.Unix(), NotBefore: now.Unix(), Expiry: exp.Unix(), ID: ids.NewV7().String(),
		PAP: claimsPAP{
			V: 1, Org: c.Org.String(), Env: c.Environment.String(), Run: c.Run.String(), Connection: c.Connection,
			Client: client{Kind: c.ClientKind, ID: c.Client.String()}, Proof: ProofBearer, Ops: c.Scope,
		},
	})
	if err != nil {
		return "", time.Time{}, err
	}
	tok, err := signer.Sign(TokenType, payload)
	return tok, exp, err
}

// Token is a verified MCP access token.
type Token struct {
	Instance    pap.Instance
	Environment ids.UUID
	Run         ids.UUID
	Connection  string
	Resource    string
	ClientKind  string
	Client      ids.UUID
	Operations  []string
	ID          ids.UUID
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

// Verify checks a token: typ and signature with an mcp_tokens key, issuer,
// audience exactly url (the request's own URL, so a token for another
// server is refused), validity window, lifetime and claim shapes.
func Verify(v *jws.Verifier, issuer, compact, url string, now time.Time) (Token, error) {
	if v == nil || len(compact) > MaxBytes {
		return Token{}, bad("size")
	}
	payload, _, err := v.Verify(compact)
	if err != nil {
		return Token{}, bad("signature: %v", err)
	}
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return Token{}, bad("claims")
	}
	iat, nbf, exp := time.Unix(c.IssuedAt, 0), time.Unix(c.NotBefore, 0), time.Unix(c.Expiry, 0)
	switch {
	case c.Issuer != issuer:
		return Token{}, bad("issuer")
	case c.Audience == "" || c.Audience != url:
		return Token{}, bad("audience")
	case c.PAP.V != 1 || c.PAP.Proof != ProofBearer:
		return Token{}, bad("version")
	case !now.Before(exp.Add(Leeway)):
		return Token{}, ErrExpired
	case nbf.After(now.Add(Leeway)) || iat.After(now.Add(Leeway)) || nbf.Before(iat):
		return Token{}, bad("not yet valid")
	case !exp.After(iat) || exp.Sub(iat) > domain.AccessTokenTTL:
		return Token{}, bad("lifetime")
	case c.PAP.Client.Kind != ports.ClientAssertion && c.PAP.Client.Kind != ports.ClientMcp:
		return Token{}, bad("client")
	case c.PAP.Connection == "" || len(c.PAP.Ops) > domain.MaxScopeValues:
		return Token{}, bad("connection or ops")
	}
	if !strings.HasSuffix(c.Audience, domain.ResourcePath+c.PAP.Connection) || strings.ContainsAny(c.PAP.Connection, "/?#%") {
		return Token{}, bad("connection does not match the audience")
	}
	inst, err := pap.ParseInstance(c.Subject)
	if err != nil || inst.Org.String() != c.PAP.Org {
		return Token{}, bad("subject")
	}
	parse := func(s string) (ids.UUID, bool) {
		u, err := ids.ParseUUID(s)
		return u, err == nil && !u.IsZero()
	}
	env, ok1 := parse(c.PAP.Env)
	run, ok2 := parse(c.PAP.Run)
	cl, ok3 := parse(c.PAP.Client.ID)
	id, ok4 := parse(c.ID)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return Token{}, bad("ids")
	}
	return Token{
		Instance: inst, Environment: env, Run: run, Connection: c.PAP.Connection, Resource: c.Audience,
		ClientKind: c.PAP.Client.Kind, Client: cl, Operations: slices.Clone(c.PAP.Ops), ID: id, IssuedAt: iat, ExpiresAt: exp,
	}, nil
}
