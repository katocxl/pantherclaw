// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain is IdP-native agent access (G0 M26 D400-D402, D408; H8):
// what an assertion from the org's identity provider proves, how it narrows
// an existing grant, and the names of the org's authorization server and
// protected resources. It decides nothing about authority: an assertion
// names who is represented and the grant still decides (HR-146).
package domain

import (
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"

	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Limits. An assertion lives as briefly as a subject token (HR-145): the
// draft sets no number and leaves its lifetime to this server's policy.
const (
	AssertionMaxAge   = 5 * time.Minute
	AssertionMaxLife  = 5 * time.Minute
	AssertionSkew     = 60 * time.Second
	MaxAssertionBytes = 16 << 10
	// AccessTokenTTL is a pap-mcp+jwt's lifetime (D402).
	AccessTokenTTL = 5 * time.Minute
	// MaxScopeValues bounds an assertion's or a request's scope.
	MaxScopeValues = 64
)

// Row states.
const (
	StatePending  = "PENDING"
	StateActive   = "ACTIVE"
	StateDisabled = "DISABLED"
	StateRemoved  = "REMOVED"
)

// ResourcePath is the gateway path prefix of a protected resource: the OAuth
// route of the MCP face, apart from the PAP/1 routes (D402).
const ResourcePath = "/mcp-oauth/"

// Errors of an assertion. Every one is the same refusal to the caller; the
// detail is for logs only.
var (
	// ErrAssertion: the assertion failed a validation rule.
	ErrAssertion = errors.New("idaccess: assertion rejected")
	// ErrNoGrant: the assertion is valid and no existing grant covers it.
	ErrNoGrant = errors.New("idaccess: no grant")
	// ErrAmbiguousGrant: several grants match and the scope names none.
	ErrAmbiguousGrant = errors.New("idaccess: several grants match")
)

// Issuer is an org's trusted assertion issuer, as the verifier needs it.
type Issuer struct {
	ID ids.UUID
	// URL is the issuer identifier an assertion's iss must equal.
	URL string
	// Audience is the only aud an assertion may name.
	Audience string
	// Tenant, for a multi-tenant issuer, is the tenant the assertion must
	// carry; empty for a single-tenant issuer.
	Tenant string
	// Algorithms the issuer may sign with.
	Algorithms []string
}

// Assertion is what a verified ID-JAG says.
type Assertion struct {
	Issuer  string
	Subject string
	// ClientID identifies the client at this server, which must be the
	// authenticated one.
	ClientID string
	JTI      string
	// Resources are the protected resources it was issued for.
	Resources []string
	// Scope is the raw scope claim; see ParseScope.
	Scope     string
	HasScope  bool
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// IssuerID is the org's authorization server issuer: the audience its
// assertions pin. Org ids are in the URL because one server serves many
// orgs, and each org trusts its own issuers.
func IssuerID(publicURL string, org ids.OrgID) string {
	return strings.TrimSuffix(publicURL, "/") + "/orgs/" + org.String()
}

// OrgOf returns the org an issuer identifier of this server names. It only
// chooses which org's records verify an assertion: nothing is trusted yet.
func OrgOf(publicURL, issuer string) (ids.OrgID, bool) {
	rest, ok := strings.CutPrefix(issuer, strings.TrimSuffix(publicURL, "/")+"/orgs/")
	if !ok {
		return ids.OrgID{}, false
	}
	org, err := ids.Parse[ids.Org](rest)
	return org, err == nil && !org.IsZero() && IssuerID(publicURL, org) == issuer
}

// ResourceURL is a connection's protected resource under gatewayURL.
func ResourceURL(gatewayURL, connection string) string {
	return strings.TrimSuffix(gatewayURL, "/") + ResourcePath + connection
}

// ConnectionOf returns the connection name a resource identifier of this
// gateway names, by simple string comparison: no normalizing, so an
// identifier is one exact string (draft -06 §4.3).
func ConnectionOf(gatewayURL, resource string) (string, bool) {
	name, ok := strings.CutPrefix(resource, strings.TrimSuffix(gatewayURL, "/")+ResourcePath)
	if !ok || name == "" || strings.ContainsAny(name, "/?#%") {
		return "", false
	}
	return name, true
}

var (
	scopeOpPattern    = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+){0,7}(\.\*)?$`)
	scopeGrantPattern = regexp.MustCompile(`^pc\.grant:([0-9a-f-]{36})$`)
)

// Scope is an assertion's or a request's scope in PantherClaw's meaning: the
// operation names and prefixes of a grant's bounds, and at most one
// pc.grant:<uuid> naming the grant to use. Present with no operations means
// nothing PantherClaw knows was asked for, which is never the whole grant.
type Scope struct {
	Present    bool
	Operations gdomain.Ops
	Grant      *ids.UUID
}

// ParseScope reads a space-separated scope. Values it does not know are not
// granted (RFC 6749 §3.3). Two grant names are refused.
func ParseScope(raw string, present bool) (Scope, error) {
	s := Scope{Present: present}
	if !present {
		return s, nil
	}
	values := strings.Fields(raw)
	if len(values) > MaxScopeValues {
		return Scope{}, ErrAssertion
	}
	for _, v := range values {
		if m := scopeGrantPattern.FindStringSubmatch(v); m != nil {
			id, err := ids.ParseUUID(m[1])
			if err != nil || s.Grant != nil {
				return Scope{}, ErrAssertion
			}
			s.Grant = &id
			continue
		}
		if scopeOpPattern.MatchString(v) && !slices.Contains(s.Operations, v) {
			s.Operations = append(s.Operations, v)
		}
	}
	return s, nil
}

// Candidate is an active root grant of the agent and principal.
type Candidate struct {
	ID ids.UUID
	// Operations are the grant's operation bound; nil is no bound at this
	// level.
	Operations *gdomain.Ops
}

// Choice is the grant a run uses and how the scope narrows it.
type Choice struct {
	Grant ids.UUID
	// Operations narrow the run within the grant; nil is the whole grant.
	Operations []string
}

// Choose picks the existing grant an assertion uses and intersects the scope
// with it (D400, D408.3). It never creates or widens anything: no candidate
// is ErrNoGrant, a scope naming a grant that is not a candidate is
// ErrNoGrant, an empty intersection is ErrNoGrant, and several candidates
// that the scope does not tell apart are ErrAmbiguousGrant.
func Choose(cands []Candidate, s Scope) (Choice, error) {
	if s.Grant != nil {
		i := slices.IndexFunc(cands, func(c Candidate) bool { return c.ID == *s.Grant })
		if i < 0 {
			return Choice{}, ErrNoGrant
		}
		cands = cands[i : i+1]
	}
	switch len(cands) {
	case 0:
		return Choice{}, ErrNoGrant
	case 1:
	default:
		return Choice{}, ErrAmbiguousGrant
	}
	c := cands[0]
	// A scope that only names the grant asks for all of it.
	if !s.Present || (s.Grant != nil && len(s.Operations) == 0) {
		return Choice{Grant: c.ID}, nil
	}
	ops := s.Operations
	if c.Operations != nil {
		ops = ops.Intersect(*c.Operations)
	}
	if len(ops) == 0 {
		return Choice{}, ErrNoGrant
	}
	return Choice{Grant: c.ID, Operations: ops}, nil
}
