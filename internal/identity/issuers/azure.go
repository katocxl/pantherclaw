// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package issuers

import (
	"encoding/json/v2"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// The Azure presets (D129, HR-469). Their tokens are Microsoft Entra
// access tokens for an operator-pinned Entra app, so their audience is
// that app, never pantherclaw:<org> (the HR-140 exception for these kinds
// only), and they live up to a day (the HR-143 exception for these kinds
// only): the server grants at most AzureAssurance from the attestation,
// and the token stays single use.
const (
	// AzureMaxLifetime bounds exp − iat of an Azure token.
	AzureMaxLifetime = 24 * time.Hour
	// AzureAssurance bounds the assurance an Azure attestation grants,
	// from the moment it is accepted.
	AzureAssurance = time.Hour
)

// AzureAlgorithms are the only signature algorithms Entra tokens may use.
var AzureAlgorithms = []string{"RS256"}

var guid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ValidGUID reports whether s is a lower-case GUID.
func ValidGUID(s string) bool { return guid.MatchString(s) }

// AzureIssuers are the two issuers of a tenant's tokens: v1.0 and v2.0.
func AzureIssuers(tenant string) []string {
	return []string{"https://sts.windows.net/" + tenant + "/", "https://login.microsoftonline.com/" + tenant + "/v2.0"}
}

// AzureIssuer is the issuer recorded for a tenant's entries and
// attestations, whichever version the token was.
func AzureIssuer(tenant string) string { return AzureIssuers(tenant)[1] }

// AzureKeysURL is the pinned key set of a tenant (D129).
func AzureKeysURL(tenant string) string {
	return "https://login.microsoftonline.com/" + tenant + "/discovery/v2.0/keys"
}

// AzureAppAudience returns the app id an Entra audience names: the app id
// itself or its api://<app id> URI; "" for anything else.
func AzureAppAudience(aud string) string {
	app := strings.TrimPrefix(aud, "api://")
	if !ValidGUID(app) {
		return ""
	}
	return app
}

// AzureMIBinding pins Azure managed identity tokens to one identity
// (HR-469).
type AzureMIBinding struct {
	// TenantID and AppID are an operator-pinned pair (identity.entra_apps)
	// listed for the entry's org.
	TenantID string `json:"tenant_id"`
	AppID    string `json:"app_id"`
	// ObjectID is the managed identity's service principal object id.
	ObjectID string `json:"object_id"`
	// ResourceID optionally pins xms_mirid exactly.
	ResourceID string `json:"resource_id,omitzero"`
}

// Validate checks the binding (HR-469).
func (b AzureMIBinding) Validate() error {
	var errs []string
	for name, v := range map[string]string{"tenant_id": b.TenantID, "app_id": b.AppID, "object_id": b.ObjectID} {
		if !ValidGUID(v) {
			errs = append(errs, name+" must be a lower-case GUID")
		}
	}
	if b.ResourceID != "" && (len(b.ResourceID) > 512 || !strings.HasPrefix(b.ResourceID, "/subscriptions/")) {
		errs = append(errs, "resource_id must be an Azure resource id")
	}
	if len(errs) > 0 {
		slices.Sort(errs)
		return fmt.Errorf("%w: %s", ErrInvalidEntry, strings.Join(errs, "; "))
	}
	return nil
}

// Widening lists what b accepts that prev did not (HR-141).
func (b AzureMIBinding) Widening(prev *AzureMIBinding) []string {
	if prev == nil {
		return []string{"new trusted issuer entry"}
	}
	var out []string
	if prev.TenantID != b.TenantID || prev.AppID != b.AppID || prev.ObjectID != b.ObjectID {
		out = append(out, "tenant, app or managed identity changed")
	}
	return append(out, widenedPin("resource_id", prev.ResourceID, b.ResourceID)...)
}

// AzureClaims are the claims of an Entra access token whose signature was
// verified with its tenant's pinned keys.
type AzureClaims struct {
	Issuer   string  `json:"iss"`
	Audience string  `json:"aud"`
	TenantID string  `json:"tid"`
	ObjectID string  `json:"oid"`
	IDType   *string `json:"idtyp"`
	MIRID    string  `json:"xms_mirid"`
	UTI      string  `json:"uti"`
}

// ParseAzureClaims decodes a verified payload.
func ParseAzureClaims(payload []byte) (AzureClaims, error) {
	var c AzureClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, rejected("azure claims: %v", err)
	}
	return c, nil
}

// AzureWindow applies the Azure lifetime rule (HR-469) at now: the token
// is valid now and lives at most AzureMaxLifetime; the window it attests
// starts now and ends at its exp or AzureAssurance later, whichever is
// first. The window's JTI is the token's uti.
func AzureWindow(w Window, uti string, now time.Time) (Window, error) {
	switch {
	case w.ExpiresAt.IsZero() || w.IssuedAt.IsZero():
		return Window{}, rejected("exp and iat are required")
	case !now.Before(w.ExpiresAt.Add(Leeway)):
		return Window{}, rejected("expired")
	case w.IssuedAt.After(now.Add(Leeway)) || (!w.NotBefore.IsZero() && w.NotBefore.After(now.Add(Leeway))):
		return Window{}, rejected("not yet valid")
	case !w.ExpiresAt.After(w.IssuedAt) || w.ExpiresAt.Sub(w.IssuedAt) > AzureMaxLifetime+Leeway:
		return Window{}, rejected("lifetime over %s", AzureMaxLifetime)
	}
	end := now.Add(AzureAssurance)
	if w.ExpiresAt.Before(end) {
		end = w.ExpiresAt
	}
	if !end.After(now) {
		end = now.Add(time.Second)
	}
	return Window{IssuedAt: now, ExpiresAt: end, JTI: uti}, nil
}

// matchEntra applies the rules both Azure presets share (HR-469): the
// tenant's issuer (v1.0 or v2.0), tid the pinned tenant, aud exactly the
// pinned app id or its api:// URI, and oid the pinned object.
func matchEntra(tenant, app, object string, c AzureClaims) error {
	switch {
	case !slices.Contains(AzureIssuers(tenant), c.Issuer):
		return rejected("issuer %q", c.Issuer)
	case c.TenantID != tenant:
		return rejected("tenant")
	case c.Audience != app && c.Audience != "api://"+app:
		return rejected("audience")
	case c.ObjectID != object:
		return rejected("object id")
	}
	return nil
}

// MatchAzureMI applies the Azure managed identity preset (HR-469): the
// shared Entra rules, an app-only token (idtyp app when present) and the
// pinned xms_mirid when the entry pins one.
func MatchAzureMI(b AzureMIBinding, c AzureClaims) (Match, error) {
	if err := b.Validate(); err != nil {
		return Match{}, err
	}
	if err := matchEntra(b.TenantID, b.AppID, b.ObjectID, c); err != nil {
		return Match{}, err
	}
	switch {
	case c.IDType != nil && *c.IDType != "app":
		return Match{}, rejected("not an app-only token")
	case b.ResourceID != "" && c.MIRID != b.ResourceID:
		return Match{}, rejected("managed identity resource")
	}
	return Match{Binding: Binding{"tenant_id": c.TenantID, "object_id": c.ObjectID}}, nil
}

// agentIdentityFacet is the facet value Entra uses for an agent identity
// in xms_sub_fct and xms_act_fct (space-separated, any order).
const agentIdentityFacet = "11"

// EntraAgentBinding pins Entra Agent ID tokens to one agent identity
// acting autonomously (HR-469).
type EntraAgentBinding struct {
	// TenantID and AppID are an operator-pinned pair (identity.entra_apps)
	// listed for the entry's org; AppID is the token's audience.
	TenantID string `json:"tenant_id"`
	AppID    string `json:"app_id"`
	// ObjectID is the agent identity's service principal object id.
	ObjectID string `json:"object_id"`
}

// Validate checks the binding (HR-469).
func (b EntraAgentBinding) Validate() error {
	for _, v := range []string{b.TenantID, b.AppID, b.ObjectID} {
		if !ValidGUID(v) {
			return fmt.Errorf("%w: tenant_id, app_id and object_id must be lower-case GUIDs", ErrInvalidEntry)
		}
	}
	return nil
}

// Widening lists what b accepts that prev did not (HR-141).
func (b EntraAgentBinding) Widening(prev *EntraAgentBinding) []string {
	switch {
	case prev == nil:
		return []string{"new trusted issuer entry"}
	case *prev != b:
		return []string{"tenant, app or agent identity changed"}
	}
	return nil
}

// EntraAgentClaims are the agent claims of a verified Entra token.
type EntraAgentClaims struct {
	AzureClaims
	SubjectFacets string `json:"xms_sub_fct"`
	ActorFacets   string `json:"xms_act_fct"`
}

// ParseEntraAgentClaims decodes a verified payload.
func ParseEntraAgentClaims(payload []byte) (EntraAgentClaims, error) {
	var c EntraAgentClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, rejected("entra agent claims: %v", err)
	}
	return c, nil
}

// MatchEntraAgent applies the Entra Agent ID preset (HR-469): the shared
// Entra rules, an app-only token (idtyp app, required), and both the
// subject and the actor marked as an agent identity (facet 11 in
// xms_sub_fct and xms_act_fct): an agent acting autonomously as itself,
// never on behalf of a user or as its user account.
func MatchEntraAgent(b EntraAgentBinding, c EntraAgentClaims) (Match, error) {
	if err := b.Validate(); err != nil {
		return Match{}, err
	}
	if err := matchEntra(b.TenantID, b.AppID, b.ObjectID, c.AzureClaims); err != nil {
		return Match{}, err
	}
	switch {
	case c.IDType == nil || *c.IDType != "app":
		return Match{}, rejected("not an app-only token")
	case !slices.Contains(strings.Fields(c.SubjectFacets), agentIdentityFacet):
		return Match{}, rejected("subject is not an agent identity")
	case !slices.Contains(strings.Fields(c.ActorFacets), agentIdentityFacet):
		return Match{}, rejected("actor is not an agent identity")
	}
	return Match{Binding: Binding{"tenant_id": c.TenantID, "object_id": c.ObjectID}}, nil
}
