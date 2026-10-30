// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package issuers

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"regexp"
	"strings"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// GCP issuer and keys (D121): Google-signed ID tokens from the metadata
// server, verified only with the pinned key URL.
const (
	GCPIssuer  = "https://accounts.google.com"
	GCPKeysURL = "https://www.googleapis.com/oauth2/v3/certs"
)

// GCPAlgorithms are the only signature algorithms Google ID tokens may use.
var GCPAlgorithms = []string{"RS256"}

var (
	// gcpAccountID is a service account's unique numeric id (21 digits
	// today; never its email, which can be deleted and recreated).
	gcpAccountID = regexp.MustCompile(`^[1-9][0-9]{0,29}$`)
	gcpProjectID = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
)

// GCPBinding pins Google-signed ID tokens to one service account (HR-463).
type GCPBinding struct {
	ServiceAccountID string `json:"service_account_id"`
	// ProjectID and InstanceID optionally pin the Compute Engine instance
	// (google.compute_engine, present with format=full).
	ProjectID  string `json:"project_id,omitzero"`
	InstanceID string `json:"instance_id,omitzero"`
}

// Validate checks the binding (HR-463, HR-140).
func (b GCPBinding) Validate() error {
	var errs []string
	if !gcpAccountID.MatchString(b.ServiceAccountID) {
		errs = append(errs, "service_account_id must be the account's numeric unique id")
	}
	if b.ProjectID != "" && !gcpProjectID.MatchString(b.ProjectID) {
		errs = append(errs, fmt.Sprintf("project_id %q", b.ProjectID))
	}
	if b.InstanceID != "" && !gcpAccountID.MatchString(b.InstanceID) {
		errs = append(errs, fmt.Sprintf("instance_id %q must be numeric", b.InstanceID))
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalidEntry, strings.Join(errs, "; "))
	}
	return nil
}

// Widening lists what b accepts that prev did not (HR-141).
func (b GCPBinding) Widening(prev *GCPBinding) []string {
	if prev == nil {
		return []string{"new trusted issuer entry"}
	}
	var out []string
	if prev.ServiceAccountID != b.ServiceAccountID {
		out = append(out, "service account changed")
	}
	out = append(out, widenedPin("project_id", prev.ProjectID, b.ProjectID)...)
	out = append(out, widenedPin("instance_id", prev.InstanceID, b.InstanceID)...)
	return out
}

// GCPClaims are the claims of a Google-signed ID token whose signature was
// verified with the pinned keys.
type GCPClaims struct {
	Issuer   string         `json:"iss"`
	Audience jsontext.Value `json:"aud"`
	Subject  string         `json:"sub"`
	Email    string         `json:"email"`
	Google   struct {
		ComputeEngine struct {
			ProjectID  string `json:"project_id"`
			InstanceID string `json:"instance_id"`
			Zone       string `json:"zone"`
		} `json:"compute_engine"`
	} `json:"google"`
}

// ParseGCPClaims decodes a verified payload.
func ParseGCPClaims(payload []byte) (GCPClaims, error) {
	var c GCPClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, rejected("gcp claims: %v", err)
	}
	return c, nil
}

// MatchGCP applies the GCP preset. The rules no configuration can disable
// (HR-463): iss is exactly GCPIssuer (keys came only from GCPKeysURL), aud
// is exactly pantherclaw:<org>, sub is the pinned numeric service-account
// id, and a pinned project or instance must be the token's.
func MatchGCP(b GCPBinding, org ids.OrgID, c GCPClaims) (Match, error) {
	if err := b.Validate(); err != nil {
		return Match{}, err
	}
	ce := c.Google.ComputeEngine
	switch {
	case c.Issuer != GCPIssuer:
		return Match{}, rejected("issuer %q", c.Issuer)
	case !audienceIs(c.Audience, Audience(org)):
		return Match{}, rejected("audience")
	case c.Subject != b.ServiceAccountID:
		return Match{}, rejected("service account")
	case b.ProjectID != "" && ce.ProjectID != b.ProjectID:
		return Match{}, rejected("project")
	case b.InstanceID != "" && ce.InstanceID != b.InstanceID:
		return Match{}, rejected("instance")
	}
	return Match{Binding: Binding{"service_account_id": c.Subject}}, nil
}
