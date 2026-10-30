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

// SPIFFEAlgorithms are the JWT-SVID algorithms PantherClaw verifies: the
// SPIFFE set less ES512, whose P-521 keys issuerkeys does not hold.
var SPIFFEAlgorithms = []string{"RS256", "RS384", "RS512", "ES256", "ES384", "PS256", "PS384", "PS512"}

var (
	trustDomain  = regexp.MustCompile(`^[a-z0-9._-]{1,255}$`)
	spiffePathSg = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// ParseSPIFFEID returns the trust domain of a SPIFFE ID with a workload
// path: spiffe://<trust domain>/<segment>/…, with no empty, "." or ".."
// segment, no query, fragment, port or user, and at most 2048 bytes.
func ParseSPIFFEID(id string) (string, bool) {
	rest, ok := strings.CutPrefix(id, "spiffe://")
	if !ok || len(id) > 2048 {
		return "", false
	}
	td, path, ok := strings.Cut(rest, "/")
	if !ok || !trustDomain.MatchString(td) {
		return "", false
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." || !spiffePathSg.MatchString(seg) {
			return "", false
		}
	}
	return td, true
}

// ValidTrustDomain reports whether td is a SPIFFE trust domain name.
func ValidTrustDomain(td string) bool { return trustDomain.MatchString(td) }

// SPIFFEBinding pins JWT-SVIDs to one workload: one exact SPIFFE ID, never
// a prefix or pattern (HR-462, HR-140).
type SPIFFEBinding struct {
	// TrustDomain names a trust domain from the server configuration
	// (identity.spiffe_trust_domains); never a tenant-supplied bundle.
	TrustDomain string `json:"trust_domain"`
	SPIFFEID    string `json:"spiffe_id"`
}

// Issuer is the issuer name recorded for this binding's tokens.
func (b SPIFFEBinding) Issuer() string { return "spiffe://" + b.TrustDomain }

// Validate checks the binding (HR-462).
func (b SPIFFEBinding) Validate() error {
	td, ok := ParseSPIFFEID(b.SPIFFEID)
	switch {
	case !ValidTrustDomain(b.TrustDomain):
		return fmt.Errorf("%w: trust domain %q", ErrInvalidEntry, b.TrustDomain)
	case !ok || strings.ContainsAny(b.SPIFFEID, "*?"):
		return fmt.Errorf("%w: spiffe_id %q must be an exact spiffe://<trust domain>/<path>", ErrInvalidEntry, b.SPIFFEID)
	case td != b.TrustDomain:
		return fmt.Errorf("%w: spiffe_id %q is not in trust domain %q", ErrInvalidEntry, b.SPIFFEID, b.TrustDomain)
	}
	return nil
}

// Widening lists what b accepts that prev did not (HR-141).
func (b SPIFFEBinding) Widening(prev *SPIFFEBinding) []string {
	switch {
	case prev == nil:
		return []string{"new trusted issuer entry"}
	case *prev != b:
		return []string{"trust domain or SPIFFE ID changed"}
	}
	return nil
}

// SPIFFEClaims are the claims of a JWT-SVID whose signature was verified
// with its trust domain's bundle.
type SPIFFEClaims struct {
	Subject  string         `json:"sub"`
	Audience jsontext.Value `json:"aud"`
}

// ParseSPIFFEClaims decodes a verified payload.
func ParseSPIFFEClaims(payload []byte) (SPIFFEClaims, error) {
	var c SPIFFEClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, rejected("spiffe claims: %v", err)
	}
	return c, nil
}

// MatchSPIFFE applies the SPIFFE preset to claims verified with the bundle
// of trust domain bundleTD. The rules no configuration can disable
// (HR-462):
//   - sub is a SPIFFE ID whose trust domain is the bundle's, so one trust
//     domain's keys never vouch for another's workloads;
//   - sub is exactly the pinned SPIFFE ID;
//   - aud is exactly pantherclaw:<org>.
func MatchSPIFFE(b SPIFFEBinding, org ids.OrgID, bundleTD string, c SPIFFEClaims) (Match, error) {
	if err := b.Validate(); err != nil {
		return Match{}, err
	}
	td, ok := ParseSPIFFEID(c.Subject)
	switch {
	case !ok || td != bundleTD || bundleTD != b.TrustDomain:
		return Match{}, rejected("sub %q is not in the bundle's trust domain %q", c.Subject, bundleTD)
	case c.Subject != b.SPIFFEID:
		return Match{}, rejected("spiffe id %q not pinned", c.Subject)
	case !audienceIs(c.Audience, Audience(org)):
		return Match{}, rejected("audience")
	}
	return Match{Binding: Binding{"spiffe_id": c.Subject}}, nil
}
