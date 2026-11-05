// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package issuers

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// L3 "Infrastructure-attested" (PAP-1 §3.3, G0 M35 D1030): evidence the
// workload's infrastructure issued that is bound to one enrollment. It
// proves the PAP key thumbprint (jkt) and a fresh server nonce of the
// request it arrives with, so it can't be replayed for another key
// (HR-777).

// l3Kinds are the presets whose evidence is bound to the request's key and
// nonce.
var l3Kinds = []Kind{KindSPIFFEX509, KindGCPInstance}

// L3 reports whether k is an L3 preset.
func L3(k Kind) bool { return slices.Contains(l3Kinds, k) }

// Level is the attestation level an instance enrolled through k holds
// while its attestation is current: 3 for the L3 presets, else 2.
func Level(k Kind) int {
	if L3(k) {
		return 3
	}
	return 2
}

// L3Bind is what L3 evidence must prove: the org, the nonce of the request
// it arrives with and the thumbprint of the key that signed that request.
type L3Bind struct {
	Org   ids.OrgID
	Nonce string
	JKT   string
}

// complete reports whether every part is set.
func (b L3Bind) complete() bool { return !b.Org.IsZero() && b.Nonce != "" && b.JKT != "" }

// L3BindingPrefix starts every L3 binding string.
const L3BindingPrefix = "pantherclaw-l3:v1:"

// String is the binding string the SVID key signs:
// pantherclaw-l3:v1:<org>:<nonce>:<jkt>.
func (b L3Bind) String() string {
	return L3BindingPrefix + b.Org.String() + ":" + b.Nonce + ":" + b.JKT
}

// Audience is the audience of a GCE identity token bound to b:
// pantherclaw:<org>:l3:<nonce>:<jkt>.
func (b L3Bind) Audience() string {
	return Audience(b.Org) + ":l3:" + b.Nonce + ":" + b.JKT
}

// L3OrgOfAudience reads the org of an L3 audience without checking the
// rest; zero when aud is not one.
func L3OrgOfAudience(aud string) ids.OrgID {
	rest, ok := strings.CutPrefix(aud, "pantherclaw:")
	if !ok {
		return ids.OrgID{}
	}
	org, tail, ok := strings.Cut(rest, ":l3:")
	if !ok || tail == "" {
		return ids.OrgID{}
	}
	o, err := ids.Parse[ids.Org](org)
	if err != nil {
		return ids.OrgID{}
	}
	return o
}

// L3OrgOfBinding reads the org of a binding string without checking the
// rest; zero when s is not one.
func L3OrgOfBinding(s string) ids.OrgID {
	rest, ok := strings.CutPrefix(s, L3BindingPrefix)
	if !ok {
		return ids.OrgID{}
	}
	org, _, ok := strings.Cut(rest, ":")
	if !ok {
		return ids.OrgID{}
	}
	o, err := ids.Parse[ids.Org](org)
	if err != nil {
		return ids.OrgID{}
	}
	return o
}

// SPIFFEX509Algorithms are the X.509-SVID signature algorithms the
// spiffe_x509 preset verifies (stdlib x509 key types: ECDSA P-256/P-384,
// RSA of at least 2048 bits with PKCS #1 v1.5 or PSS, Ed25519).
var SPIFFEX509Algorithms = []string{"ES256", "ES384", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "EdDSA"}

// X509SVID is an X.509-SVID whose chain verified against its trust
// domain's X.509 bundle and whose key signed Payload.
type X509SVID struct {
	// TrustDomain is the bundle's trust domain.
	TrustDomain string
	// SPIFFEID is the leaf's single URI SAN.
	SPIFFEID string
	// Payload is what the leaf's key signed.
	Payload []byte
	// NotAfter is the leaf's expiry.
	NotAfter time.Time
}

// MatchSPIFFEX509 applies the spiffe_x509 preset to an SVID verified with
// the X.509 bundle of trust domain svid.TrustDomain. The rules no
// configuration can disable (HR-778):
//   - the SPIFFE ID's trust domain is the bundle's and the entry's;
//   - the SPIFFE ID is exactly the pinned one;
//   - the signed payload is exactly the binding string of bind.
func MatchSPIFFEX509(b SPIFFEBinding, bind L3Bind, svid X509SVID) (Match, error) {
	if err := b.Validate(); err != nil {
		return Match{}, err
	}
	td, ok := ParseSPIFFEID(svid.SPIFFEID)
	switch {
	case !bind.complete():
		return Match{}, rejected("the request carries no key or nonce to bind")
	case !ok || td != svid.TrustDomain || svid.TrustDomain != b.TrustDomain:
		return Match{}, rejected("spiffe id %q is not in the bundle's trust domain %q", svid.SPIFFEID, svid.TrustDomain)
	case svid.SPIFFEID != b.SPIFFEID:
		return Match{}, rejected("spiffe id %q not pinned", svid.SPIFFEID)
	case string(svid.Payload) != bind.String():
		return Match{}, rejected("the signed binding is not this request's org, nonce and key")
	}
	return Match{Binding: Binding{"spiffe_id": svid.SPIFFEID}}, nil
}

var gcpZone = regexp.MustCompile(`^[a-z]+-[a-z]+[0-9]+-[a-z]$`)

// GCPInstanceBinding pins GCE identity tokens to one Compute Engine
// project and optionally one instance and zone (G0 M35 D1030, HR-779).
type GCPInstanceBinding struct {
	ProjectID  string `json:"project_id"`
	InstanceID string `json:"instance_id,omitzero"`
	Zone       string `json:"zone,omitzero"`
}

// Validate checks the binding (HR-779, HR-140).
func (b GCPInstanceBinding) Validate() error {
	var errs []string
	if !gcpProjectID.MatchString(b.ProjectID) {
		errs = append(errs, "project_id must be a Compute Engine project id")
	}
	if b.InstanceID != "" && !gcpAccountID.MatchString(b.InstanceID) {
		errs = append(errs, "instance_id must be numeric")
	}
	if b.Zone != "" && !gcpZone.MatchString(b.Zone) {
		errs = append(errs, "zone must be a Compute Engine zone such as us-central1-a")
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalidEntry, strings.Join(errs, "; "))
	}
	return nil
}

// Widening lists what b accepts that prev did not (HR-141).
func (b GCPInstanceBinding) Widening(prev *GCPInstanceBinding) []string {
	if prev == nil {
		return []string{"new trusted issuer entry"}
	}
	var out []string
	if prev.ProjectID != b.ProjectID {
		out = append(out, "project changed")
	}
	out = append(out, widenedPin("instance_id", prev.InstanceID, b.InstanceID)...)
	out = append(out, widenedPin("zone", prev.Zone, b.Zone)...)
	return out
}

// MatchGCPInstance applies the gcp_instance preset to a Google-signed ID
// token verified with the pinned keys. The rules no configuration can
// disable (HR-779): iss is exactly GCPIssuer, aud is exactly the L3
// audience of bind (org, the request's nonce and key), the token carries
// the Compute Engine claims (format=full), and the pinned project, instance
// and zone are the token's. The instance's binding is the project and the
// instance that attested, so a re-attestation must come from the same VM.
func MatchGCPInstance(b GCPInstanceBinding, bind L3Bind, c GCPClaims) (Match, error) {
	if err := b.Validate(); err != nil {
		return Match{}, err
	}
	ce := c.Google.ComputeEngine
	switch {
	case !bind.complete():
		return Match{}, rejected("the request carries no key or nonce to bind")
	case c.Issuer != GCPIssuer:
		return Match{}, rejected("issuer %q", c.Issuer)
	case !audienceIs(c.Audience, bind.Audience()):
		return Match{}, rejected("audience is not this request's org, nonce and key")
	case ce.ProjectID == "" || ce.InstanceID == "":
		return Match{}, rejected("no Compute Engine claims (format=full is required)")
	case ce.ProjectID != b.ProjectID:
		return Match{}, rejected("project")
	case b.InstanceID != "" && ce.InstanceID != b.InstanceID:
		return Match{}, rejected("instance")
	case b.Zone != "" && gcpZoneName(ce.Zone) != b.Zone:
		return Match{}, rejected("zone")
	}
	return Match{Binding: Binding{"project_id": ce.ProjectID, "instance_id": ce.InstanceID}}, nil
}

// gcpZoneName is the zone's name when the claim is a resource path
// (projects/<n>/zones/<zone>).
func gcpZoneName(z string) string {
	if i := strings.LastIndex(z, "/"); i >= 0 {
		return z[i+1:]
	}
	return z
}
