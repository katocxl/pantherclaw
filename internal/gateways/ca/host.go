// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package ca

import (
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// HostPurpose is the only purpose a host certificate carries (G0 M19
// D203): it lets a hosting host agent fetch its work, nothing else.
const HostPurpose = "hosting"

// ErrHostIdentity reports a certificate without exactly one valid host
// identity.
var ErrHostIdentity = errors.New("ca: certificate does not name exactly one hosting host")

// HostIdentity is what a host certificate binds: one shared hosting host
// and one certificate row, and no org (HR-500). Its URI SAN is
// pc:hosting/host/<host>/cert/<cert>, which ParseIdentity never accepts, so
// a host certificate can never authenticate as a gateway of an org.
type HostIdentity struct {
	Host ids.UUID
	Cert ids.UUID
}

// URI is the host identity's URI SAN.
func (i HostIdentity) URI() *url.URL {
	return &url.URL{Scheme: uriScheme, Opaque: HostPurpose + "/host/" + i.Host.String() + "/cert/" + i.Cert.String()}
}

// ParseHostIdentity reads the host identity of a verified client
// certificate: exactly one URI SAN, of the hosting form, and no other SAN.
func ParseHostIdentity(cert *x509.Certificate) (HostIdentity, error) {
	if len(cert.URIs) != 1 || len(cert.DNSNames)+len(cert.EmailAddresses)+len(cert.IPAddresses) != 0 {
		return HostIdentity{}, ErrHostIdentity
	}
	u := cert.URIs[0]
	if u.Scheme != uriScheme || u.Host != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return HostIdentity{}, ErrHostIdentity
	}
	parts := strings.Split(u.Opaque, "/")
	if len(parts) != 5 || parts[0] != HostPurpose || parts[1] != "host" || parts[3] != "cert" {
		return HostIdentity{}, ErrHostIdentity
	}
	h, err1 := ids.ParseUUID(parts[2])
	c, err2 := ids.ParseUUID(parts[4])
	if err1 != nil || err2 != nil || h.IsZero() || c.IsZero() {
		return HostIdentity{}, ErrHostIdentity
	}
	id := HostIdentity{Host: h, Cert: c}
	if u.Opaque != id.URI().Opaque {
		return HostIdentity{}, ErrHostIdentity
	}
	return id, nil
}

// IssueHost issues a host client certificate for pub, with the gateway
// certificate's lifetime.
func (a *Authority) IssueHost(pub ed25519.PublicKey, id HostIdentity, now time.Time) (Issued, error) {
	if len(pub) != ed25519.PublicKeySize || id.Host.IsZero() || id.Cert.IsZero() {
		return Issued{}, ErrRequest
	}
	tmpl := &x509.Certificate{
		SerialNumber:          a.serial(),
		Subject:               pkix.Name{CommonName: "hosting host " + id.Host.String()},
		URIs:                  []*url.URL{id.URI()},
		NotBefore:             now.Add(-ClientSkew),
		NotAfter:              now.Add(ClientLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	return a.issue(tmpl, pub)
}

// hostedNameRE is a hosted gateway's one name: <slug>.gw.<domain>, lower
// case, no wildcard.
var hostedNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.gw\.[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)

// IssueHostedServer issues a hosted gateway's agent-facing server
// certificate (G0 M19 D210): exactly one DNS name, <slug>.gw.<domain>, never
// a wildcard, valid ServerLifetime, for a key the gateway keeps in its own
// volume. The caller derives the name from the org's hosted gateway record.
func (a *Authority) IssueHostedServer(pub ed25519.PublicKey, name string, now time.Time) (Issued, error) {
	if len(pub) != ed25519.PublicKeySize || len(name) > 253 || !hostedNameRE.MatchString(name) {
		return Issued{}, ErrRequest
	}
	tmpl := &x509.Certificate{
		SerialNumber:          a.serial(),
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{name},
		NotBefore:             now.Add(-ClientSkew),
		NotAfter:              now.Add(ServerLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	return a.issue(tmpl, pub)
}
