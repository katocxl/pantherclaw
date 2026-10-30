// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package issuerkeys

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
)

// TrustDomain is one SPIFFE trust domain in identity.spiffe_trust_domains
// (D120): its JWT-SVID bundle comes from a SPIFFE bundle endpoint
// (https_web) or a static JWKS file, never from a tenant.
type TrustDomain struct {
	TrustDomain string `json:"trust_domain"`
	// BundleURL is the https_web bundle endpoint.
	BundleURL string `json:"bundle_url,omitzero"`
	// BundleFile is a JWKS file holding the trust domain's bundle.
	BundleFile string `json:"bundle_file,omitzero"`
	Access
}

// Validate checks one trust domain without reading files.
func (d TrustDomain) Validate() error {
	var errs []error
	if !issuers.ValidTrustDomain(d.TrustDomain) {
		errs = append(errs, errors.New("trust_domain must be a SPIFFE trust domain name"))
	}
	if (d.BundleURL == "") == (d.BundleFile == "") {
		errs = append(errs, errors.New("exactly one of bundle_url and bundle_file is required"))
	}
	if d.BundleURL != "" && !httpsURL(d.BundleURL) {
		errs = append(errs, errors.New("bundle_url must be an https URL"))
	}
	if err := d.Access.Validate(); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("spiffe trust domain %q: %w", d.TrustDomain, err)
	}
	return nil
}

// ValidateSPIFFE checks every trust domain and refuses duplicates.
func ValidateSPIFFE(cfgs []TrustDomain) error {
	var errs []error
	seen := map[string]bool{}
	for _, d := range cfgs {
		if err := d.Validate(); err != nil {
			errs = append(errs, err)
		}
		if seen[d.TrustDomain] {
			errs = append(errs, fmt.Errorf("spiffe trust domain %q is configured twice", d.TrustDomain))
		}
		seen[d.TrustDomain] = true
	}
	return errors.Join(errs...)
}

// spiffeConfig is the JWT-SVID profile: SPIFFE algorithms, jwt-svid keys
// only, and only the header members the JWT-SVID specification allows.
func spiffeConfig() Config {
	return Config{
		Algorithms: issuers.SPIFFEAlgorithms, Uses: []string{"jwt-svid"},
		Header: []string{"alg", "kid", "typ"}, Types: []string{"JWT", "JOSE"},
	}
}

// NewSPIFFEDirectory returns the configured trust domains, keyed by name.
// A bundle file is read once, here.
func NewSPIFFEDirectory(cfgs []TrustDomain, timeout time.Duration) (*Directory, error) {
	if err := ValidateSPIFFE(cfgs); err != nil {
		return nil, err
	}
	d := &Directory{entries: map[string]dirEntry{}}
	for _, td := range cfgs {
		cfg := spiffeConfig()
		var client *http.Client
		if td.BundleFile != "" {
			raw, err := os.ReadFile(td.BundleFile)
			if err != nil {
				return nil, fmt.Errorf("spiffe trust domain %q: %w", td.TrustDomain, err)
			}
			cfg.StaticJWKS = raw
		} else {
			ec, err := td.client(timeout)
			if err != nil {
				return nil, fmt.Errorf("spiffe trust domain %q: %w", td.TrustDomain, err)
			}
			cfg.JWKSURL, client = td.BundleURL, httpx.NewEgressClient(*ec)
		}
		f, err := NewFetcher(client, cfg, nil)
		if err != nil {
			return nil, fmt.Errorf("spiffe trust domain %q: %w", td.TrustDomain, err)
		}
		d.entries[td.TrustDomain] = dirEntry{f: f, orgs: td.Orgs}
	}
	return d, nil
}
