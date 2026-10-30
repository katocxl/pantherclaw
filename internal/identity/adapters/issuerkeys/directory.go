// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package issuerkeys

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Directory is the set of operator-configured issuers of one preset (GitLab
// instances, SPIFFE trust domains), each with its own key fetcher. A
// tenant can only name an issuer that is in it (HR-142, T-045).
type Directory struct {
	entries map[string]dirEntry
}

type dirEntry struct {
	f    *Fetcher
	orgs []string // empty: every org
}

// Allowed reports whether org may bind entries to issuer.
func (d *Directory) Allowed(issuer string, org ids.OrgID) bool {
	if d == nil {
		return false
	}
	e, ok := d.entries[issuer]
	return ok && (len(e.orgs) == 0 || slices.Contains(e.orgs, org.String()))
}

// Verify checks token with the keys of issuer, which must be configured
// for org; the payload's claims are the preset's to check.
func (d *Directory) Verify(ctx context.Context, issuer string, org ids.OrgID, token string) ([]byte, error) {
	if !d.Allowed(issuer, org) {
		return nil, fmt.Errorf("%w: issuer %q is not configured for this organization", ErrUnverified, issuer)
	}
	return d.entries[issuer].f.Verify(ctx, token)
}

// Access is how one configured issuer is reached: the CA its TLS
// certificate chains to (system roots when empty), the private ranges it
// may resolve to (operator only, HR-142), and the orgs that may use it
// (every org when empty).
type Access struct {
	CAFile          string   `json:"ca_file,omitzero"`
	AllowedPrefixes []string `json:"allowed_prefixes,omitzero"`
	Orgs            []string `json:"orgs,omitzero"`
}

// Validate checks the fields without reading files.
func (a Access) Validate() error {
	var errs []error
	for _, p := range a.AllowedPrefixes {
		if _, err := netip.ParsePrefix(p); err != nil {
			errs = append(errs, fmt.Errorf("allowed_prefixes: %q is not a CIDR", p))
		}
	}
	for _, o := range a.Orgs {
		if _, err := ids.Parse[ids.Org](o); err != nil {
			errs = append(errs, fmt.Errorf("orgs: %q is not an org id", o))
		}
	}
	return errors.Join(errs...)
}

// client returns the egress client for a: public addresses only, unless the
// operator allowed private ranges.
func (a Access) client(timeout time.Duration) (*httpx.EgressConfig, error) {
	cfg := &httpx.EgressConfig{Timeout: timeout}
	for _, p := range a.AllowedPrefixes {
		pp, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, err
		}
		cfg.AllowedPrefixes = append(cfg.AllowedPrefixes, pp.Masked())
	}
	if a.CAFile != "" {
		pem, err := os.ReadFile(a.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file %s holds no certificate", a.CAFile)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// GitLabIssuer is one GitLab instance in identity.gitlab_issuers (D119).
type GitLabIssuer struct {
	// Issuer is the instance URL, the iss of its ID tokens (https, no path).
	Issuer string `json:"issuer"`
	Access
}

// Validate checks one instance without reading files.
func (g GitLabIssuer) Validate() error {
	u, err := url.Parse(g.Issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") {
		return fmt.Errorf("gitlab issuer %q: must be an https URL without path, query or credentials", g.Issuer)
	}
	if err := g.Access.Validate(); err != nil {
		return fmt.Errorf("gitlab issuer %q: %w", g.Issuer, err)
	}
	return nil
}

// GitLabIssuers returns cfgs, or gitlab.com for every org when none are
// configured.
func GitLabIssuers(cfgs []GitLabIssuer) []GitLabIssuer {
	if len(cfgs) == 0 {
		return []GitLabIssuer{{Issuer: issuers.GitLabDefaultIssuer}}
	}
	return cfgs
}

// ValidateGitLab checks every instance and refuses duplicates.
func ValidateGitLab(cfgs []GitLabIssuer) error {
	var errs []error
	seen := map[string]bool{}
	for _, g := range cfgs {
		if err := g.Validate(); err != nil {
			errs = append(errs, err)
		}
		k := strings.TrimSuffix(g.Issuer, "/")
		if seen[k] {
			errs = append(errs, fmt.Errorf("gitlab issuer %q is configured twice", g.Issuer))
		}
		seen[k] = true
	}
	return errors.Join(errs...)
}

// NewGitLabDirectory returns the configured GitLab instances (gitlab.com
// when none are), each verified by discovery on its own host with RS256.
func NewGitLabDirectory(cfgs []GitLabIssuer, timeout time.Duration) (*Directory, error) {
	cfgs = GitLabIssuers(cfgs)
	if err := ValidateGitLab(cfgs); err != nil {
		return nil, err
	}
	d := &Directory{entries: map[string]dirEntry{}}
	for _, g := range cfgs {
		ec, err := g.client(timeout)
		if err != nil {
			return nil, fmt.Errorf("gitlab issuer %q: %w", g.Issuer, err)
		}
		iss := strings.TrimSuffix(g.Issuer, "/")
		f, err := NewFetcher(httpx.NewEgressClient(*ec), Config{Issuer: iss, Algorithms: issuers.GitLabAlgorithms}, nil)
		if err != nil {
			return nil, err
		}
		d.entries[iss] = dirEntry{f: f, orgs: g.Orgs}
	}
	return d, nil
}
