// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package kube talks to customer Kubernetes clusters for the Kubernetes L2
// preset (HR-142, HR-144; founder decision 3). Clusters are operator
// configuration, never tenant input: each names its API server, the CA to
// pin, a credential file for a service account bound to
// system:auth-delegator (TokenReview) and allowed to get pods in pinned
// namespaces, the private address ranges its API server may use, and the
// orgs allowed to use it.
package kube

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var clusterName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ClusterConfig is one entry of identity.kubernetes_clusters.
type ClusterConfig struct {
	// Name is how issuer entries refer to the cluster.
	Name string `json:"name"`
	// APIServer is the cluster's API server URL (https only).
	APIServer string `json:"api_server"`
	// CAFile is the PEM bundle the API server's certificate must chain to.
	CAFile string `json:"ca_file"`
	// TokenFile holds the bearer token of PantherClaw's service account in
	// the cluster.
	TokenFile string `json:"token_file"`
	// AllowedPrefixes are private address ranges the API server may resolve
	// to; every other private address is refused at dial time (HR-142).
	AllowedPrefixes []string `json:"allowed_prefixes"`
	// Orgs lists the org ids that may bind issuer entries to this cluster.
	Orgs []string `json:"orgs"`
	// WebhookSecretFile holds the secret of this cluster's admission
	// webhook path (G0 M32 D967): at least 32 bytes, re-read every minute.
	// Empty: the admission listener answers every request for the cluster
	// with 404.
	WebhookSecretFile string `json:"webhook_secret_file"`
}

// Validate checks one cluster entry.
func (c ClusterConfig) Validate() error {
	var errs []error
	if !clusterName.MatchString(c.Name) {
		errs = append(errs, errors.New("name must be a DNS label"))
	}
	u, err := url.Parse(c.APIServer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") {
		errs = append(errs, errors.New("api_server must be an https URL without path, query or credentials"))
	}
	if c.CAFile == "" || c.TokenFile == "" {
		errs = append(errs, errors.New("ca_file and token_file are required"))
	}
	for _, p := range c.AllowedPrefixes {
		if _, err := netip.ParsePrefix(p); err != nil {
			errs = append(errs, fmt.Errorf("allowed_prefixes: %q is not a CIDR", p))
		}
	}
	if c.WebhookSecretFile != "" && strings.TrimSpace(c.WebhookSecretFile) != c.WebhookSecretFile {
		errs = append(errs, errors.New("webhook_secret_file must be a path without surrounding spaces"))
	}
	if len(c.Orgs) == 0 {
		errs = append(errs, errors.New("orgs must list at least one org id"))
	}
	for _, o := range c.Orgs {
		if _, err := ids.Parse[ids.Org](o); err != nil {
			errs = append(errs, fmt.Errorf("orgs: %q is not an org id", o))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("kubernetes cluster %q: %w", c.Name, err)
	}
	return nil
}

// Prefixes returns the parsed allowed prefixes.
func (c ClusterConfig) Prefixes() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(c.AllowedPrefixes))
	for _, p := range c.AllowedPrefixes {
		if pp, err := netip.ParsePrefix(p); err == nil {
			out = append(out, pp.Masked())
		}
	}
	return out
}

// Directory is the set of configured clusters.
type Directory struct {
	clusters map[string]ClusterConfig
}

// NewDirectory validates cfgs and returns their directory.
func NewDirectory(cfgs []ClusterConfig) (*Directory, error) {
	d := &Directory{clusters: map[string]ClusterConfig{}}
	var errs []error
	for _, c := range cfgs {
		if err := c.Validate(); err != nil {
			errs = append(errs, err)
			continue
		}
		if _, dup := d.clusters[c.Name]; dup {
			errs = append(errs, fmt.Errorf("kubernetes cluster %q is configured twice", c.Name))
		}
		d.clusters[c.Name] = c
	}
	return d, errors.Join(errs...)
}

// Allowed reports whether org may bind issuer entries to cluster.
func (d *Directory) Allowed(cluster string, org ids.OrgID) bool {
	if d == nil {
		return false
	}
	c, ok := d.clusters[cluster]
	if !ok {
		return false
	}
	for _, o := range c.Orgs {
		if o == org.String() {
			return true
		}
	}
	return false
}

// Get returns a cluster's configuration.
func (d *Directory) Get(cluster string) (ClusterConfig, bool) {
	if d == nil {
		return ClusterConfig{}, false
	}
	c, ok := d.clusters[cluster]
	return c, ok
}
