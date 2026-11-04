// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"errors"
	"fmt"
	"net"
	"regexp"
)

// The M32 admission stream's wiring (G0 M32 D967).

// AdmissionConfig is the Kubernetes admission webhook's listener (G0 M32
// D967). Off by default: with listen empty there is no listener. It is its
// own TLS listener, which the clusters' API servers call; the path names
// the cluster, the org and the cluster's webhook secret
// (identity.kubernetes_clusters[].webhook_secret_file).
type AdmissionConfig struct {
	// Listen is host:port, for example 0.0.0.0:8444 in a pod.
	Listen string `json:"listen" env:"PC_ADMISSION_LISTEN"`
	// TLSCertFile and TLSKeyFile are the listener's certificate pair,
	// re-read when they change.
	TLSCertFile string `json:"tls_cert_file" env:"PC_ADMISSION_TLS_CERT_FILE"`
	TLSKeyFile  string `json:"tls_key_file" env:"PC_ADMISSION_TLS_KEY_FILE"`
	// EdgeImageDigests are the edge images (sha256:…) an agent pod's
	// pantherclaw-edge sidecar may run.
	EdgeImageDigests []string `json:"edge_image_digests"`
	// ProbeImageDigests are the probe images (sha256:…) whose closure
	// reports the server accepts (D970).
	ProbeImageDigests []string `json:"probe_image_digests"`
}

var admissionDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// maxAdmissionDigests bounds each digest list.
const maxAdmissionDigests = 64

func (c *Config) validateAdmission() []error {
	a := c.Admission
	if a.Listen == "" {
		if a.TLSCertFile != "" || a.TLSKeyFile != "" || len(a.EdgeImageDigests) > 0 || len(a.ProbeImageDigests) > 0 {
			return []error{errors.New("admission: listen is required when any other admission setting is set")}
		}
		return nil
	}
	var errs []error
	if c.Role == RoleWorker {
		errs = append(errs, fmt.Errorf("admission.listen is for roles %s and %s", RoleAPI, RoleAll))
	}
	if _, _, err := net.SplitHostPort(a.Listen); err != nil {
		errs = append(errs, fmt.Errorf("admission.listen must be host:port: %w", err))
	}
	if a.TLSCertFile == "" || a.TLSKeyFile == "" {
		errs = append(errs, errors.New("admission.tls_cert_file and admission.tls_key_file are required: the listener serves TLS only"))
	}
	if len(a.EdgeImageDigests) == 0 {
		errs = append(errs, errors.New("admission.edge_image_digests must list at least one edge image digest"))
	}
	for _, l := range []struct {
		name string
		list []string
	}{{"edge_image_digests", a.EdgeImageDigests}, {"probe_image_digests", a.ProbeImageDigests}} {
		name, list := l.name, l.list
		if len(list) > maxAdmissionDigests {
			errs = append(errs, fmt.Errorf("admission.%s lists more than %d digests", name, maxAdmissionDigests))
		}
		for _, d := range list {
			if !admissionDigest.MatchString(d) {
				errs = append(errs, fmt.Errorf("admission.%s: %q is not sha256:<64 hex>", name, d))
			}
		}
	}
	return errs
}
