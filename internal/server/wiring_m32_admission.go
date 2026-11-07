// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"regexp"

	"golang.org/x/sync/errgroup"

	"github.com/katocxl/pantherclaw/internal/identity/adapters/kube"
	"github.com/katocxl/pantherclaw/internal/kubeadmission"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
)

// serveAdmission starts the admission webhook's TLS listener when
// admission.listen is set (G0 M32 D967): its own listener, with the
// certificate pair re-read when it changes, serving only POST
// /admission/v1/{cluster}/{org}/{secret}. Roles api and all.
func serveAdmission(ctx context.Context, g *errgroup.Group, cfg *Config, pool *db.Pool, clusters *kube.Directory, log *slog.Logger) error {
	a := cfg.Admission
	if a.Listen == "" {
		return nil
	}
	certs, err := httpx.NewCertReloader(a.TLSCertFile, a.TLSKeyFile, log)
	if err != nil {
		return fmt.Errorf("server: admission: %w", err)
	}
	mux := http.NewServeMux()
	kubeadmission.New(kubeadmission.Config{
		Clusters: clusters, Pool: pool, EdgeDigests: a.EdgeImageDigests, ProbeDigests: a.ProbeImageDigests, Log: log,
	}).Mount(mux)
	srv, err := httpx.NewServer(httpx.ServerConfig{
		Addr: a.Listen, Handler: mux, TLS: httpx.ReloadingServerTLSConfig(certs), BodyLimit: kubeadmission.MaxBody, Logger: log,
	})
	if err != nil {
		return err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", a.Listen)
	if err != nil {
		return fmt.Errorf("server: admission listener: %w", err)
	}
	serveCertReloads(ctx, g, certs)
	g.Go(func() error {
		if err := srv.ServeTLS(ln, "", ""); !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})
	g.Go(func() error {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
		defer cancel()
		return srv.Shutdown(sctx)
	})
	log.InfoContext(ctx, "server.admission_listening", slog.String("addr", ln.Addr().String()))
	return nil
}

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
	// ReleaseNamespace is the chart's release namespace: the one namespace
	// the gateway and api pods run in, and the only one a control closure
	// is accepted from (D1218 M1, M2). Empty: no NetworkPolicy check
	// passes and no control closure is accepted.
	ReleaseNamespace string `json:"release_namespace"`
	// GatewayPort is the gateway pods' port, the only one an agent
	// NetworkPolicy may name for them; APIPort the api pods'.
	GatewayPort int `json:"gateway_port"`
	APIPort     int `json:"api_port"`
	// APIEgressCIDRs are the agent namespaces' apiEgressCIDRs, the only
	// ipBlocks an agent NetworkPolicy may name, on APIEgressPort (the API
	// Service port, D965a).
	APIEgressCIDRs []string `json:"api_egress_cidrs"`
	APIEgressPort  int      `json:"api_egress_port"`
}

var (
	admissionDigest    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	admissionNamespace = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// maxAdmissionDigests bounds each digest list.
const maxAdmissionDigests = 64

func (c *Config) validateAdmission() []error {
	a := c.Admission
	if a.Listen == "" {
		if a.TLSCertFile != "" || a.TLSKeyFile != "" || len(a.EdgeImageDigests) > 0 || len(a.ProbeImageDigests) > 0 ||
			a.ReleaseNamespace != "" || a.GatewayPort != 0 || a.APIPort != 0 || len(a.APIEgressCIDRs) > 0 || a.APIEgressPort != 0 {
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
	if a.ReleaseNamespace != "" && !admissionNamespace.MatchString(a.ReleaseNamespace) {
		errs = append(errs, fmt.Errorf("admission.release_namespace %q is not a namespace name", a.ReleaseNamespace))
	}
	for _, p := range []struct {
		name string
		port int
	}{{"gateway_port", a.GatewayPort}, {"api_port", a.APIPort}, {"api_egress_port", a.APIEgressPort}} {
		if p.port < 0 || p.port > 65535 {
			errs = append(errs, fmt.Errorf("admission.%s %d is not a port", p.name, p.port))
		}
	}
	if len(a.APIEgressCIDRs) > maxAdmissionDigests {
		errs = append(errs, fmt.Errorf("admission.api_egress_cidrs lists more than %d CIDRs", maxAdmissionDigests))
	}
	for _, c := range a.APIEgressCIDRs {
		if pr, err := netip.ParsePrefix(c); err != nil || pr != pr.Masked() {
			errs = append(errs, fmt.Errorf("admission.api_egress_cidrs: %q is not a CIDR", c))
		}
	}
	if len(a.APIEgressCIDRs) > 0 && a.APIEgressPort == 0 {
		errs = append(errs, errors.New("admission.api_egress_port is required with admission.api_egress_cidrs"))
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
