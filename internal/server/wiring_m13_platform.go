// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"fmt"
	"log/slog"

	"golang.org/x/sync/errgroup"

	"github.com/katocxl/pantherclaw/internal/platform/httpx"
)

// The M13 platform stream's wiring (G0 M13 D3–D7).

// publicCertReloader reads the public listener's certificate files, when
// configured, through a reloader (G0 M13 D4, HR-371); nil without TLS.
func publicCertReloader(cfg *Config, log *slog.Logger) (*httpx.CertReloader, error) {
	if cfg.HTTP.TLSCertFile == "" {
		return nil, nil
	}
	r, err := httpx.NewCertReloader(cfg.HTTP.TLSCertFile, cfg.HTTP.TLSKeyFile, log)
	if err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}
	return r, nil
}

// serveCertReloads polls the certificate files until ctx ends.
func serveCertReloads(ctx context.Context, g *errgroup.Group, certs *httpx.CertReloader) {
	if certs == nil {
		return
	}
	g.Go(func() error {
		certs.Run(ctx, httpx.CertReloadInterval)
		return nil
	})
}
