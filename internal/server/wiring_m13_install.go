// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"

	"golang.org/x/sync/errgroup"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
)

// The M13 installers stream's wiring (G0 M13 D36).

// HealthConfig is the worker role's health listener (G0 M13 D36, HR-397):
// a process that runs only the job workers has no API listener, so an
// orchestrator (the Helm chart's probes) reaches its /livez and /readyz
// here. It serves nothing else. Roles api and all serve both on the API
// listener and refuse it.
type HealthConfig struct {
	// Addr is host:port, for example 0.0.0.0:8081 in a pod. Empty: no
	// health listener.
	Addr string `json:"addr" env:"PC_HEALTH_ADDR"`
}

func (c *Config) validateHealth() []error {
	if c.Health.Addr == "" {
		return nil
	}
	var errs []error
	if c.Role != RoleWorker {
		errs = append(errs, fmt.Errorf("health.addr is only for role %s: roles %s and %s serve /livez and /readyz on the API listener (http.addr)",
			RoleWorker, RoleAPI, RoleAll))
	}
	if _, _, err := net.SplitHostPort(c.Health.Addr); err != nil {
		errs = append(errs, fmt.Errorf("health.addr must be host:port: %w", err))
	}
	return errs
}

// healthHandler serves only GET /livez and GET /readyz; every other path
// is 404.
func healthHandler(pool *db.Pool, workers *workerHeartbeat, held bool, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.Handle("GET /readyz", readiness{pool: pool, workers: workers, held: held, log: log})
	return mux
}

// serveHealth starts the worker's health listener when health.addr is set
// and returns its bound address ("" without one). The listener is plain
// HTTP on any address: the probes carry no credentials and the bodies are
// fixed words (HR-370), and a kubelet probes the pod's address, not
// loopback.
func serveHealth(ctx context.Context, g *errgroup.Group, cfg *Config, pool *db.Pool, workers *workerHeartbeat, log *slog.Logger) (string, error) {
	if cfg.Health.Addr == "" {
		return "", nil
	}
	srv, err := httpx.NewServer(httpx.ServerConfig{
		Addr: cfg.Health.Addr, Handler: healthHandler(pool, workers, cfg.Maintenance.Hold, log),
		// Not behind a proxy: plain HTTP is allowed on a non-loopback
		// address because nothing here needs protecting in transit.
		PlaintextBehindProxy: true, Logger: log,
	})
	if err != nil {
		return "", err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", cfg.Health.Addr)
	if err != nil {
		return "", fmt.Errorf("server: health listener: %w", err)
	}
	g.Go(func() error {
		if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
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
	log.InfoContext(ctx, "server.health_listening", slog.String("addr", ln.Addr().String()))
	return ln.Addr().String(), nil
}
