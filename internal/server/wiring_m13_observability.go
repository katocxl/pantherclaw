// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"golang.org/x/sync/errgroup"

	"github.com/katocxl/pantherclaw/internal/platform/config"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/telemetry"
	"github.com/katocxl/pantherclaw/internal/platform/version"
)

// The M13 observability stream's wiring (G0 M13 D30, D31; F5).

// TelemetryConfig configures the OTLP exporter (G0 M13 D30).
type TelemetryConfig struct {
	OTLP OTLPConfig `json:"otlp"`
}

// OTLPConfig is telemetry.otlp: traces and metrics go to Endpoint over
// OTLP/HTTP (protobuf, gzip); export is off when Endpoint is empty.
type OTLPConfig struct {
	// Endpoint is the OTLP/HTTP base URL; /v1/traces and /v1/metrics are
	// appended (Grafana Cloud: its OTLP gateway URL, which ends in /otlp).
	Endpoint string `json:"endpoint" env:"PC_TELEMETRY_OTLP_ENDPOINT"`
	// HeadersFile holds one "Name: value" header per line, sent with every
	// export (Grafana Cloud: "Authorization: Basic …"). A secret file.
	HeadersFile string `json:"headers_file" env:"PC_TELEMETRY_OTLP_HEADERS_FILE"`
	// SampleRatio is the share of traces kept (default 0.1); spans that end
	// with an error are always kept.
	SampleRatio float64 `json:"sample_ratio" env:"PC_TELEMETRY_OTLP_SAMPLE_RATIO"`
	// ServiceName names the exported resource (default pantherclaw-server).
	ServiceName string `json:"service_name" env:"PC_TELEMETRY_OTLP_SERVICE_NAME"`
}

// AdminConfig is the private admin listener: pprof and /metrics (G0 M13
// D30, HR-382). Off by default; only a loopback address is accepted.
type AdminConfig struct {
	Addr string `json:"addr" env:"PC_ADMIN_ADDR"`
}

func defaultTelemetry() TelemetryConfig {
	return TelemetryConfig{OTLP: OTLPConfig{SampleRatio: telemetry.DefaultSampleRatio, ServiceName: "pantherclaw-server"}}
}

func (c *Config) validateObservability() []error {
	var errs []error
	o := c.Telemetry.OTLP
	if o.Endpoint != "" {
		if err := telemetry.CheckEndpoint(o.Endpoint); err != nil {
			errs = append(errs, err)
		}
	} else if o.HeadersFile != "" {
		errs = append(errs, errors.New("telemetry.otlp.headers_file needs telemetry.otlp.endpoint"))
	}
	if o.SampleRatio < 0 || o.SampleRatio > 1 {
		errs = append(errs, errors.New("telemetry.otlp.sample_ratio must be 0..1"))
	}
	if o.ServiceName == "" || len(o.ServiceName) > 64 {
		errs = append(errs, errors.New("telemetry.otlp.service_name must be 1..64 characters"))
	}
	// HR-382: the admin listener is loopback only.
	if err := telemetry.CheckAdminAddr(c.Admin.Addr); err != nil {
		errs = append(errs, err)
	}
	return errs
}

// startTelemetry installs the exporter and the metrics the admin listener
// serves, as configured; with neither it installs nothing.
func startTelemetry(cfg *Config, log *slog.Logger) (*telemetry.Telemetry, error) {
	o := cfg.Telemetry.OTLP
	var headers []telemetry.Header
	if o.HeadersFile != "" {
		raw, err := config.ReadSecretFile(o.HeadersFile)
		if err != nil {
			return nil, err
		}
		if headers, err = telemetry.ParseHeaders(raw.Reveal()); err != nil {
			return nil, err
		}
	}
	tel, err := telemetry.Setup(telemetry.Config{
		ServiceName: o.ServiceName, ServiceVersion: version.Get().Version, Endpoint: o.Endpoint, Headers: headers,
		SampleRatio: o.SampleRatio, Metrics: cfg.Admin.Addr != "", Logger: log,
	})
	if err != nil {
		return nil, fmt.Errorf("server: telemetry: %w", err)
	}
	telemetry.SetMaintenanceHold(cfg.Maintenance.Hold)
	if tel.Enabled() {
		log.Info("telemetry.otlp_on", slog.Float64("sample_ratio", o.SampleRatio))
	}
	return tel, nil
}

// withQueryTracer traces the app pool's queries when traces are exported.
func withQueryTracer(c db.Config, tel *telemetry.Telemetry) db.Config {
	if tel.Enabled() {
		c.Tracer = telemetry.NewQueryTracer()
	}
	return c
}

// observePool makes the pool gauges read pool.
func observePool(pool *db.Pool) {
	telemetry.ObservePool(func() telemetry.PoolStats {
		s := pool.Pgx().Stat()
		return telemetry.PoolStats{
			InUse: int64(s.AcquiredConns()), Idle: int64(s.IdleConns()),
			Waits: s.EmptyAcquireCount(), WaitTime: s.EmptyAcquireWaitTime(),
		}
	})
}

// observeJobs counts the worker client's jobs by kind and state.
func observeJobs(ctx context.Context, client *jobs.Client) {
	jobs.ObserveOutcomes(ctx, client, telemetry.Job)
}

// serveAdmin runs the admin listener when admin.addr is set (HR-382).
func serveAdmin(ctx context.Context, g *errgroup.Group, cfg *Config, tel *telemetry.Telemetry, log *slog.Logger) error {
	if cfg.Admin.Addr == "" {
		return nil
	}
	ln, err := telemetry.ListenAdmin(ctx, cfg.Admin.Addr)
	if err != nil {
		return fmt.Errorf("server: %w", err)
	}
	srv := telemetry.NewAdminServer(telemetry.AdminHandler(tel.Reader()))
	log.InfoContext(ctx, "server.admin_listening", slog.String("addr", ln.Addr().String()))
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
	return nil
}
