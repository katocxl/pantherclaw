// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/billing"
	contentapp "github.com/katocxl/pantherclaw/internal/contentsignals/app"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/intel"
	"github.com/katocxl/pantherclaw/internal/intel/adapters/intelrpc"
	intelapp "github.com/katocxl/pantherclaw/internal/intel/app"
	inteldomain "github.com/katocxl/pantherclaw/internal/intel/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

// Shared threat intel's wiring (G0 M38 D1103..D1105).

// intelFetchTimeout bounds one feed fetch.
const intelFetchTimeout = 30 * time.Second

// intelRoots are the embedded intel roots and, on a server reachable only
// from this machine, the development intel key of dev.intel_key_file
// (D1103). Validate refuses that setting otherwise; the check is repeated
// here so that no other path can skip it. With no root at all, every feed
// is refused (INTEL_NO_ROOT).
func intelRoots(ctx context.Context, cfg *Config, log *slog.Logger) (inteldomain.Roots, error) {
	roots, err := intel.EmbeddedRoots()
	if err != nil || cfg.Dev.IntelKeyFile == "" {
		return roots, err
	}
	if err := cfg.localOnly(); err != nil {
		return nil, fmt.Errorf("server: dev.intel_key_file is development-only (D1103): %w", err)
	}
	b, err := os.ReadFile(cfg.Dev.IntelKeyFile)
	if errors.Is(err, fs.ErrNotExist) {
		log.WarnContext(ctx, "intel.dev_key_missing", slog.String("file", cfg.Dev.IntelKeyFile))
		return roots, nil
	}
	if err != nil {
		return nil, fmt.Errorf("server: dev.intel_key_file: %w", err)
	}
	dev, err := inteldomain.ParseDevKey(b)
	if err != nil {
		return nil, fmt.Errorf("server: dev.intel_key_file: %w", err)
	}
	all := maps.Clone(roots)
	if all == nil {
		all = inteldomain.Roots{}
	}
	maps.Copy(all, dev)
	for kid := range dev {
		log.WarnContext(ctx, "intel.dev_key_trusted", slog.String("kid", kid),
			slog.String("note", "DEVELOPMENT ONLY: intel feeds signed with this key are trusted"))
	}
	return all, nil
}

// intelMatcher matches discovery, drift and content against the feed; a
// nil billing service matches nothing (consuming is Business, D1103).
func intelMatcher(bill *billing.Service) *intelapp.Matcher {
	m := &intelapp.Matcher{}
	if bill != nil {
		m.Ents = bill
	}
	return m
}

// withIntelContent gives the content sink the intel matcher, so a shared
// injection_text match the gateway found is recorded (D1104).
func withIntelContent(s *contentapp.Sink, bill *billing.Service) *contentapp.Sink {
	s.Intel = intelMatcher(bill)
	return s
}

// registerM38Intel serves IntelService and holds a loosening of the consume
// mode behind the Gate (D1104a). The procedure permissions are in
// procedures_m38_intel.go.
func registerM38Intel(rs *connect.Server, d apiDeps) {
	svc := &intelapp.Service{Pool: d.pool}
	if d.billing != nil {
		svc.Ents = d.billing
	}
	svc.RegisterProtect(d.m11protect.gate) // a loosening waits for a second person (D1104a)
	pantherclawv1connect.RegisterIntelServiceHandler(rs, intelrpc.New(svc))
}

// registerM38IntelJobs registers the daily feed fetch when intel.feed_url
// is set, through the egress client (public addresses only), and returns
// periodic with its schedule.
func registerM38IntelJobs(ctx context.Context, periodic []*river.PeriodicJob, reg *jobs.Registry, cfg *Config, pool *db.Pool,
	log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	if cfg.Intel.FeedURL == "" {
		return periodic, nil
	}
	roots, err := intelRoots(ctx, cfg, log)
	if err != nil {
		return nil, err
	}
	f := &intelapp.Fetcher{
		URL:      cfg.Intel.FeedURL,
		HTTP:     httpx.NewEgressClient(httpx.EgressConfig{Timeout: intelFetchTimeout}),
		Importer: &intelapp.Importer{Pool: pool, Roots: roots, Log: log},
	}
	jobs, err := intelapp.RegisterFetch(reg, f)
	if err != nil {
		return nil, err
	}
	return append(periodic, jobs...), nil
}
