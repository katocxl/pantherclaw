// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"
	"net/http"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/otlpexport"
	"github.com/katocxl/pantherclaw/internal/otlpexport/otlprpc"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
)

// The M36 OTel GenAI wiring (G0 M36 D1060–D1062): OTLPDestinationService,
// the destination activation page and the per-org span exporter. The
// operator's own telemetry (wiring_m13_observability.go, HR-380) is
// separate and unchanged.

// newOTLPExport builds the exporter as pc_app: headers sealed under the
// org's DEKs and the evidence feed; nil without a key provider (no
// destination can be created or exported, fail closed).
func newOTLPExport(pool *db.Pool, kp keys.KeyProvider, publicURL, consoleURL string, log *slog.Logger) (*otlpexport.Service, error) {
	if pool == nil || kp == nil {
		return nil, nil
	}
	env := pccrypto.NewEnvelope(keystore.NewDEKStore(pool, kp))
	return otlpexport.New(pool, env, feed.Reader{}, otlpexport.Config{PublicURL: publicURL, ConsoleURL: consoleURL},
		clock.System{}, log)
}

// registerM36OTel serves OTLPDestinationService and returns the activation
// page's mount; nil when the service cannot run.
func registerM36OTel(rs *connect.Server, d apiDeps) (func(mux *http.ServeMux), error) {
	svc, err := newOTLPExport(d.pool, d.kp, d.publicURL, consoleBaseURL(d.publicURL, d.ext), d.log)
	if err != nil || svc == nil {
		return nil, err
	}
	pantherclawv1connect.RegisterOTLPDestinationServiceHandler(rs, otlprpc.New(svc))
	if d.web == nil {
		return nil, nil
	}
	web := d.web
	return func(mux *http.ServeMux) { web.MountOTLPDestinations(mux, svc) }, nil
}

// registerM36OTelJobs adds the exporter's dispatch, every 30 seconds.
func registerM36OTelJobs(periodic []*river.PeriodicJob, reg *jobs.Registry, pool *db.Pool, kp keys.KeyProvider, publicURL,
	consoleURL string, log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	svc, err := newOTLPExport(pool, kp, publicURL, consoleURL, log)
	if err != nil || svc == nil {
		return periodic, err
	}
	p, err := otlpexport.RegisterExport(reg, svc)
	if err != nil {
		return nil, err
	}
	return append(periodic, p...), nil
}
