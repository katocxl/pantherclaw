// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"
	"net/http"
	"sync"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/federationkeys"
	"github.com/katocxl/pantherclaw/internal/federationkeys/federationrpc"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// The M35 federation core's wiring (G0 M35 D1020–D1025): FederationService,
// the Authority's federation calls and receipts, the public document and
// peer message routes, and the daily refresh.

// processFederation holds one federation key store per pool in this
// process, so the service, the Authority and the jobs share its caches.
var processFederation = struct {
	sync.Mutex
	m map[*db.Pool]*keystore.FederationKeys
}{m: map[*db.Pool]*keystore.FederationKeys{}}

func processFederationKeys(pool *db.Pool, kp keys.KeyProvider) *keystore.FederationKeys {
	processFederation.Lock()
	defer processFederation.Unlock()
	f, ok := processFederation.m[pool]
	if !ok {
		f = keystore.NewFederationKeys(pool, kp)
		processFederation.m[pool] = f
	}
	return f
}

// registerM35Federation serves FederationService and gives the Authority
// its federation calls; nil without a key provider (federation refuses,
// fail closed).
func registerM35Federation(rs *connect.Server, d apiDeps, grants *grantsapp.Service) *federationkeys.Service {
	if d.pool == nil || d.kp == nil {
		return nil
	}
	cfg := federationkeys.Config{
		Pool: d.pool, Keys: processFederationKeys(d.pool, d.kp), Grants: grants, ServerURL: d.publicURL, Logger: d.log,
	}
	if d.ui != nil && d.ui.ents != nil {
		cfg.Editions = d.ui.ents
	}
	svc := federationkeys.New(cfg)
	pantherclawv1connect.RegisterFederationServiceHandler(rs, federationrpc.New(svc))
	if d.authority != nil {
		d.authority.WithFederation(svc.Calls())
	}
	return svc
}

// mountM35Federation serves the public document and peer message routes.
func mountM35Federation(mux *http.ServeMux, svc *federationkeys.Service, d apiDeps) {
	if svc != nil {
		svc.Mount(mux, d.clientIP)
	}
}

// registerM35FederationJobs adds the hourly refresh dispatch.
func registerM35FederationJobs(periodic []*river.PeriodicJob, reg *jobs.Registry, pool *db.Pool, kp keys.KeyProvider, publicURL string,
	log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	if kp == nil {
		return periodic, nil
	}
	svc := federationkeys.New(federationkeys.Config{Pool: pool, Keys: processFederationKeys(pool, kp), ServerURL: publicURL, Logger: log})
	if err := federationkeys.RegisterJobs(reg, pool, svc, log); err != nil {
		return nil, err
	}
	return append(periodic, federationkeys.PeriodicJobs()...), nil
}
