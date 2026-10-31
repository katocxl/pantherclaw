// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"log/slog"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/datarequests"
	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/exports"
	"github.com/katocxl/pantherclaw/internal/exports/exportsrpc"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// exportsDeps is what the export service is built from.
type exportsDeps struct {
	pool      *db.Pool
	kp        keys.KeyProvider
	reg       *keys.Registry
	bill      *billing.Service
	publicURL string
	logOrigin string
	log       *slog.Logger
}

// newExports builds the export destinations service as pc_app: credentials
// under the org's DEKs, the licence, the proof bundles, the key that signs
// removal notices, and Operations' owned failures.
func newExports(d exportsDeps) (*exports.Service, error) {
	env := pccrypto.NewEnvelope(keystore.NewDEKStore(d.pool, d.kp))
	svc, err := exports.New(d.pool, env, exports.Config{PublicURL: d.publicURL}, clock.System{}, d.log)
	if err != nil {
		return nil, err
	}
	insert, err := jobs.NewClient(d.pool, nil, jobs.Config{Logger: d.log})
	if err != nil {
		return nil, err
	}
	svc.WithPushes(insert, evapp.New(d.pool, d.logOrigin), d.reg, edgesFailures())
	if d.bill != nil {
		svc.WithEditions(d.bill)
	}
	return svc, nil
}

// exportStream adapts exports.Service to the export build's stream. A nil
// *exports.Stream must stay a nil interface.
type exportStream struct{ svc *exports.Service }

func (e exportStream) Open(ctx context.Context, org ids.OrgID, request, requestedBy ids.UUID) (datarequests.PushWriter, error) {
	st, err := e.svc.Open(ctx, org, request, requestedBy)
	if err != nil || st == nil {
		return nil, err
	}
	return st, nil
}

// wireExportStream lets a push waiting for an export take it as it builds.
func wireExportStream(data *datarequests.Service, d exportsDeps) error {
	s, err := newExports(d)
	if err != nil {
		return err
	}
	data.Stream = exportStream{svc: s}
	return nil
}

// registerM20Exports serves ExportDestinationService and adds the
// activation page when the browser pages are mounted.
func registerM20Exports(rs *connect.Server, d apiDeps) error {
	s, err := newExports(exportsDeps{pool: d.pool, kp: d.kp, reg: d.reg, bill: d.billing, publicURL: d.publicURL, logOrigin: d.logOrigin, log: d.log})
	if err != nil {
		return err
	}
	pantherclawv1connect.RegisterExportDestinationServiceHandler(rs, exportsrpc.New(s))
	if d.web != nil {
		d.web.WithExportDestinations(s)
	}
	return nil
}

// registerM20ExportsJobs adds the pushes and the hourly sweep and returns
// the sweep's schedule.
func registerM20ExportsJobs(periodic []*river.PeriodicJob, reg *jobs.Registry, d exportsDeps) ([]*river.PeriodicJob, error) {
	s, err := newExports(d)
	if err != nil {
		return nil, err
	}
	sweep, err := exports.Register(reg, s)
	if err != nil {
		return nil, err
	}
	return append(periodic, sweep...), nil
}
