// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"net/http"
	"time"

	"connectrpc.com/connect/v2"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/authn/token"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/operations"
	"github.com/katocxl/pantherclaw/internal/operations/adapters/operationsrpc"
	"github.com/katocxl/pantherclaw/internal/operations/stream"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/search"
	"github.com/katocxl/pantherclaw/internal/search/adapters/searchrpc"
)

// m10OpsDeps are what the Operations surface needs beyond apiDeps: the
// bearer authenticator and the token service, for the live stream.
type m10OpsDeps struct {
	authn  *authnapp.Authenticator
	tokens *token.Service
}

// registerM10Ops registers OperationsService and SearchService (G0 M10
// D33, D34) and returns the function that mounts the live stream (D32,
// HR-256) on the API mux.
func registerM10Ops(rs *connect.Server, d apiDeps) (func(*http.ServeMux), error) {
	pantherclawv1connect.RegisterOperationsServiceHandler(rs,
		operationsrpc.New(&operations.Service{Pool: d.pool, Clock: clock.System{}, Sources: opsSources(d)}))
	pantherclawv1connect.RegisterSearchServiceHandler(rs,
		searchrpc.New(&search.Service{
			Pool: d.pool, Defs: &defspg.Store{Pool: d.pool}, Clock: clock.System{},
			Exposure: searchExposure{svc: m10Exposure(d.pool, d.billing)},
		}))
	if d.m10ops.authn == nil {
		return func(*http.ServeMux) {}, nil // no bearer authentication configured (tests)
	}
	tokens := d.m10ops.tokens
	expiry := func(bearer string) (time.Time, bool) {
		if tokens == nil {
			return time.Time{}, false
		}
		v, err := tokens.Verify(bearer, time.Now())
		if err != nil {
			return time.Time{}, false
		}
		return v.ExpiresAt, true
	}
	h, err := stream.New(stream.PoolFeed{Pool: d.pool}, d.m10ops.authn, stream.PoolScoper{Pool: d.pool}, expiry,
		clock.System{}, stream.Config{}, d.log)
	if err != nil {
		return nil, err
	}
	return h.Mount, nil
}
