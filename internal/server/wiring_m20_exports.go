// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/exports"
	"github.com/katocxl/pantherclaw/internal/exports/exportsrpc"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// newExports builds the export destinations service as pc_app: credentials
// under the org's DEKs and the licence.
func newExports(pool *db.Pool, kp keys.KeyProvider, bill *billing.Service, publicURL string, log *slog.Logger) (*exports.Service, error) {
	env := pccrypto.NewEnvelope(keystore.NewDEKStore(pool, kp))
	svc, err := exports.New(pool, env, exports.Config{PublicURL: publicURL}, clock.System{}, log)
	if err != nil {
		return nil, err
	}
	if bill != nil {
		svc.WithEditions(bill)
	}
	return svc, nil
}

// registerM20Exports serves ExportDestinationService and adds the
// activation page when the browser pages are mounted.
func registerM20Exports(rs *connect.Server, d apiDeps) error {
	s, err := newExports(d.pool, d.kp, d.billing, d.publicURL, d.log)
	if err != nil {
		return err
	}
	pantherclawv1connect.RegisterExportDestinationServiceHandler(rs, exportsrpc.New(s))
	if d.web != nil {
		d.web.WithExportDestinations(s)
	}
	return nil
}
