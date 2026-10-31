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

	"connectrpc.com/connect/v2"

	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	defsapp "github.com/katocxl/pantherclaw/internal/definitions/app"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/hub"
	"github.com/katocxl/pantherclaw/internal/hub/adapters/drafts"
	"github.com/katocxl/pantherclaw/internal/hub/adapters/hubrpc"
	"github.com/katocxl/pantherclaw/internal/hub/adapters/pghub"
	hubapp "github.com/katocxl/pantherclaw/internal/hub/app"
	hubdomain "github.com/katocxl/pantherclaw/internal/hub/domain"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	reflexapp "github.com/katocxl/pantherclaw/internal/reflex/app"
)

// hubRoots returns the roots the API verifies a Hub index with: the embedded
// Hub roots and, when dev.hub_key_file names it, the development Hub key
// (G0 M23 D101). Validate refuses that setting unless the server is reachable
// only from this machine; the check is repeated here so that no other path
// can skip it. With no root at all, verification ends in HUB_NO_ROOT.
func hubRoots(ctx context.Context, cfg *Config, log *slog.Logger) (hubdomain.Roots, error) {
	roots, err := hub.EmbeddedRoots()
	if err != nil || cfg.Dev.HubKeyFile == "" {
		return roots, err
	}
	if err := cfg.localOnly(); err != nil {
		return nil, fmt.Errorf("server: dev.hub_key_file is development-only (D101): %w", err)
	}
	b, err := os.ReadFile(cfg.Dev.HubKeyFile)
	if errors.Is(err, fs.ErrNotExist) {
		log.WarnContext(ctx, "hub.dev_key_missing", slog.String("file", cfg.Dev.HubKeyFile))
		return roots, nil
	}
	if err != nil {
		return nil, fmt.Errorf("server: dev.hub_key_file: %w", err)
	}
	dev, err := hubdomain.ParseDevKey(b)
	if err != nil {
		return nil, fmt.Errorf("server: dev.hub_key_file: %w", err)
	}
	all := maps.Clone(roots)
	maps.Copy(all, dev)
	for kid := range dev {
		log.WarnContext(ctx, "hub.dev_key_trusted", slog.String("kid", kid),
			slog.String("note", "DEVELOPMENT ONLY: Hub indexes signed with this key are trusted"))
	}
	return all, nil
}

// registerM23Hub serves HubService. The server never fetches an index and has
// no outbound call here (D107).
func registerM23Hub(rs *connect.Server, d apiDeps, core *automationsCore) error {
	roots := d.hubRoots
	if roots == nil {
		var err error
		if roots, err = hub.EmbeddedRoots(); err != nil {
			return err
		}
	}
	packages := d.packageRoots
	if packages == nil {
		var err error
		if packages, err = trust.EmbeddedRoots(); err != nil {
			return err
		}
	}
	defs := &defspg.Store{Pool: d.pool}
	var notify policyapp.Notifier
	if d.m5 != nil && d.m5.notifications != nil {
		notify = d.m5.notifications
	}
	reflex := newReflexCore(d.pool, d.cel, d.billing, nil, d.log)
	det := &reflexapp.Detections{Pool: d.pool, PackErr: reflex.packErr, Env: reflex.env}
	if d.billing != nil {
		det.Ents = d.billing
	}
	svc := &hubapp.Service{
		Store: &pghub.Store{Pool: d.pool}, Roots: roots, Clock: clock.System{},
		Policies:   newPolicyVersions(d.pool, notify, d.publicURL, d.cel),
		Detections: drafts.Detections{Rules: det},
		Packages: drafts.Packages{Admin: &defsapp.Admin{
			Importer: &defsapp.Importer{Roots: packages, Repo: defs, Keys: defs, Clock: clock.System{}}, Reads: defs,
			Authz: grantsapp.SubjectAuthorizer{}, Ents: d.billing,
		}},
	}
	if core != nil && core.svc != nil {
		svc.Automations = drafts.Automations{Pool: d.pool, Svc: core.svc}
	}
	pantherclawv1connect.RegisterHubServiceHandler(rs, hubrpc.New(svc))
	return nil
}
