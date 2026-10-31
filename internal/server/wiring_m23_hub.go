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

	autoapp "github.com/katocxl/pantherclaw/internal/automations/app"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	defsapp "github.com/katocxl/pantherclaw/internal/definitions/app"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/hub"
	"github.com/katocxl/pantherclaw/internal/hub/adapters/hubrpc"
	"github.com/katocxl/pantherclaw/internal/hub/adapters/pghub"
	hubapp "github.com/katocxl/pantherclaw/internal/hub/app"
	hubdomain "github.com/katocxl/pantherclaw/internal/hub/domain"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	reflexapp "github.com/katocxl/pantherclaw/internal/reflex/app"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
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

// hubDetections installs a detection rule through CreateCustomRule.
type hubDetections struct{ det *reflexapp.Detections }

func (h hubDetections) CreateDraft(ctx context.Context, content string) (string, error) {
	r, err := h.det.CreateCustomRule(ctx, content)
	if err != nil {
		return "", err
	}
	return r.Custom.ID.String(), nil
}

// hubAutomations installs an automation through CreateDraftTx: the automation
// and its first version in one transaction, owned by the caller.
type hubAutomations struct {
	pool *db.Pool
	svc  *autoapp.Service
}

func (h hubAutomations) CreateDraft(ctx context.Context, b hubdomain.AutomationBody) (string, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return "", err
	}
	var id string
	err = h.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		a, _, err := h.svc.CreateDraftTx(ctx, tx, autoapp.Draft{
			Name: b.AutomationName, Purpose: b.Purpose, Kind: autodomain.WorkKind(b.WorkKind), Owner: c.Principal.ID, Definition: []byte(b.Definition),
		})
		id = a.ID.String()
		return err
	})
	return id, err
}

// hubPackages installs a tool package through ImportPackage's use case.
type hubPackages struct{ admin *defsapp.Admin }

func (h hubPackages) ImportPackage(ctx context.Context, name, version, targets string, raw []byte) error {
	_, _, err := h.admin.Import(ctx, name, version, targets, raw)
	return err
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
		Detections: hubDetections{det},
		Packages: hubPackages{&defsapp.Admin{
			Importer: &defsapp.Importer{Roots: packages, Repo: defs, Keys: defs, Clock: clock.System{}}, Reads: defs,
			Authz: grantsapp.SubjectAuthorizer{}, Ents: d.billing,
		}},
	}
	if core != nil && core.svc != nil {
		svc.Automations = hubAutomations{d.pool, core.svc}
	}
	pantherclawv1connect.RegisterHubServiceHandler(rs, hubrpc.New(svc))
	return nil
}
