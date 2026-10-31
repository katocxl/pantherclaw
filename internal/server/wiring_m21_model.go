// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"fmt"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/automations/securitysteps"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	defsdomain "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/model/adapters/anthropic"
	"github.com/katocxl/pantherclaw/internal/model/adapters/modelrpc"
	modelapp "github.com/katocxl/pantherclaw/internal/model/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/search"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
	pca2a "github.com/katocxl/pantherclaw/packages/pc-a2a"
	pcaws "github.com/katocxl/pantherclaw/packages/pc-aws"
	pcawsecs "github.com/katocxl/pantherclaw/packages/pc-aws-ecs"
	pcgithub "github.com/katocxl/pantherclaw/packages/pc-github"
	pcgitlab "github.com/katocxl/pantherclaw/packages/pc-gitlab"
	pcjira "github.com/katocxl/pantherclaw/packages/pc-jira"
	pcpostgres "github.com/katocxl/pantherclaw/packages/pc-postgres"
	pcshell "github.com/katocxl/pantherclaw/packages/pc-shell"
	pcslack "github.com/katocxl/pantherclaw/packages/pc-slack"
	pcstripe "github.com/katocxl/pantherclaw/packages/pc-stripe"
	pcteams "github.com/katocxl/pantherclaw/packages/pc-teams"
)

// newModel builds model drafting's service (G0 M21 D304, D309). Without the
// server's switch it is still built, so an organization can always read that
// it is off and clear its key.
func newModel(d apiDeps) *modelapp.Service {
	svc := &modelapp.Service{
		Pool: d.pool, Envelope: pccrypto.NewEnvelope(keystore.NewDEKStore(d.pool, d.kp)), Provider: anthropic.New(),
		Config: modelapp.Config{Enabled: d.model.Enabled, CallsPerMinute: d.model.CallsPerMinute, TokensPerDay: d.model.TokensPerDay},
	}
	if d.billing != nil {
		svc.Editions = d.billing
	}
	if n := edgesNotifier(d.m5); n != nil {
		svc.Notify = n
	}
	return svc
}

// builtinPackages are the packages PantherClaw ships, the only ones a model is
// told of (D316, D321).
func builtinPackages() ([]*defsdomain.Package, error) {
	raws := [][]byte{
		mockpayments.Package, pca2a.Package, pcaws.Package, pcawsecs.Package, pcgithub.Package, pcgitlab.Package, pcjira.Package,
		pcpostgres.Package, pcshell.Package, pcslack.Package, pcstripe.Package, pcteams.Package,
	}
	pkgs := make([]*defsdomain.Package, 0, len(raws))
	for _, raw := range raws {
		p, err := manifest.Decode(raw)
		if err != nil {
			return nil, fmt.Errorf("model drafting: built-in package: %w", err)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

// registerM21Model registers ModelService. A built-in package that does not
// load is an error that reaches cmdServe.
func registerM21Model(rs *connect.Server, d apiDeps, core *automationsCore) error {
	pkgs, err := builtinPackages()
	if err != nil {
		return err
	}
	svc := newModel(d)
	builtin := modelapp.BuiltinOperations(pkgs...)
	svc.Params, svc.Builtin, svc.Clock = modelapp.BuiltinParams(pkgs...), builtin, clock.System{}
	if core != nil && core.svc != nil {
		svc.Automations = core.svc
	}
	defs := &defspg.Store{Pool: d.pool}
	queries := &search.Service{Pool: d.pool, Defs: defs, Clock: clock.System{}}
	if d.billing != nil {
		queries.Editions = d.billing
	}
	drafter := &search.Drafter{Search: queries, Model: svc, Builtin: builtin}
	svc.Operations = drafter
	svc.Policies = securitysteps.NewPolicyDrafts(&factspg.Store{Pool: d.pool}, defs, d.cel)
	pantherclawv1connect.RegisterModelServiceHandler(rs, modelrpc.New(svc, drafter))
	if d.web != nil {
		d.web.WithModelDrafting(svc)
	}
	return nil
}
