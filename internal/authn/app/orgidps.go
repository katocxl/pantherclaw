// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// OrgIdPs resolves an organization's own identity providers on each
// request (G0 M18 D155): its ACTIVE providers, and whether the org signs
// in with them alone ("own providers only").
type OrgIdPs interface {
	OrgProviders(ctx context.Context, org ids.OrgID) (own []IdP, ownOnly bool, err error)
}

// providers are the deployment's providers (auth.oidc_providers) and,
// when wired, the organizations' own.
type providers struct {
	deployment map[string]IdP
	orgs       OrgIdPs
}

func newProviders(idps []IdP) providers {
	m := map[string]IdP{}
	for _, p := range idps {
		m[p.Name()] = p
	}
	return providers{deployment: m}
}

// any reports whether some sign-in can be possible at all.
func (ps providers) any() bool { return len(ps.deployment) > 0 || ps.orgs != nil }

// named returns a deployment provider; "" names the only one.
func (ps providers) named(name string) (IdP, bool) {
	return pick(ps.deployment, name)
}

// forOrg returns the provider name signs an org's people in with: a
// deployment provider unless the org uses its own providers only, else one
// of the org's ACTIVE providers. A deployment provider wins a name the org
// also uses (the org's names are refused at creation). "" names the only
// provider the org has.
func (ps providers) forOrg(ctx context.Context, org ids.OrgID, name string) (IdP, bool, error) {
	if ps.orgs == nil {
		p, ok := ps.named(name)
		return p, ok, nil
	}
	own, only, err := ps.orgs.OrgProviders(ctx, org)
	if err != nil {
		return nil, false, err
	}
	m := map[string]IdP{}
	for _, p := range own {
		m[p.Name()] = p
	}
	if !only {
		for n, p := range ps.deployment {
			m[n] = p
		}
	}
	p, ok := pick(m, name)
	return p, ok, nil
}

func pick(m map[string]IdP, name string) (IdP, bool) {
	if name == "" && len(m) == 1 {
		for _, p := range m {
			return p, true
		}
	}
	p, ok := m[name]
	return p, ok
}
