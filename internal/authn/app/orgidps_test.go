// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

type namedIdP struct {
	IdP
	name string
	org  bool
}

func (p namedIdP) Name() string { return p.name }

type fakeOrgIdPs struct {
	own  map[ids.OrgID][]IdP
	only map[ids.OrgID]bool
	err  error
}

func (f fakeOrgIdPs) OrgProviders(_ context.Context, org ids.OrgID) ([]IdP, bool, error) {
	return f.own[org], f.only[org], f.err
}

// TestOrgProviderResolution: an org signs in with the deployment's
// providers plus its own ACTIVE ones, resolved per request; with "own
// providers only" set, with its own alone; another org's providers never
// (G0 M18 D155). A deployment provider wins a name; "" names the only
// provider; a resolver error fails the lookup.
//
// Covers: PN-012.7
func TestOrgProviderResolution(t *testing.T) {
	a, b := ids.New[ids.Org](), ids.New[ids.Org]()
	corp, acme := namedIdP{name: "corp"}, namedIdP{name: "acme", org: true}
	ps := newProviders([]IdP{corp})
	if p, ok, err := ps.forOrg(context.Background(), a, ""); err != nil || !ok || p.Name() != "corp" {
		t.Fatalf("without org providers: %v %v %v", p, ok, err)
	}
	f := fakeOrgIdPs{own: map[ids.OrgID][]IdP{a: {acme, namedIdP{name: "corp", org: true}}}, only: map[ids.OrgID]bool{}}
	ps.orgs = f
	ctx := context.Background()
	if p, ok, _ := ps.forOrg(ctx, a, "acme"); !ok || p != IdP(acme) {
		t.Fatal("org a's own provider not resolved")
	}
	if p, ok, _ := ps.forOrg(ctx, a, "corp"); !ok || p != IdP(corp) {
		t.Fatal("a deployment provider lost its name to an org's")
	}
	if _, ok, _ := ps.forOrg(ctx, b, "acme"); ok {
		t.Fatal("org b resolved org a's provider")
	}
	if p, ok, _ := ps.forOrg(ctx, b, ""); !ok || p != IdP(corp) {
		t.Fatal("org b's only provider is the deployment's")
	}
	if _, ok, _ := ps.forOrg(ctx, a, ""); ok {
		t.Fatal(`"" chose among several providers`)
	}
	f.only[a] = true
	if p, ok, _ := ps.forOrg(ctx, a, "corp"); !ok || p == IdP(corp) {
		t.Fatal("own providers only still signed in through the deployment's provider")
	}
	if p, ok, _ := ps.forOrg(ctx, b, "corp"); !ok || p != IdP(corp) {
		t.Fatal("org a's setting changed org b")
	}
	if p, ok := ps.named("corp"); !ok || p != IdP(corp) {
		t.Fatal("a sign-in without an org must use the deployment's providers")
	}
	if _, ok := ps.named("acme"); ok {
		t.Fatal("a sign-in without an org resolved an org's provider")
	}
	ps.orgs = fakeOrgIdPs{err: errors.New("down")}
	if _, ok, err := ps.forOrg(ctx, a, "corp"); err == nil || ok {
		t.Fatal("a resolver failure fell back to the deployment's providers")
	}
}
