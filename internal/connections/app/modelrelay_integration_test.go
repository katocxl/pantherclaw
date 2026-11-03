// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/connections/app"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
)

// TestHR613_AModelRelayIsASimulatedConnectionWithoutAPackage: a model relay is
// created as simulated http, with no package, routes, agent hosts or
// credential, and an 8 MiB cap; any other shape is refused, and "model" is a
// reserved name (G0 M25 D313).
// Covers: F906
func TestHR613_AModelRelayIsASimulatedConnectionWithoutAPackage(t *testing.T) {
	e := newEnv(t)
	relay := func() app.CreateInput {
		return app.CreateInput{
			Name: "relay", Kind: app.KindHTTP, Package: app.ModelRelayPackage, BaseURL: "http://127.0.0.1:9100", Gateway: e.gateway,
			AccessMode: app.AccessNone, Simulated: true, ModelRelay: true,
		}
	}
	c, err := e.svc.Create(e.admin, relay())
	if err != nil {
		t.Fatal(err)
	}
	if !c.ModelRelay || !c.Simulated || c.MaxResponseBytes != 8<<20 || len(c.Routes) != 0 {
		t.Fatalf("relay %+v", c.PcConnection)
	}
	for name, edit := range map[string]func(*app.CreateInput){
		"a real one":      func(in *app.CreateInput) { in.Simulated = false },
		"another package": func(in *app.CreateInput) { in.Package = "pc.github" },
		"agent hosts":     func(in *app.CreateInput) { in.AgentHosts = []string{"api.anthropic.com"} },
		"a held key": func(in *app.CreateInput) {
			in.AccessMode, in.CredentialHeader = app.AccessHeld, "X-Api-Key"
		},
		"a public target": func(in *app.CreateInput) { in.BaseURL = "https://api.anthropic.com" },
	} {
		in := relay()
		in.Name = "relay-2"
		edit(&in)
		if _, err := e.svc.Create(e.admin, in); pcerr.CodeOf(err) != pcerr.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A relay is known by its mark, never by a name: "model" is an
	// ordinary connection name (D525 L5).
	plain := app.CreateInput{
		Name: "model", Kind: app.KindHTTP, Package: mockpayments.Name, BaseURL: "https://payments.example.test/v1/", Gateway: e.gateway,
		AccessMode: app.AccessNone,
	}
	if m, err := e.svc.Create(e.admin, plain); err != nil || m.ModelRelay {
		t.Fatalf("a connection named model: %v", err)
	}

	// The relay keeps its shape on update (D525 L3).
	other := app.ClassInternal
	if c.DestinationClass == app.ClassInternal {
		other = app.ClassPublic
	}
	held := app.AccessHeld
	for name, u := range map[string]app.UpdateInput{
		"access mode":       {AccessMode: &held},
		"agent hosts":       {AgentHosts: []string{"api.anthropic.com"}, SetAgentHosts: true},
		"destination class": {DestinationClass: &other},
	} {
		u.ID, u.Revision = c.ID, c.Revision
		if _, err := e.svc.Update(e.admin, u); pcerr.ReasonOf(err) != "MODEL_RELAY_INVALID" {
			t.Errorf("update of the %s: %v", name, err)
		}
	}
	timeout := int32(5000)
	if _, err := e.svc.Update(e.admin, app.UpdateInput{ID: c.ID, Revision: c.Revision, TimeoutMs: &timeout}); err != nil {
		t.Fatalf("a timeout change: %v", err)
	}
}
