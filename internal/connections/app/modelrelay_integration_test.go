// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/connections/app"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
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
	in := relay()
	in.Name, in.ModelRelay = "model", false
	if _, err := e.svc.Create(e.admin, in); pcerr.ReasonOf(err) != "CONNECTION_NAME_RESERVED" {
		t.Fatalf("the name model: %v", err)
	}
}
