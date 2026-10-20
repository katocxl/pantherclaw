// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/connections/app"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func pgConfig() app.PostgresConfig {
	return app.PostgresConfig{
		Host: "db.example.test", Database: "shop", User: "agent_reader", SSLMode: app.SSLVerifyFull,
		Tables: []app.PostgresTable{{
			Schema: "shop", Name: "customers", ScopeKey: "customer", ScopeColumn: "id",
			Columns: []app.PostgresColumn{
				{Name: "id", Type: "uuid", Class: "public"},
				{Name: "email", Type: "text", Class: "pii"},
				{Name: "ssn", Type: "text", Class: "secret"},
			},
		}},
	}
}

func a2aConfig() app.A2AConfig {
	return app.A2AConfig{
		CardURL:   "https://peer.example.test/.well-known/agent-card.json",
		Interface: app.A2AInterface{Protocol: app.A2AJSONRPC, URL: "https://peer.example.test/a2a"},
		Skills:    []string{"refunds"},
	}
}

// TestPostgresConfigCheck: a postgres manifest takes its defaults and
// refuses quoted or upper-case identifiers, unknown types and classes,
// sslmode require without an internal database and a pinned CA, a
// private address without internal, a scope key without its column and
// limits out of range (G0 M14 D15).
func TestPostgresConfigCheck(t *testing.T) {
	got, err := pgConfig().Check()
	if err != nil {
		t.Fatal(err)
	}
	if got.Port != 5432 || got.MaxRows != 200 || got.StatementTimeoutMs != 5000 || got.MaxResultBytes != 1<<20 || got.MinGroupSize != 5 {
		t.Fatalf("defaults: %+v", got)
	}
	bad := map[string]func(c *app.PostgresConfig){
		"no host":                    func(c *app.PostgresConfig) { c.Host = "" },
		"quoted database":            func(c *app.PostgresConfig) { c.Database = `"Shop"` },
		"upper-case user":            func(c *app.PostgresConfig) { c.User = "Reader" },
		"sslmode disable":            func(c *app.PostgresConfig) { c.SSLMode = "disable" },
		"sslmode empty":              func(c *app.PostgresConfig) { c.SSLMode = "" },
		"require, public":            func(c *app.PostgresConfig) { c.SSLMode = app.SSLRequire },
		"private, not internal":      func(c *app.PostgresConfig) { c.Host = "10.0.0.5" },
		"loopback, not internal":     func(c *app.PostgresConfig) { c.Host = "127.0.0.1" },
		"cgnat, not internal":        func(c *app.PostgresConfig) { c.Host = "100.64.0.9" },
		"benchmarking, not internal": func(c *app.PostgresConfig) { c.Host = "198.18.0.1" },
		"ietf range, not internal":   func(c *app.PostgresConfig) { c.Host = "192.0.0.8" },
		"ula, not internal":          func(c *app.PostgresConfig) { c.Host = "fd00::5" },
		"ca not a certificate": func(c *app.PostgresConfig) {
			c.CAPEM = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
		},
		"no tables":            func(c *app.PostgresConfig) { c.Tables = nil },
		"table twice":          func(c *app.PostgresConfig) { c.Tables = append(c.Tables, c.Tables[0]) },
		"dotted table":         func(c *app.PostgresConfig) { c.Tables[0].Name = "a.b" },
		"no columns":           func(c *app.PostgresConfig) { c.Tables[0].Columns = nil },
		"column twice":         func(c *app.PostgresConfig) { c.Tables[0].Columns[1].Name = "id" },
		"jsonb column":         func(c *app.PostgresConfig) { c.Tables[0].Columns[1].Type = "jsonb" },
		"unknown class":        func(c *app.PostgresConfig) { c.Tables[0].Columns[1].Class = "confidential" },
		"scope key alone":      func(c *app.PostgresConfig) { c.Tables[0].ScopeColumn = "" },
		"scope column unknown": func(c *app.PostgresConfig) { c.Tables[0].ScopeColumn = "customer_id" },
		"max rows over":        func(c *app.PostgresConfig) { c.MaxRows = 1001 },
		"table max rows over":  func(c *app.PostgresConfig) { c.Tables[0].MaxRows = 1001 },
		"timeout over":         func(c *app.PostgresConfig) { c.StatementTimeoutMs = 30_001 },
		"result over":          func(c *app.PostgresConfig) { c.MaxResultBytes = 4<<20 + 1 },
		"group of one":         func(c *app.PostgresConfig) { c.MinGroupSize = 1 },
		"port over":            func(c *app.PostgresConfig) { c.Port = 65536 },
	}
	for name, mutate := range bad {
		c := pgConfig()
		c.Tables[0].Columns = append([]app.PostgresColumn(nil), c.Tables[0].Columns...)
		mutate(&c)
		if _, err := c.Check(); !errors.Is(err, app.ErrPostgresConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
	internal := pgConfig()
	internal.Host, internal.Internal = "10.0.0.5", true
	if _, err := internal.Check(); err != nil {
		t.Errorf("a private address with internal: %v", err)
	}
}

// TestA2AConfigCheck: an a2a configuration takes its defaults, needs https
// URLs (http only on a local literal for a simulated connection), a
// JSONRPC or HTTP+JSON interface, distinct skills, a peer scope exactly
// with a peer agent, and never takes the card digest from the caller
// (G0 M14 D30).
func TestA2AConfigCheck(t *testing.T) {
	in := a2aConfig()
	in.CardDigest = []byte("from the caller")
	got, err := in.Check(false)
	if err != nil {
		t.Fatal(err)
	}
	if got.MaxAnswerBytes != 1<<20 || got.MaxStreamSeconds != 300 || got.CardDigest != nil {
		t.Fatalf("defaults: %+v", got)
	}
	peer := ids.NewV7()
	bad := map[string]func(c *app.A2AConfig){
		"http card":          func(c *app.A2AConfig) { c.CardURL = "http://peer.example.test/card" },
		"card with userinfo": func(c *app.A2AConfig) { c.CardURL = "https://u:p@peer.example.test/card" },
		"no interface url":   func(c *app.A2AConfig) { c.Interface.URL = "" },
		"grpc":               func(c *app.A2AConfig) { c.Interface.Protocol = "GRPC" },
		"skill twice":        func(c *app.A2AConfig) { c.Skills = []string{"refunds", "refunds"} },
		"empty skill":        func(c *app.A2AConfig) { c.Skills = []string{""} },
		"card not an object": func(c *app.A2AConfig) { c.PinnedCard = []byte(`[1]`) },
		"peer without scope": func(c *app.A2AConfig) { c.PeerAgent = &peer },
		"scope without peer": func(c *app.A2AConfig) { c.PeerScope = &app.A2APeerScope{Bounds: []byte(`{}`)} },
		"answer over":        func(c *app.A2AConfig) { c.MaxAnswerBytes = 8<<20 + 1 },
		"stream over":        func(c *app.A2AConfig) { c.MaxStreamSeconds = 3601 },
	}
	for name, mutate := range bad {
		c := a2aConfig()
		mutate(&c)
		if _, err := c.Check(false); !errors.Is(err, app.ErrA2AConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
	local := a2aConfig()
	local.CardURL, local.Interface.URL = "http://127.0.0.1:9000/card", "http://127.0.0.1:9000/a2a"
	if _, err := local.Check(false); !errors.Is(err, app.ErrA2AConfig) {
		t.Errorf("http on loopback, not simulated: %v", err)
	}
	if _, err := local.Check(true); err != nil {
		t.Errorf("http on loopback, simulated: %v", err)
	}
	withPeer := a2aConfig()
	withPeer.PeerAgent, withPeer.PeerScope = &peer, &app.A2APeerScope{Bounds: []byte(`{"version":1}`)}
	if _, err := withPeer.Check(false); err != nil {
		t.Errorf("a peer with its scope: %v", err)
	}
}

// TestM14KindsFailClosed: a postgres or a2a connection with a valid
// configuration is refused with KIND_NOT_IMPLEMENTED before anything is
// stored, and only when held by PantherClaw with its own configuration;
// no other kind carries one (G0 M14 D4).
func TestM14KindsFailClosed(t *testing.T) {
	svc := app.New(nil, nil, "https://pantherclaw.example.test", "https://gateway-api.example.test")
	ctx, org := context.Background(), ids.New[ids.Org]()
	pg, peer := pgConfig(), a2aConfig()
	base := app.CreateInput{Name: "target", Package: "pc.test", Gateway: ids.NewV7(), AccessMode: app.AccessHeld, CredentialHeader: "Authorization"}
	cases := []struct {
		name string
		edit func(in *app.CreateInput)
		want error
	}{
		{"postgres", func(in *app.CreateInput) { in.Kind, in.Postgres = app.KindPostgres, &pg }, app.ErrKindNotImplemented},
		{"a2a", func(in *app.CreateInput) { in.Kind, in.A2A = app.KindA2A, &peer }, app.ErrKindNotImplemented},
		{"postgres without config", func(in *app.CreateInput) { in.Kind = app.KindPostgres }, app.ErrShape},
		{"a2a without config", func(in *app.CreateInput) { in.Kind = app.KindA2A }, app.ErrShape},
		{"postgres agent held", func(in *app.CreateInput) {
			in.Kind, in.Postgres, in.AccessMode, in.CredentialHeader = app.KindPostgres, &pg, app.AccessAgentHeld, ""
		}, app.ErrShape},
		{"a2a with postgres config", func(in *app.CreateInput) { in.Kind, in.A2A, in.Postgres = app.KindA2A, &peer, &pg }, app.ErrShape},
		{"http with postgres config", func(in *app.CreateInput) {
			in.Kind, in.BaseURL, in.Postgres = app.KindHTTP, "https://api.example.test", &pg
		}, app.ErrShape},
		{"invalid postgres config", func(in *app.CreateInput) {
			c := pg
			c.SSLMode = "disable"
			in.Kind, in.Postgres = app.KindPostgres, &c
		}, app.ErrPostgresConfig},
	}
	for _, tc := range cases {
		in := base
		tc.edit(&in)
		if _, err := svc.Seed(ctx, org, "test", in); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	if !strings.Contains(app.ErrKindNotImplemented.Error(), "not available") {
		t.Errorf("message: %v", app.ErrKindNotImplemented)
	}
}

// TestM14_CapabilitiesOfTheNewKinds: a postgres connection declares that the
// gateway builds every query itself, an a2a connection that it builds every
// message, with the limit that a peer outside the org acts on its own; both
// are held by PantherClaw, so no agent-held limit applies (G0 M14 D100).
func TestM14_CapabilitiesOfTheNewKinds(t *testing.T) {
	for kind, limit := range map[string]string{app.KindPostgres: "", app.KindA2A: "PEER_AUTHORITY"} {
		c := app.Declare(app.Connection{PcConnection: dbq.PcConnection{
			Kind: kind, AccessMode: app.AccessHeld, DefaultMode: app.ModeEnforce, TimeoutMs: 2500,
		}}, &defs.Package{})
		has := false
		for _, l := range c.Limits {
			has = has || l.Code == limit
			if l.Code == "KIND_NOT_IMPLEMENTED" || l.Code == "AGENT_HELD_CREDENTIAL" {
				t.Errorf("%s: limit %s", kind, l.Code)
			}
		}
		if c.Enforcement.Level != app.Supported || (limit != "" && !has) {
			t.Errorf("%s: %+v %+v", kind, c.Enforcement, c.Limits)
		}
	}
}
