// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"testing"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/gateways/app"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
)

func (e *env) pinMockPayments(t *testing.T) {
	t.Helper()
	pkg, ver, raw := ids.NewV7(), ids.NewV7(), mockpayments.Package
	e.exec(t, "INSERT INTO pc.tool_packages (org_id, id, name) VALUES ($1, $2, $3)", e.org, pkg, mockpayments.Name)
	e.exec(t, `INSERT INTO pc.package_versions (org_id, id, package_id, version, file_digest, raw, state)
		VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE')`, e.org, ver, pkg, mockpayments.Version, manifest.FileDigest(raw), raw)
	e.exec(t, "INSERT INTO pc.package_pins (org_id, package_id, version_id, version, digest) VALUES ($1, $2, $3, $4, $5)",
		e.org, pkg, ver, mockpayments.Version, manifest.FileDigest(raw))
}

// TestHR182_TheConfigurationCarriesOnlyThisGatewaysConnectionsAndCredentials:
// a gateway's configuration lists its own connections with their route
// modes and pinned packages, and only credentials sealed to its own broker
// key; another gateway's connection and a credential sealed to another
// gateway's key are absent. A current known version returns nothing else,
// and a revoked gateway gets nothing.
func TestHR182_TheConfigurationCarriesOnlyThisGatewaysConnectionsAndCredentials(t *testing.T) {
	e := newEnv(t)
	e.pinMockPayments(t)
	_, mine := e.enroll(t, "mine")
	_, theirs := e.enroll(t, "theirs")
	ctx := context.Background()
	key := func(id app.Identity) ids.UUID {
		k, err := pccrypto.GenerateSealKey()
		if err != nil {
			t.Fatal(err)
		}
		b, err := e.svc.RegisterBrokerKey(ctx, id, k.PublicKey().Bytes())
		if err != nil {
			t.Fatal(err)
		}
		return b.ID
	}
	myKey, theirKey := key(mine), key(theirs)

	conns := capp.New(e.pool, nil, "https://pc.example.test", "https://gw.example.test:8443")
	create := func(name string, gw ids.UUID) capp.Connection {
		c, err := conns.Create(e.admin, capp.CreateInput{
			Name: name, Kind: capp.KindHTTP, Package: mockpayments.Name, BaseURL: "https://" + name + ".example.test", Gateway: gw,
			AccessMode: capp.AccessHeld, CredentialHeader: "Authorization",
		})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	a := create("a", mine.Gateway)
	b := create("b", theirs.Gateway)
	if _, err := conns.SetRouteMode(e.admin, a.ID, "payments-refund", capp.ModeEnforce); err != nil {
		t.Fatal(err)
	}
	blob := append([]byte{0x01}, make([]byte, 1200)...) // the shape of a sealed credential; never opened here
	put := func(conn ids.UUID, version int, broker ids.UUID, hosts string) {
		e.exec(t, `INSERT INTO pc.credentials (org_id, id, connection_id, version, broker_key_id, sealed, allowed_hosts, header, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, ARRAY[$7], 'Authorization', 'test')`, e.org, ids.NewV7(), conn, version, broker, blob, hosts)
	}
	put(a.ID, 1, myKey, "a.example.test")
	put(b.ID, 1, theirKey, "b.example.test")

	cfg, err := e.svc.Configuration(ctx, mine, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Unchanged || len(cfg.Connections) != 1 || cfg.Connections[0].ID != a.ID || len(cfg.Packages) != 1 ||
		cfg.Packages[0].Name != mockpayments.Name || len(cfg.Credentials) != 1 || cfg.Credentials[0].ConnectionID != a.ID {
		t.Fatalf("configuration of mine: %+v", cfg)
	}
	enforced := false
	for _, r := range cfg.Routes {
		if r.ConnectionID != a.ID {
			t.Fatalf("a route of another connection: %+v", r)
		}
		enforced = enforced || (r.Route == "payments-refund" && r.Mode == capp.ModeEnforce)
	}
	if !enforced {
		t.Fatal("the route mode is not in the configuration")
	}
	again, err := e.svc.Configuration(ctx, mine, cfg.Version)
	if err != nil || !again.Unchanged || again.Connections != nil {
		t.Fatalf("known version: %+v %v", again, err)
	}

	// A credential of connection a sealed to the other gateway's key is
	// never sent to this one.
	e.exec(t, "UPDATE pc.credentials SET state = 'SUPERSEDED', superseded_at = now() WHERE connection_id = $1", a.ID)
	put(a.ID, 2, theirKey, "a.example.test")
	cfg, err = e.svc.Configuration(ctx, mine, 0)
	if err != nil || len(cfg.Credentials) != 0 {
		t.Fatalf("a credential sealed to another gateway was sent: %+v %v", cfg.Credentials, err)
	}

	// The GitHub App installations of its own connections, and only those
	// (G0 M8).
	for _, c := range []capp.Connection{a, b} {
		e.exec(t, `INSERT INTO pc.connection_github (org_id, connection_id, app_client_id, installation_id, account_login, updated_by)
			VALUES ($1, $2, 'Iv23liApp', 7, $3, 'test')`, e.org, c.ID, c.Name)
	}
	cfg, err = e.svc.Configuration(ctx, mine, 0)
	if err != nil || len(cfg.GitHub) != 1 || cfg.GitHub[0].ConnectionID != a.ID || cfg.GitHub[0].AccountLogin != "a" {
		t.Fatalf("installations sent to this gateway: %+v %v", cfg.GitHub, err)
	}

	if _, err := e.svc.RevokeGateway(e.caller(td.KindUser, td.RoleGatewayAdmin), mine.Gateway, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Configuration(ctx, mine, 0); !errors.Is(err, app.ErrGatewayCredentials) {
		t.Fatalf("a revoked gateway got its configuration: %v", err)
	}
}

// TestHR221_TheConfigurationCarriesTheSimulatedFlag (G0 M12 W1a): the
// connections a gateway receives say which of them are simulated, so the
// gateway can hold a simulated connection to the simulator handshake.
func TestHR221_TheConfigurationCarriesTheSimulatedFlag(t *testing.T) {
	e := newEnv(t)
	e.pinMockPayments(t)
	_, gw := e.enroll(t, "mine")
	conns := capp.New(e.pool, nil, "https://pc.example.test", "https://gw.example.test:8443")
	for name, in := range map[string]capp.CreateInput{
		"real": {BaseURL: "https://real.example.test"},
		"sim":  {BaseURL: "http://127.0.0.1:9000", Simulated: true},
	} {
		in.Name, in.Kind, in.Package, in.Gateway, in.AccessMode = name, capp.KindHTTP, mockpayments.Name, gw.Gateway, capp.AccessNone
		if _, err := conns.Create(e.admin, in); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := e.svc.Configuration(context.Background(), gw, 0)
	if err != nil || len(cfg.Connections) != 2 {
		t.Fatalf("configuration: %+v, %v", cfg.Connections, err)
	}
	for _, c := range cfg.Connections {
		if c.Simulated != (c.Name == "sim") {
			t.Errorf("connection %s: simulated = %v", c.Name, c.Simulated)
		}
	}
}
