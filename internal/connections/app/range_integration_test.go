// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"strconv"
	"testing"

	"github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
)

func (e *env) simulated(base string) app.CreateInput {
	return app.CreateInput{
		Name: "sim", Kind: app.KindHTTP, Package: mockpayments.Name, BaseURL: base, Gateway: e.gateway,
		AccessMode: app.AccessNone, Simulated: true,
	}
}

// TestHR221_SimulatedTargetsMustBeLocalLiterals (D3): a simulated http or
// mcp connection names an IP literal on loopback or a private network;
// any name, public address, mapped address or odd spelling is refused, and
// a connector container cannot be simulated.
func TestHR221_SimulatedTargetsMustBeLocalLiterals(t *testing.T) {
	e := newEnv(t)
	for i, base := range []string{
		"http://127.0.0.1:9000", "http://127.9.9.9", "http://10.1.2.3:8080/v1", "http://172.16.0.5", "http://172.31.255.255:1",
		"http://192.168.1.10:9000", "http://[::1]:9000", "http://[fd12:3456::1]:9000", "https://127.0.0.1:9443",
	} {
		in := e.simulated(base)
		in.Name = "sim-" + strconv.Itoa(i)
		c, err := e.svc.Create(e.admin, in)
		if err != nil || !c.Simulated {
			t.Errorf("%s: %+v, %v, want a simulated connection", base, c.PcConnection, err)
		}
	}
	for _, base := range []string{
		"https://payments.example.test", "http://localhost:9000", "http://payments.internal", "https://8.8.8.8", "http://1.1.1.1:80",
		"http://172.15.0.1", "http://172.32.0.1", "http://192.169.0.1", "http://11.0.0.1", "http://[2001:db8::1]", "http://[fe80::1]",
		"http://[::ffff:127.0.0.1]:9000", "https://[::ffff:10.0.0.1]", "http://[fc00::1]x",
		"http://0.0.0.0", "http://169.254.169.254",
	} {
		_, err := e.svc.Create(e.admin, e.simulated(base))
		if pcerr.CodeOf(err) != pcerr.InvalidArgument || (pcerr.ReasonOf(err) != "SIMULATED_TARGET_NOT_LOCAL" && pcerr.ReasonOf(err) != "BASE_URL_INVALID" &&
			pcerr.ReasonOf(err) != "PLAIN_HTTP_PUBLIC") {
			t.Errorf("%s: err = %v, want a refusal", base, err)
		}
	}
	// The named rule, for targets the ordinary checks accept (https only).
	for _, base := range []string{"https://payments.example.test", "https://8.8.8.8", "https://[2001:db8::1]", "https://172.32.0.1"} {
		if _, err := e.svc.Create(e.admin, e.simulated(base)); pcerr.ReasonOf(err) != "SIMULATED_TARGET_NOT_LOCAL" {
			t.Errorf("%s: err = %v, want SIMULATED_TARGET_NOT_LOCAL", base, err)
		}
	}

	// An odd spelling of loopback is stored in its canonical form, so what
	// the gateway checks and dials is 127.0.0.1.
	odd := e.simulated("http://0x7f.1:9000")
	odd.Name = "odd"
	if c, err := e.svc.Create(e.admin, odd); err != nil || deref(c.BaseUrl) != "http://127.0.0.1:9000" {
		t.Errorf("0x7f.1: %v, stored %q, want http://127.0.0.1:9000", err, deref(c.BaseUrl))
	}

	// Every host a credential may be sent to is a local literal too.
	for i, hosts := range [][]string{{"api.example.com"}, {"127.0.0.1", "api.example.com"}, {"8.8.8.8:443"}, {"localhost"}} {
		in := e.simulated("http://127.0.0.1:9000")
		in.Name, in.AllowedHosts = "hosts-"+strconv.Itoa(i), hosts
		if _, err := e.svc.Create(e.admin, in); pcerr.ReasonOf(err) != "SIMULATED_TARGET_NOT_LOCAL" {
			t.Errorf("allowed hosts %v: err = %v, want SIMULATED_TARGET_NOT_LOCAL", hosts, err)
		}
	}
	ok := e.simulated("http://127.0.0.1:9000")
	ok.Name, ok.AllowedHosts = "hosts-ok", []string{"127.0.0.1:9000", "[::1]", "10.0.0.5"}
	c, err := e.svc.Create(e.admin, ok)
	if err != nil {
		t.Fatalf("local allowed hosts: %v", err)
	}
	// An update cannot move a simulated connection off the local literals.
	pub, hosts := "https://payments.example.test", []string{"api.example.com"}
	for what, u := range map[string]app.UpdateInput{
		"base URL": {ID: c.ID, Revision: c.Revision, BaseURL: &pub}, "allowed hosts": {ID: c.ID, Revision: c.Revision, AllowedHosts: hosts, SetAllowedHosts: true},
	} {
		if _, err := e.svc.Update(e.admin, u); pcerr.ReasonOf(err) != "SIMULATED_TARGET_NOT_LOCAL" {
			t.Errorf("update of the %s: err = %v, want SIMULATED_TARGET_NOT_LOCAL", what, err)
		}
	}
	loc := "http://10.0.0.9:9000"
	if _, err := e.svc.Update(e.admin, app.UpdateInput{ID: c.ID, Revision: c.Revision, BaseURL: &loc}); err != nil {
		t.Errorf("update to another local literal: %v", err)
	}

	// A real connection keeps its ordinary rules and is not simulated.
	real := e.payments(t, "real")
	if real.Simulated {
		t.Error("a real connection reads as simulated")
	}

	// Local connections may be simulated; connector containers may not.
	local, err := e.svc.Create(e.admin, app.CreateInput{
		Name: "sim-laptop", Kind: app.KindLocal, Package: "pc.shell", Gateway: e.gateway, AccessMode: app.AccessNone, Simulated: true,
	})
	if err != nil || !local.Simulated || local.BaseUrl != nil {
		t.Errorf("simulated local connection: %+v, %v", local.PcConnection, err)
	}
	through := real.ID
	_, err = e.svc.Create(e.admin, app.CreateInput{
		Name: "sim-container", Kind: app.KindMCPContainer, Package: mockpayments.Name, Gateway: e.gateway, AccessMode: app.AccessNone,
		Simulated: true, Connector: &app.ConnectorSpec{Image: "ghcr.io/example/x@sha256:" + zeros(64), Command: []string{"/server"}, EgressConnection: &through},
	})
	if pcerr.CodeOf(err) != pcerr.InvalidArgument || pcerr.ReasonOf(err) != "SIMULATED_CONNECTOR_UNSUPPORTED" {
		t.Errorf("simulated connector container: err = %v, want SIMULATED_CONNECTOR_UNSUPPORTED", err)
	}
	if n := e.int64(t, "SELECT count(*) FROM pc.connections WHERE org_id = $1 AND kind = 'mcp_container'", e.org); n != 0 {
		t.Errorf("%d connector containers stored", n)
	}
}

func zeros(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = '0'
	}
	return string(b)
}

// TestHR220_ConnectionSimulatedFlagIsImmutable: pc_app sets the flag when it
// inserts the connection and can never change it, and an update through the
// service keeps it.
func TestHR220_ConnectionSimulatedFlagIsImmutable(t *testing.T) {
	e := newEnv(t)
	sim, err := e.svc.Create(e.admin, e.simulated("http://127.0.0.1:9000"))
	if err != nil || !sim.Simulated {
		t.Fatal(sim.PcConnection, err)
	}
	real := e.payments(t, "real")
	for _, c := range []struct {
		id string
		to bool
	}{{real.ID.String(), true}, {sim.ID.String(), false}} {
		err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, "UPDATE pc.connections SET simulated = $1 WHERE org_id = $2 AND id = $3", c.to, e.org, c.id)
			return err
		})
		if err == nil {
			t.Errorf("connection %s: the update succeeded, want permission denied", c.id)
		}
	}
	got, err := e.svc.Get(e.admin, sim.ID)
	if err != nil || !got.Simulated {
		t.Errorf("read back: %+v, %v", got.PcConnection, err)
	}
}
