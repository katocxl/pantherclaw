// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

const (
	hookGatewayID  = "0192aaaa-bbbb-7ccc-8ddd-0000000000a1"
	otherGatewayID = "0192aaaa-bbbb-7ccc-8ddd-0000000000a2"
	thirdGatewayID = "0192aaaa-bbbb-7ccc-8ddd-0000000000a3"
)

// fakeHookOrg is the org's side of the hook connection: its connections,
// its pc.shell versions and its gateways, and the connections init
// creates.
type fakeHookOrg struct {
	pantherclawv1connect.UnimplementedConnectionServiceHandler
	pantherclawv1connect.UnimplementedPackageServiceHandler
	pantherclawv1connect.UnimplementedGatewayAdminServiceHandler
	mu          sync.Mutex
	connections []*pantherclawv1.Connection
	packages    []*pantherclawv1.PackageVersion
	gateways    []*pantherclawv1.Gateway
	// listErr and createErr, when set, answer those calls.
	listErr, createErr error
	created            []*pantherclawv1.CreateConnectionRequest
}

func (o *fakeHookOrg) ListConnections(context.Context, *pantherclawv1.ListConnectionsRequest) (*pantherclawv1.ListConnectionsResponse, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.listErr != nil {
		return nil, o.listErr
	}
	return &pantherclawv1.ListConnectionsResponse{Connections: o.connections}, nil
}

func (o *fakeHookOrg) CreateConnection(_ context.Context, req *pantherclawv1.CreateConnectionRequest) (*pantherclawv1.CreateConnectionResponse, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.createErr != nil {
		return nil, o.createErr
	}
	o.created = append(o.created, req)
	c := &pantherclawv1.Connection{Id: "0192aaaa-bbbb-7ccc-8ddd-0000000000c1", Name: req.GetName(), Kind: req.GetKind(), Package: req.GetPackage()}
	o.connections = append(o.connections, c)
	return &pantherclawv1.CreateConnectionResponse{Connection: c}, nil
}

func (o *fakeHookOrg) ListPackages(_ context.Context, req *pantherclawv1.ListPackagesRequest) (*pantherclawv1.ListPackagesResponse, error) {
	if req.GetName() != "pc.shell" {
		return nil, connect.NewError(connect.CodeInvalidArgument, "init asks only about pc.shell")
	}
	return &pantherclawv1.ListPackagesResponse{Packages: o.packages}, nil
}

func (o *fakeHookOrg) ListGateways(context.Context, *pantherclawv1.ListGatewaysRequest) (*pantherclawv1.ListGatewaysResponse, error) {
	return &pantherclawv1.ListGatewaysResponse{Gateways: o.gateways}, nil
}

// freshHookOrg has pc.shell active and one gateway, and no connection.
func freshHookOrg() *fakeHookOrg {
	return &fakeHookOrg{
		packages: []*pantherclawv1.PackageVersion{{Name: "pc.shell", Version: "1.0.0", State: pantherclawv1.PackageState_PACKAGE_STATE_ACTIVE, Pinned: true}},
		gateways: []*pantherclawv1.Gateway{
			{Id: otherGatewayID, Name: "old", State: pantherclawv1.GatewayState_GATEWAY_STATE_REVOKED},
			{Id: hookGatewayID, Name: "laptop", State: pantherclawv1.GatewayState_GATEWAY_STATE_ACTIVE},
		},
	}
}

// hookOrgServer serves the fake and signs init in with an API key; the
// key file stays the enrolled one.
func (f *initFixture) hookOrgServer(t *testing.T, org *fakeHookOrg) {
	t.Helper()
	cs := connect.NewServer()
	pantherclawv1connect.RegisterConnectionServiceHandler(cs, org)
	pantherclawv1connect.RegisterPackageServiceHandler(cs, org)
	pantherclawv1connect.RegisterGatewayAdminServiceHandler(cs, org)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	f.env["PANTHERCLAW_SERVER"], f.env["PANTHERCLAW_API_KEY"] = ts.URL, "pck_test_x"
}

// TestHR208_InitCreatesTheHookConnectionTheOrgLacks (D80): when the org
// has no connection of the hook's name and pc.shell is active, init shows
// the connection it would create with the rest of its plan; a dry run and
// a "no" create nothing; a yes creates it on the org's only active
// gateway, kind local, serving pc.shell, enforced and without a
// credential, before it writes the hook. A second run finds it and
// creates nothing.
func TestHR208_InitCreatesTheHookConnectionTheOrgLacks(t *testing.T) {
	f := newInitFixture(t)
	org := freshHookOrg()
	f.hookOrgServer(t, org)
	line := "Create the connection shell on gateway laptop (" + hookGatewayID + ")"

	if code, out, errs := f.run(t, "--dry-run"); code != 0 || !strings.Contains(out, line) || len(org.created) != 0 {
		t.Fatalf("dry run: %d %s %s", code, out, errs)
	}
	f.answer = "n\n"
	if code, out, errs := f.run(t); code != 1 || !strings.Contains(out, line) || len(org.created) != 0 {
		t.Fatalf("not confirmed: %d %s %s", code, out, errs)
	}
	f.answer = "y\n"
	code, out, errs := f.run(t)
	if code != 0 || len(org.created) != 1 || !hookRunsIn(t, f.local()) || !strings.Contains(out, "Created the connection shell") {
		t.Fatalf("init: %d %s %s", code, out, errs)
	}
	got := org.created[0]
	if got.GetName() != "shell" || got.GetKind() != pantherclawv1.ConnectionKind_CONNECTION_KIND_LOCAL || got.GetPackage() != "pc.shell" ||
		got.GetGatewayId() != hookGatewayID || got.GetAccessMode() != pantherclawv1.AccessMode_ACCESS_MODE_NONE ||
		got.GetDestinationClass() != pantherclawv1.DestinationClass_DESTINATION_CLASS_INTERNAL ||
		got.GetDefaultMode() != pantherclawv1.RouteMode_ROUTE_MODE_ENFORCE || got.GetBaseUrl() != "" {
		t.Fatalf("created %v", got)
	}
	if !strings.Contains(createCommand("shell", hookGatewayID), "--kind local --gateway "+hookGatewayID+" --package pc.shell --access none") {
		t.Fatalf("the command: %s", createCommand("shell", hookGatewayID))
	}

	code, out, errs = f.run(t)
	if code != 0 || len(org.created) != 1 || !strings.Contains(out, "already installed") || strings.Contains(out, "Create the connection") {
		t.Fatalf("second run: %d %s %s", code, out, errs)
	}
}

// TestHR208_InitSaysHowToActivatePcShell (D80): without an active pc.shell
// init creates no connection, writes nothing and prints the exact commands
// that import and activate it (or only activate it, when the org pins a
// version that is not active).
func TestHR208_InitSaysHowToActivatePcShell(t *testing.T) {
	for name, tc := range map[string]struct {
		versions []*pantherclawv1.PackageVersion
		want     []string
	}{
		"not imported": {want: []string{
			"pclaw package import --name pc.shell --version 1.0.0 --targets-file TARGETS_FILE --file packages/pc-shell/package.yaml\n",
			"pclaw package transition pc.shell 1.0.0 --to active",
		}},
		"imported, not active": {
			versions: []*pantherclawv1.PackageVersion{{Name: "pc.shell", Version: "1.0.0", State: pantherclawv1.PackageState_PACKAGE_STATE_REVIEWED, Pinned: true}},
			want:     []string{"is reviewed, not active", "pclaw package transition pc.shell 1.0.0 --to active"},
		},
	} {
		f := newInitFixture(t)
		org := freshHookOrg()
		org.packages = tc.versions
		f.hookOrgServer(t, org)
		code, out, errs := f.run(t, "--yes")
		if _, err := os.Stat(f.local()); code != 1 || err == nil || len(org.created) != 0 || !strings.Contains(errs, "changes nothing") {
			t.Errorf("%s: %d %s %s", name, code, out, errs)
		}
		for _, w := range tc.want {
			if !strings.Contains(errs, w) {
				t.Errorf("%s: %q is not in\n%s", name, w, errs)
			}
		}
		if name == "imported, not active" && strings.Contains(errs, "package import") {
			t.Errorf("%s: asks to import again:\n%s", name, errs)
		}
	}
}

// TestHR208_InitCreatesTheHookConnectionOnlyWhereItCan (D80): init picks
// the gateway only when the org has one active gateway or --gateway-id
// names one; refuses a connection of the hook's name that is not kind
// local; keeps going, and says so, when it cannot read the connections;
// and changes nothing when the server refuses the creation.
func TestHR208_InitCreatesTheHookConnectionOnlyWhereItCan(t *testing.T) {
	two := func(o *fakeHookOrg) {
		o.gateways = append(o.gateways, &pantherclawv1.Gateway{Id: thirdGatewayID, Name: "ci", State: pantherclawv1.GatewayState_GATEWAY_STATE_ACTIVE})
	}
	for name, tc := range map[string]struct {
		setup   func(*fakeHookOrg)
		args    []string
		code    int
		created string
		errs    string
	}{
		"no active gateway": {setup: func(o *fakeHookOrg) { o.gateways = o.gateways[:1] }, code: 1, errs: "no active gateway"},
		"two gateways":      {setup: two, code: 1, errs: "laptop (" + hookGatewayID + "), ci (" + thirdGatewayID + "). Pass --gateway-id"},
		"two gateways, one named": {
			setup: two, args: []string{"--gateway-id", thirdGatewayID}, created: thirdGatewayID,
		},
		"a gateway that is not active": {args: []string{"--gateway-id", otherGatewayID}, code: 1, errs: "not an active gateway"},
		"not a gateway id":             {args: []string{"--gateway-id", "laptop"}, code: 1, errs: "--gateway-id must be a gateway id"},
		"a connection of another kind": {
			setup: func(o *fakeHookOrg) {
				o.connections = []*pantherclawv1.Connection{{Name: "shell", Kind: pantherclawv1.ConnectionKind_CONNECTION_KIND_HTTP}}
			},
			code: 1, errs: "connection shell is not a kind-local connection",
		},
		"connections unreadable": {
			setup: func(o *fakeHookOrg) {
				o.listErr = connect.NewError(connect.CodePermissionDenied, "connection.read is needed")
			},
			errs: "could not check that connection shell exists (listing the connections: permission denied: connection.read is needed)",
		},
		"creation refused": {
			setup: func(o *fakeHookOrg) {
				o.createErr = connect.NewError(connect.CodePermissionDenied, "connection.manage is needed")
			},
			code: 1, errs: "permission denied: connection.manage is needed; nothing was changed. Someone holding connection.manage can create it:\n  " +
				createCommand("shell", hookGatewayID),
		},
	} {
		f := newInitFixture(t)
		org := freshHookOrg()
		if tc.setup != nil {
			tc.setup(org)
		}
		f.hookOrgServer(t, org)
		code, out, errs := f.run(t, append([]string{"--yes"}, tc.args...)...)
		_, statErr := os.Stat(f.local())
		if code != tc.code || !strings.Contains(errs, tc.errs) || (code == 0) != (statErr == nil) {
			t.Errorf("%s: %d %s %s", name, code, out, errs)
		}
		if tc.created == "" && len(org.created) != 0 || tc.created != "" && (len(org.created) != 1 || org.created[0].GetGatewayId() != tc.created) {
			t.Errorf("%s: created %v", name, org.created)
		}
	}
}

// TestHR208_InitSaysWhenItCannotCheckTheHookConnection (D80): signed out,
// init still installs the hook, and says that it could not check the
// connection and how to create it.
func TestHR208_InitSaysWhenItCannotCheckTheHookConnection(t *testing.T) {
	f := newInitFixture(t)
	code, out, errs := f.run(t, "--yes")
	if code != 0 || !hookRunsIn(t, f.local()) || !strings.Contains(errs, "could not check that connection shell exists") ||
		!strings.Contains(errs, createCommand("shell", "GATEWAY_ID")) {
		t.Fatalf("init: %d %s %s", code, out, errs)
	}
}
