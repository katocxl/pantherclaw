// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pcshell "github.com/katocxl/pantherclaw/packages/pc-shell"
)

// The hook asks the gateway about every shell command at /hook/{connection},
// on the kind-local connection serving pc.shell, and blocks the command
// when it cannot ask (fail closed). A fresh org has no such connection, so
// `pclaw init` checks it (the UI milestone's D80 follow-up): when the
// person is signed in and the org has no connection of that name, init
// plans to create it, in enforce mode, and shows and asks about it with
// the rest of its plan (HR-208). When pc.shell is not imported and active,
// or init cannot tell which gateway serves it, it prints the commands that
// would and changes nothing. Creating the connection needs a person holding
// connection.manage, as `pclaw connection create` does.

// hookConnectionPlan is the hook connection init creates.
type hookConnectionPlan struct {
	req         *pantherclawv1.CreateConnectionRequest
	gatewayName string
}

// shellConnectionRequest is the hook connection on gateway: kind local,
// pc.shell, no credential, internal, every route enforced (as dev seed
// --shell creates it).
func shellConnectionRequest(name, gateway string) *pantherclawv1.CreateConnectionRequest {
	return &pantherclawv1.CreateConnectionRequest{
		Name: name, Kind: pantherclawv1.ConnectionKind_CONNECTION_KIND_LOCAL, GatewayId: gateway, Package: pcshell.Name,
		AccessMode: pantherclawv1.AccessMode_ACCESS_MODE_NONE, DestinationClass: pantherclawv1.DestinationClass_DESTINATION_CLASS_INTERNAL,
		DefaultMode: pantherclawv1.RouteMode_ROUTE_MODE_ENFORCE,
	}
}

// createCommand is `pclaw connection create` for the hook connection.
func createCommand(name, gateway string) string {
	return "pclaw connection create " + name + " --kind local --gateway " + gateway + " --package " + pcshell.Name +
		" --access none --class internal --default-mode enforce"
}

// hookConnection checks the hook's connection. It returns nil when the
// connection exists, and also when init cannot read the org's connections
// (not signed in, or not allowed), after saying so; the connection to
// create when the org has none of that name; and an exitError, with
// nothing changed, when it cannot be created yet.
func (f initFlags) hookConnection(ctx context.Context, a *app) (*hookConnectionPlan, error) {
	c, err := a.clients()
	if err != nil {
		f.uncheckedConnection(a, describe(err))
		return nil, nil
	}
	conn, err := connectionNamed(ctx, c, f.connection)
	switch {
	case err != nil:
		f.uncheckedConnection(a, describe(err))
		return nil, nil
	case conn != nil && conn.GetKind() != pantherclawv1.ConnectionKind_CONNECTION_KIND_LOCAL:
		return nil, &exitError{code: 1, msg: fmt.Sprintf("pclaw init: connection %s is not a kind-local connection, so the hook "+
			"could not ask it about a shell command and every command would be blocked; init changes nothing: pass --connection "+
			"with the name of the kind-local connection serving %s", f.connection, pcshell.Name)}
	case conn != nil:
		return nil, nil
	}
	if err := shellPackageActive(ctx, c, f.connection); err != nil {
		return nil, err
	}
	gw, err := f.hookGateway(ctx, c)
	if err != nil {
		return nil, err
	}
	return &hookConnectionPlan{req: shellConnectionRequest(f.connection, gw.GetId()), gatewayName: gw.GetName()}, nil
}

// uncheckedConnection says that init could not check the hook connection,
// and what happens without it.
func (f initFlags) uncheckedConnection(a *app, why string) {
	_, _ = fmt.Fprintf(a.stderr, "pclaw init: could not check that connection %s exists (%s). The hook asks it about every shell "+
		"command and blocks the command when it cannot, so if the org has no such connection, sign in (pclaw login) and run pclaw "+
		"init again, or have someone holding connection.manage create it:\n  %s\n", f.connection, why, createCommand(f.connection, "GATEWAY_ID"))
}

// connectionNamed is the org's connection named name that is not retired,
// or nil.
func connectionNamed(ctx context.Context, c clients, name string) (*pantherclawv1.Connection, error) {
	for token := ""; ; {
		res, err := c.connections.ListConnections(ctx, &pantherclawv1.ListConnectionsRequest{PageSize: 200, PageToken: token})
		if err != nil {
			return nil, fmt.Errorf("listing the connections: %w", err)
		}
		if i := slices.IndexFunc(res.GetConnections(), func(x *pantherclawv1.Connection) bool { return x.GetName() == name }); i >= 0 {
			return res.GetConnections()[i], nil
		}
		if token = res.GetNextPageToken(); token == "" {
			return nil, nil
		}
	}
}

// shellPackageActive fails, printing the commands that import and activate
// pc.shell, unless the org's pinned version of it is active: a connection
// serves its package's pinned version, and only an active one decides.
func shellPackageActive(ctx context.Context, c clients, connection string) error {
	res, err := c.packages.ListPackages(ctx, &pantherclawv1.ListPackagesRequest{Name: pcshell.Name})
	if err != nil {
		return &exitError{code: 1, msg: fmt.Sprintf("pclaw init: the org has no connection %s, and init could not read whether %s "+
			"is active (%s), so it changes nothing. Once %s is active, run pclaw init again or have someone holding connection.manage "+
			"run:\n  %s", connection, pcshell.Name, describe(err), pcshell.Name, createCommand(connection, "GATEWAY_ID"))}
	}
	versions := res.GetPackages()
	i := slices.IndexFunc(versions, func(v *pantherclawv1.PackageVersion) bool { return v.GetPinned() })
	if i >= 0 && versions[i].GetState() == pantherclawv1.PackageState_PACKAGE_STATE_ACTIVE {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "pclaw init: the org has no connection %s, and the hook's connection serves %s, ", connection, pcshell.Name)
	if i < 0 {
		fmt.Fprintf(&b, "which this org has not imported, so init changes nothing. An Org Admin imports it with the signed targets "+
			"document that lists it (the release has both; packages/pc-shell/package.yaml in the source), activates it, and runs "+
			"pclaw init again:\n  pclaw package import --name %[1]s --version %[2]s --targets-file TARGETS_FILE --file "+
			"packages/pc-shell/package.yaml\n  pclaw package transition %[1]s %[2]s --to active", pcshell.Name, pcshell.Version)
	} else {
		v := versions[i]
		fmt.Fprintf(&b, "whose version %[2]s this org pins is %[3]s, not active, so init changes nothing. An Org Admin activates "+
			"it and runs pclaw init again:\n  pclaw package transition %[1]s %[2]s --to active", pcshell.Name, v.GetVersion(), packageStateName(v.GetState()))
	}
	return &exitError{code: 1, msg: b.String()}
}

// packageStateName is a package state as people read it ("reviewed").
func packageStateName(s pantherclawv1.PackageState) string {
	return strings.ToLower(strings.TrimPrefix(s.String(), "PACKAGE_STATE_"))
}

// hookGateway is the gateway the hook connection is created on: the one
// --gateway-id names, or the org's only active gateway.
func (f initFlags) hookGateway(ctx context.Context, c clients) (*pantherclawv1.Gateway, error) {
	var active []*pantherclawv1.Gateway
	for token := ""; ; {
		res, err := c.gateways.ListGateways(ctx, &pantherclawv1.ListGatewaysRequest{PageSize: 200, PageToken: token})
		if err != nil {
			return nil, &exitError{code: 1, msg: fmt.Sprintf("pclaw init: the org has no connection %s, and init could not list its "+
				"gateways (%s), so it changes nothing; have someone holding connection.manage run:\n  %s", f.connection, describe(err),
				createCommand(f.connection, "GATEWAY_ID"))}
		}
		for _, g := range res.GetGateways() {
			if g.GetState() == pantherclawv1.GatewayState_GATEWAY_STATE_ACTIVE {
				active = append(active, g)
			}
		}
		if token = res.GetNextPageToken(); token == "" {
			break
		}
	}
	if f.gatewayID != "" {
		if i := slices.IndexFunc(active, func(g *pantherclawv1.Gateway) bool { return g.GetId() == f.gatewayID }); i >= 0 {
			return active[i], nil
		}
		return nil, &exitError{code: 1, msg: "pclaw init: --gateway-id " + f.gatewayID + " is not an active gateway of this org; nothing was changed"}
	}
	switch len(active) {
	case 1:
		return active[0], nil
	case 0:
		return nil, &exitError{code: 1, msg: fmt.Sprintf("pclaw init: the org has no connection %s and no active gateway to serve it, so "+
			"init changes nothing. Create and enroll the gateway at --gateway first (pclaw gateway create, then pclaw gateway enroll-token "+
			"for the gateway to start with), and run pclaw init again", f.connection)}
	}
	var names []string
	for _, g := range active {
		names = append(names, g.GetName()+" ("+g.GetId()+")")
	}
	return nil, &exitError{code: 1, msg: fmt.Sprintf("pclaw init: the org has no connection %s, and several active gateways could serve "+
		"it: %s. Pass --gateway-id with the one at --gateway; nothing was changed", f.connection, strings.Join(names, ", "))}
}

// line is the plan's line for the connection.
func (p *hookConnectionPlan) line() string {
	return fmt.Sprintf("Create the connection %s on gateway %s (%s): kind local, package %s, every route enforced, no credential",
		p.req.GetName(), p.gatewayName, p.req.GetGatewayId(), pcshell.Name)
}

// create creates the connection; on failure it says who can.
func (p *hookConnectionPlan) create(ctx context.Context, a *app) error {
	c, err := a.clients()
	if err != nil {
		return err
	}
	res, err := c.connections.CreateConnection(ctx, p.req)
	if err != nil {
		return &exitError{code: 1, msg: fmt.Sprintf("pclaw init: creating the connection %s: %s; nothing was changed. Someone holding "+
			"connection.manage can create it:\n  %s", p.req.GetName(), describe(err), createCommand(p.req.GetName(), p.req.GetGatewayId()))}
	}
	_, err = fmt.Fprintf(a.stdout, "Created the connection %s (%s).\n", res.GetConnection().GetName(), res.GetConnection().GetId())
	return err
}

// validGatewayID checks --gateway-id.
func validGatewayID(id string) error {
	if id == "" {
		return nil
	}
	if _, err := ids.ParseUUID(id); err != nil {
		return errors.New("--gateway-id must be a gateway id")
	}
	return nil
}
