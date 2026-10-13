// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gatewaysrpc

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	gwapp "github.com/katocxl/pantherclaw/internal/gateways/app"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// GetConfiguration implements GatewayServiceHandler: the calling gateway's
// configuration, on the mTLS listener only (gateway.sync).
func (h *GatewayHandler) GetConfiguration(ctx context.Context, req *pb.GetConfigurationRequest) (*pb.GetConfigurationResponse, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}
	c, err := h.s.Configuration(ctx, id, req.GetKnownVersion())
	if err != nil {
		return nil, err
	}
	out := &pb.GetConfigurationResponse{Version: c.Version, Unchanged: c.Unchanged}
	if c.Unchanged {
		return out, nil
	}
	out.OrgId, out.GatewayId = id.Org.String(), id.Gateway.String()
	routes := map[string][]*pb.RouteModeSetting{}
	for _, r := range c.Routes {
		k := r.ConnectionID.String()
		routes[k] = append(routes[k], &pb.RouteModeSetting{Route: r.Route, Mode: r.Mode})
	}
	versions := map[string]string{}
	for _, p := range c.Packages {
		versions[p.Name] = p.Version
		out.Packages = append(out.Packages, &pb.GatewayPackage{Name: p.Name, Version: p.Version, Raw: p.Raw})
	}
	for _, conn := range c.Connections {
		out.Connections = append(out.Connections, &pb.GatewayConnection{
			Id: conn.ID.String(), Name: conn.Name, Kind: conn.Kind, Package: conn.Package, PackageVersion: versions[conn.Package],
			BaseUrl: deref(conn.BaseUrl), AllowedHosts: conn.AllowedHosts, DestinationClass: conn.DestinationClass,
			AccessMode: conn.AccessMode, DefaultMode: conn.DefaultMode, Routes: routes[conn.ID.String()],
			MaxResponseBytes: conn.MaxResponseBytes, TimeoutMs: conn.TimeoutMs, State: conn.State, Revision: conn.Revision,
		})
	}
	for _, cr := range c.Credentials {
		out.Credentials = append(out.Credentials, &pb.SealedCredential{
			Id: cr.ID.String(), ConnectionId: cr.ConnectionID.String(), Version: cr.Version, BrokerKeyId: cr.BrokerKeyID.String(),
			Sealed: cr.Sealed, AllowedHosts: cr.AllowedHosts, Header: cr.Header, Scheme: deref(cr.Scheme),
		})
	}
	out.CaptureProfiles = captureProfiles(c)
	return out, nil
}

// captureProfiles are the capture profiles of the gateway's connections,
// each naming only the connections this gateway serves (G0 M7 design
// decision 10, HR-199).
func captureProfiles(c gwapp.Configuration) []*pb.GatewayCaptureProfile {
	served := map[string]bool{}
	for _, conn := range c.Connections {
		served[conn.ID.String()] = true
	}
	var out []*pb.GatewayCaptureProfile
	for _, p := range c.Captures {
		g := &pb.GatewayCaptureProfile{
			Id: p.ID.String(), Operations: p.Operations, Request: p.CaptureRequest, Response: p.CaptureResponse,
			ByteCap: p.ByteCap, ExpireTime: timestamppb.New(p.ExpiresAt),
		}
		for _, id := range p.Connections {
			if served[id.String()] {
				g.ConnectionIds = append(g.ConnectionIds, id.String())
			}
		}
		if len(g.ConnectionIds) > 0 {
			out = append(out, g)
		}
	}
	return out
}
