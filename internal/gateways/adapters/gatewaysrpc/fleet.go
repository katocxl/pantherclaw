// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gatewaysrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	gwapp "github.com/katocxl/pantherclaw/internal/gateways/app"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// FleetAdminHandler serves GatewayAdminService with the fleet procedures
// (G0 M18 D151): GetFleetPolicy, SetFleetPolicy and ListFleet. Every other
// procedure is the embedded AdminHandler's.
type FleetAdminHandler struct {
	*AdminHandler
	f *gwapp.Fleet
}

// WithFleet returns h serving the fleet procedures from f.
func WithFleet(h *AdminHandler, f *gwapp.Fleet) *FleetAdminHandler {
	return &FleetAdminHandler{AdminHandler: h, f: f}
}

var compliances = map[gwapp.Compliance]pb.VersionCompliance{
	gwapp.NoMinimum:        pb.VersionCompliance_VERSION_COMPLIANCE_NO_MINIMUM,
	gwapp.VersionCompliant: pb.VersionCompliance_VERSION_COMPLIANCE_COMPLIANT,
	gwapp.BelowMinimum:     pb.VersionCompliance_VERSION_COMPLIANCE_BELOW_MINIMUM,
	gwapp.VersionUnknown:   pb.VersionCompliance_VERSION_COMPLIANCE_UNKNOWN,
}

func fleetPolicyOf(p gwapp.FleetPolicy) *pb.FleetPolicy {
	out := &pb.FleetPolicy{SilenceAfterSeconds: int32(p.SilenceAfter / time.Second), UpdatedBy: p.UpdatedBy}
	if p.MinimumVersion.Known() {
		out.MinimumVersion = p.MinimumVersion.String()
	}
	if !p.UpdatedAt.IsZero() {
		out.UpdateTime = timestamppb.New(p.UpdatedAt)
	}
	return out
}

// GetFleetPolicy implements GatewayAdminServiceHandler.
func (h *FleetAdminHandler) GetFleetPolicy(ctx context.Context, _ *pb.GetFleetPolicyRequest) (*pb.GetFleetPolicyResponse, error) {
	p, err := h.f.GetFleetPolicy(ctx)
	if err != nil {
		return nil, err
	}
	return &pb.GetFleetPolicyResponse{Policy: fleetPolicyOf(p)}, nil
}

// SetFleetPolicy implements GatewayAdminServiceHandler.
func (h *FleetAdminHandler) SetFleetPolicy(ctx context.Context, req *pb.SetFleetPolicyRequest) (*pb.SetFleetPolicyResponse, error) {
	p, err := h.f.SetFleetPolicy(ctx, req.GetMinimumVersion(), time.Duration(req.GetSilenceAfterSeconds())*time.Second)
	if err != nil {
		return nil, err
	}
	return &pb.SetFleetPolicyResponse{Policy: fleetPolicyOf(p)}, nil
}

// ListFleet implements GatewayAdminServiceHandler.
func (h *FleetAdminHandler) ListFleet(ctx context.Context, req *pb.ListFleetRequest) (*pb.ListFleetResponse, error) {
	v, err := h.f.ListFleet(ctx, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pb.ListFleetResponse{Policy: fleetPolicyOf(v.Policy), NextPageToken: v.Next}
	for _, g := range v.Gateways {
		fg := &pb.FleetGateway{
			GatewayId: g.Gateway.ID.String(), Name: g.Gateway.Name, ConfigVersion: g.Gateway.ConfigVersion,
			Connected: g.Connected, BelowMinimum: g.BelowMinimum,
		}
		if g.SilentSince != nil {
			fg.SilentSinceTime = timestamppb.New(*g.SilentSince)
		}
		for _, r := range g.Replicas {
			fg.Replicas = append(fg.Replicas, &pb.FleetReplica{
				Replica: replicaOf(r.Replica), ParsedVersion: r.Version.String(), Compliance: compliances[r.Compliance], ConfigLag: r.ConfigLag,
			})
		}
		out.Gateways = append(out.Gateways, fg)
	}
	return out, nil
}
