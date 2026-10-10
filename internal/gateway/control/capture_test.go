// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package control

import (
	"context"
	"testing"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// TestHR199_CaptureProfilesReachTheConnectionsTheyName: the gateway keeps
// each capture profile on the connections it serves that the profile
// names, and on no other.
func TestHR199_CaptureProfilesReachTheConnectionsTheyName(t *testing.T) {
	f := &configServer{version: 1, org: cfgOrg, raw: mockRaw(t)}
	s := newStore(func(ctx context.Context, known int64) (*pb.GetConfigurationResponse, error) {
		res, err := f.fetch(ctx, known)
		if err == nil && !res.GetUnchanged() {
			res.CaptureProfiles = []*pb.GatewayCaptureProfile{
				{Id: "p1", ConnectionIds: []string{"c1"}, Operations: []string{"payments.refund.create"}, Request: true, ByteCap: 64},
				{Id: "p2", ConnectionIds: []string{"c9"}, Operations: []string{"payments.refund.create"}, Response: true, ByteCap: 64},
			}
		}
		return res, err
	}, cfgOrg, cfgGateway, nil)
	if err := s.load(context.Background()); err != nil {
		t.Fatal(err)
	}
	c := s.Current().ByID["c1"]
	if c == nil || len(c.Captures) != 1 || c.Captures[0].GetId() != "p1" {
		t.Fatalf("captures of c1 = %v", c)
	}
}
