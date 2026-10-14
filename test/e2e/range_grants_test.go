// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"google.golang.org/protobuf/types/known/timestamppb"

	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	grantspg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// workloadService is the WorkloadService as the seeded workload calls it.
func (d *rangeDriver) workloadService() pantherclawv1connect.WorkloadServiceClient {
	return pantherclawv1connect.NewWorkloadServiceClient(connect.NewClient(connecthttp.NewTransport(&http.Client{
		Timeout: 30 * time.Second, Transport: &workloadclient.Transport{Key: d.s.key, Token: func() string { return d.s.token }},
	}, d.s.apiURL)))
}

// agentChild starts a child run, asks to delegate a grant wider than the
// parent's, and then has the child act: with no delegated grant it holds none.
// The observation is the child's action; the delegation's refusal is its code.
func (d *rangeDriver) agentChild(ctx context.Context, st domain.Step, _ map[string]string) (domain.Observation, error) {
	var w struct {
		Grant struct {
			Widen []string `json:"widen"`
		} `json:"grant"`
		Then callWith `json:"then"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	var agent string
	d.s.query(d.t, "SELECT agent_id::text FROM pc.runs WHERE id = $1", []any{d.s.run}, &agent)
	wc := d.workloadService()
	child, err := wc.StartChildRun(ctx, &pantherclawv1.StartChildRunRequest{ParentRunId: d.s.run, AgentId: agent})
	if err != nil {
		return domain.Observation{}, fmt.Errorf("StartChildRun: %w", err)
	}
	req := &pantherclawv1.DelegateGrantRequest{RunId: d.s.run, ChildRunId: child.GetRun().GetId(), Bounds: []byte(`{}`)}
	for _, dim := range w.Grant.Widen {
		switch dim {
		case "operations":
			req.Bounds = []byte(`{"operations": ["github.*", "payments.*"]}`)
		case "lifetime":
			req.ExpireTime = timestamppb.New(time.Now().Add(1000 * time.Hour))
		default:
			return domain.Observation{}, fmt.Errorf("the harness driver cannot widen %q", dim)
		}
	}
	_, derr := wc.DelegateGrant(ctx, req)
	code := ""
	if derr != nil {
		code = "DELEGATION_REFUSED"
		if strings.Contains(derr.Error(), "OUTSIDE_ALLOWED_AUTHORITY") {
			code = "OUTSIDE_ALLOWED_AUTHORITY"
		}
	}
	w.Then.run = child.GetRun().GetId()
	obs, _, err := d.callOnce(w.Then, nil, 0)
	if err != nil {
		return obs, err
	}
	if derr == nil {
		obs.Detail = "the delegation was accepted: " + obs.Detail
	} else {
		obs.Detail = "delegation: " + derr.Error() + " " + obs.Detail
	}
	obs.Code = code
	return obs, nil
}

// revokeGrant has a security admin revoke the seeded grant, and with it
// everything delegated from it.
func (d *rangeDriver) revokeGrant() (domain.Observation, error) {
	var id string
	d.s.query(d.t, "SELECT id::text FROM pc.grants ORDER BY created_at LIMIT 1", nil, &id)
	var gid gdomain.GrantID
	if err := gid.UnmarshalText([]byte(id)); err != nil {
		return domain.Observation{}, err
	}
	p := d.s.person(d.t, "range-security", td.RoleSecurityAdmin)
	gs := &grantspg.Store{Pool: d.s.pool}
	svc := &grantsapp.Service{Repo: gs, Subjects: gs, Defs: &defspg.Store{Pool: d.s.pool}, Authz: grantsapp.SubjectAuthorizer{}, Clock: clock.System{}}
	if _, err := svc.Revoke(p.ctx, gid, "range"); err != nil {
		return domain.Observation{}, err
	}
	return domain.Observation{}, nil
}

var _ jsontext.Value
