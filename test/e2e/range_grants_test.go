// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
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

// ownGrant makes the scenario's agent act under a grant of its own: issued
// by the org's administrator with these bounds and limits, and a run on it.
// Calls are made in that run from then on.
func (d *rangeDriver) ownGrant(bounds, limits string) {
	t, s := d.t, d.s
	if d.admin == nil {
		d.adminOnly()
	}
	var agent, inst, alice string
	s.query(t, "SELECT agent_id::text FROM pc.runs WHERE id = $1", []any{s.run}, &agent)
	s.query(t, "SELECT id::text FROM pc.agent_instances WHERE agent_id = $1 AND state = 'ADMITTED' LIMIT 1", []any{agent}, &inst)
	s.query(t, "SELECT id::text FROM pc.users WHERE subject = 'alice'", nil, &alice)
	dir := t.TempDir()
	for _, role := range []string{"grant_issuer", "run_launcher"} {
		if code, out, errs := d.admin.pclaw(t, "role", "bind", "--role", role, "--user", alice); code != 0 {
			t.Fatalf("role bind %s: %d %s %s", role, code, out, errs)
		}
	}
	doc := func(name, content string) string {
		return writeFile(t, dir, name, []byte(content))
	}
	args := []string{"grant", "issue", agent, "--principal", "user:" + alice, "--expires", "24h", "--bounds-file", doc("bounds.json", bounds),
		"--delegation-depth", "1", "--max-children", "2", "--task", "range"}
	if limits != "" {
		args = append(args, "--limits-file", doc("limits.json", limits))
	}
	code, out, errs := d.admin.pclaw(t, args...)
	if code != 0 {
		t.Fatalf("grant issue: %d %s %s", code, out, errs)
	}
	grant := field(t, out, "id")
	code, out, errs = d.admin.pclaw(t, "run", "start", agent, "--instance", inst, "--grant", grant, "--task", "range")
	if code != 0 {
		t.Fatalf("run start: %d %s %s", code, out, errs)
	}
	d.defaultRun = field(t, out, "id")
}

// adminOnly makes alice the org's administrator, signed in to the CLI.
func (d *rangeDriver) adminOnly() {
	t, s := d.t, d.s
	var out, errb bytes.Buffer
	if code := runServerCmd(&out, &errb, "org", "admin-invite", "--config", s.serverCfg, "--org", s.org.String()); code != 0 {
		t.Fatalf("org admin-invite: %d %s", code, errb.String())
	}
	alice := d.people.user(t, "alice", "alice@example.test")
	alice.login(t, s.org.String(), pciToken.FindStringSubmatch(out.String())[1])
	d.admin = alice
}
