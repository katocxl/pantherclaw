// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"path/filepath"
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
	d.defaultRun = d.grantRun(bounds, limits)
}

// grantRun issues the agent a grant with these bounds and limits and starts a
// run on it, and returns the run.
func (d *rangeDriver) grantRun(bounds, limits string) string {
	return d.grantRunWith(bounds, limits, "")
}

// grantRunWith is grantRun for a grant that also holds requirements.
func (d *rangeDriver) grantRunWith(bounds, limits, requirements string) string {
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
		if code, out, errs := d.admin.pclaw(t, "role", "bind", "--role", role, "--user", alice); code != 0 && !strings.Contains(errs, "ROLE_BINDING_EXISTS") {
			t.Fatalf("role bind %s: %d %s %s", role, code, out, errs)
		}
	}
	doc := func(name, content string) string {
		return writeFile(t, dir, name, []byte(content))
	}
	args := []string{
		"grant", "issue", agent, "--principal", "user:" + alice, "--expires", "24h", "--bounds-file", doc("bounds.json", bounds),
		"--delegation-depth", "2", "--max-children", "10", "--task", "range",
	}
	if limits != "" {
		args = append(args, "--limits-file", doc("limits.json", limits))
	}
	if requirements != "" {
		args = append(args, "--requirements-file", doc("requirements.json", requirements))
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
	return field(t, out, "id")
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

// ineligible are the codes the approval flow gives for a person who may not
// count (approvals/domain/eligibility.go).
var ineligible = []string{"LAUNCHER_EXCLUDED", "PRINCIPAL_EXCLUDED", "OWNER_EXCLUDED", "GRANT_ISSUER_EXCLUDED", "REQUESTER_EXCLUDED", "ANCESTOR_RUN_EXCLUDED"}

// refusedApproval has a reviewer who is also the run's launcher (or the
// principal it acts for) try to approve its hold. The seeded run is theirs for
// the attempt, and the seeded launcher is restored after it.
func (d *rangeDriver) refusedApproval(rec *callRec, as string) (domain.Observation, error) {
	if len(d.reviewers) == 0 {
		return domain.Observation{}, fmt.Errorf("no reviewer to act as the %s", as)
	}
	r := d.reviewers[0]
	if as != "launcher" && as != "developer" {
		return domain.Observation{}, fmt.Errorf("approval as %q", as)
	}
	db, run := d.s.db, d.s.run
	var launcher, principal, source string
	d.s.query(d.t, "SELECT launcher_user_id::text, principal_user_id::text, principal_source FROM pc.runs WHERE id = $1", []any{run}, &launcher, &principal, &source)
	defer func() {
		db.AdminExec(d.t, "UPDATE pc.runs SET launcher_user_id = $1, principal_user_id = $2, principal_source = $3, subject_issuer = NULL, subject_subject = NULL WHERE id = $4",
			mustUUID(d.t, launcher), mustUUID(d.t, principal), source, run)
	}()
	if as == "launcher" {
		// The launcher is the principal too (runs_self_launched).
		db.AdminExec(d.t, "UPDATE pc.runs SET launcher_user_id = $1, principal_user_id = $1 WHERE id = $2", r.user, run)
	} else {
		db.AdminExec(d.t, "UPDATE pc.runs SET principal_user_id = $1, principal_source = 'subject_token', "+
			"subject_issuer = 'https://idp.test', subject_subject = 'range-developer' WHERE id = $2", r.user, run)
	}
	code, body := d.s.approveMerge(d.t, r.b, r.key, rec.txn)
	if code == http.StatusOK {
		return domain.Observation{Outcome: domain.OutcomeAllow, Detail: "the " + as + " approved"}, nil
	}
	// The page only says the person is not eligible; the CLI says why.
	_, why, _ := r.cli.pclaw(d.t, "approval", "get", d.s.requestOf(d.t, rec.txn))
	body += " " + why
	for _, c := range ineligible {
		if strings.Contains(body, c) {
			return domain.Observation{Outcome: domain.OutcomeRefused, Code: c, Detail: body}, nil
		}
	}
	return domain.Observation{Outcome: domain.OutcomeRefused, Code: fmt.Sprintf("http_%d", code), Detail: body}, nil
}

// enrolOtherInstance enrols and admits a second instance of the agent, with
// a key of its own, and returns the key and a workload token.
func (d *rangeDriver) enrolOtherInstance() (ed25519.PrivateKey, string) {
	t, s := d.t, d.s
	if d.admin == nil {
		d.adminOnly()
	}
	var agent, alice string
	s.query(t, "SELECT agent_id::text FROM pc.runs WHERE id = $1", []any{s.run}, &agent)
	s.query(t, "SELECT id::text FROM pc.users WHERE subject = 'alice'", nil, &alice)
	for _, role := range []string{"agent_owner", "agent_admitter"} {
		if code, out, errs := d.admin.pclaw(t, "role", "bind", "--role", role, "--user", alice); code != 0 {
			t.Fatalf("role bind %s: %d %s %s", role, code, out, errs)
		}
	}
	s.db.AdminExec(t, "UPDATE pc.role_bindings SET created_at = now() - interval '30 days' WHERE org_id = $1", s.org)
	s.db.AdminExec(t, "UPDATE pc.agents SET owner_user_id = $3 WHERE org_id = $1 AND id = $2", s.org, mustUUID(t, agent), mustUUID(t, alice))
	dir := t.TempDir()
	enrollFile, keyFile := filepath.Join(dir, "enroll.token"), filepath.Join(dir, "workload.json")
	must := func(args ...string) string {
		t.Helper()
		code, out, errs := d.admin.pclaw(t, args...)
		if code != 0 {
			t.Fatalf("pclaw %s: %d %s %s", strings.Join(args, " "), code, out, errs)
		}
		return out
	}
	must("agent", "enroll-token", agent, "--out", enrollFile)
	must("workload", "init", "--key-file", keyFile)
	o := must("workload", "enroll", "--key-file", keyFile, "--server", s.apiURL, "--enrollment-token-file", enrollFile)
	inst, fp := enrolledInstance.FindStringSubmatch(o), enrolledPrint.FindStringSubmatch(o)
	if inst == nil || fp == nil {
		t.Fatalf("enroll output %q", o)
	}
	must("instance", "admit", inst[1], "--fingerprint", fp[1])
	token := strings.TrimSpace(must("workload", "token", "--key-file", keyFile))
	kf, err := workloadclient.ReadKeyFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	key, err := kf.Key()
	if err != nil {
		t.Fatal(err)
	}
	return key, token
}
