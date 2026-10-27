// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/katocxl/pantherclaw/internal/datarequests"
	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/pclaw"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// rangeExport is a READY tenant export of org, built by the export job's
// own code with the server's signing keys, and a context of that org's
// admin (a person in a browser session) who may download it.
type rangeExport struct {
	org   ids.OrgID
	id    ids.UUID
	admin context.Context
}

// exportFixture builds an export of org as the data.export job does after
// an admin asked for one (G0 M13 D34). The request row is written the way
// CreateExportPage writes it; the security-key step-up of that page is
// covered by the datarequests tests, not here.
func rangeExportFixture(t *testing.T, s *stack, svc *datarequests.Service, org ids.OrgID) rangeExport {
	t.Helper()
	user, id := ids.NewV7(), ids.NewV7()
	s.db.AdminExec(t, "INSERT INTO pc.users(org_id,id,issuer,subject,email) VALUES($1,$2,'https://range.test',$3,'admin@range.test')", org, user, user.String())
	s.db.AdminExec(t, "INSERT INTO pc.role_bindings(org_id,id,role,user_id,scope_type,created_by) VALUES($1,$2,'org_admin',$3,'ORG','range')", org, ids.NewV7(), user)
	s.db.AdminExec(t, "INSERT INTO pc.data_requests(org_id,id,kind,state,created_by,admin_accounts) VALUES($1,$2,'EXPORT','BUILDING',$3,'{}')", org, id, user)
	if err := svc.Build(context.Background(), org, id); err != nil {
		t.Fatalf("building the export: %v", err)
	}
	var state string
	s.db.AdminQueryRow(t, "SELECT state FROM pc.data_requests WHERE org_id = $1 AND id = $2", []any{org, id}, &state)
	if state != "READY" {
		t.Fatalf("export of %s is %s, want READY", org, state)
	}
	return rangeExport{org: org, id: id, admin: tapp.WithCaller(context.Background(), tapp.Caller{
		Subject: td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user}, Bindings: []td.Binding{{Role: td.RoleOrgAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}}},
		Credential: tapp.CredBrowserSession, Session: ids.NewV7(),
	})}
}

// dataProbe runs data.probe (G0 M13 D34; RT-069, T-177). Downloads go
// through the service the DataRequestService's DownloadExport calls, as
// the app role under FORCE RLS; the offline check is `pclaw verify
// export` with the trust file pinned from the server, and no network.
func (d *rangeDriver) dataProbe(st domain.Step) (domain.Observation, error) {
	var w struct {
		Attack string `json:"attack"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	p := d.s.proof(d.t)
	svc := &datarequests.Service{Pool: d.s.pool, Keys: p.reg, Jobs: p.jobs, Bundles: evapp.New(d.s.pool, p.origin), BackupRetentionDays: 60}
	own := rangeExportFixture(d.t, d.s, svc, d.s.org)
	target := own
	switch w.Attack {
	case "other_org":
		other := ids.New[ids.Org]()
		d.s.db.AdminExec(d.t, "INSERT INTO pc.orgs(id,name) VALUES($1,'range other org')", other)
		target = rangeExportFixture(d.t, d.s, svc, other)
	case "expired_export":
		d.s.db.AdminExec(d.t, "UPDATE pc.data_requests SET expires_at = now() - interval '1 second' WHERE org_id = $1 AND id = $2", own.org, own.id)
	}
	// The attacker is always the range org's admin: target is another
	// org's export only for other_org.
	part, err := svc.Download(own.admin, target.id, 1)
	if err != nil {
		return domain.Observation{Outcome: domain.OutcomeRefused, Reason: pcerr.ReasonOf(err), Detail: err.Error()}, nil
	}
	if w.Attack == "tampered_part" {
		part.Content = bytes.Clone(part.Content)
		part.Content[len(part.Content)/2] ^= 0x01
	}
	var manifest string
	d.s.query(d.t, "SELECT manifest FROM pc.data_requests WHERE org_id = $1 AND id = $2", []any{own.org, own.id}, &manifest)
	report, err := verifyExportOffline(d.t, p, manifest, part.Content)
	if err != nil {
		return domain.Observation{}, err
	}
	if report.Failed() {
		return domain.Observation{Outcome: domain.OutcomeRefused, Reason: "EXPORT_VERIFY_FAILED", Detail: report.Text()}, nil
	}
	return domain.Observation{Outcome: domain.OutcomeAllow, Detail: fmt.Sprintf("%d checks passed", report.Count(bundle.Passed))}, nil
}

// verifyExportOffline writes the signed manifest and its one part as a
// user saves them and runs `pclaw verify export` on them, offline.
func verifyExportOffline(t *testing.T, p *proof, manifest string, part []byte) (*bundle.Report, error) {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "manifest.jws")
	if err := os.WriteFile(file, []byte(manifest), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "part-001.zip"), part, 0o600); err != nil {
		return nil, err
	}
	var out, errb bytes.Buffer
	code := pclaw.Run(context.Background(), []string{"verify", "export", file, "--trust", p.trust, "--parts", dir, "--json"}, &out, &errb, noEnv,
		pclaw.Options{HTTPClient: &http.Client{Transport: offline{t}}})
	var r bundle.Report
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		return nil, fmt.Errorf("pclaw verify export: %d %q %q", code, out.String(), errb.String())
	}
	if (code == 0) == r.Failed() {
		return nil, fmt.Errorf("pclaw verify export exit %d for a %s report", code, r.Result)
	}
	return &r, nil
}
