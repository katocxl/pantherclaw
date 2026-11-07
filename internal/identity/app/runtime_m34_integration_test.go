// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/identity/app"
	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// m34Grant inserts a root grant of agent for the world's owner.
func (w *world) m34Grant(t *testing.T, agent ids.UUID) ids.UUID {
	t.Helper()
	id := ids.NewV7()
	w.exec(t, `INSERT INTO pc.grants (org_id, id, agent_id, principal_user_id, environment_id, depth,
		current_revision, grantor_kind, grantor_id, basis) VALUES ($1, $2, $3, $4, $5, 0, 1, 'user', $4, 'test')`,
		w.org, id, agent, w.owner, w.env)
	w.exec(t, `INSERT INTO pc.grant_revisions (org_id, id, grant_id, revision, not_before, expires_at, bounds, requirements, limits,
		delegation_depth, max_children, min_attestation, widens, created_by)
		VALUES ($1, $2, $3, 1, now() - interval '1 hour', now() + interval '2 hours',
		convert_to('{"operations":["payments.refund.create"]}', 'UTF8'), convert_to('[]', 'UTF8'), convert_to('{}', 'UTF8'),
		0, 0, 0, false, 'test')`, w.org, ids.NewV7(), id)
	w.exec(t, "INSERT INTO pc.grant_lineage (org_id, grant_id, ancestor_id, distance) VALUES ($1, $2, $2, 0)", w.org, id)
	return id
}

// TestHR761_ACloudIssuerEntryMayNameARunGrant: an aws_iam or gcp_workload
// entry may name the run grant a cloud agent runtime's runs start under,
// and changing it is a widening; a GitHub entry may not, and a grant of no
// row of this organization is refused (G0 M34 D992).
//
// Covers: F1042, HR-761
func TestHR761_ACloudIssuerEntryMayNameARunGrant(t *testing.T) {
	w := newWorld(t)
	w.svc.WithEntitlements(edition(billing.Enterprise))
	agent := w.agent(t, adomain.ContextService)
	g := w.m34Grant(t, agent)
	aws := app.Binding{AWS: &issuers.AWSBinding{AccountID: "123456789012", RoleName: "orders-interceptor"}}
	r, err := w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{AgentID: agent, Binding: aws, Reason: "AgentCore gateway", RunGrantID: &g}, nil)
	if err != nil || r.RunGrantID == nil || *r.RunGrantID != g || r.Kind != issuers.KindAWS {
		t.Fatalf("aws_iam with a run grant: %+v %v", r, err)
	}
	gcp := app.Binding{GCP: &issuers.GCPBinding{ServiceAccountID: "1"}}
	if _, err := w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{AgentID: agent, Binding: gcp, Reason: "Vertex", RunGrantID: &g}, nil); err != nil {
		t.Errorf("gcp_workload with a run grant: %v", err)
	}

	stranger := ids.NewV7()
	if _, err := w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{AgentID: agent, Binding: aws, Reason: "x", RunGrantID: &stranger}, nil); pcerr.ReasonOf(err) != "ISSUER_RUN_GRANT" {
		t.Errorf("a grant of no row: %v", err)
	}
	zero := ids.UUID{}
	if _, err := w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{AgentID: agent, Binding: aws, Reason: "x", RunGrantID: &zero}, nil); pcerr.ReasonOf(err) != "ISSUER_RUN_GRANT" {
		t.Errorf("a zero grant: %v", err)
	}
	ci := w.agent(t, adomain.ContextCI)
	if _, err := w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{AgentID: ci, Binding: gh(mainRef), Reason: "x", RunGrantID: &g}, nil); pcerr.ReasonOf(err) != "ISSUER_RUN_GRANT" {
		t.Errorf("a GitHub entry with a run grant: %v", err)
	}
}
