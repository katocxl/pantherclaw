// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package datarequests

import (
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"testing"
)

func TestHR393_LapseUsesHostedModeAndRecoveryBeforeFreezeWins(t *testing.T) {
	d, s, org := setup(t)
	d.AdminExec(t, `INSERT INTO pc.org_entitlements(org_id,plan_id,edition,status,source,last_event_at,lapsed_at)
        VALUES($1,'team','team','LAPSED','BILLING',now()-interval '91 days',now()-interval '91 days')`, org)
	s.LapseEnabled = false
	if err := s.Daily(t.Context(), org); err != nil {
		t.Fatal(err)
	}
	var n int
	d.AdminQueryRow(t, "SELECT count(*) FROM pc.data_requests WHERE org_id=$1", []any{org}, &n)
	if n != 0 {
		t.Fatal("stale hosted plan triggered deletion in licence mode")
	}
	s.LapseEnabled = true
	for range 2 {
		if err := s.Daily(t.Context(), org); err != nil {
			t.Fatal(err)
		}
	}
	d.AdminQueryRow(t, "SELECT count(*) FROM pc.data_requests WHERE org_id=$1", []any{org}, &n)
	if n != 1 {
		t.Fatalf("lapse requests=%d", n)
	}
	var request ids.UUID
	d.AdminQueryRow(t, "SELECT id FROM pc.data_requests WHERE org_id=$1", []any{org}, &request)
	d.AdminExec(t, "UPDATE pc.org_entitlements SET status='ACTIVE' WHERE org_id=$1", org)
	if err := s.DeleteOrg(t.Context(), org, request); err != nil {
		t.Fatal(err)
	}
	var state, code string
	d.AdminQueryRow(t, "SELECT state,error_code FROM pc.data_requests WHERE org_id=$1", []any{org}, &state, &code)
	if state != "FAILED" || code != "PLAN_RESTORED" {
		t.Fatalf("recovery lost: state=%s code=%s", state, code)
	}
	d.AdminQueryRow(t, "SELECT state FROM pc.orgs WHERE id=$1", []any{org}, &state)
	if state != "ACTIVE" {
		t.Fatalf("recovered org became %s", state)
	}
}

func TestHR390_ExportBytesExpireForClosedOrgsWithoutHostedBilling(t *testing.T) {
	d, s, org := setup(t)
	s.LapseEnabled = false
	id := ids.NewV7()
	d.AdminExec(t, `INSERT INTO pc.data_requests(org_id,id,kind,state,created_by,ready_at,expires_at,parts,total_size,manifest)
        VALUES($1,$2,'EXPORT','READY',$3,now()-interval '8 days',now()-interval '1 day',1,1,'test')`, org, id, ids.NewV7())
	d.AdminExec(t, "INSERT INTO pc.data_request_parts(org_id,request_id,number,content,sha256) VALUES($1,$2,1,$3,$4)", org, id, []byte{1}, make([]byte, 32))
	d.AdminExec(t, "UPDATE pc.orgs SET state='CLOSED' WHERE id=$1", org)
	if err := s.Daily(t.Context(), org); err != nil {
		t.Fatal(err)
	}
	var state string
	var n int
	d.AdminQueryRow(t, "SELECT state FROM pc.data_requests WHERE org_id=$1 AND id=$2", []any{org, id}, &state)
	d.AdminQueryRow(t, "SELECT count(*) FROM pc.data_request_parts WHERE org_id=$1", []any{org}, &n)
	if state != "EXPIRED" || n != 0 {
		t.Fatalf("expiry state=%s retained parts=%d", state, n)
	}
}
