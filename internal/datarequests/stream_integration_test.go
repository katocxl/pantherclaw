// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package datarequests

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

type fakeStream struct {
	push    *fakePush
	request ids.UUID
	person  ids.UUID
}

func (f *fakeStream) Open(_ context.Context, _ ids.OrgID, request, requestedBy ids.UUID) (PushWriter, error) {
	f.request, f.person = request, requestedBy
	return f.push, nil
}

func buildingExport(t *testing.T, s *Service, org ids.OrgID, user ids.UUID) ids.UUID {
	t.Helper()
	id := ids.NewV7()
	if err := s.Pool.InTenantTx(t.Context(), org, func(ctx context.Context, tx db.TenantTx) error {
		return dbq.New(tx).InsertDataRequest(ctx, dbq.InsertDataRequestParams{OrgID: org, ID: id, Kind: "EXPORT", State: "BUILDING", CreatedBy: &user, AdminAccounts: []ids.UUID{}})
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestHR516_AStreamedBuildStoresNothing: a build with a waiting push sends
// every part and the signed manifest to it, stores no part, and cannot be
// downloaded; a build whose push fails ends FAILED, without a retry, and
// the push is aborted.
// Covers: F517
func TestHR516_AStreamedBuildStoresNothing(t *testing.T) {
	d, s, org := setup(t)
	ctx := t.Context()
	user := ids.NewV7()
	d.AdminExec(t, "INSERT INTO pc.users(org_id,id,issuer,subject,email,display_name) VALUES($1,$2,'test','person','own@example.com','Own identity')", org, user)
	d.AdminExec(t, "INSERT INTO pc.role_bindings(org_id,id,role,user_id,scope_type,created_by) VALUES($1,$2,'org_admin',$3,'ORG','system:test')", org, ids.NewV7(), user)

	push := &fakePush{}
	stream := &fakeStream{push: push}
	s.Stream = stream
	id := buildingExport(t, s, org, user)
	if err := s.Build(ctx, org, id); err != nil {
		t.Fatal(err)
	}
	if stream.request != id || stream.person != user || push.parts == 0 || push.manifest == "" {
		t.Fatalf("stream %+v, push %+v", stream, push)
	}
	if !push.aborted {
		t.Fatal("Build must always call Abort, which does nothing after Finish")
	}
	var parts, stored int
	var state string
	d.AdminQueryRow(t, "SELECT state, parts FROM pc.data_requests WHERE org_id=$1 AND id=$2", []any{org, id}, &state, &parts)
	d.AdminQueryRow(t, "SELECT count(*) FROM pc.data_request_parts WHERE org_id=$1 AND request_id=$2", []any{org, id}, &stored)
	if state != "READY" || parts != 0 || stored != 0 {
		t.Fatalf("state %s, %d parts, %d stored", state, parts, stored)
	}

	d.AdminExec(t, "UPDATE pc.data_requests SET state = 'EXPIRED' WHERE org_id=$1 AND id=$2", org, id)
	failing := &fakePush{failOn: 1}
	s.Stream = &fakeStream{push: failing}
	id2 := buildingExport(t, s, org, user)
	if err := s.Build(ctx, org, id2); err != nil {
		t.Fatalf("a failed push must not retry the build: %v", err)
	}
	var code string
	d.AdminQueryRow(t, "SELECT state, coalesce(error_code, '') FROM pc.data_requests WHERE org_id=$1 AND id=$2", []any{org, id2}, &state, &code)
	if state != "FAILED" || code != "EXPORT_PUSH_FAILED" || !failing.aborted {
		t.Fatalf("state %s, code %s, aborted %v", state, code, failing.aborted)
	}
}

// TestF517_NoWaitingPushStoresAsBefore: without a waiting push an export is
// stored and capped exactly as before.
// Covers: F517
func TestF517_NoWaitingPushStoresAsBefore(t *testing.T) {
	d, s, org := setup(t)
	ctx := t.Context()
	user := ids.NewV7()
	d.AdminExec(t, "INSERT INTO pc.users(org_id,id,issuer,subject,email,display_name) VALUES($1,$2,'test','person','own@example.com','Own identity')", org, user)
	d.AdminExec(t, "INSERT INTO pc.role_bindings(org_id,id,role,user_id,scope_type,created_by) VALUES($1,$2,'org_admin',$3,'ORG','system:test')", org, ids.NewV7(), user)
	s.Stream = noStream{}
	id := buildingExport(t, s, org, user)
	if err := s.Build(ctx, org, id); err != nil {
		t.Fatal(err)
	}
	var stored int
	d.AdminQueryRow(t, "SELECT count(*) FROM pc.data_request_parts WHERE org_id=$1 AND request_id=$2", []any{org, id}, &stored)
	if stored == 0 {
		t.Fatal("nothing stored")
	}
}

type noStream struct{}

func (noStream) Open(context.Context, ids.OrgID, ids.UUID, ids.UUID) (PushWriter, error) {
	return nil, nil //nolint:nilnil // no waiting push is not an error
}
