// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

type recordAdmin struct {
	pantherclawv1connect.UnimplementedEvidenceAdminServiceHandler
	set     *pantherclawv1.SetRetentionPolicyRequest
	create  *pantherclawv1.CreateLegalHoldRequest
	list    *pantherclawv1.ListLegalHoldsRequest
	release *pantherclawv1.ReleaseLegalHoldRequest
	got     bool
}

func (r *recordAdmin) GetRetentionPolicies(context.Context, *pantherclawv1.GetRetentionPoliciesRequest) (*pantherclawv1.GetRetentionPoliciesResponse, error) {
	r.got = true
	return &pantherclawv1.GetRetentionPoliciesResponse{}, nil
}

func (r *recordAdmin) SetRetentionPolicy(_ context.Context, req *pantherclawv1.SetRetentionPolicyRequest) (*pantherclawv1.SetRetentionPolicyResponse, error) {
	r.set = req
	return &pantherclawv1.SetRetentionPolicyResponse{Changed: true, Shortened: true}, nil
}

func (r *recordAdmin) CreateLegalHold(_ context.Context, req *pantherclawv1.CreateLegalHoldRequest) (*pantherclawv1.CreateLegalHoldResponse, error) {
	r.create = req
	return &pantherclawv1.CreateLegalHoldResponse{Hold: &pantherclawv1.LegalHold{Id: "0192aaaa-bbbb-7ccc-8ddd-0000000000bb"}}, nil
}

func (r *recordAdmin) ListLegalHolds(_ context.Context, req *pantherclawv1.ListLegalHoldsRequest) (*pantherclawv1.ListLegalHoldsResponse, error) {
	r.list = req
	return &pantherclawv1.ListLegalHoldsResponse{}, nil
}

func (r *recordAdmin) ReleaseLegalHold(_ context.Context, req *pantherclawv1.ReleaseLegalHoldRequest) (*pantherclawv1.ReleaseLegalHoldResponse, error) {
	r.release = req
	return &pantherclawv1.ReleaseLegalHoldResponse{}, nil
}

func TestRetentionAndHoldCommands(t *testing.T) {
	ra := &recordAdmin{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterEvidenceAdminServiceHandler(cs, ra)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})
	const id = "0192aaaa-bbbb-7ccc-8ddd-000000000001"

	if code, _, errs := run(t, env, "retention", "get"); code != 0 || !ra.got {
		t.Fatalf("retention get: %d %s", code, errs)
	}
	if code, out, errs := run(t, env, "retention", "set", "receipts", "--days", "30"); code != 0 ||
		ra.set.GetCategory() != pantherclawv1.RetentionCategory_RETENTION_CATEGORY_RECEIPTS || ra.set.GetDays() != 30 {
		t.Fatalf("retention set: %d %s %s", code, out, errs)
	}
	if code, _, _ := run(t, env, "retention", "set", "versions", "--days", "30"); code == 0 {
		t.Fatal("an unknown category was sent")
	}
	if code, _, _ := run(t, env, "retention", "set", "receipts"); code == 0 {
		t.Fatal("a period without --days was sent")
	}

	if code, _, errs := run(t, env, "hold", "create", "--scope", "transaction", "--id", id, "--reason", "dispute"); code != 0 ||
		ra.create.GetScope() != pantherclawv1.LegalHoldScope_LEGAL_HOLD_SCOPE_TRANSACTION || ra.create.GetScopeId() != id ||
		ra.create.GetReason() != "dispute" || ra.create.StartTime != nil {
		t.Fatalf("hold create: %d %s %+v", code, errs, ra.create)
	}
	if code, _, errs := run(t, env, "hold", "create", "--scope", "time_range", "--start", "720h", "--end", "2030-01-01T00:00:00Z",
		"--reason", "audit"); code != 0 || ra.create.ScopeId != nil || time.Since(ra.create.GetStartTime().AsTime()) < 719*time.Hour ||
		ra.create.GetEndTime().AsTime().Year() != 2030 {
		t.Fatalf("hold create time range: %d %s %+v", code, errs, ra.create)
	}
	if code, _, _ := run(t, env, "hold", "create", "--scope", "org"); code == 0 {
		t.Fatal("a hold without a reason was sent")
	}
	if code, _, errs := run(t, env, "hold", "list", "--state", "active", "--page-size", "5"); code != 0 ||
		ra.list.GetState() != pantherclawv1.LegalHoldState_LEGAL_HOLD_STATE_ACTIVE || ra.list.GetPageSize() != 5 {
		t.Fatalf("hold list: %d %s", code, errs)
	}
	if code, _, errs := run(t, env, "hold", "release", id, "--reason", "closed"); code != 0 ||
		ra.release.GetId() != id || ra.release.GetReason() != "closed" {
		t.Fatalf("hold release: %d %s", code, errs)
	}
	if code, _, _ := run(t, env, "hold", "release", id); code == 0 {
		t.Fatal("a release without a reason was sent")
	}
}
