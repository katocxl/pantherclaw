// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

type recordCaptures struct {
	pantherclawv1connect.UnimplementedEvidenceAdminServiceHandler
	create  *pantherclawv1.CreateCaptureProfileRequest
	list    *pantherclawv1.ListCaptureProfilesRequest
	disable *pantherclawv1.DisableCaptureProfileRequest
	read    *pantherclawv1.ReadPayloadCaptureRequest
}

func (r *recordCaptures) CreateCaptureProfile(_ context.Context, req *pantherclawv1.CreateCaptureProfileRequest) (*pantherclawv1.CreateCaptureProfileResponse, error) {
	r.create = req
	return &pantherclawv1.CreateCaptureProfileResponse{}, nil
}

func (r *recordCaptures) ListCaptureProfiles(_ context.Context, req *pantherclawv1.ListCaptureProfilesRequest) (*pantherclawv1.ListCaptureProfilesResponse, error) {
	r.list = req
	return &pantherclawv1.ListCaptureProfilesResponse{}, nil
}

func (r *recordCaptures) DisableCaptureProfile(_ context.Context, req *pantherclawv1.DisableCaptureProfileRequest) (*pantherclawv1.DisableCaptureProfileResponse, error) {
	r.disable = req
	return &pantherclawv1.DisableCaptureProfileResponse{}, nil
}

func (r *recordCaptures) ReadPayloadCapture(_ context.Context, req *pantherclawv1.ReadPayloadCaptureRequest) (*pantherclawv1.ReadPayloadCaptureResponse, error) {
	r.read = req
	return &pantherclawv1.ReadPayloadCaptureResponse{Id: "c1", Content: []byte(`{"amount":"30.00"}`)}, nil
}

func TestCaptureCommands(t *testing.T) {
	rc := &recordCaptures{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterEvidenceAdminServiceHandler(cs, rc)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})
	const id = "0192aaaa-bbbb-7ccc-8ddd-000000000001"

	if code, _, errs := run(t, env, "capture", "profile", "create", "--purpose", "dispute", "--connection", id,
		"--operation", "payments.refund.create", "--response", "--byte-cap", "4096", "--retention-days", "7", "--expires-in-days", "30"); code != 0 ||
		rc.create.GetPurpose() != "dispute" || rc.create.GetConnectionIds()[0] != id || rc.create.GetCaptureRequest() ||
		!rc.create.GetCaptureResponse() || rc.create.GetByteCap() != 4096 || rc.create.GetRetentionDays() != 7 || rc.create.GetExpiresInDays() != 30 {
		t.Fatalf("capture profile create: %d %s %+v", code, errs, rc.create)
	}
	for name, args := range map[string][]string{
		"no purpose":    {"--connection", id, "--operation", "x.y", "--request", "--byte-cap", "1", "--retention-days", "1", "--expires-in-days", "1"},
		"no body":       {"--purpose", "p", "--connection", id, "--operation", "x.y", "--byte-cap", "1", "--retention-days", "1", "--expires-in-days", "1"},
		"a 31-day keep": {"--purpose", "p", "--connection", id, "--operation", "x.y", "--request", "--byte-cap", "1", "--retention-days", "31", "--expires-in-days", "1"},
	} {
		rc.create = nil
		if code, _, _ := run(t, env, append([]string{"capture", "profile", "create"}, args...)...); code == 0 || rc.create != nil {
			t.Errorf("%s was sent", name)
		}
	}
	if code, _, errs := run(t, env, "capture", "profile", "list", "--state", "expired"); code != 0 ||
		rc.list.GetState() != pantherclawv1.CaptureProfileState_CAPTURE_PROFILE_STATE_EXPIRED {
		t.Fatalf("capture profile list: %d %s", code, errs)
	}
	if code, _, errs := run(t, env, "capture", "profile", "disable", id); code != 0 || rc.disable.GetId() != id {
		t.Fatalf("capture profile disable: %d %s", code, errs)
	}
	if code, _, _ := run(t, env, "capture", "read", id, "--direction", "request"); code == 0 || rc.read != nil {
		t.Fatal("a read without a reason was sent")
	}
	out := filepath.Join(t.TempDir(), "body.json")
	code, stdout, errs := run(t, env, "capture", "read", id, "--direction", "response", "--reason", "dispute 117", "--out", out)
	if code != 0 || rc.read.GetTransactionId() != id || rc.read.GetReason() != "dispute 117" ||
		rc.read.GetDirection() != pantherclawv1.CaptureDirection_CAPTURE_DIRECTION_RESPONSE {
		t.Fatalf("capture read: %d %s %+v", code, errs, rc.read)
	}
	if b, err := os.ReadFile(out); err != nil || string(b) != `{"amount":"30.00"}` || strings.Contains(stdout, "content") {
		t.Fatalf("written %q (%v), printed %q", b, err, stdout)
	}
}
