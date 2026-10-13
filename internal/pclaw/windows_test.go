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

type recordWindows struct {
	pantherclawv1connect.UnimplementedChangeWindowServiceHandler
	create *pantherclawv1.CreateChangeWindowRequest
}

func (r *recordWindows) CreateChangeWindow(_ context.Context, req *pantherclawv1.CreateChangeWindowRequest) (*pantherclawv1.CreateChangeWindowResponse, error) {
	r.create = req
	return &pantherclawv1.CreateChangeWindowResponse{}, nil
}

// TestHR207_WindowCreateBuildsTheRequest: weekly entries, one-off windows
// and freezes map onto the request; a malformed one sends nothing.
func TestHR207_WindowCreateBuildsTheRequest(t *testing.T) {
	rec := &recordWindows{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterChangeWindowServiceHandler(cs, rec)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})
	code, _, errs := run(t, env, "window", "create", "--environment", "production", "--repository", "acme/payments", "--time-zone", "Europe/London",
		"--weekly", "Mon 09:00 480", "--weekly", "fri 22:00 240", "--freeze", "2026-12-21T00:00:00Z/2027-01-04T00:00:00Z")
	if code != 0 {
		t.Fatalf("window create = %d %s", code, errs)
	}
	r := rec.create
	if r.GetEnvironment() != "production" || r.GetRepository() != "acme/payments" || r.GetTimeZone() != "Europe/London" || len(r.GetWeekly()) != 2 ||
		r.GetWeekly()[0].GetDay() != "mon" || r.GetWeekly()[1].GetMinutes() != 240 || len(r.GetFreezes()) != 1 ||
		!r.GetFreezes()[0].GetEndTime().AsTime().Equal(time.Date(2027, 1, 4, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("request %v", r)
	}
	rec.create = nil
	for _, bad := range [][]string{{"--weekly", "mon 09:00"}, {"--weekly", "mon 09:00 eight"}, {"--one-off", "2026-12-21T00:00:00Z"}} {
		args := append([]string{"window", "create", "--environment", "production", "--time-zone", "UTC"}, bad...)
		if code, _, _ := run(t, env, args...); code == 0 || rec.create != nil {
			t.Errorf("%v accepted", bad)
		}
	}
}
