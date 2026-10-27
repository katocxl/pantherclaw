// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// serveStoppable starts cmdServe with cfgPath; stop ends it and waits.
func serveStoppable(t *testing.T, cfgPath string, env Env) (base string, stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	addrCh := make(chan string, 1)
	done := make(chan error, 1)
	var logs bytes.Buffer
	go func() {
		done <- cmdServe(ctx, []string{"--config", cfgPath}, &logs, env, func(a string) { addrCh <- a })
	}()
	stop = func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("server did not stop")
		}
	}
	select {
	case a := <-addrCh:
		return "http://" + a, stop
	case err := <-done:
		cancel()
		t.Fatalf("serve exited early: %v\n%s", err, logs.String())
	case <-time.After(60 * time.Second):
		stop()
		t.Fatal("server did not start")
	}
	return "", stop
}

func postBody(t *testing.T, url, ctype, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Content-Type", ctype)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// TestHR379_HeldServerRefusesDecisionsAuditsAndIsNotReady: a server
// started with maintenance.hold audits platform.maintenance_hold_on, is
// not ready (hold: fail), refuses the workload data plane and AuthZEN
// decisions with MAINTENANCE_HOLD, and still serves public and management
// routes; the first start without the hold audits
// platform.maintenance_hold_off, later ones nothing.
func TestHR379_HeldServerRefusesDecisionsAuditsAndIsNotReady(t *testing.T) {
	d := dbtest.New(t)
	count := func(event string) int {
		var n int
		d.AdminQueryRow(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = $2`,
			[]any{ids.PlatformOrg, "audit." + event}, &n)
		return n
	}
	cfgPath := testConfig(t, d, RoleAll)
	// The hold comes from the environment, as an operator would set it.
	holdEnv := func(k string) (string, bool) {
		if k == "PC_MAINTENANCE_HOLD" {
			return "true", true
		}
		return "", false
	}
	base, stop := serveStoppable(t, cfgPath, holdEnv)
	if code, body := getBody(t, base+"/readyz"); code != http.StatusServiceUnavailable ||
		!strings.Contains(string(body), `"hold":"fail"`) || !strings.Contains(string(body), `"ready":false`) {
		t.Errorf("held /readyz = %d %s", code, body)
	}
	for _, p := range []string{"IssueToken", "Enroll", "StartChildRun", "RequestAccess"} {
		code, body := postBody(t, base+"/pantherclaw.v1.WorkloadService/"+p, "application/json", "{}")
		if code != http.StatusServiceUnavailable || !strings.Contains(body, "MAINTENANCE_HOLD") {
			t.Errorf("held WorkloadService/%s = %d %s", p, code, body)
		}
	}
	for _, p := range []string{authzenEvaluationPath, authzenEvaluationsPath} {
		if code, body := postBody(t, base+p, "application/json", "{}"); code != http.StatusServiceUnavailable || !strings.Contains(body, "MAINTENANCE_HOLD") {
			t.Errorf("held %s = %d %s", p, code, body)
		}
	}
	if code, body := postBody(t, base+"/pantherclaw.v1.SystemService/GetBuildInfo", "application/json", `{"client_request_id":"h"}`); code != http.StatusOK {
		t.Errorf("held GetBuildInfo = %d %s", code, body)
	}
	// Management procedures still authenticate: unauthenticated, not held.
	if code, body := postBody(t, base+"/pantherclaw.v1.AgentService/ListAgents", "application/json", "{}"); code != http.StatusUnauthorized ||
		strings.Contains(body, "MAINTENANCE_HOLD") {
		t.Errorf("held ListAgents = %d %s, want unauthenticated", code, body)
	}
	stop()
	if on, off := count(holdOnEvent), count(holdOffEvent); on != 1 || off != 0 {
		t.Fatalf("after a held start: on=%d off=%d", on, off)
	}

	for run := range 2 {
		base, stop := serveStoppable(t, cfgPath, noEnv)
		if code, body := getBody(t, base+"/readyz"); code != http.StatusOK || !strings.Contains(string(body), `"hold":"ok"`) {
			t.Errorf("run %d: /readyz = %d %s", run, code, body)
		}
		stop()
		if on, off := count(holdOnEvent), count(holdOffEvent); on != 1 || off != 1 {
			t.Errorf("after plain start %d: on=%d off=%d, want 1 and 1", run, on, off)
		}
	}
}
