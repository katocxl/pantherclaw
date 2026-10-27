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
)

// TestHR397_WorkerServesProbesOnHealthListener: a worker-only process
// with health.addr serves /livez and /readyz there — ready once its job
// workers beat — and nothing else; the probe body carries the fixed check
// words. With the maintenance hold on, /readyz reports not ready.
func TestHR397_WorkerServesProbesOnHealthListener(t *testing.T) {
	for _, held := range []bool{false, true} {
		name := "not held"
		if held {
			name = "held"
		}
		t.Run(name, func(t *testing.T) {
			d := dbtest.New(t)
			cfgPath := testConfig(t, d, RoleWorker, func(c map[string]any) {
				c["health"] = map[string]any{"addr": "127.0.0.1:0"}
				c["maintenance"] = map[string]any{"hold": held}
			})
			ctx, cancel := context.WithCancel(context.Background())
			addrCh := make(chan string, 1)
			done := make(chan error, 1)
			var logs bytes.Buffer
			go func() {
				done <- cmdServe(ctx, []string{"--config", cfgPath}, &logs, noEnv, func(a string) { addrCh <- a })
			}()
			var base string
			select {
			case a := <-addrCh:
				base = "http://" + a
			case err := <-done:
				t.Fatalf("serve exited early: %v\n%s", err, logs.String())
			case <-time.After(60 * time.Second):
				cancel()
				t.Fatal("the worker's health listener did not start")
			}
			hc := &http.Client{Timeout: 5 * time.Second}
			get := func(path string) (int, string) {
				req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, base+path, nil)
				resp, err := hc.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = resp.Body.Close() }()
				b, _ := io.ReadAll(resp.Body)
				return resp.StatusCode, strings.TrimSpace(string(b))
			}
			if code, _ := get("/livez"); code != http.StatusOK {
				t.Errorf("/livez = %d", code)
			}
			wantCode, want := http.StatusOK, `{"ready":true,"checks":{"db":"ok","schema":"ok","workers":"ok","hold":"ok"}}`
			if held {
				wantCode, want = http.StatusServiceUnavailable, `{"ready":false,"checks":{"db":"ok","schema":"ok","workers":"ok","hold":"fail"}}`
			}
			if code, body := get("/readyz"); code != wantCode || body != want {
				t.Errorf("/readyz = %d %s, want %d %s", code, body, wantCode, want)
			}
			for _, path := range []string{"/.well-known/pantherclaw/jwks.json", "/pantherclaw.v1.SystemService/GetBuildInfo", "/"} {
				if code, _ := get(path); code != http.StatusNotFound {
					t.Errorf("%s on the health listener = %d, want 404", path, code)
				}
			}
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("serve returned %v\n%s", err, logs.String())
				}
			case <-time.After(30 * time.Second):
				t.Fatal("graceful shutdown did not finish")
			}
		})
	}
}
