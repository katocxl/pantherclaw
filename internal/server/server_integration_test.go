// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

func secretFile(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// testConfig writes a server config for the test database d.
func testConfig(t *testing.T, d *dbtest.DB, role string, mutate ...func(map[string]any)) string {
	t.Helper()
	dir := t.TempDir()
	kek := filepath.Join(dir, "kek")
	if err := keys.GenerateKEKFile(kek); err != nil {
		t.Fatal(err)
	}
	cfg := map[string]any{
		"role": role,
		"log":  map[string]any{"level": "warn"},
		"http": map[string]any{"addr": "127.0.0.1:0"},
		"database": map[string]any{
			"host": d.App.Host, "port": d.App.Port, "name": d.Name, "sslmode": "disable",
			"app_password_file":      secretFile(t, dir, "app-pw", d.App.Password.Reveal()),
			"migrator_password_file": secretFile(t, dir, "mig-pw", d.Migrator.Password.Reveal()),
			"max_conns":              5,
		},
		"kek_files":          []string{kek},
		"worker_concurrency": 2,
		// Not live, so dev seed accepts the configuration (HR-163).
		"auth": map[string]any{"api_key_env": "test"},
	}
	for _, m := range mutate {
		m(cfg)
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return secretFile(t, dir, "server.json", b)
}

func TestIntServeAPIAndWorkers(t *testing.T) {
	d := dbtest.New(t)
	cfgPath := testConfig(t, d, RoleAll)
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
		t.Fatal("server did not start")
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
		return resp.StatusCode, string(b)
	}
	if code, _ := get("/livez"); code != http.StatusOK {
		t.Fatalf("/livez = %d", code)
	}
	if code, body := get("/readyz"); code != http.StatusOK {
		t.Fatalf("/readyz = %d %s", code, body)
	}
	code, jwks := get("/.well-known/pantherclaw/jwks.json")
	// Receipts, permits, workload tokens and action tokens (M6); never the
	// gateway CA, checkpoint or access-token keys, never private parts.
	if code != http.StatusOK || strings.Count(jwks, `"kid"`) != 4 || strings.Contains(jwks, `"d"`) || strings.Contains(jwks, "gateway-ca-") {
		t.Fatalf("JWKS = %d %s", code, jwks)
	}
	client := pantherclawv1connect.NewSystemServiceClient(connect.NewClient(connecthttp.NewTransport(hc, base)))
	res, err := client.GetBuildInfo(context.Background(), &pantherclawv1.GetBuildInfoRequest{ClientRequestId: "it-1"})
	if err != nil || res.GetClientRequestId() != "it-1" || res.GetVersion() == "" {
		t.Fatalf("GetBuildInfo = %v, %v", res, err)
	}
	if code, _ := get("/nope"); code != http.StatusNotFound {
		t.Fatalf("unknown path = %d", code)
	}

	// Workers chain the key-creation audit entries written at start-up.
	p := d.AppPool(t)
	deadline := time.Now().Add(30 * time.Second)
	for {
		var n int
		err := p.InTenantTx(context.Background(), ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, "SELECT count(*) FROM pc.ledger_chain").Scan(&n)
		})
		if err != nil {
			t.Fatal(err)
		}
		if n >= len(keys.Purposes()) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("workers chained %d entries within 30s, want ≥ %d", n, len(keys.Purposes()))
		}
		time.Sleep(100 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve returned %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("graceful shutdown did not finish")
	}
}

func TestIntMigrateStatus(t *testing.T) {
	d := dbtest.New(t)
	cfgPath := testConfig(t, d, RoleAPI)
	var out, errb bytes.Buffer
	if code := Run(context.Background(), []string{"migrate", "status", "--config", cfgPath}, &out, &errb, noEnv); code != 0 {
		t.Fatalf("migrate status: %d %s", code, errb.String())
	}
	v, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(out.String(), "schema version ")))
	if err != nil || v < 13 {
		t.Fatalf("schema version output %q", out.String())
	}
	out.Reset()
	if code := Run(context.Background(), []string{"migrate", "up", "--config", cfgPath}, &out, &errb, noEnv); code != 0 {
		t.Fatalf("migrate up (no-op): %d %s", code, errb.String())
	}
	if !strings.Contains(out.String(), fmt.Sprintf("schema version %d", v)) {
		t.Fatalf("migrate up output %q", out.String())
	}
}
