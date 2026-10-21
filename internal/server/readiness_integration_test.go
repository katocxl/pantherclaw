// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

func readyz(t *testing.T, h http.Handler) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil))
	return rec.Code, strings.TrimSpace(rec.Body.String())
}

// TestHR370_ReadyzRequiresDBSchemaAndWorkers: /readyz is 200 only when the
// database answers, the recorded schema is the binary's and (role all) the
// workers beat; the body is the fixed JSON of check words, never a version
// or an error.
func TestHR370_ReadyzRequiresDBSchemaAndWorkers(t *testing.T) {
	d := dbtest.New(t)
	pool := d.AppPool(t)
	latest, err := db.LatestMigration()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	beat := &workerHeartbeat{now: func() time.Time { return now }}
	beat.beat()
	rd := readiness{pool: pool, workers: beat, log: pclog.Discard()}
	noDigits := regexp.MustCompile(`[0-9]`)
	check := func(name string, h http.Handler, wantCode int, want string) {
		t.Helper()
		code, body := readyz(t, h)
		if code != wantCode || body != want {
			t.Errorf("%s: /readyz = %d %s, want %d %s", name, code, body, wantCode, want)
		}
		if noDigits.MatchString(body) {
			t.Errorf("%s: body carries a number: %s", name, body)
		}
	}
	check("ready", rd, http.StatusOK, `{"ready":true,"checks":{"db":"ok","schema":"ok","workers":"ok","hold":"ok"}}`)
	check("api role", readiness{pool: pool, log: pclog.Discard()}, http.StatusOK,
		`{"ready":true,"checks":{"db":"ok","schema":"ok","workers":"skip","hold":"ok"}}`)

	// Workers that stopped beating more than 30 s ago.
	now = now.Add(workerHeartbeatMaxAge + time.Second)
	check("stale workers", rd, http.StatusServiceUnavailable, `{"ready":false,"checks":{"db":"ok","schema":"ok","workers":"fail","hold":"ok"}}`)
	beat.beat()
	unstarted := readiness{pool: pool, workers: &workerHeartbeat{now: time.Now}, log: pclog.Discard()}
	check("workers not started", unstarted, http.StatusServiceUnavailable,
		`{"ready":false,"checks":{"db":"ok","schema":"ok","workers":"fail","hold":"ok"}}`)

	for name, v := range map[string]int64{"newer schema": latest + 1, "pending schema": latest - 1} {
		d.AdminExec(t, "UPDATE pc.schema_info SET version = $1", v)
		check(name, rd, http.StatusServiceUnavailable, `{"ready":false,"checks":{"db":"ok","schema":"fail","workers":"ok","hold":"ok"}}`)
	}
	d.AdminExec(t, "DELETE FROM pc.schema_info")
	check("no schema row", rd, http.StatusServiceUnavailable, `{"ready":false,"checks":{"db":"ok","schema":"fail","workers":"ok","hold":"ok"}}`)

	// A database migrated before 00180 has no pc.schema_info (D24).
	d.AdminExec(t, "DROP TABLE pc.schema_info")
	check("no schema table", rd, http.StatusServiceUnavailable, `{"ready":false,"checks":{"db":"ok","schema":"fail","workers":"ok","hold":"ok"}}`)
	for dep, want := range map[string]error{"": nil, "staging": errSchemaPending, "production": errSchemaPending} {
		if err := checkSchemaAtStart(context.Background(), &Config{Deployment: dep}, pool, pclog.Discard()); !errors.Is(err, want) {
			t.Errorf("no schema table, deployment %q: start = %v, want %v", dep, err, want)
		}
	}

	down := d.Pool(t, d.App)
	down.Close()
	check("database down", readiness{pool: down, log: pclog.Discard()}, http.StatusServiceUnavailable,
		`{"ready":false,"checks":{"db":"fail","schema":"fail","workers":"skip","hold":"ok"}}`)
}

// TestHR370_ServeRefusesNewerSchemaAndPendingOutsideDevelopment: serve
// stops with SCHEMA_NEWER before it listens; a pending schema stops it
// with SCHEMA_PENDING outside development and only warns in development.
func TestHR370_ServeRefusesNewerSchemaAndPendingOutsideDevelopment(t *testing.T) {
	d := dbtest.New(t)
	latest, err := db.LatestMigration()
	if err != nil {
		t.Fatal(err)
	}
	d.AdminExec(t, "UPDATE pc.schema_info SET version = $1", latest+1)
	cfgPath := testConfig(t, d, RoleAll)
	var logs bytes.Buffer
	err = cmdServe(context.Background(), []string{"--config", cfgPath}, &logs, noEnv, func(string) {
		t.Error("serve listened on a newer schema")
	})
	if !errors.Is(err, errSchemaNewer) {
		t.Fatalf("serve on a newer schema = %v, want SCHEMA_NEWER", err)
	}

	pool := d.AppPool(t)
	d.AdminExec(t, "UPDATE pc.schema_info SET version = $1", latest-1)
	for _, dep := range []string{"staging", "production"} {
		if err := checkSchemaAtStart(context.Background(), &Config{Deployment: dep}, pool, pclog.Discard()); !errors.Is(err, errSchemaPending) {
			t.Errorf("%s with a pending schema = %v, want SCHEMA_PENDING", dep, err)
		}
	}
	var warn bytes.Buffer
	log := pclog.New(&warn, pclog.Options{Service: "test"})
	if err := checkSchemaAtStart(context.Background(), &Config{}, pool, log); err != nil {
		t.Errorf("development with a pending schema = %v, want a warning only", err)
	}
	if !strings.Contains(warn.String(), "server.schema_pending") {
		t.Errorf("no schema_pending warning: %s", warn.String())
	}
	d.AdminExec(t, "UPDATE pc.schema_info SET version = $1", latest)
	if err := checkSchemaAtStart(context.Background(), &Config{Deployment: "production"}, pool, pclog.Discard()); err != nil {
		t.Errorf("production with the current schema = %v", err)
	}
}
