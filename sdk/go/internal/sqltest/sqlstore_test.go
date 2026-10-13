// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// Package sqltest runs the verifier's SQL replay store against a real
// PostgreSQL, the test cluster of `task up PROFILE=test`. It is its own
// module, so the SDK itself keeps no driver dependency.
package sqltest_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json/jsontext"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/katocxl/pantherclaw/sdk/go/internal/vectors"
	"github.com/katocxl/pantherclaw/sdk/go/pap"
	"github.com/katocxl/pantherclaw/sdk/go/verifier"
)

// open returns a pool on a fresh schema of the test cluster
// (PC_TEST_PG_ADMIN_URL) holding the store's table, dropped afterwards.
// Without the cluster the test is skipped, unless PC_TEST_REQUIRE_DB is
// set.
func open(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("PC_TEST_PG_ADMIN_URL")
	if dsn == "" {
		if os.Getenv("PC_TEST_REQUIRE_DB") != "" {
			t.Fatal("PC_TEST_PG_ADMIN_URL is required")
		}
		t.Skip("no test cluster: set PC_TEST_PG_ADMIN_URL (task up PROFILE=test)")
	}
	var b [6]byte
	_, _ = rand.Read(b[:])
	schema := "pc_sdk_replay_" + hex.EncodeToString(b[:])
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(context.Background(), "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close()
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(context.Background(), verifier.Schema); err != nil {
		t.Fatal(err)
	}
	return db
}

func store(t *testing.T, db *sql.DB) *verifier.SQLStore {
	t.Helper()
	s, err := verifier.NewSQLStore(db, verifier.PostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestT081_ReplicasOnOnePostgreSQLStoreSpendATokenOnce: two replicas of a
// target, each with its own middleware on the shared table, run a token
// once: the second presentation is a 409 replay.
func TestT081_ReplicasOnOnePostgreSQLStoreSpendATokenOnce(t *testing.T) {
	db := open(t)
	var f struct {
		JWKS  jsontext.Value `json:"jwks"`
		Cases []struct {
			Token      string `json:"token"`
			Body       string `json:"body"`
			Operation  string `json:"operation"`
			TargetType string `json:"target_type"`
			TargetID   string `json:"target_id"`
			Issuer     string `json:"issuer"`
			Audience   string `json:"audience"`
			Now        int64  `json:"now"`
		} `json:"cases"`
	}
	vectors.Load(t, "action_tokens.json", &f)
	c := f.Cases[0]
	keys := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(f.JWKS) }))
	t.Cleanup(keys.Close)
	var ran atomic.Int32
	replica := func() http.Handler {
		v, err := verifier.New(verifier.Config{
			JWKSURL: keys.URL, Issuer: c.Issuer, Audience: c.Audience, Store: store(t, db), Now: func() time.Time { return time.Unix(c.Now, 0) },
		})
		if err != nil {
			t.Fatal(err)
		}
		match := func(_ *http.Request, cl verifier.Claims) bool {
			return cl.PAP.Op == c.Operation && cl.PAP.Target.Type == c.TargetType && cl.PAP.Target.ID == c.TargetID
		}
		return v.Middleware(match, 0, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			ran.Add(1)
			w.WriteHeader(http.StatusCreated)
		}))
	}
	post := func(h http.Handler) int {
		r := httptest.NewRequest(http.MethodPost, "/v1/refunds", strings.NewReader(c.Body))
		r.Header.Set(pap.HeaderAction, c.Token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	a, b := replica(), replica()
	if s := post(a); s != http.StatusCreated {
		t.Fatalf("the first replica: HTTP %d", s)
	}
	if s := post(b); s != http.StatusConflict || ran.Load() != 1 {
		t.Fatalf("the second replica: HTTP %d, handler ran %d times", s, ran.Load())
	}
}

// TestHR202_PostgreSQLSpendsEachAudienceAndIDOnce: of concurrent inserts
// of one (aud, jti), exactly one is first; another audience's jti is its
// own.
func TestHR202_PostgreSQLSpendsEachAudienceAndIDOnce(t *testing.T) {
	s := store(t, open(t))
	until := time.Now().Add(time.Minute)
	var first atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			ok, err := s.Use(context.Background(), verifier.Spend{Audience: "connection-a", ID: "jti-1", Until: until})
			if err != nil {
				t.Error(err)
			}
			if ok {
				first.Add(1)
			}
		})
	}
	wg.Wait()
	if first.Load() != 1 {
		t.Fatalf("%d first uses", first.Load())
	}
	if ok, err := s.Use(context.Background(), verifier.Spend{Audience: "connection-b", ID: "jti-1", Until: until}); !ok || err != nil {
		t.Fatalf("another audience: %v %v", ok, err)
	}
}

// TestHR202_PostgreSQLPurgeKeepsRowsThroughTheGrace: a row stays until its
// keeping time is PurgeGrace behind the purging clock.
func TestHR202_PostgreSQLPurgeKeepsRowsThroughTheGrace(t *testing.T) {
	s := store(t, open(t))
	until := time.Unix(1_791_201_665, 0)
	if ok, err := s.Use(context.Background(), verifier.Spend{Audience: "a", ID: "jti", Until: until}); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if n, err := s.Purge(context.Background(), until.Add(verifier.PurgeGrace)); n != 0 || err != nil {
		t.Fatalf("purged %d at the grace's end: %v", n, err)
	}
	if n, err := s.Purge(context.Background(), until.Add(verifier.PurgeGrace+time.Second)); n != 1 || err != nil {
		t.Fatalf("purged %d after the grace: %v", n, err)
	}
}
