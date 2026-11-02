// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

const selfCall = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_timeline","arguments":{"run_id":"0194f1a0-0000-7000-8000-000000000001"}}}`

// selfServer answers each read with an empty Connect JSON message and records
// the path and bearer of what reaches it.
func selfServer(t *testing.T) (*httptest.Server, func() ([]string, []string)) {
	t.Helper()
	var mu sync.Mutex
	var paths, bearers []string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		mu.Lock()
		paths, bearers = append(paths, r.URL.Path), append(bearers, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/proto")
	}))
	t.Cleanup(s.Close)
	return s, func() ([]string, []string) {
		mu.Lock()
		defer mu.Unlock()
		return paths, bearers
	}
}

func selfRun(t *testing.T, env map[string]string, stdin string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(context.Background(), []string{"mcp", "self"}, &out, &errb, envOf(env), Options{Stdin: strings.NewReader(stdin)})
	return code, out.String(), errb.String()
}

// TestF947_McpSelfServesStdioWithTheKeyFile: the key from the file reaches
// the server as the bearer, the read goes to its one procedure, and stdout
// carries one labeled answer.
// Covers: F947
func TestF947_McpSelfServesStdioWithTheKeyFile(t *testing.T) {
	s, seen := selfServer(t)
	keyFile := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyFile, []byte("pc_test_key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := selfRun(t, map[string]string{
		"PANTHERCLAW_API_KEY_FILE": keyFile, "PANTHERCLAW_SERVER": s.URL,
	}, selfCall+"\n")
	if code != 0 {
		t.Fatalf("mcp self = %d: %s", code, errs)
	}
	if strings.Count(out, "\n") != 1 || !strings.Contains(out, "UNTRUSTED_RECORD_DATA") {
		t.Errorf("stdout %q", out)
	}
	paths, bearers := seen()
	if len(paths) != 1 || paths[0] != pantherclawv1connect.InvestigationServiceGetRunTimelineProcedure {
		t.Errorf("paths %v", paths)
	}
	if len(bearers) != 1 || bearers[0] != "Bearer pc_test_key" {
		t.Errorf("bearers %v", bearers)
	}
}

// TestF947_McpSelfRefusesAPersonsLogin: a person's stored login, valid and
// pointing at a live server, is not used: without a service account key it
// stops before anything is read, on stderr, and stdout stays the protocol's.
// Covers: F947
func TestF947_McpSelfRefusesAPersonsLogin(t *testing.T) {
	s, seen := selfServer(t)
	dir := t.TempDir()
	login := Credentials{
		Server: s.URL, Org: "0194f1a0-0000-7000-8000-0000000000aa",
		AccessToken: "pc_person_access", AccessExpiry: time.Now().Add(time.Hour), RefreshToken: "pc_person_refresh",
	}
	if err := writeCredsFile(filepath.Join(dir, "credentials.json"), storedCreds{Credentials: login}); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"PANTHERCLAW_CONFIG_DIR": dir}
	if c, err := loadCreds(envOf(env)); err != nil || c.AccessToken != login.AccessToken {
		t.Fatalf("the stored login is not readable: %v", err)
	}
	for _, e := range []map[string]string{env, {"PANTHERCLAW_CONFIG_DIR": dir, "PANTHERCLAW_SERVER": s.URL}} {
		code, out, errs := selfRun(t, e, selfCall+"\n")
		if code == 0 || out != "" || !strings.Contains(errs, "service account key") {
			t.Errorf("code %d, stdout %q, stderr %q", code, out, errs)
		}
	}
	if paths, _ := seen(); len(paths) != 0 {
		t.Errorf("the stored login reached the server: %v", paths)
	}
}

// TestF947_McpSelfTakesNoArguments: nothing widens it from the command line.
// Covers: F947
func TestF947_McpSelfTakesNoArguments(t *testing.T) {
	var out, errb bytes.Buffer
	code := Run(context.Background(), []string{"mcp", "self", "--tool", "revoke_grant"}, &out, &errb,
		envOf(map[string]string{"PANTHERCLAW_API_KEY": "k", "PANTHERCLAW_SERVER": "https://pc.example.test"}), Options{})
	if code == 0 {
		t.Errorf("code 0, stdout %q", out.String())
	}
}
