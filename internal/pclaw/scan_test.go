// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

type recordScan struct {
	pantherclawv1connect.UnimplementedAgentServiceHandler
	req *pantherclawv1.SubmitScanFindingsRequest
}

func (r *recordScan) SubmitScanFindings(_ context.Context, req *pantherclawv1.SubmitScanFindingsRequest) (*pantherclawv1.SubmitScanFindingsResponse, error) {
	r.req = req
	return &pantherclawv1.SubmitScanFindingsResponse{Created: int32(len(req.GetFindings()))}, nil
}

// TestF015_ScanStaysLocalUnlessSubmitted: the scan prints its findings;
// --submit sends MCP servers and agent projects, never credentials.
func TestF015_ScanStaysLocalUnlessSubmitted(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		".mcp.json":    `{"mcpServers": {"tickets": {"command": "python", "env": {"OPENAI_API_KEY": "sk-proj-LEAKCHECK0000"}}}}`,
		"package.json": `{"dependencies": {"@openai/agents": "1"}}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rec := &recordScan{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterAgentServiceHandler(cs, rec)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})

	code, out, errs := run(t, env, "scan", "--path", dir, "--no-user-config", "--no-env")
	if code != 0 || !strings.Contains(out, "MCP servers: 1") || !strings.Contains(out, "openai-agents") ||
		!strings.Contains(out, "Credentials (redacted): 1") || strings.Contains(out, "LEAKCHECK") || rec.req != nil {
		t.Fatalf("scan = %d %q %q", code, out, errs)
	}
	code, out, errs = run(t, env, "scan", "--path", dir, "--no-user-config", "--no-env", "--submit")
	if code != 0 || !strings.Contains(out, "2 new discovered agents") || len(rec.req.GetFindings()) != 2 {
		t.Fatalf("scan --submit = %d %q %q, request %v", code, out, errs, rec.req)
	}
	for _, f := range rec.req.GetFindings() {
		if f.GetKind() == "env_secret" || f.GetAttributes()["host"] != "" {
			t.Errorf("submitted %v", f)
		}
	}
}

// TestScanCIMode: --scope and --complete go with --submit; a complete scan
// names its scope and is one submission of at most 200 findings (D115,
// D130), so the CLI refuses a larger one and sends nothing.
// Covers: PN-001.3
func TestScanCIMode(t *testing.T) {
	small, large := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(small, ".mcp.json"), []byte(`{"mcpServers": {"tickets": {"command": "python"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var servers []string
	for i := range 201 {
		servers = append(servers, fmt.Sprintf(`"s%d": {"command": "python"}`, i))
	}
	if err := os.WriteFile(filepath.Join(large, ".mcp.json"), []byte(`{"mcpServers": {`+strings.Join(servers, ",")+`}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := &recordScan{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterAgentServiceHandler(cs, rec)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})
	base := []string{"scan", "--no-user-config", "--no-env"}

	for _, args := range [][]string{
		{"--path", small, "--scope", "org/repo"},                    // scope without --submit
		{"--path", small, "--complete", "--submit"},                 // complete without scope
		{"--path", large, "--submit", "--scope", "x", "--complete"}, // over 200
	} {
		if code, _, _ := run(t, env, append(slices.Clone(base), args...)...); code == 0 || rec.req != nil {
			t.Fatalf("scan %v = %d, request %v", args, code, rec.req)
		}
	}
	if _, _, errs := run(t, env, append(slices.Clone(base), "--path", large, "--submit", "--scope", "x", "--complete")...); !strings.Contains(errs,
		"complete scans are limited to 200 findings per scope; narrow --scope") {
		t.Errorf("over-200 complete scan: %q", errs)
	}
	code, out, errs := run(t, env, append(slices.Clone(base), "--path", small, "--submit", "--scope", "org/repo", "--complete")...)
	if code != 0 || rec.req.GetScope() != "org/repo" || !rec.req.GetComplete() || !strings.Contains(out, "complete scan of org/repo") {
		t.Fatalf("complete scan = %d %q %q, request %v", code, out, errs, rec.req)
	}
}
