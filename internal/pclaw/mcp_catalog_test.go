// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

const catalogServer = "0192aaaa-bbbb-7ccc-8ddd-000000000001"

type recordCatalog struct {
	pantherclawv1connect.UnimplementedMcpCatalogServiceHandler
	propose *pb.ProposeServerRequest
	approve *pb.ApproveServerRequest
	deny    *pb.DenyServerRequest
	list    []*pb.ListServersRequest
	preview *pb.PreviewCatalogModeRequest
	mode    *pb.SetCatalogModeRequest
	review  *pb.PreviewServerRevokeRequest
	revoke  *pb.RevokeServerRequest
	got     bool
}

func (r *recordCatalog) ProposeServer(_ context.Context, q *pb.ProposeServerRequest) (*pb.ProposeServerResponse, error) {
	r.propose = q
	return &pb.ProposeServerResponse{}, nil
}

func (r *recordCatalog) ApproveServer(_ context.Context, q *pb.ApproveServerRequest) (*pb.ApproveServerResponse, error) {
	r.approve = q
	return &pb.ApproveServerResponse{}, nil
}

func (r *recordCatalog) DenyServer(_ context.Context, q *pb.DenyServerRequest) (*pb.DenyServerResponse, error) {
	r.deny = q
	return &pb.DenyServerResponse{}, nil
}

// ListServers answers two pages, so export has to follow the token.
func (r *recordCatalog) ListServers(_ context.Context, q *pb.ListServersRequest) (*pb.ListServersResponse, error) {
	r.list = append(r.list, q)
	if q.GetPageToken() == "" {
		return &pb.ListServersResponse{NextPageToken: "more", Servers: []*pb.McpServer{{
			Name: "payments", Title: "Payments", UrlHost: "mcp.example.test", UrlPathPrefix: "/v1",
		}}}, nil
	}
	return &pb.ListServersResponse{Servers: []*pb.McpServer{{
		Name: "github", Title: "GitHub", PackageRef: "@modelcontextprotocol/server-github",
	}, {
		Name: "local", Title: "Local", ImageDigest: "sha256:abc",
	}}}, nil
}

func (r *recordCatalog) GetCatalogSettings(context.Context, *pb.GetCatalogSettingsRequest) (*pb.GetCatalogSettingsResponse, error) {
	r.got = true
	return &pb.GetCatalogSettingsResponse{}, nil
}

func (r *recordCatalog) PreviewCatalogMode(_ context.Context, q *pb.PreviewCatalogModeRequest) (*pb.PreviewCatalogModeResponse, error) {
	r.preview = q
	return &pb.PreviewCatalogModeResponse{}, nil
}

func (r *recordCatalog) SetCatalogMode(_ context.Context, q *pb.SetCatalogModeRequest) (*pb.SetCatalogModeResponse, error) {
	r.mode = q
	return nil, stepUpRequired()
}

func (r *recordCatalog) PreviewServerRevoke(_ context.Context, q *pb.PreviewServerRevokeRequest) (*pb.PreviewServerRevokeResponse, error) {
	r.review = q
	return &pb.PreviewServerRevokeResponse{}, nil
}

func (r *recordCatalog) RevokeServer(_ context.Context, q *pb.RevokeServerRequest) (*pb.RevokeServerResponse, error) {
	r.revoke = q
	return &pb.RevokeServerResponse{}, nil
}

func stepUpRequired() error {
	return connect.NewError(connect.CodePermissionDenied, "STEP_UP_REQUIRED")
}

func catalogEnv(t *testing.T) (*recordCatalog, Env) {
	t.Helper()
	rc := &recordCatalog{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterMcpCatalogServiceHandler(cs, rc)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return rc, envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})
}

// Covers: F878
func TestF878_CatalogCommandsSendWhatTheySay(t *testing.T) {
	rc, env := catalogEnv(t)
	if code, _, errs := run(t, env, "mcp", "catalog", "propose", "payments", "--title", "Payments", "--transport", "http",
		"--url-host", "mcp.example.test", "--url-path-prefix", "/v1", "--notes", "why"); code != 0 ||
		rc.propose.GetName() != "payments" || rc.propose.GetTransport() != pb.McpServerTransport_MCP_SERVER_TRANSPORT_HTTP ||
		rc.propose.GetUrlHost() != "mcp.example.test" || rc.propose.GetUrlPathPrefix() != "/v1" {
		t.Fatalf("propose = %d %q, request %v", code, errs, rc.propose)
	}
	if code, _, errs := run(t, env, "mcp", "catalog", "propose", "x", "--transport", "ftp"); code == 0 || !strings.Contains(errs, "--transport") {
		t.Fatalf("bad transport = %d %q", code, errs)
	}
	if code, _, _ := run(t, env, "mcp", "catalog", "approve", catalogServer); code != 0 || rc.approve.GetId() != catalogServer {
		t.Fatalf("approve = %d, request %v", code, rc.approve)
	}
	if code, _, _ := run(t, env, "mcp", "catalog", "deny", catalogServer); code != 0 || rc.deny.GetId() != catalogServer {
		t.Fatalf("deny = %d, request %v", code, rc.deny)
	}
	if code, _, _ := run(t, env, "mcp", "catalog", "list", "--status", "approved"); code != 0 ||
		rc.list[0].GetStatuses()[0] != pb.McpServerStatus_MCP_SERVER_STATUS_APPROVED {
		t.Fatalf("list = %d, request %v", code, rc.list)
	}
	if code, _, _ := run(t, env, "mcp", "catalog", "mode", "show"); code != 0 || !rc.got {
		t.Fatalf("mode show = %d", code)
	}
	if code, _, _ := run(t, env, "mcp", "catalog", "mode", "enforce", "--preview"); code != 0 ||
		rc.preview.GetMode() != pb.McpCatalogMode_MCP_CATALOG_MODE_ENFORCE || rc.mode != nil {
		t.Fatalf("mode preview = %d, request %v, set %v", code, rc.preview, rc.mode)
	}
	if code, _, _ := run(t, env, "mcp", "catalog", "mode", "observe"); code == 0 {
		t.Fatal("an unknown mode was sent")
	}
	if code, _, _ := run(t, env, "mcp", "catalog", "revoke", catalogServer, "--preview"); code != 0 ||
		rc.review.GetId() != catalogServer || rc.revoke != nil {
		t.Fatalf("revoke preview = %d, request %v, revoke %v", code, rc.review, rc.revoke)
	}
	digest := base64.StdEncoding.EncodeToString([]byte("digest"))
	if code, _, _ := run(t, env, "mcp", "catalog", "revoke", catalogServer, "--digest", digest, "--reason", "compromised"); code != 0 ||
		string(rc.revoke.GetPreviewDigest()) != "digest" || rc.revoke.GetReason() != "compromised" {
		t.Fatalf("revoke = %d, request %v", code, rc.revoke)
	}
}

// Covers: F878
func TestF878_ModeOverACLITokenSaysWhereToStepUp(t *testing.T) {
	rc, env := catalogEnv(t)
	code, _, errs := run(t, env, "mcp", "catalog", "mode", "watch", "--reason", "rollback")
	if code == 0 || rc.mode.GetMode() != pb.McpCatalogMode_MCP_CATALOG_MODE_WATCH || !strings.Contains(errs, "browser session") {
		t.Fatalf("mode = %d %q, request %v", code, errs, rc.mode)
	}
}

// Covers: F878
func TestF878_ExportWritesAStaticFileOfApprovedServers(t *testing.T) {
	rc, env := catalogEnv(t)
	out := filepath.Join(t.TempDir(), "allow.json")
	if code, _, errs := run(t, env, "mcp", "catalog", "export", "--format", "managed-allow", "--out", out); code != 0 {
		t.Fatalf("export = %d %q", code, errs)
	}
	if len(rc.list) != 2 || rc.list[0].GetStatuses()[0] != pb.McpServerStatus_MCP_SERVER_STATUS_APPROVED {
		t.Fatalf("export read %v", rc.list)
	}
	raw, err := os.ReadFile(out) //nolint:gosec // G304: the test's own temp file
	if err != nil {
		t.Fatal(err)
	}
	var allow struct {
		Servers []struct {
			Name    string `json:"name"`
			URL     string `json:"url"`
			Command string `json:"command"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(raw, &allow); err != nil {
		t.Fatal(err)
	}
	if len(allow.Servers) != 3 || allow.Servers[0].URL != "https://mcp.example.test/v1" ||
		allow.Servers[1].Command != "@modelcontextprotocol/server-github" {
		t.Fatalf("allow file %s", raw)
	}

	code, stdout, errs := run(t, env, "mcp", "catalog", "export", "--format", "registry-v0")
	if code != 0 {
		t.Fatalf("export = %d %q", code, errs)
	}
	var reg struct {
		Servers []struct {
			Server struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				Remotes []struct {
					URL string `json:"url"`
				} `json:"remotes"`
				Packages []struct {
					RegistryType string `json:"registryType"`
					Identifier   string `json:"identifier"`
				} `json:"packages"`
			} `json:"server"`
		} `json:"servers"`
		Metadata struct {
			Count int `json:"count"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal([]byte(stdout), &reg); err != nil {
		t.Fatal(err)
	}
	if len(reg.Servers) != 3 || reg.Metadata.Count != 3 || reg.Servers[0].Server.Remotes[0].URL != "https://mcp.example.test/v1" ||
		reg.Servers[1].Server.Packages[0].RegistryType != "npm" || reg.Servers[2].Server.Packages[0].RegistryType != "oci" ||
		reg.Servers[0].Server.Version == "" {
		t.Fatalf("registry file %s", stdout)
	}
	if code, _, _ := run(t, env, "mcp", "catalog", "export", "--format", "yaml"); code == 0 {
		t.Fatal("an unknown format was written")
	}
}
