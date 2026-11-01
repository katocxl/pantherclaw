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
	"regexp"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

const catalogServer = "0192aaaa-bbbb-7ccc-8ddd-000000000001"

// registryName is the pattern of a name in the registry's server.json schema.
var registryName = regexp.MustCompile(`^[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+$`)

func TestF878_ARegistryTextStopsAtItsLimit(t *testing.T) {
	if got := clip(strings.Repeat("é", 101)); len([]rune(got)) != 100 {
		t.Fatalf("clipped to %d", len([]rune(got)))
	}
}

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
	}, {
		Name: "both", Title: "Both", UrlHost: "both.example.test", PackageRef: "@acme/both",
	}, {
		Name: "dotted.name", Title: "Dotted", UrlHost: "dotted.example.test",
	}, {
		Name: "wild", Title: "Wild", UrlHost: "*.example.test",
	}, {
		Name: "creds", Title: "Creds", UrlHost: "user:pw@example.test",
	}, {
		Name: "query", Title: "Query", UrlHost: "example.test", UrlPathPrefix: "/x?y=1",
	}, {
		Name: "unknown", Title: "Unknown", PackageRef: "acme/thing",
	}, {
		Name: "image", Title: "Image", PackageRef: "ghcr.io/acme/mcp:1.0",
	}, {
		Name: "private", Title: "Private", UrlHost: "http://10.0.0.5:8080",
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
	code, _, warned := run(t, env, "mcp", "catalog", "export", "--format", "managed-allow", "--out", out)
	if code != 0 {
		t.Fatalf("export = %d %q", code, warned)
	}
	if len(rc.list) != 2 || rc.list[0].GetStatuses()[0] != pb.McpServerStatus_MCP_SERVER_STATUS_APPROVED {
		t.Fatalf("export read %v", rc.list)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	// The rules of the allow file's reader, readAllowFile in S23b's
	// managedsettings.go: no other member, a name it takes, and exactly one of
	// an exact URL and a command. The catalog records no launch command, so
	// no entry claims one: a package reference is not what runs (D268).
	var allow struct {
		Servers []struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(raw, &allow, json.RejectUnknownMembers(true)); err != nil {
		t.Fatalf("%v in %s", err, raw)
	}
	names := []string{}
	for _, s := range allow.Servers {
		names = append(names, s.Name)
		if !allowName.MatchString(s.Name) || !exactURL(s.URL) {
			t.Fatalf("the reader would refuse %+v", s)
		}
	}
	// The kit itself reads the file, through its own reader and generator
	// (D138 with M23).
	if got, err := readAllowFile(out); err != nil || len(got) != len(allow.Servers) {
		t.Fatalf("the kit read %v: %v", got, err)
	}
	if code, stdout, errs := run(t, env, "managed-settings", "generate", "--client", "copilot", "--allow-file", out); code != 0 || !strings.Contains(stdout, "serverUrl") {
		t.Fatalf("generate = %d %q %q", code, stdout, errs)
	}
	if got := strings.Join(names, ","); got != "payments,both,private" {
		t.Fatalf("allow file %s", raw)
	}
	if allow.Servers[1].URL != "https://both.example.test" || allow.Servers[2].URL != "http://10.0.0.5:8080" {
		t.Fatalf("allow file %s", raw)
	}
	for _, name := range []string{"github", "local", "dotted.name", "wild", "creds", "query", "unknown", "image"} {
		if !strings.Contains(warned, "left out "+name+":") {
			t.Fatalf("%s was not listed: %q", name, warned)
		}
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
	// A bare digest and a package of unknown type stay out, each on stderr, so
	// the file claims nothing the schema cannot say (D268).
	if len(reg.Servers) != 9 || reg.Metadata.Count != 9 || reg.Servers[0].Server.Remotes[0].URL != "https://mcp.example.test/v1" ||
		reg.Servers[1].Server.Packages[0].RegistryType != "npm" || reg.Servers[7].Server.Packages[0].RegistryType != "oci" ||
		reg.Servers[0].Server.Version == "" || !strings.Contains(stdout, "http://10.0.0.5:8080") {
		t.Fatalf("registry file %s", stdout)
	}
	for _, s := range reg.Servers {
		if strings.HasSuffix(s.Server.Name, "/local") || strings.HasSuffix(s.Server.Name, "/unknown") {
			t.Fatalf("registry file %s", stdout)
		}
	}
	for _, want := range []string{"left out local: a bare digest", "left out unknown: the registry type"} {
		if !strings.Contains(errs, want) {
			t.Fatalf("%q was not listed: %q", want, errs)
		}
	}
	for _, s := range reg.Servers {
		if !registryName.MatchString(s.Server.Name) {
			t.Fatalf("name %q is not the registry's namespace/name", s.Server.Name)
		}
	}
	if code, _, _ := run(t, env, "mcp", "catalog", "export", "--format", "yaml"); code == 0 {
		t.Fatal("an unknown format was written")
	}
}
