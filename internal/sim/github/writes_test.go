// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package github

import (
	"encoding/base64"
	"net/http"
	"testing"
)

// TestContentsWritesAndTheWorkflowsRule: a file is created without a SHA
// and updated only with its current blob SHA, each as one commit on the
// branch; a write under .github/workflows/ needs the workflows permission,
// as on GitHub.
func TestContentsWritesAndTheWorkflowsRule(t *testing.T) {
	w := newWorld(t)
	_, tok := w.mint(`{"repositories":["payments"],"permissions":{"contents":"write"}}`)
	auth := "Bearer " + tok
	put := func(path, body string) (int, map[string]any) {
		return w.do(http.MethodPut, "/repos/acme/payments/contents/"+path, auth, body)
	}
	content := base64.StdEncoding.EncodeToString([]byte("package parser // v2\n"))
	status, out := put("src/parser.go", `{"message":"Add","content":"`+content+`","branch":"fix/a"}`)
	if status != http.StatusCreated {
		t.Fatalf("create: %d %v", status, out)
	}
	blob := out["content"].(map[string]any)["sha"].(string)
	if status, _ := put("src/parser.go", `{"message":"Again","content":"`+content+`","branch":"fix/a"}`); status != http.StatusUnprocessableEntity {
		t.Fatalf("update without a SHA: %d", status)
	}
	if status, _ := put("src/parser.go", `{"message":"Stale","content":"`+content+`","branch":"fix/a","sha":"`+blobSHA("other")+`"}`); status != http.StatusConflict {
		t.Fatalf("update with another SHA: %d", status)
	}
	if status, _ := put("src/parser.go", `{"message":"Update","content":"`+content+`","branch":"fix/a","sha":"`+blob+`"}`); status != http.StatusOK {
		t.Fatalf("update: %d", status)
	}
	if got := w.sim.Files("acme/payments", w.sim.Branch("acme/payments", "fix/a"))["src/parser.go"]; got != "package parser // v2\n" {
		t.Fatalf("file %q", got)
	}
	if status, out := put(".github/workflows/x.yml", `{"message":"Sneak","content":"`+content+`","branch":"fix/a"}`); status != http.StatusForbidden {
		t.Fatalf("a workflow without the permission: %d %v", status, out)
	}
	w.sim.AddToken("ghp_admin", "admin", []string{"acme/payments"}, map[string]string{"contents": "write", "workflows": "write"})
	if status, _ := w.do(http.MethodPut, "/repos/acme/payments/contents/.github/workflows/x.yml", "token ghp_admin",
		`{"message":"Add","content":"`+content+`","branch":"fix/a"}`); status != http.StatusCreated {
		t.Fatalf("a workflow with the permission: %d", status)
	}
}

// TestInstallationEndpoints: the App reads its installation (account,
// permissions, selection), and an installation token lists the
// repositories it reaches, the connection test's read.
func TestInstallationEndpoints(t *testing.T) {
	w := newWorld(t)
	status, out := w.do(http.MethodGet, "/app/installations/7", "Bearer "+w.jwt(), "")
	perms, _ := out["permissions"].(map[string]any)
	if status != http.StatusOK || out["account"].(map[string]any)["login"] != "acme" || perms["contents"] != "write" {
		t.Fatalf("installation: %d %v", status, out)
	}
	if status, _ := w.do(http.MethodGet, "/app/installations/8", "Bearer "+w.jwt(), ""); status != http.StatusNotFound {
		t.Fatalf("another installation: %d", status)
	}
	_, tok := w.mint(`{"repositories":["payments"],"permissions":{"metadata":"read"}}`)
	status, out = w.do(http.MethodGet, "/installation/repositories", "Bearer "+tok, "")
	if status != http.StatusOK || out["total_count"] != float64(1) {
		t.Fatalf("repositories: %d %v", status, out)
	}
	w.sim.AddToken("ghp_x", "x", []string{"acme/payments"}, map[string]string{"contents": "read"})
	if status, _ := w.do(http.MethodGet, "/installation/repositories", "token ghp_x", ""); status != http.StatusForbidden {
		t.Fatalf("a personal token: %d", status)
	}
}
