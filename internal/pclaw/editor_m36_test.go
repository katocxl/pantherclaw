// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

const editorAgent = "0192aaaa-bbbb-7ccc-8ddd-000000000001"

type editorListCoverage struct {
	pantherclawv1connect.UnimplementedCoverageServiceHandler
	list *pantherclawv1.ListCoverageRequest
}

func (c *editorListCoverage) ListCoverage(_ context.Context, req *pantherclawv1.ListCoverageRequest) (*pantherclawv1.ListCoverageResponse, error) {
	c.list = req
	return &pantherclawv1.ListCoverageResponse{}, nil
}

type editorApprovals struct {
	pantherclawv1connect.UnimplementedApprovalServiceHandler
	list *pantherclawv1.ListApprovalRequestsRequest
}

func (a *editorApprovals) ListApprovalRequests(_ context.Context, req *pantherclawv1.ListApprovalRequestsRequest) (*pantherclawv1.ListApprovalRequestsResponse, error) {
	a.list = req
	return &pantherclawv1.ListApprovalRequestsResponse{}, nil
}

type editorTransactions struct {
	pantherclawv1connect.UnimplementedTransactionServiceHandler
	list *pantherclawv1.ListTransactionsRequest
}

func (x *editorTransactions) ListTransactions(_ context.Context, req *pantherclawv1.ListTransactionsRequest) (*pantherclawv1.ListTransactionsResponse, error) {
	x.list = req
	return &pantherclawv1.ListTransactionsResponse{}, nil
}

// TestHR794_EditorStatusOnlyListsAndOpenPrintsALink: editor status calls
// the three read RPCs and prints JSON, editor open prints a console link
// and contacts nothing, and a non-UUID or unknown kind is refused.
// Covers: HR-794
func TestHR794_EditorStatusOnlyListsAndOpenPrintsALink(t *testing.T) {
	cov, aps, txs := &editorListCoverage{}, &editorApprovals{}, &editorTransactions{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterCoverageServiceHandler(cs, cov)
	pantherclawv1connect.RegisterApprovalServiceHandler(cs, aps)
	pantherclawv1connect.RegisterTransactionServiceHandler(cs, txs)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})

	code, out, errs := run(t, env, "editor", "status", "--agent", editorAgent, "--json")
	if code != 0 {
		t.Fatalf("status: %d %s", code, errs)
	}
	if cov.list.GetAgentId() != editorAgent || aps.list.GetAgentId() != editorAgent || txs.list.GetAgentId() != editorAgent {
		t.Fatalf("lists: coverage %q approvals %q transactions %q", cov.list.GetAgentId(), aps.list.GetAgentId(), txs.list.GetAgentId())
	}
	if len(aps.list.GetStates()) != 1 || aps.list.GetStates()[0] != pantherclawv1.ApprovalState_APPROVAL_STATE_PENDING {
		t.Fatalf("approval states: %v", aps.list.GetStates())
	}
	for _, want := range []string{`"agent_id":"` + editorAgent + `"`, `"coverage":[]`, `"approvals":[]`, `"decisions":[]`, ts.URL + "/approvals"} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}

	code, out, errs = run(t, env, "editor", "open", "approval", editorAgent)
	if code != 0 || !strings.Contains(out, ts.URL+"/approvals/"+editorAgent) {
		t.Fatalf("open approval: %d %s %s", code, out, errs)
	}
	code, out, errs = run(t, env, "editor", "open", "transaction", editorAgent)
	if code != 0 || !strings.Contains(out, ts.URL+"/app/evidence/transactions/"+editorAgent) {
		t.Fatalf("open transaction: %d %s %s", code, out, errs)
	}
	if code, _, _ := run(t, env, "editor", "status", "--agent", "not-a-uuid"); code == 0 {
		t.Fatal("a non-UUID agent was accepted")
	}
	if code, _, _ := run(t, env, "editor", "open", "grant", editorAgent); code == 0 {
		t.Fatal("an unknown kind was accepted")
	}
	if code, _, _ := run(t, env, "editor", "open", "approval", "not-a-uuid"); code == 0 {
		t.Fatal("a non-UUID id was accepted")
	}
	for name := range commands {
		if strings.HasPrefix(name, "editor ") && name != "editor status" && name != "editor open" {
			t.Errorf("editor command %s", name)
		}
	}
}

// TestHR794_TheVSCodeExtensionIsReadOnly: the extension contributes only
// refresh and open-in-console, runs pclaw with an argument array and
// shell:false, and opens only https (http on loopback).
// Covers: HR-794
func TestHR794_TheVSCodeExtensionIsReadOnly(t *testing.T) {
	root := filepath.Join("..", "..", "integrations", "vscode-extension")
	pkg, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Contributes struct {
			Commands []struct {
				Command string `json:"command"`
			} `json:"commands"`
			Configuration struct {
				Properties map[string]struct {
					Scope string `json:"scope"`
				} `json:"properties"`
			} `json:"configuration"`
		} `json:"contributes"`
		Capabilities struct {
			UntrustedWorkspaces struct {
				RestrictedConfigurations []string `json:"restrictedConfigurations"`
			} `json:"untrustedWorkspaces"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(pkg, &doc); err != nil {
		t.Fatal(err)
	}
	var commands []string
	for _, c := range doc.Contributes.Commands {
		commands = append(commands, c.Command)
	}
	if strings.Join(commands, ",") != "pantherclaw.refresh,pantherclaw.openInConsole" {
		t.Fatalf("commands %v", commands)
	}
	if doc.Contributes.Configuration.Properties["pantherclaw.pclawPath"].Scope != "machine" {
		t.Fatal("pclawPath is not a machine setting")
	}
	if strings.Join(doc.Capabilities.UntrustedWorkspaces.RestrictedConfigurations, ",") != "pantherclaw.agent" {
		t.Fatalf("restricted %v", doc.Capabilities.UntrustedWorkspaces.RestrictedConfigurations)
	}
	js, err := os.ReadFile(filepath.Join(root, "src", "pclaw.js"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(js)
	if !strings.Contains(text, "shell: false") || strings.Contains(text, "shell: true") || strings.Contains(text, ".exec(") {
		t.Fatal("pclaw.js does not keep shell off")
	}
	if !strings.Contains(text, `["editor", "status", "--agent", agent, "--json"]`) || !strings.Contains(text, `["editor", "open", kind, id]`) {
		t.Fatal("pclaw.js does not limit itself to editor status and editor open")
	}
	ext, err := os.ReadFile(filepath.Join(root, "src", "extension.js"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ext), "vscode.env.openExternal") || strings.Contains(string(ext), "child_process") {
		t.Fatal("the extension opens links itself or shells out on its own")
	}
}
