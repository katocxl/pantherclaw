// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

type recordInventory struct {
	pantherclawv1connect.UnimplementedConnectionServiceHandler
	list    *pb.ListConnectionInventoryRequest
	dismiss *pb.DismissInventoryItemRequest
	draft   *pb.DraftPackageFromInventoryRequest
	items   []*pb.InventoryItem
}

func (r *recordInventory) ListConnectionInventory(_ context.Context, req *pb.ListConnectionInventoryRequest) (*pb.ListConnectionInventoryResponse, error) {
	r.list = req
	return &pb.ListConnectionInventoryResponse{Items: r.items}, nil
}

func (r *recordInventory) DismissInventoryItem(_ context.Context, req *pb.DismissInventoryItemRequest) (*pb.DismissInventoryItemResponse, error) {
	r.dismiss = req
	return &pb.DismissInventoryItemResponse{Item: &pb.InventoryItem{Id: req.GetId()}}, nil
}

func (r *recordInventory) DraftPackageFromInventory(_ context.Context, req *pb.DraftPackageFromInventoryRequest) (*pb.DraftPackageFromInventoryResponse, error) {
	r.draft = req
	return &pb.DraftPackageFromInventoryResponse{ManifestYaml: []byte("format: 1\n"), Todo: []string{"effects of draft.search"}}, nil
}

// TestInventoryCommands: pclaw reaches the three-word inventory commands,
// maps their flags, and package draft drafts every NEW item without
// --item, writing the draft to -o and what to fill in to stderr.
// Covers: F352
func TestInventoryCommands(t *testing.T) {
	r := &recordInventory{items: []*pb.InventoryItem{{Id: "i1"}, {Id: "i2"}}}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterConnectionServiceHandler(cs, r)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})

	if code, _, errs := run(t, env, "connection", "inventory", "list", "c1", "--state", "new", "--kind", "resource_template"); code != 0 ||
		r.list.GetConnectionId() != "c1" || !slices.Equal(r.list.GetStates(), []pb.InventoryItemState{pb.InventoryItemState_INVENTORY_ITEM_STATE_NEW}) ||
		!slices.Equal(r.list.GetKinds(), []pb.InventoryItemKind{pb.InventoryItemKind_INVENTORY_ITEM_KIND_RESOURCE_TEMPLATE}) {
		t.Fatalf("list = %d %q, sent %v", code, errs, r.list)
	}
	if code, _, errs := run(t, env, "connection", "inventory", "list", "c1", "--state", "gone"); code == 0 || !strings.Contains(errs, "--state") {
		t.Fatalf("unknown state = %d %q", code, errs)
	}
	if code, _, errs := run(t, env, "connection", "inventory", "dismiss", "i1", "--reason", "unused"); code != 0 ||
		r.dismiss.GetId() != "i1" || r.dismiss.GetReason() != "unused" {
		t.Fatalf("dismiss = %d %q, sent %v", code, errs, r.dismiss)
	}

	out := filepath.Join(t.TempDir(), "draft.yaml")
	code, _, errs := run(t, env, "package", "draft", "--connection", "c1", "-o", out)
	if code != 0 || !slices.Equal(r.draft.GetItemIds(), []string{"i1", "i2"}) || !strings.Contains(errs, "effects of draft.search") {
		t.Fatalf("draft = %d %q, sent %v", code, errs, r.draft)
	}
	if b, err := os.ReadFile(out); err != nil || string(b) != "format: 1\n" {
		t.Fatalf("draft file %q, %v", b, err)
	}
	if code, stdout, _ := run(t, env, "package", "draft", "--connection", "c1", "--item", "i2"); code != 0 ||
		stdout != "format: 1\n" || !slices.Equal(r.draft.GetItemIds(), []string{"i2"}) {
		t.Fatalf("draft to stdout = %d %q, sent %v", code, stdout, r.draft)
	}
	r.items = nil
	if code, _, errs := run(t, env, "package", "draft", "--connection", "c1"); code == 0 || !strings.Contains(errs, "no NEW inventory items") {
		t.Fatalf("draft of nothing = %d %q", code, errs)
	}
	if code, _, _ := run(t, env, "package", "draft"); code == 0 {
		t.Fatal("draft without --connection")
	}
}
