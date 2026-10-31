// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package connectionsrpc

import (
	"context"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var (
	inventoryKinds = map[pb.InventoryItemKind]string{
		pb.InventoryItemKind_INVENTORY_ITEM_KIND_TOOL: capp.InventoryTool, pb.InventoryItemKind_INVENTORY_ITEM_KIND_RESOURCE: capp.InventoryResource,
		pb.InventoryItemKind_INVENTORY_ITEM_KIND_RESOURCE_TEMPLATE: capp.InventoryTemplate,
	}
	inventoryStates = map[pb.InventoryItemState]string{
		pb.InventoryItemState_INVENTORY_ITEM_STATE_NEW: capp.InventoryNew, pb.InventoryItemState_INVENTORY_ITEM_STATE_COVERED: capp.InventoryCovered,
		pb.InventoryItemState_INVENTORY_ITEM_STATE_DISMISSED: capp.InventoryDismissed,
		pb.InventoryItemState_INVENTORY_ITEM_STATE_VANISHED:  capp.InventoryVanished,
	}
	inventoryKindOf  = invert(inventoryKinds)
	inventoryStateOf = invert(inventoryStates)
)

// inventoryItemOf is an inventory row as the API shows it; the
// description stays UNTRUSTED (HR-415).
func inventoryItemOf(r dbq.PcConnectionInventory) *pb.InventoryItem {
	out := &pb.InventoryItem{
		Id: r.ID.String(), ConnectionId: r.ConnectionID.String(), Kind: inventoryKindOf[r.Kind], Name: r.Name,
		DisplayName: r.DisplayName, MimeType: r.MimeType, Digest: r.Digest, Description: r.Description,
		DescriptionScan: r.DescriptionScan, State: inventoryStateOf[r.State], DismissedBy: deref(r.DismissedBy),
		DismissReason: deref(r.DismissReason), FirstSeenTime: stamp(r.FirstSeen), LastSeenTime: stamp(r.LastSeen),
		UpdateTime: stamp(r.UpdatedAt), DisplayTruncated: r.DisplayTruncated, InputSchema: r.InputSchema,
		InputSchemaDigest: r.InputSchemaDigest, InputSchemaTruncated: r.InputSchemaTruncated,
	}
	if r.ReviewEntryID != nil {
		out.ReviewEntryId = r.ReviewEntryID.String()
	}
	return out
}

// ListConnectionInventory implements ConnectionServiceHandler.
func (h *Handler) ListConnectionInventory(ctx context.Context, req *pb.ListConnectionInventoryRequest) (
	*pb.ListConnectionInventoryResponse, error,
) {
	id, err := parseID(req.GetConnectionId())
	if err != nil {
		return nil, err
	}
	var states, kinds []string
	for _, s := range req.GetStates() {
		states = append(states, inventoryStates[s])
	}
	for _, k := range req.GetKinds() {
		kinds = append(kinds, inventoryKinds[k])
	}
	rows, next, err := h.s.ListInventory(ctx, id, states, kinds, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pb.ListConnectionInventoryResponse{NextPageToken: next}
	for _, r := range rows {
		out.Items = append(out.Items, inventoryItemOf(r))
	}
	return out, nil
}

// DismissInventoryItem implements ConnectionServiceHandler.
func (h *Handler) DismissInventoryItem(ctx context.Context, req *pb.DismissInventoryItemRequest) (*pb.DismissInventoryItemResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	r, err := h.s.DismissInventory(ctx, id, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pb.DismissInventoryItemResponse{Item: inventoryItemOf(r)}, nil
}

// DraftPackageFromInventory implements ConnectionServiceHandler.
func (h *Handler) DraftPackageFromInventory(ctx context.Context, req *pb.DraftPackageFromInventoryRequest) (
	*pb.DraftPackageFromInventoryResponse, error,
) {
	conn, err := parseID(req.GetConnectionId())
	if err != nil {
		return nil, err
	}
	items := make([]ids.UUID, 0, len(req.GetItemIds()))
	for _, s := range req.GetItemIds() {
		id, err := parseID(s)
		if err != nil {
			return nil, err
		}
		items = append(items, id)
	}
	d, err := h.s.DraftPackage(ctx, conn, items)
	if err != nil {
		return nil, err
	}
	return &pb.DraftPackageFromInventoryResponse{ManifestYaml: d.Manifest, Todo: d.Todo}, nil
}
