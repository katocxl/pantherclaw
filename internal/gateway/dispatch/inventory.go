// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/upstream"
)

// Inventory is what a kind-mcp connection's upstream server lists (F352,
// G0 M15 D20): its tools, resources and resource templates as it defines
// them, and whether every page of every list was read. The gateway only
// reports it; nothing listed here is served, listed to agents or
// dispatched unless a reviewed package version covers it (HR-414).
type Inventory struct {
	Complete                    bool
	Tools, Resources, Templates upstream.Listing
}

// ListInventory lists a kind-mcp connection's upstream server with the
// credential a drift check lists with.
func (e *Engine) ListInventory(ctx context.Context, conn *control.Connection) (Inventory, error) {
	if conn.GetKind() != "mcp" {
		return Inventory{}, nil
	}
	ce, err := e.entry(conn)
	if err != nil {
		return Inventory{}, err
	}
	cred := &upstreamCredential{}
	if conn.GetAccessMode() == "pantherclaw_held" {
		if cred, err = e.listCredential(ctx, conn); err != nil {
			return Inventory{}, err
		}
		defer cred.release()
	}
	var out Inventory
	if out.Tools, err = ce.mcp.ListToolsInventory(ctx, cred.place); err != nil {
		return Inventory{}, err
	}
	if out.Resources, err = ce.mcp.ListResources(ctx, cred.place); err != nil {
		return Inventory{}, err
	}
	if out.Templates, err = ce.mcp.ListResourceTemplates(ctx, cred.place); err != nil {
		return Inventory{}, err
	}
	out.Complete = out.Tools.Complete && out.Resources.Complete && out.Templates.Complete
	return out, nil
}
