// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package upstream

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"net/http"
)

// Bounds on an inventory listing (G0 M15 D20, HR-418): at most
// maxListPages pages and MaxListItems entries per list.
const (
	maxListPages = 10
	MaxListItems = 1000
)

// Listing is one list an upstream server answered, as it defines each
// entry, and whether every page of it was read: a listing cut at a bound,
// or by a server that kept paging, is not Complete.
type Listing struct {
	Items    []jsontext.Value
	Complete bool
}

// ListToolsInventory lists the server's tools for the connection's
// inventory (tools/list): every page up to the bounds, which cut the
// listing short instead of failing it.
func (c *Client) ListToolsInventory(ctx context.Context, decorate Decorate) (Listing, error) {
	return c.list(ctx, "tools/list", "tools", decorate)
}

// ListResources lists the server's resources (resources/list). A server
// without resources (method not found) lists none, completely.
func (c *Client) ListResources(ctx context.Context, decorate Decorate) (Listing, error) {
	return c.list(ctx, "resources/list", "resources", decorate)
}

// ListResourceTemplates lists the server's resource templates
// (resources/templates/list). A server without them lists none,
// completely.
func (c *Client) ListResourceTemplates(ctx context.Context, decorate Decorate) (Listing, error) {
	return c.list(ctx, "resources/templates/list", "resourceTemplates", decorate)
}

// list reads method page by page by cursor, as the specification pages
// lists, and keeps the entries under field.
func (c *Client) list(ctx context.Context, method, field string, decorate Decorate) (Listing, error) {
	var out Listing
	cursor := ""
	for range maxListPages {
		p := map[string]any{}
		if cursor != "" {
			p["cursor"] = cursor
		}
		ex, err := c.do(ctx, method, "", p, nil, decorate)
		if err != nil {
			return Listing{}, err
		}
		if ex.reply != nil && ex.reply.Error != nil && ex.reply.Error.Code == codeMethodNotFound && cursor == "" {
			return Listing{Complete: true}, nil
		}
		if ex.reply == nil || ex.reply.Error != nil || ex.status != http.StatusOK {
			return Listing{}, fmt.Errorf("%w: %s answered HTTP %d", ErrProtocol, method, ex.status)
		}
		var page map[string]jsontext.Value
		if err := json.Unmarshal(ex.reply.Result, &page); err != nil {
			return Listing{}, fmt.Errorf("%w: %w", ErrProtocol, err)
		}
		var items []jsontext.Value
		if raw, ok := page[field]; ok {
			if err := json.Unmarshal(raw, &items); err != nil {
				return Listing{}, fmt.Errorf("%w: %s: %w", ErrProtocol, method, err)
			}
		}
		next := ""
		if raw, ok := page["nextCursor"]; ok {
			if err := json.Unmarshal(raw, &next); err != nil {
				return Listing{}, fmt.Errorf("%w: %s cursor: %w", ErrProtocol, method, err)
			}
		}
		out.Items = append(out.Items, items...)
		if len(out.Items) > MaxListItems {
			out.Items = out.Items[:MaxListItems]
			return out, nil
		}
		if next == "" {
			out.Complete = true
			return out, nil
		}
		cursor = next
	}
	return out, nil
}
