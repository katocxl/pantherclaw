// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"unicode"

	"google.golang.org/protobuf/proto"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// Discovery inventory commands (F352, G0 M15 D23): what a connection's
// upstream MCP server lists, the dismissal of a NEW item, and an unsigned
// draft package from NEW items. Descriptions are the upstream server's
// UNTRUSTED text.

var (
	inventoryStates = map[string]pb.InventoryItemState{
		"new": pb.InventoryItemState_INVENTORY_ITEM_STATE_NEW, "covered": pb.InventoryItemState_INVENTORY_ITEM_STATE_COVERED,
		"dismissed": pb.InventoryItemState_INVENTORY_ITEM_STATE_DISMISSED, "vanished": pb.InventoryItemState_INVENTORY_ITEM_STATE_VANISHED,
	}
	inventoryKinds = map[string]pb.InventoryItemKind{
		"tool": pb.InventoryItemKind_INVENTORY_ITEM_KIND_TOOL, "resource": pb.InventoryItemKind_INVENTORY_ITEM_KIND_RESOURCE,
		"resource_template": pb.InventoryItemKind_INVENTORY_ITEM_KIND_RESOURCE_TEMPLATE,
	}
)

func init() {
	for k, v := range inventoryCommands() {
		commands[k] = v
	}
}

func inventoryCommands() map[string]command {
	return map[string]command{
		"connection inventory list": rpc("connection inventory list CONNECTION_ID [--state new|covered|dismissed|vanished...] "+
			"[--kind tool|resource|resource_template...]", 1, func(fs *flag.FlagSet) call {
			var states, kinds list
			fs.Var(&states, "state", "only items in this state (repeatable)")
			fs.Var(&kinds, "kind", "only items of this kind (repeatable)")
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				req := &pb.ListConnectionInventoryRequest{ConnectionId: a[0], PageSize: size(n), PageToken: *tok}
				var errs []error
				for _, s := range states {
					v, err := enumFlag(inventoryStates, "state", s)
					req.States, errs = append(req.States, v), append(errs, err)
				}
				for _, k := range kinds {
					v, err := enumFlag(inventoryKinds, "kind", k)
					req.Kinds, errs = append(req.Kinds, v), append(errs, err)
				}
				if err := errors.Join(errs...); err != nil {
					return nil, err
				}
				res, err := c.connections.ListConnectionInventory(ctx, req)
				for _, it := range res.GetItems() {
					escapeItem(it)
				}
				return res, err
			}
		}),
		"connection inventory dismiss": rpc("connection inventory dismiss ITEM_ID --reason TEXT", 1, func(fs *flag.FlagSet) call {
			reason := fs.String("reason", "", "why the item is dismissed (1 to 500 characters)")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				res, err := c.connections.DismissInventoryItem(ctx, &pb.DismissInventoryItemRequest{Id: a[0], Reason: *reason})
				escapeItem(res.GetItem())
				return res, err
			}
		}),
		"package draft": {"package draft --connection CONNECTION_ID [--item ITEM_ID...] [-o FILE]", packageDraft},
	}
}

// errDraftItems: a draft needs at least one NEW item.
var errDraftItems = errors.New("the connection has no NEW inventory items to draft")

// packageDraft writes an unsigned draft package from NEW inventory items
// (every NEW item of the connection, up to 100, without --item) to -o or
// stdout, and what to fill in to stderr. The draft does not validate until
// a person completes it, signs it with an org package key and imports it
// (HR-416).
func packageDraft(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("package draft", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	conn := fs.String("connection", "", "the connection whose inventory to draft from")
	out := fs.String("o", "", "write the draft to this file (default stdout)")
	var items list
	fs.Var(&items, "item", "a NEW inventory item (repeatable; default: every NEW item, up to 100)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *conn == "" {
		return errUsage
	}
	c, err := a.clients()
	if err != nil {
		return err
	}
	if len(items) == 0 {
		req := &pb.ListConnectionInventoryRequest{
			ConnectionId: *conn, States: []pb.InventoryItemState{pb.InventoryItemState_INVENTORY_ITEM_STATE_NEW}, PageSize: 100,
		}
		res, err := c.connections.ListConnectionInventory(ctx, req)
		if err != nil {
			return err
		}
		for _, it := range res.GetItems() {
			items = append(items, it.GetId())
		}
		if len(items) == 0 {
			return errDraftItems
		}
	}
	res, err := c.connections.DraftPackageFromInventory(ctx, &pb.DraftPackageFromInventoryRequest{ConnectionId: *conn, ItemIds: items})
	if err != nil {
		return err
	}
	if *out == "" {
		if _, err := a.stdout.Write(res.GetManifestYaml()); err != nil {
			return err
		}
	} else if err := os.WriteFile(*out, res.GetManifestYaml(), 0o600); err != nil {
		return err
	}
	_, err = fmt.Fprintln(a.stderr, "The draft is UNSIGNED and does not validate until you fill in:")
	for _, t := range res.GetTodo() {
		if err == nil {
			_, err = fmt.Fprintln(a.stderr, "  - "+escapeControls(t))
		}
	}
	return err
}

// escapeControls writes every control, format (bidirectional, zero-width)
// and line or paragraph separator character of upstream text as \uXXXX,
// so what a server listed cannot drive the terminal it is printed to
// (HR-415, D43).
func escapeControls(s string) string {
	var b strings.Builder
	for _, r := range strings.ToValidUTF8(s, string(unicode.ReplacementChar)) {
		switch {
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), r == 0x2028, r == 0x2029:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// escapeItem escapes the upstream and person-written text of an item.
func escapeItem(it *pb.InventoryItem) {
	if it == nil {
		return
	}
	it.Name, it.DisplayName, it.MimeType = escapeControls(it.Name), escapeControls(it.DisplayName), escapeControls(it.MimeType)
	it.Description, it.DismissReason = escapeControls(it.Description), escapeControls(it.DismissReason)
}
