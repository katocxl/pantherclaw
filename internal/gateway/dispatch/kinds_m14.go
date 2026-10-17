// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"errors"
	"slices"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
)

// CodeKindNotImplemented: the connection's kind is defined (G0 M14 D4) but
// this gateway has no sender for it. The call is refused before the
// Authority is asked, and nothing is sent.
const CodeKindNotImplemented = "kind_not_implemented"

// errKindNotImplemented is what a client lookup returns for such a kind.
var errKindNotImplemented = errors.New("dispatch: connection kind not implemented")

// kindSender sends a permitted action through a connection of one kind, in
// the shape of sendMCP: BeginDispatch, the call, RecordExecution.
type kindSender func(e *Engine, ctx context.Context, r Result, conn *control.Connection, def *defs.Definition, bound actionir.Parsed,
	want permitWant, t *timer) Result

// kindSenders are the senders of the M14 kinds (G0 M14 D75), registered
// from the kinds' own files in init: postgres (D16), a2a (D31). A kind with
// none is refused (KIND_NOT_IMPLEMENTED).
var kindSenders = map[string]kindSender{}

// builtinKinds are the kinds the dispatch switch serves itself.
var builtinKinds = []string{"http", "mcp", "mcp_container", "local"}

// kindNotImplemented reports whether this build cannot dispatch the kind:
// neither a built-in kind nor one with a registered sender.
func kindNotImplemented(kind string) bool {
	if slices.Contains(builtinKinds, kind) {
		return false
	}
	_, ok := kindSenders[kind]
	return !ok
}
