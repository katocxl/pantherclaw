// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import "errors"

// CodeKindNotImplemented: the connection's kind is defined (G0 M14 D4) but
// this gateway cannot dispatch it yet. The call is refused before the
// Authority is asked, and nothing is sent.
const CodeKindNotImplemented = "kind_not_implemented"

// errKindNotImplemented is what a client lookup returns for such a kind.
var errKindNotImplemented = errors.New("dispatch: connection kind not implemented")

// kindNotImplemented reports whether this build cannot dispatch the kind:
// postgres (D16) and a2a (D31) until their dispatch lands.
func kindNotImplemented(kind string) bool {
	return kind == "postgres" || kind == "a2a"
}
