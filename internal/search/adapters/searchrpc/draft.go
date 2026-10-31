// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package searchrpc

import (
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/search"
)

// InterpretationProto is the wire form of an interpretation, for a drafted
// query (G0 M21 D304), which ModelService serves.
func InterpretationProto(in search.Interpretation) *pantherclawv1.Interpretation {
	return interpretationProto(in)
}
