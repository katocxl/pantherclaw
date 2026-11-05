// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/contentsignals/domain"
	intel "github.com/katocxl/pantherclaw/internal/intel/domain"
)

// Shared injection_text indicators in the content scan (G0 M38 D1104;
// HR-818, HR-819). Where the gateway scans a body, it also matches the
// body's shingles against the org's injection_text indicators, sent with
// its configuration while the org consumes the intel feed. A match is a
// finding of kind intel_injection_text whose location names the scanned
// part and the indicator ("arg/intel/<id>"), never a value; the Authority
// alone decides what it means (hold or alert, never refuse).

// intelKey holds a call's indicator set, for its tool result.
type intelKey struct{}

// withIntel keeps set in ctx for the call's result scan.
func withIntel(ctx context.Context, set *intel.Set) context.Context {
	if set.Empty() {
		return ctx
	}
	return context.WithValue(ctx, intelKey{}, set)
}

// intelOf is the call's indicator set, or nil.
func intelOf(ctx context.Context) *intel.Set {
	s, _ := ctx.Value(intelKey{}).(*intel.Set)
	return s
}

// intelFindings are the injection_text matches of one body.
func intelFindings(set *intel.Set, location string, body []byte) []domain.Finding {
	if set.Empty() || len(body) == 0 || len(body) > domain.MaxBody {
		return nil
	}
	var out []domain.Finding
	for _, h := range set.Text(intel.BodyShingles(body)) {
		out = append(out, domain.Finding{Kind: domain.KindIntelInjectionText, Location: location + "/intel/" + h.ID})
	}
	return out
}
