// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package authority

import (
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// modelUsageOf maps a model call's reported usage (G0 M29 D818); nil when
// the gateway sent none (every other operation). protovalidate already
// bounds each count to 0..1,000,000,000.
func modelUsageOf(u *pantherclawv1.ModelUsage) *finalize.ModelUsage {
	if u == nil {
		return nil
	}
	return &finalize.ModelUsage{
		InputTokens: u.GetInputTokens(), OutputTokens: u.GetOutputTokens(),
		CacheReadTokens: u.GetCacheReadTokens(), CacheWriteTokens: u.GetCacheWriteTokens(),
		Reported: u.GetReported(),
	}
}
