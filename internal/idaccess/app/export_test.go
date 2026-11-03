// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"net/url"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// The token endpoint's two steps, for tests that interleave a second use
// between them; compiled into tests only.

func (f *CodeFlow) SpendCode(ctx context.Context, org ids.OrgID, code string) (dbq.PcMcpAuthorizationCode, error) {
	return f.spendCode(ctx, org, code)
}

func (f *CodeFlow) FinishCode(ctx context.Context, org ids.OrgID, row dbq.PcMcpAuthorizationCode, form url.Values) (
	authnapp.TokenResponse, error,
) {
	return f.finishCode(ctx, org, row, form.Get("client_id"), form, f.Clock.Now())
}
