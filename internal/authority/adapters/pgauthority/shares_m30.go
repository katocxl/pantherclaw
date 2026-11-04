// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgauthority

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var (
	_ pipeline.OwnedAccounts = (*Reader)(nil)
	_ pipeline.OwnedAccounts = (*snapshot)(nil)
)

// OwnedAccounts implements pipeline.OwnedAccounts.
func (r *Reader) OwnedAccounts(ctx context.Context, org ids.OrgID, kind string) ([]string, error) {
	return read(ctx, r, org, func(ctx context.Context, s *snapshot) ([]string, error) {
		return s.OwnedAccounts(ctx, org, kind)
	})
}

// OwnedAccounts implements pipeline.OwnedAccounts: the org's listed values
// of one kind (G0 M30 D935); none is an empty list, which owns nothing.
func (s *snapshot) OwnedAccounts(ctx context.Context, org ids.OrgID, kind string) ([]string, error) {
	return dbq.New(s.tx).OwnedAccountValues(ctx, org, kind)
}
