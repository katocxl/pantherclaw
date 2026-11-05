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
	_ pipeline.BrowserSites = (*Reader)(nil)
	_ pipeline.BrowserSites = (*snapshot)(nil)
)

// BrowserSites implements pipeline.BrowserSites.
func (r *Reader) BrowserSites(ctx context.Context, org ids.OrgID) ([]pipeline.BrowserSite, error) {
	return read(ctx, r, org, func(ctx context.Context, s *snapshot) ([]pipeline.BrowserSite, error) {
		return s.BrowserSites(ctx, org)
	})
}

// BrowserSites implements pipeline.BrowserSites: the org's browser site
// list (G0 M33 D977); none is an empty list, which holds every site.
func (s *snapshot) BrowserSites(ctx context.Context, org ids.OrgID) ([]pipeline.BrowserSite, error) {
	rows, err := dbq.New(s.tx).ListBrowserSites(ctx, org)
	if err != nil {
		return nil, err
	}
	out := make([]pipeline.BrowserSite, 0, len(rows))
	for _, r := range rows {
		out = append(out, pipeline.BrowserSite{Host: r.Host, IncludeSubdomains: r.IncludeSubdomains})
	}
	return out, nil
}
