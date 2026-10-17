// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"slices"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
)

// ErrPatternNeedsStatic: the connection's package names a credential
// pattern, which only a static credential can match (G0 M14 D85, HR-301).
var ErrPatternNeedsStatic = pcerr.New(pcerr.FailedPrecondition, "CREDENTIAL_PATTERN_NEEDS_STATIC",
	"the connection's package requires credentials of a pattern, which only a static credential can have")

// checkPattern refuses a GitHub App credential on a connection whose
// pinned package declares a credential pattern on any definition: the
// gateway would refuse every dispatch with it anyway (D85).
func checkPattern(ctx context.Context, q *dbq.Queries, conn dbq.PcConnection, kind string) error {
	if kind != domain.KindGitHubApp {
		return nil
	}
	pin, err := q.PinnedPackageRaw(ctx, conn.OrgID, conn.Package)
	if db.IsNoRows(err) {
		return nil // the connection cannot dispatch without its package
	} else if err != nil {
		return err
	}
	p, err := manifest.Decode(pin.Raw)
	if err != nil {
		return nil // an unreadable package dispatches nothing
	}
	if slices.ContainsFunc(p.Definitions, func(d defs.Definition) bool {
		return d.Dispatch != nil && d.Dispatch.CredentialPattern != ""
	}) {
		return ErrPatternNeedsStatic
	}
	return nil
}
