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

// ErrPatternUnchecked: the connection's pinned package cannot be read, so
// whether it requires a credential pattern cannot be checked (D85).
var ErrPatternUnchecked = pcerr.New(pcerr.FailedPrecondition, "CREDENTIAL_PATTERN_UNCHECKED",
	"the connection's pinned package cannot be read, so the credential cannot be checked against it")

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
	return patternRefusal(pin.Raw)
}

// patternRefusal is checkPattern's decision on a pinned package file: a
// package that declares a credential pattern refuses a GitHub App, and one
// that cannot be read cannot be checked, so it refuses too (fail closed).
func patternRefusal(raw []byte) error {
	p, err := manifest.Decode(raw)
	if err != nil {
		return ErrPatternUnchecked
	}
	if slices.ContainsFunc(p.Definitions, func(d defs.Definition) bool {
		return d.Dispatch != nil && d.Dispatch.CredentialPattern != ""
	}) {
		return ErrPatternNeedsStatic
	}
	return nil
}
