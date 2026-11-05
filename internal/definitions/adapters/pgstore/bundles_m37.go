// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/katocxl/pantherclaw/internal/definitions/app"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// checkBundlePackage refuses an ext.* package unless this org has a
// DRAFTED tool_package bundle item for the same name@version whose
// SHA-256 equals the imported package.yaml bytes (G0 M37 D1082b, HR-796).
// The item rows are locked for the import's transaction, so a revocation
// running at the same time waits and then withdraws the new version.
func checkBundlePackage(ctx context.Context, q *dbq.Queries, org ids.OrgID, rec app.Record) error {
	if !strings.HasPrefix(rec.Package.Name, domain.ExtensionPrefix) {
		return nil
	}
	sum := sha256.Sum256(rec.Raw)
	rows, err := q.LockDraftedBundlePackage(ctx, org, rec.Package.Name+"@"+rec.Package.Version, hex.EncodeToString(sum[:]))
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return domain.ErrBundleItemMismatch
	}
	return nil
}
