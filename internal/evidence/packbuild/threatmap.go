// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package packbuild

import (
	"context"
	"errors"

	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
	tmdomain "github.com/katocxl/pantherclaw/internal/threatmap/domain"
)

// CodeThreatMapUnavailable marks a threat map pack with no stored framework,
// whose environment is gone or out of the creator's threatmap.read, or on a
// server that does not build them.
const CodeThreatMapUnavailable = "THREAT_MAP_UNAVAILABLE"

var (
	errThreatMap        = errors.New("packbuild: no threat map report for this pack")
	errThreatMapEdition = errors.New("packbuild: the edition does not include threat map exports")
)

// ThreatMap evaluates the report of a pack of scope threat_map for the
// caller in ctx, the pack's creator (internal/threatmap/app.Service
// .PackReport, G0 M28 D720).
type ThreatMap interface {
	PackReport(ctx context.Context, f catalog.Framework, env ids.UUID) (tmdomain.Report, error)
}

// loadThreatMap evaluates threat_map.json as the creator, at build time: the
// framework and environment come from the pack's row (D720a), never the
// manifest.
func (b *builder) loadThreatMap() (*pack.File, error) {
	if b.s.ThreatMap == nil {
		return nil, errThreatMap
	}
	var row dbq.EvidencePackThreatMapRow
	err := b.s.Pool.InTenantTx(b.ctx, b.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		row, err = dbq.New(tx).EvidencePackThreatMap(ctx, b.org, b.r.id)
		return err
	}, db.ReadOnly())
	if err != nil {
		return nil, err
	}
	if row.ThreatFramework == nil {
		return nil, errThreatMap
	}
	var env ids.UUID
	if row.ThreatEnvironment != nil {
		env = *row.ThreatEnvironment
	}
	report, err := b.s.ThreatMap.PackReport(b.ctx, catalog.Framework(*row.ThreatFramework), env)
	switch code := pcerr.CodeOf(err); {
	case err == nil:
	case code == pcerr.FailedPrecondition:
		return nil, errors.Join(errThreatMapEdition, err)
	case code == pcerr.NotFound || code == pcerr.PermissionDenied || code == pcerr.InvalidArgument:
		return nil, errors.Join(errThreatMap, err)
	default:
		return nil, err
	}
	data, err := pack.Canonical(report)
	if err != nil {
		return nil, err
	}
	return &pack.File{Path: pack.ThreatMapPath, Kind: pack.KindThreatMap, Data: data}, nil
}
