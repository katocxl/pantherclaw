// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package packbuild

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"time"

	coapp "github.com/katocxl/pantherclaw/internal/compliance/app"
	"github.com/katocxl/pantherclaw/internal/compliance/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// CodeComplianceUnavailable marks a compliance pack with no readable report
// row, or on a server that does not build them.
const CodeComplianceUnavailable = "COMPLIANCE_UNAVAILABLE"

var errCompliance = errors.New("packbuild: no compliance report for this pack")

// Compliance derives a framework's coverage for the caller in ctx, the
// pack's creator (internal/compliance/app.Service.Report).
type Compliance interface {
	Report(ctx context.Context, f domain.Framework, start, end time.Time) (domain.Report, error)
}

// complianceData is the report of a pack of scope compliance.
type complianceData struct {
	file         pack.File
	digest       []byte
	transactions []ids.UUID
}

// loadCompliance derives the report as the creator: what they may not read is
// a gap in it (D312).
func (b *builder) loadCompliance() (*complianceData, error) {
	if b.s.Compliance == nil {
		return nil, errCompliance
	}
	var row dbq.PcComplianceReport
	err := b.s.Pool.InTenantTx(b.ctx, b.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		row, err = dbq.New(tx).GetComplianceReportOfPack(ctx, b.org, b.r.id)
		return err
	}, db.ReadOnly())
	if db.IsNoRows(err) {
		return nil, errCompliance
	} else if err != nil {
		return nil, err
	}
	report, err := b.s.Compliance.Report(b.ctx, domain.Framework(row.Framework), row.PeriodStart, row.PeriodEnd)
	if permanent(err) {
		return nil, errors.Join(errCompliance, err)
	} else if err != nil {
		return nil, err
	}
	data, err := pack.Canonical(report)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	return &complianceData{
		file:         pack.File{Path: pack.CompliancePath, Kind: pack.KindCompliance, Data: data},
		digest:       sum[:],
		transactions: citedTransactions(report),
	}, nil
}

// permanent reports a report error no retry can mend: the pack fails at once
// with CodeComplianceUnavailable rather than staying pending.
func permanent(err error) bool {
	return errors.Is(err, coapp.ErrBadPeriod) || errors.Is(err, coapp.ErrUnknown) || errors.Is(err, coapp.ErrUnavailable)
}

// citedTransactions lists the transactions the report cites, once each: the
// pack holds these, so `pclaw verify` can check them against their receipts.
func citedTransactions(r domain.Report) []ids.UUID {
	var out []ids.UUID
	for _, s := range r.Inputs.Sources {
		for _, ref := range s.Refs {
			if ref.Type != domain.RefTransaction {
				continue
			}
			if id, err := ids.ParseUUID(ref.ID); err == nil {
				out = append(out, id)
			}
		}
	}
	slices.SortFunc(out, func(x, y ids.UUID) int { return strings.Compare(x.String(), y.String()) })
	return slices.Compact(out)
}
