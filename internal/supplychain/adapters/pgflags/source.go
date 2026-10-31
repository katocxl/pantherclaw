// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgflags

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pvdomain "github.com/katocxl/pantherclaw/internal/postureview/domain"
	"github.com/katocxl/pantherclaw/internal/postureview/ports"
	"github.com/katocxl/pantherclaw/internal/supplychain/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Source feeds open flags to the ranked posture queue (G0 M24 D204, D212). A
// flag has no agent, so it needs org scope. A flag on a listed entry also
// needs connection.read and one on a package tool package.read, what reading
// each directly needs. A finding clears when its flag does (D207); dismissing
// the item or settling the version is what clears it.
type Source struct{ Pool *db.Pool }

var _ ports.Source = (*Source)(nil)

// Name implements ports.Source.
func (*Source) Name() pvdomain.Source { return pvdomain.SourceSupplyChain }

// under is whether v may read what has no agent under both posture.read and p.
func under(ctx context.Context, v ports.Viewer, p td.Permission) (bool, error) {
	if v.Under == nil {
		return v.Posture.Has(nil), nil
	}
	r, err := v.Under(ctx, p)
	if err != nil {
		return false, err
	}
	return v.Posture.Intersect(r).Has(nil), nil
}

// Findings implements ports.Source. It reads the worst first, so what a cap
// drops is the least severe.
func (s *Source) Findings(ctx context.Context, v ports.Viewer, f pvdomain.Filter) ([]pvdomain.Finding, bool, error) {
	if !v.Posture.Has(nil) || f.Agent != nil || f.Team != nil {
		return []pvdomain.Finding{}, false, nil // a flag has no agent or team
	}
	conns, err := under(ctx, v, td.PermConnectionRead)
	if err != nil {
		return nil, false, err
	}
	pkgs, err := under(ctx, v, td.PermPackageRead)
	if err != nil {
		return nil, false, err
	}
	var rows []dbq.PcSupplychainFlag
	err = s.Pool.InTenantTx(ctx, v.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		rows, err = dbq.New(tx).ListOpenSupplyChainFlags(ctx, dbq.ListOpenSupplyChainFlagsParams{
			OrgID: v.Org, Connections: conns, Packages: pkgs, ConnectionID: f.Connection, MaxRows: pvdomain.MaxPerSource + 1,
		})
		return err
	}, db.ReadOnly())
	if err != nil {
		return nil, false, err
	}
	truncated := len(rows) > pvdomain.MaxPerSource
	if truncated {
		rows = rows[:pvdomain.MaxPerSource]
	}
	out := make([]pvdomain.Finding, 0, len(rows))
	for _, r := range rows {
		out = append(out, finding(r))
	}
	return out, truncated, nil
}

// subject is the record a flag is on, in "<type>:<id>" form.
func subject(r dbq.PcSupplychainFlag) string {
	if r.InventoryID != nil {
		return "connection_inventory:" + r.InventoryID.String()
	}
	if r.PackageVersionID != nil {
		return "package_version:" + r.PackageVersionID.String()
	}
	return ""
}

// finding is a flag in the queue's shape. Its title is PantherClaw's, with
// only a pattern-checked tool name in it (HR-583).
func finding(r dbq.PcSupplychainFlag) pvdomain.Finding {
	var connection *ids.UUID
	if r.ConnectionID != nil {
		c := *r.ConnectionID
		connection = &c
	}
	return pvdomain.Finding{
		Source: pvdomain.SourceSupplyChain, SourceID: r.ID.String(), Kind: r.CheckKind, RootCause: subject(r), ConnectionID: connection,
		Title: domain.Title(domain.CheckKind(r.CheckKind), r.Tool), Severity: pvdomain.Severity(r.Severity),
		SeverityBasis: pvdomain.BasisStated, State: r.State, Since: r.FirstSeen,
		Fix: pvdomain.Fix{Kind: pvdomain.FixReviewTool, TargetID: subject(r), Label: "Review this tool"},
	}
}
