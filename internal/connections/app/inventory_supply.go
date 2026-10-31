// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"slices"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/supplychain/adapters/pgflags"
	scdomain "github.com/katocxl/pantherclaw/internal/supplychain/domain"
)

// Supply-chain checks on what a server lists (G0 M24 D211, D212; HR-582).
// They run on an item that is about to wait for review, and their flags go on
// its TOOL_REVIEW entry. They only inform the person reviewing it: an item's
// state follows coverage and dismissal as before, and the drift quarantine
// stays where it was. An item a reviewed version already covers does not wait
// for anyone, so it has no flags. When an item leaves review its flags clear.

// wasApproved reports a state of a version that a person let into use. Drift
// quarantines before the inventory report arrives, so a quarantined version
// still says what was approved.
func wasApproved(s domain.State) bool {
	return s == domain.StateActive || s == domain.StateStale || s == domain.StateQuarantined
}

// baseline is what the pinned version reviewed for an entry, nil when it names
// no such tool or it reviewed exactly this digest. The approved text is known
// when the inventory holds that digest's listing.
func baseline(ctx context.Context, tx db.TenantTx, c actor, conn dbq.PcConnection, cov coverage, e InventoryEntry) (*scdomain.Baseline, error) {
	if e.Kind != InventoryTool {
		return nil, nil //nolint:nilnil // no baseline is an answer
	}
	var digests []string
	for _, d := range cov.approved {
		if d.Dispatch != nil && d.Dispatch.MCP != nil && d.Dispatch.MCP.Tool == e.Name {
			digests = append(digests, d.Dispatch.MCP.UpstreamDigest)
		}
	}
	if len(digests) == 0 || slices.Contains(digests, e.Digest) {
		return nil, nil //nolint:nilnil // no baseline is an answer
	}
	b := &scdomain.Baseline{Digest: digests[0], Version: cov.version}
	row, err := dbq.New(tx).GetInventoryItemByKey(ctx, dbq.GetInventoryItemByKeyParams{
		OrgID: c.Org, ConnectionID: conn.ID, Kind: e.Kind, Name: e.Name, Digest: b.Digest,
	})
	switch {
	case db.IsNoRows(err):
		return b, nil
	case err != nil:
		return nil, err
	}
	// A listing from before schemas were reported says nothing about its
	// schema, so only the digest counts.
	if row.InputSchemaDigest != "" {
		b.TextKnown, b.Description, b.SchemaDigest = true, row.Description, row.InputSchemaDigest
	}
	return b, nil
}

// named reports whether a reviewed package names the entry, whatever digest
// it reviewed.
func named(cov coverage, e InventoryEntry) bool {
	if e.Kind == InventoryTool {
		return slices.ContainsFunc(cov.named, func(d domain.Definition) bool {
			return d.Dispatch != nil && d.Dispatch.MCP != nil && d.Dispatch.MCP.Tool == e.Name
		})
	}
	return coverage{templates: reviewedTemplates(cov.named)}.covers(e.Kind, e.Name, e.Digest)
}

// supplyCheck runs the checks on one entry.
func supplyCheck(ctx context.Context, tx db.TenantTx, c actor, conn dbq.PcConnection, cov coverage, e InventoryEntry) (scdomain.Result, error) {
	k := scdomain.Known{BuiltIns: pgflags.BuiltIns(), Provenance: named(cov, e)}
	var err error
	if k.Baseline, err = baseline(ctx, tx, c, conn, cov, e); err != nil {
		return scdomain.Result{}, err
	}
	if e.Kind == InventoryTool {
		if k.Approved, err = pgflags.ApprovedElsewhere(ctx, tx, c.Org, conn.ID, e.Name); err != nil {
			return scdomain.Result{}, err
		}
	}
	return scdomain.Check(scdomain.Tool{
		Name: e.Name, IsTool: e.Kind == InventoryTool, Digest: e.Digest, Description: e.Description, DescriptionCut: e.DescriptionTruncated,
		InputSchema: []byte(e.InputSchema), InputSchemaDigest: e.InputSchemaDigest, InputSchemaCut: e.InputSchemaCut, Version: cov.version,
	}, k), nil
}

// flagItem checks an entry and stores its flags, for its review entry to show.
func flagItem(ctx context.Context, tx db.TenantTx, c actor, conn dbq.PcConnection, cov coverage, item pgflags.Item, e InventoryEntry) (string, error) {
	r, err := supplyCheck(ctx, tx, c, conn, cov, e)
	if err != nil {
		return "", err
	}
	return scdomain.Summary(r), pgflags.RecordItem(ctx, tx, c.Org, item, r)
}

// fillSchema gives a NEW item first listed without a schema the one a report
// now has, and checks it again. The item's review entry is already open and
// its evidence does not change, so these flags show in the flag list and the
// queue.
func fillSchema(ctx context.Context, tx db.TenantTx, c actor, conn dbq.PcConnection, cov coverage, row dbq.PcConnectionInventory, e InventoryEntry) error {
	if err := db.ExpectOneRow(dbq.New(tx).SetInventorySchema(ctx, dbq.SetInventorySchemaParams{
		InputSchema: e.InputSchema, InputSchemaDigest: e.InputSchemaDigest, InputSchemaTruncated: e.InputSchemaCut, OrgID: c.Org, ID: row.ID,
	})); err != nil {
		return err
	}
	_, err := flagItem(ctx, tx, c, conn, cov, pgflags.Item{Connection: conn.ID, Inventory: row.ID, Name: e.Name, Digest: e.Digest}, e)
	return err
}
