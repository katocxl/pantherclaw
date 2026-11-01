// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"slices"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/supplychain/adapters/pgflags"
	scdomain "github.com/katocxl/pantherclaw/internal/supplychain/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// MaxInventoryNote bounds an operator's note, in bytes.
const MaxInventoryNote = 8 << 10

// ErrInventoryNote: a note is empty, too long or not UTF-8.
var ErrInventoryNote = pcerr.New(pcerr.InvalidArgument, "INVENTORY_NOTE_INVALID", "a note is 1 byte to 8 KiB of UTF-8 text")

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
		InputSchema: []byte(e.InputSchema), InputSchemaDigest: e.InputSchemaDigest, InputSchemaCut: e.InputSchemaCut, SchemaOmitted: e.SchemaOmitted,
		Extra: []byte(e.ListedExtra), ExtraCut: e.ListedExtraCut, Version: cov.version,
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

// AddInventoryNote records what an operator reported about an item from
// `pclaw mcp inspect --submit` (G0 M24 D214): at most 8 KiB of UNTRUSTED text.
// It is someone's word about their own machine, so it changes nothing else:
// not the item's state, its review or its flags (HR-582).
func (s *Service) AddInventoryNote(ctx context.Context, id ids.UUID, note string) (dbq.PcConnectionInventory, error) {
	c, err := s.caller(ctx, td.PermConnectionManage)
	if err != nil {
		return dbq.PcConnectionInventory{}, err
	}
	if note == "" || len(note) > MaxInventoryNote || !utf8.ValidString(note) {
		return dbq.PcConnectionInventory{}, ErrInventoryNote
	}
	var out dbq.PcConnectionInventory
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.LockInventoryItem(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrInventoryNotFound
		} else if err != nil {
			return err
		}
		if err := db.ExpectOneRow(q.SetInventoryNote(ctx, dbq.SetInventoryNoteParams{
			OperatorNote: note, OperatorNoteBy: &c.By, OrgID: c.Org, ID: id,
		})); err != nil {
			return err
		}
		if err := record(ctx, tx, c, "connection.inventory_note_added", row.ConnectionID, map[string]string{
			"item_id": id.String(), "kind": row.Kind, "name": row.Name, "digest": row.Digest,
		}); err != nil {
			return err
		}
		out, err = q.LockInventoryItem(ctx, c.Org, id)
		return err
	})
	return out, err
}

// fillsSchema reports whether an entry brings the digest or schema a NEW item
// has been waiting for, once a report has room (D240).
func fillsSchema(row dbq.PcConnectionInventory, e InventoryEntry) bool {
	return row.InputSchema == "" && (e.InputSchema != "" || row.InputSchemaDigest == "" && e.InputSchemaDigest != "")
}

// fillsExtra reports whether an entry brings the other listed fields.
func fillsExtra(row dbq.PcConnectionInventory, e InventoryEntry) bool {
	return row.ListedExtra == "" && e.ListedExtra != ""
}

// fills reports whether an entry brings text a NEW item has been waiting for.
func fills(row dbq.PcConnectionInventory, e InventoryEntry) bool {
	return fillsSchema(row, e) || fillsExtra(row, e)
}

// GetInventoryItem reads one item in full, schema included: the one read that
// returns it (D241).
func (s *Service) GetInventoryItem(ctx context.Context, id ids.UUID) (dbq.PcConnectionInventory, error) {
	c, err := s.caller(ctx, td.PermConnectionRead)
	if err != nil {
		return dbq.PcConnectionInventory{}, err
	}
	var out dbq.PcConnectionInventory
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).GetInventoryItemByID(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrInventoryNotFound
		}
		out = row
		return err
	}, db.ReadOnly())
	return out, err
}

// withHeld is an entry with the text its item already holds. The digest is the
// same, so the text is too, and a report that left it out loses no flag it
// raised. Held text that had lost a field still has (D289).
func withHeld(row dbq.PcConnectionInventory, e InventoryEntry) InventoryEntry {
	if e.InputSchema == "" && row.InputSchema != "" {
		e.InputSchema, e.InputSchemaDigest, e.InputSchemaCut, e.SchemaOmitted = row.InputSchema, row.InputSchemaDigest, false, false
	}
	if e.ListedExtra == "" && row.ListedExtra != "" {
		e.ListedExtra, e.ListedExtraCut = row.ListedExtra, row.ListedExtraTruncated
	}
	return e
}

// fill gives a NEW item first listed without some of its text what a report
// now has, and checks it again. The schema and the other listed fields fill on
// their own, each guarded by its own column, and a fill that finds its column
// taken changes nothing: a server cannot abort its own reports by what it
// lists (D269). The item's review entry is already open and its evidence does
// not change, so these flags show in the flag list and the queue.
func fill(ctx context.Context, tx db.TenantTx, c actor, conn dbq.PcConnection, cov coverage, row dbq.PcConnectionInventory, e InventoryEntry) error {
	q := dbq.New(tx)
	if fillsSchema(row, e) {
		if _, err := q.SetInventorySchema(ctx, dbq.SetInventorySchemaParams{
			InputSchema: e.InputSchema, InputSchemaDigest: e.InputSchemaDigest, InputSchemaTruncated: e.InputSchemaCut, OrgID: c.Org, ID: row.ID,
		}); err != nil {
			return err
		}
	}
	if fillsExtra(row, e) {
		if _, err := q.SetInventoryExtra(ctx, dbq.SetInventoryExtraParams{
			ListedExtra: e.ListedExtra, ListedExtraTruncated: e.ListedExtraCut, OrgID: c.Org, ID: row.ID,
		}); err != nil {
			return err
		}
	}
	_, err := flagItem(ctx, tx, c, conn, cov, pgflags.Item{Connection: conn.ID, Inventory: row.ID, Name: e.Name, Digest: e.Digest}, withHeld(row, e))
	return err
}
