// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"unicode/utf8"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/detection/injection"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/supplychain/adapters/pgflags"
	scdomain "github.com/katocxl/pantherclaw/internal/supplychain/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/waitlist/adapters/pgwaitlist"
	wdomain "github.com/katocxl/pantherclaw/internal/waitlist/domain"
)

// Discovery inventory (F352, G0 M15 D20–D23). A gateway reports what each
// kind-mcp connection's upstream server lists: tools, resources and
// resource templates. Each (kind, name, digest) becomes an inventory item.
// An item no active reviewed package version covers is NEW: inert (the
// gateway serves only reviewed definitions, HR-414), with a TOOL_REVIEW
// entry. Its description is the upstream server's UNTRUSTED text, scanned
// for instruction-like content and never served (HR-415).

// Inventory kinds and states.
const (
	InventoryTool     = "TOOL"
	InventoryResource = "RESOURCE"
	InventoryTemplate = "RESOURCE_TEMPLATE"

	InventoryNew       = "NEW"
	InventoryCovered   = "COVERED"
	InventoryDismissed = "DISMISSED"
	InventoryVanished  = "VANISHED"
)

// Bounds on an inventory report (HR-418).
const (
	MaxInventoryItems       = 1000
	MaxInventoryDescription = 8 << 10
	maxInventoryName        = 2048
	maxInventoryDisplay     = 128
	maxDraftItems           = 100
)

var (
	// ErrInventory: a report breaks the bounds of HR-418 or its shape.
	ErrInventory = pcerr.New(pcerr.InvalidArgument, "INVENTORY_INVALID",
		"an inventory report holds at most 1,000 items of each kind, descriptions of at most 8 KiB and sha256 digests")
	ErrInventoryNotFound = pcerr.New(pcerr.NotFound, "INVENTORY_ITEM_NOT_FOUND", "inventory item not found")
	ErrInventoryState    = pcerr.New(pcerr.FailedPrecondition, "INVENTORY_ITEM_NOT_NEW", "only a NEW inventory item can be dismissed or drafted")
	ErrDraftEdition      = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "drafting a package from the inventory needs the Team edition or above")
	errNoEntitlement     = pcerr.New(pcerr.Unavailable, "EDITION_UNKNOWN", "the edition could not be read")

	inventoryDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// inventoryTool is a tool name as ReportDrift takes it: the only upstream
	// name a review entry shows as trusted (D43).
	inventoryTool = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
)

// Entitlements reports the current edition (billing.Service).
type Entitlements interface {
	Current(context.Context) (billing.Entitlements, error)
}

// WithEntitlements gates DraftPackageFromInventory by edition.
func (s *Service) WithEntitlements(e Entitlements) *Service {
	s.ents = e
	return s
}

// InventoryEntry is one entry an upstream server listed, as the gateway
// reported it. Name is the tool name, resource URI or URI template;
// DisplayName and MimeType are a resource's listed name and type.
type InventoryEntry struct {
	Kind, Name, DisplayName, MimeType, Digest string
	Description                               string
	DescriptionTruncated                      bool
	// DisplayTruncated: the gateway cut DisplayName or MimeType to 128 bytes.
	DisplayTruncated bool
	// InputSchema is a tool's listed input schema, UNTRUSTED, with its digest
	// (G0 M24 D211); InputSchemaCut: it was too long to report.
	InputSchema, InputSchemaDigest string
	InputSchemaCut                 bool
	// SchemaOmitted: the schema fit its own limit and not the report's (D240).
	SchemaOmitted bool
	// ListedExtra is the tool's title, annotations and output schema as a JSON
	// object, UNTRUSTED; ListedExtraCut: they were too long to report (D245).
	ListedExtra    string
	ListedExtraCut bool
}

// InventoryReport is a gateway's listing of one connection. Complete: every
// page of every list was read, so an item it lacks has vanished.
type InventoryReport struct {
	Connection ids.UUID
	Complete   bool
	Entries    []InventoryEntry
}

func (r InventoryReport) check() error {
	count := map[string]int{}
	for _, e := range r.Entries {
		count[e.Kind]++
		switch {
		case e.Kind != InventoryTool && e.Kind != InventoryResource && e.Kind != InventoryTemplate,
			count[e.Kind] > MaxInventoryItems,
			e.Name == "" || len(e.Name) > maxInventoryName || !utf8.ValidString(e.Name),
			e.Kind == InventoryTool && !inventoryTool.MatchString(e.Name),
			len(e.DisplayName) > maxInventoryDisplay || len(e.MimeType) > maxInventoryDisplay,
			len(e.Description) > MaxInventoryDescription || !utf8.ValidString(e.Description),
			!inventoryDigest.MatchString(e.Digest),
			len(e.InputSchema) > scdomain.MaxInputSchema || !utf8.ValidString(e.InputSchema),
			len(e.ListedExtra) > scdomain.MaxListedExtra || !utf8.ValidString(e.ListedExtra),
			e.ListedExtra != "" && e.Kind != InventoryTool,
			e.SchemaOmitted && (e.Kind != InventoryTool || e.InputSchema != "" || e.InputSchemaDigest == ""),
			e.InputSchemaDigest != "" && !inventoryDigest.MatchString(e.InputSchemaDigest),
			e.InputSchema != "" && (e.Kind != InventoryTool || e.InputSchemaDigest == ""):
			return ErrInventory
		}
	}
	return nil
}

// ReportInventory records a gateway's listing of a connection it serves
// (G0 M15 D22): a new (kind, name, digest) becomes an item, NEW with a
// TOOL_REVIEW entry unless the connection's pinned active package version
// covers it; every NEW item of the connection that is now covered,
// listed or not, becomes COVERED (D25); a vanished item listed again is
// checked anew; a complete listing ends the NEW and COVERED items it lacks. Only a kind-mcp connection of the
// calling gateway is accepted (HR-418). It returns how many items became
// NEW.
func (s *Service) ReportInventory(ctx context.Context, org ids.OrgID, gateway ids.UUID, r InventoryReport) (int32, error) {
	if err := r.check(); err != nil {
		return 0, err
	}
	c := actor{Org: org, By: "gateway:" + gateway.String(), Audit: evdomain.Actor{Type: "gateway", ID: gateway.String()}}
	var added int32
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		added = 0
		q := dbq.New(tx)
		conn, err := lock(ctx, q, org, r.Connection)
		if err != nil {
			return err
		}
		if conn.GatewayID != gateway || conn.Kind != KindMCP {
			return ErrNotFound
		}
		cov, err := pinnedCoverage(ctx, q, org, conn.Package)
		if err != nil {
			return err
		}
		seen := make([]ids.UUID, 0, len(r.Entries))
		for _, e := range r.Entries {
			id, isNew, err := s.see(ctx, tx, c, conn, cov, e)
			if err != nil {
				return err
			}
			seen = append(seen, id)
			if isNew {
				added++
			}
		}
		if err := q.TouchInventoryFlags(ctx, org, seen); err != nil {
			return err
		}
		if err := recheck(ctx, tx, c, conn.ID, cov); err != nil {
			return err
		}
		if !r.Complete {
			return nil
		}
		gone, err := q.VanishInventory(ctx, org, conn.ID, seen)
		if err != nil {
			return err
		}
		for _, g := range gone {
			if err := pgwaitlist.CloseInventoryReview(ctx, tx, org, g.ID, wdomain.StateExpired, c.By, "VANISHED"); err != nil {
				return err
			}
			if err := pgflags.ClearItem(ctx, tx, org, g.ID); err != nil {
				return err
			}
			if err := record(ctx, tx, c, "connection.inventory_vanished", conn.ID, map[string]string{
				"item_id": g.ID.String(), "kind": g.Kind, "name": g.Name,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	return added, err
}

// see records one listed entry and reports its item and whether it
// became NEW.
func (s *Service) see(ctx context.Context, tx db.TenantTx, c actor, conn dbq.PcConnection, cov coverage, e InventoryEntry) (ids.UUID, bool, error) {
	q := dbq.New(tx)
	row, err := q.GetInventoryItemByKey(ctx, dbq.GetInventoryItemByKeyParams{
		OrgID: c.Org, ConnectionID: conn.ID, Kind: e.Kind, Name: e.Name, Digest: e.Digest,
	})
	switch {
	case db.IsNoRows(err):
		return s.discover(ctx, tx, c, conn, cov, e)
	case err != nil:
		return ids.UUID{}, false, err
	}
	switch {
	case row.State == InventoryNew && cov.covers(e.Kind, e.Name, e.Digest):
		return row.ID, false, cover(ctx, tx, c, conn.ID, row)
	case row.State == InventoryVanished:
		to := InventoryNew
		if cov.covers(e.Kind, e.Name, e.Digest) {
			to = InventoryCovered
		}
		if err := db.ExpectOneRow(q.MoveInventoryItem(ctx, dbq.MoveInventoryItemParams{
			ToState: to, Seen: true, OrgID: c.Org, ID: row.ID, FromState: InventoryVanished,
		})); err != nil {
			return ids.UUID{}, false, err
		}
		if to == InventoryNew {
			// Checked against what the item holds too: a report that leaves it
			// out loses no flag (D280).
			held := withHeld(row, e)
			flags, err := flagItem(ctx, tx, c, conn, cov, pgflags.Item{Connection: conn.ID, Inventory: row.ID, Name: e.Name, Digest: e.Digest}, held)
			if err != nil {
				return ids.UUID{}, false, err
			}
			if err := s.openReview(ctx, tx, c, row.ID, held, flags); err != nil {
				return ids.UUID{}, false, err
			}
		}
		return row.ID, to == InventoryNew, record(ctx, tx, c, "connection.inventory_listed_again", conn.ID, map[string]string{
			"item_id": row.ID.String(), "kind": e.Kind, "name": e.Name, "digest": e.Digest, "state": to,
		})
	case row.State == InventoryNew && fills(row, e):
		if err := fill(ctx, tx, c, conn, cov, row, e); err != nil {
			return ids.UUID{}, false, err
		}
	}
	return row.ID, false, q.SeeInventoryItem(ctx, c.Org, row.ID)
}

// discover inserts a new item, scanning its description as drift reports
// are scanned (ReportDriftDescribed).
func (s *Service) discover(ctx context.Context, tx db.TenantTx, c actor, conn dbq.PcConnection, cov coverage, e InventoryEntry) (ids.UUID, bool, error) {
	found := injection.Scan(e.Description)
	scan := injection.ScanClean
	switch {
	case found.Flagged:
		scan = injection.ScanFlagged
	case e.DescriptionTruncated:
		scan = injection.ScanPartial
	}
	state := InventoryNew
	if cov.covers(e.Kind, e.Name, e.Digest) {
		state = InventoryCovered
	}
	id := ids.NewV7()
	if err := dbq.New(tx).InsertInventoryItem(ctx, dbq.InsertInventoryItemParams{
		OrgID: c.Org, ID: id, ConnectionID: conn.ID, Kind: e.Kind, Name: e.Name, DisplayName: e.DisplayName,
		MimeType: e.MimeType, DisplayTruncated: e.DisplayTruncated, Digest: e.Digest, Description: e.Description,
		DescriptionScan: scan, State: state, InputSchema: e.InputSchema, InputSchemaDigest: e.InputSchemaDigest,
		InputSchemaTruncated: e.InputSchemaCut, ListedExtra: e.ListedExtra, ListedExtraTruncated: e.ListedExtraCut,
	}); err != nil {
		return ids.UUID{}, false, err
	}
	if found.Flagged {
		if err := injection.Record(ctx, tx, c.Audit, audit.Object{Type: "connection", ID: conn.ID.String()}, e.Name, "inventory", found, map[string]string{
			"connection_id": conn.ID.String(), "item_id": id.String(), "kind": e.Kind,
		}); err != nil {
			return ids.UUID{}, false, err
		}
	}
	details := map[string]string{
		"item_id": id.String(), "kind": e.Kind, "name": e.Name, "digest": e.Digest, "description_scan": scan, "state": state,
	}
	if state == InventoryNew {
		// The checks run first so the review entry opens with their flags
		// (G0 M24 D212). They inform the review and decide nothing (HR-582).
		flags, err := flagItem(ctx, tx, c, conn, cov, pgflags.Item{Connection: conn.ID, Inventory: id, Name: e.Name, Digest: e.Digest}, e)
		if err != nil {
			return ids.UUID{}, false, err
		}
		details["supply_chain_flags"] = flags
		if err := s.openReview(ctx, tx, c, id, e, flags); err != nil {
			return ids.UUID{}, false, err
		}
	}
	return id, state == InventoryNew, record(ctx, tx, c, "connection.inventory_discovered", conn.ID, details)
}

// openReview opens a NEW item's TOOL_REVIEW entry, with the checks' flags in
// words, and links it.
func (s *Service) openReview(ctx context.Context, tx db.TenantTx, c actor, item ids.UUID, e InventoryEntry, flags string) error {
	entry, err := pgwaitlist.OpenInventoryReview(ctx, tx, c.Org, item, e.Kind, e.Name, e.Kind == InventoryTool, flags, c.Audit)
	if err != nil {
		return err
	}
	return db.ExpectOneRow(dbq.New(tx).MoveInventoryItem(ctx, dbq.MoveInventoryItemParams{
		ToState: InventoryNew, ReviewEntryID: &entry, OrgID: c.Org, ID: item, FromState: InventoryNew,
	}))
}

// cover moves a NEW item to COVERED and approves its entry.
func cover(ctx context.Context, tx db.TenantTx, c actor, conn ids.UUID, row dbq.PcConnectionInventory) error {
	if err := db.ExpectOneRow(dbq.New(tx).MoveInventoryItem(ctx, dbq.MoveInventoryItemParams{
		ToState: InventoryCovered, Seen: false, OrgID: c.Org, ID: row.ID, FromState: InventoryNew,
	})); err != nil {
		return err
	}
	if err := pgwaitlist.CloseInventoryReview(ctx, tx, c.Org, row.ID, wdomain.StateApproved, c.By, "COVERED"); err != nil {
		return err
	}
	if err := pgflags.ClearItem(ctx, tx, c.Org, row.ID); err != nil {
		return err
	}
	return record(ctx, tx, c, "connection.inventory_covered", conn, map[string]string{
		"item_id": row.ID.String(), "kind": row.Kind, "name": row.Name, "digest": row.Digest,
	})
}

// coverage is what the connection's pinned package version reviewed, when
// that version is active: upstream tools by name and digest; a resource
// whose URI matches a reviewed mcp_resource template, through the matcher
// the resources face uses; and a resource template equal to a reviewed
// one (G0 M15 D43 L5).
type coverage struct {
	defs      []domain.Definition
	templates []string
	// version is the pinned version; named is what it reviewed, in any state;
	// approved is that again when a person let the version into use (G0 M24
	// D210: what a rug pull is measured against). They never cover anything.
	version         string
	named, approved []domain.Definition
}

func (c coverage) covers(kind, name, digest string) bool {
	switch kind {
	case InventoryTool:
		return reviewed(c.defs, name, digest)
	case InventoryTemplate:
		return slices.Contains(c.templates, name)
	}
	return slices.ContainsFunc(c.templates, func(t string) bool {
		_, ok := domain.MatchResource(t, name)
		return ok
	})
}

// pinnedCoverage reads the coverage of the org's pinned version of pkg;
// a version that is not active, or does not decode, covers nothing.
func pinnedCoverage(ctx context.Context, q *dbq.Queries, org ids.OrgID, pkg string) (coverage, error) {
	pin, err := q.PinnedPackageRaw(ctx, org, pkg)
	if db.IsNoRows(err) {
		return coverage{}, nil
	} else if err != nil {
		return coverage{}, err
	}
	p, err := manifest.Decode(pin.Raw)
	if err != nil {
		return coverage{}, nil //nolint:nilerr // an undecodable version covers nothing (fail closed)
	}
	cov := coverage{version: pin.Version, named: p.Definitions}
	if wasApproved(domain.State(pin.State)) {
		cov.approved = p.Definitions
	}
	if domain.State(pin.State) != domain.StateActive {
		return cov, nil
	}
	cov.defs, cov.templates = p.Definitions, reviewedTemplates(p.Definitions)
	return cov, nil
}

// reviewedTemplates are the URI templates of a package's mcp_resource
// mappings (G0 M15 D30).
func reviewedTemplates(defs []domain.Definition) []string {
	var out []string
	for _, d := range defs {
		for _, m := range d.Mappings {
			if m.Channel == domain.ChannelMCPResource && m.Resource != "" {
				out = append(out, m.Resource)
			}
		}
	}
	return out
}

// recheck covers the connection's NEW items that the pinned active version
// now reviews (G0 M15 D25), whether or not this report listed them: a
// version that became active, or a pin that moved, takes effect on the
// next report. Serving never waits for it (HR-414).
func recheck(ctx context.Context, tx db.TenantTx, c actor, conn ids.UUID, cov coverage) error {
	rows, err := dbq.New(tx).ListNewInventory(ctx, c.Org, conn)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if cov.covers(r.Kind, r.Name, r.Digest) {
			if err := cover(ctx, tx, c, conn, r); err != nil {
				return err
			}
		}
	}
	return nil
}

// ListInventory lists a connection's inventory items, oldest first, of the
// given states and kinds (all when empty).
func (s *Service) ListInventory(ctx context.Context, connection ids.UUID, states, kinds []string, size int32, token string) (
	[]dbq.PcConnectionInventory, string, error,
) {
	c, err := s.caller(ctx, td.PermConnectionRead)
	if err != nil {
		return nil, "", err
	}
	pr, err := page.Parse(size, token)
	if err != nil {
		return nil, "", err
	}
	var out []dbq.PcConnectionInventory
	var next string
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := q.GetConnection(ctx, c.Org, connection); db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		rows, err := q.ListConnectionInventory(ctx, dbq.ListConnectionInventoryParams{
			OrgID: c.Org, ConnectionID: connection, States: nonNil(states), Kinds: nonNil(kinds), AfterID: pr.After, MaxRows: pr.Limit(),
		})
		if err != nil {
			return err
		}
		out, next = page.Finish(pr, rows, func(r dbq.PcConnectionInventory) ids.UUID { return r.ID })
		return nil
	})
	return out, next, err
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// DismissInventory dismisses a NEW item with a person's reason (1 to 500
// characters, UNTRUSTED): the item stays inert and its entry closes
// REJECTED (HR-417).
func (s *Service) DismissInventory(ctx context.Context, id ids.UUID, reason string) (dbq.PcConnectionInventory, error) {
	c, err := s.caller(ctx, td.PermConnectionManage)
	if err != nil {
		return dbq.PcConnectionInventory{}, err
	}
	if n := utf8.RuneCountInString(reason); n == 0 || n > maxReason || !utf8.ValidString(reason) {
		return dbq.PcConnectionInventory{}, ErrReason
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
		if row.State != InventoryNew {
			return ErrInventoryState
		}
		if err := db.ExpectOneRow(q.DismissInventoryItem(ctx, dbq.DismissInventoryItemParams{
			DismissedBy: &c.By, DismissReason: &reason, OrgID: c.Org, ID: id,
		})); err != nil {
			return err
		}
		if err := pgwaitlist.CloseInventoryReview(ctx, tx, c.Org, id, wdomain.StateRejected, c.By, reason); err != nil {
			return err
		}
		if err := pgflags.ClearItem(ctx, tx, c.Org, id); err != nil {
			return err
		}
		if err := record(ctx, tx, c, "connection.inventory_dismissed", row.ConnectionID, map[string]string{
			"item_id": id.String(), "kind": row.Kind, "name": row.Name, "digest": row.Digest, "reason": reason,
		}); err != nil {
			return err
		}
		out, err = q.LockInventoryItem(ctx, c.Org, id)
		return err
	})
	return out, err
}

// Draft is an unsigned draft package and what a person must fill in.
type Draft struct {
	Manifest []byte
	Todo     []string
}

// DraftPackage generates an unsigned draft package from NEW items of a
// connection (G0 M15 D23, HR-416), on the Team edition and above. The
// draft does not validate until a person fills in what Todo lists, and it
// enters only through the normal import: signature check, then
// TOOL_REVIEW. The server never signs it.
func (s *Service) DraftPackage(ctx context.Context, connection ids.UUID, items []ids.UUID) (Draft, error) {
	c, err := s.caller(ctx, td.PermPackageImport)
	if err != nil {
		return Draft{}, err
	}
	if len(items) == 0 || len(items) > maxDraftItems {
		return Draft{}, ErrInventory
	}
	if s.ents == nil {
		return Draft{}, errNoEntitlement
	}
	e, err := s.ents.Current(ctx)
	if err != nil {
		return Draft{}, errNoEntitlement
	}
	if !e.PackageDraft() {
		return Draft{}, ErrDraftEdition
	}
	var out Draft
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		conn, err := q.GetConnection(ctx, c.Org, connection)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		want := map[ids.UUID]bool{}
		for _, id := range items {
			want[id] = true
		}
		rows, err := q.GetInventoryItems(ctx, c.Org, connection, slices.Collect(maps.Keys(want)))
		if err != nil {
			return err
		}
		if len(rows) != len(want) {
			return ErrInventoryNotFound
		}
		for _, r := range rows {
			if r.State != InventoryNew {
				return ErrInventoryState
			}
		}
		out = draft(conn, rows)
		return record(ctx, tx, c, "connection.inventory_drafted", conn.ID, map[string]string{
			"items": strconv.Itoa(len(rows)), "package": draftName(conn.Name),
		})
	})
	return out, err
}
