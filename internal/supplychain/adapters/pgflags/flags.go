// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pgflags stores supply-chain flags (G0 M24 D211, D212; HR-582) and
// reads them back for the posture queue. It writes only pc.supplychain_flags:
// nothing here moves an inventory item, a package version or a review, so a
// flag cannot approve anything.
package pgflags

import (
	"context"
	"encoding/json/v2"
	"slices"

	ddomain "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/sdk/builtin"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/supplychain/domain"
)

// detail is the stored shape of supplychain_flags.detail.
type detail struct {
	Note  string        `json:"note"`
	Spans []domain.Span `json:"spans"`
}

func encode(f domain.Flag) ([]byte, error) {
	return json.Marshal(detail{Note: f.Note, Spans: append([]domain.Span{}, f.Spans...)})
}

// Detail reads a stored detail back; one that does not decode reads empty.
func Detail(raw []byte) (string, []domain.Span) {
	var d detail
	if json.Unmarshal(raw, &d) != nil {
		return "", nil
	}
	return d.Note, d.Spans
}

// BuiltIns are the names agents have built in.
func BuiltIns() []string { return builtin.Names() }

// Item is the listed entry a result is about.
type Item struct {
	Connection, Inventory ids.UUID
	// Name and Digest are the entry's own; a name that is free text is not
	// stored.
	Name, Digest string
}

// RecordItem stores what the checks found on an item in tx, replacing what
// was open on it: a flag the checks no longer raise clears.
func RecordItem(ctx context.Context, tx db.TenantTx, org ids.OrgID, it Item, r domain.Result) error {
	q := dbq.New(tx)
	if err := q.ClearInventoryFlags(ctx, org, &it.Inventory); err != nil {
		return err
	}
	for _, f := range r.Flags {
		b, err := encode(f)
		if err != nil {
			return err
		}
		if err := q.UpsertInventoryFlag(ctx, dbq.UpsertInventoryFlagParams{
			OrgID: org, ID: ids.NewV7(), ConnectionID: &it.Connection, InventoryID: &it.Inventory, Tool: domain.ToolName(it.Name),
			Digest: it.Digest, CheckKind: string(f.Kind), Severity: string(f.Severity), Detail: b,
		}); err != nil {
			return err
		}
	}
	return nil
}

// ClearItem clears an item's flags: it left review, by a person's decision
// or by its server no longer listing it.
func ClearItem(ctx context.Context, tx db.TenantTx, org ids.OrgID, item ids.UUID) error {
	return dbq.New(tx).ClearInventoryFlags(ctx, org, &item)
}

// ClearPackage clears a version's flags: it left review.
func ClearPackage(ctx context.Context, tx db.TenantTx, org ids.OrgID, version ids.UUID) error {
	return dbq.New(tx).ClearPackageFlags(ctx, org, &version)
}

// packageEntry is one thing a package tells an agent about: a mapping of an
// MCP tool, or of a resource. Every mapping counts, also of a tool an earlier
// one names, since each has its own description (D245).
type packageEntry struct {
	mapping ddomain.Mapping
	tool    domain.Tool
}

// packageEntries lists a package's mappings as listed entries. A tool's digest
// is the upstream digest it pins, what other connections' approvals hold, so
// the same tool is not shadowing itself (D244).
func packageEntries(p *ddomain.Package) ([]packageEntry, error) {
	var out []packageEntry
	for _, d := range p.Definitions {
		for _, m := range d.Mappings {
			switch {
			case m.Channel == ddomain.ChannelMCP && m.Tool != "":
				in := domain.Tool{Name: m.Tool, IsTool: true, Digest: toolDigest(d), Description: m.Description}
				if m.InputSchema != nil {
					var err error
					if in.InputSchema, err = json.Marshal(m.InputSchema, json.Deterministic(true)); err != nil {
						return nil, err
					}
				}
				out = append(out, packageEntry{mapping: m, tool: in})
			case m.Channel == ddomain.ChannelMCPResource:
				out = append(out, packageEntry{mapping: m, tool: domain.Tool{Name: m.Resource, Digest: d.Digest, Description: m.Description}})
			}
		}
	}
	return out, nil
}

// toolDigest is what a definition pins of its upstream tool, or, when it pins
// nothing, its own digest.
func toolDigest(d ddomain.Definition) string {
	if d.Dispatch != nil && d.Dispatch.MCP != nil && d.Dispatch.MCP.UpstreamDigest != "" {
		return d.Dispatch.MCP.UpstreamDigest
	}
	return d.Digest
}

// CheckPackage runs the checks on an imported version's MCP tools (D212) and
// stores what they found. A package is signed text from outside as well: a
// signature says who sent it, not what its descriptions tell an agent. A tool
// of the development key has no provenance worth the name (HR-163). A rug
// pull needs a version that stayed the same, and an import is always a new
// version, so that check has nothing to compare here.
func CheckPackage(ctx context.Context, tx db.TenantTx, org ids.OrgID, version ids.UUID, p *ddomain.Package, devKey bool) (domain.Result, error) {
	out := domain.Result{}
	entries, err := packageEntries(p)
	if err != nil || len(entries) == 0 {
		return out, err
	}
	q := dbq.New(tx)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.tool.IsTool {
			names = append(names, e.tool.Name)
		}
	}
	rows, err := q.ApprovedToolsOutside(ctx, org, names, p.Name)
	if err != nil {
		return out, err
	}
	approved := make([]domain.Approved, 0, len(rows))
	for _, r := range rows {
		approved = append(approved, domain.Approved{Name: r.Name, Digest: r.Digest})
	}
	k := domain.Known{BuiltIns: BuiltIns(), Approved: approved, Provenance: !devKey}
	for _, e := range entries {
		in := e.tool
		r := domain.Check(in, k)
		out.Partial = out.Partial || r.Partial
		out.Flags = append(out.Flags, r.Flags...)
		for _, f := range r.Flags {
			b, err := encode(f)
			if err != nil {
				return out, err
			}
			if err := q.InsertPackageFlag(ctx, dbq.InsertPackageFlagParams{
				OrgID: org, ID: ids.NewV7(), PackageVersionID: &version, Tool: domain.ToolName(in.Name), Digest: in.Digest,
				CheckKind: string(f.Kind), Severity: string(f.Severity), Detail: b,
			}); err != nil {
				return out, err
			}
		}
	}
	return out, nil
}

// ApprovedElsewhere lists the digests a tool is approved under on the org's
// other connections.
func ApprovedElsewhere(ctx context.Context, tx db.TenantTx, org ids.OrgID, connection ids.UUID, name string) ([]domain.Approved, error) {
	digests, err := dbq.New(tx).ApprovedToolDigests(ctx, org, name, connection)
	if err != nil {
		return nil, err
	}
	slices.Sort(digests)
	out := make([]domain.Approved, 0, len(digests))
	for _, d := range digests {
		out = append(out, domain.Approved{Name: name, Digest: d})
	}
	return out, nil
}
