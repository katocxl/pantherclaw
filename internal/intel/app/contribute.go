// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"strings"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/intel/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Contributions (G0 M38 D1105; HR-818, HR-820, HR-821). A person holding
// intel.contribute, with the org's share switch on, makes an indicator from
// a confirmed finding. Only the hash or the shingles are computed, here,
// and kept with the day; the source, its text and who contributed stay in
// the org (the audit event names the source and the person, the row does
// not).

// Source is the confirmed finding an indicator is made from.
type Source string

// Sources.
const (
	// SourceQuarantinedServer: a connection whose pinned package version is
	// QUARANTINED, by its upstream server's reported name and version.
	SourceQuarantinedServer Source = "QUARANTINED_SERVER"
	// SourceQuarantinedPackage: a QUARANTINED package version, by
	// package@version.
	SourceQuarantinedPackage Source = "QUARANTINED_PACKAGE"
	// SourceQuarantinedTool: a tool of a connection whose pinned package
	// version is QUARANTINED, by its listed description.
	SourceQuarantinedTool Source = "QUARANTINED_TOOL"
	// SourceFlaggedDescription: an inventory item whose description the
	// injection scan flagged, by the description's shingles.
	SourceFlaggedDescription Source = "FLAGGED_DESCRIPTION"
)

// Quarantined is the package version state of a confirmed finding.
const quarantined = "QUARANTINED"

// flagged is the inventory item scan outcome of a confirmed injection.
const flagged = "flagged"

// made is an indicator made from a source.
type made struct {
	kind     domain.Kind
	sha256   string
	shingles []string
}

// fromSource computes the indicator of a confirmed source, or ErrSource.
func fromSource(ctx context.Context, q *dbq.Queries, org ids.OrgID, src Source, id ids.UUID) (made, error) {
	switch src {
	case SourceQuarantinedServer:
		row, err := q.IntelSourceConnection(ctx, org, id)
		if db.IsNoRows(err) {
			return made{}, ErrSourceMissing
		} else if err != nil {
			return made{}, err
		}
		info, ok := ParseServerInfo(row.UpstreamServerInfo)
		if !ok || row.PinnedState == nil || *row.PinnedState != quarantined {
			return made{}, ErrSource
		}
		return made{kind: domain.KindMCPServer, sha256: domain.ServerHash(info.Name, info.Version)}, nil
	case SourceQuarantinedPackage:
		row, err := q.IntelSourcePackageVersion(ctx, org, id)
		if db.IsNoRows(err) {
			return made{}, ErrSourceMissing
		} else if err != nil {
			return made{}, err
		}
		if row.State != quarantined {
			return made{}, ErrSource
		}
		return made{kind: domain.KindMCPServer, sha256: domain.PackageHash(row.Name, row.Version)}, nil
	case SourceQuarantinedTool, SourceFlaggedDescription:
		item, err := q.IntelSourceInventoryItem(ctx, org, id)
		if db.IsNoRows(err) {
			return made{}, ErrSourceMissing
		} else if err != nil {
			return made{}, err
		}
		if strings.TrimSpace(item.Description) == "" {
			return made{}, ErrSource
		}
		if src == SourceFlaggedDescription {
			if item.DescriptionScan != flagged {
				return made{}, ErrSource
			}
			return made{kind: domain.KindInjectionText, shingles: domain.ContributionShingles(item.Description)}, nil
		}
		conn, err := q.IntelSourceConnection(ctx, org, item.ConnectionID)
		if err != nil && !db.IsNoRows(err) {
			return made{}, err
		}
		if item.Kind != "TOOL" || db.IsNoRows(err) || conn.PinnedState == nil || *conn.PinnedState != quarantined {
			return made{}, ErrSource
		}
		return made{kind: domain.KindToolDescription, sha256: domain.DescriptionHash(item.Description)}, nil
	}
	return made{}, ErrSource
}

// Contribute makes and queues an indicator from a confirmed finding.
func (s *Service) Contribute(ctx context.Context, src Source, id ids.UUID, severity domain.Severity, techniques []string) (Contribution, error) {
	if !severity.Valid() {
		return Contribution{}, ErrSeverity
	}
	if !validTechniques(techniques) {
		return Contribution{}, ErrTechnique
	}
	c, err := caller(ctx, td.PermIntelContribute)
	if err != nil {
		return Contribution{}, err
	}
	if !c.Human() {
		return Contribution{}, ErrHuman
	}
	techniques = domain.SortedTechniques(techniques)
	if techniques == nil {
		techniques = []string{}
	}
	var out Contribution
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		st, err := ReadSettings(ctx, q, c.Org)
		if err != nil {
			return err
		}
		if !st.Share {
			return ErrShareOff
		}
		m, err := fromSource(ctx, q, c.Org, src, id)
		if err != nil {
			return err
		}
		if m.sha256 == "" && len(m.shingles) == 0 {
			return ErrSource
		}
		var sum *string
		if m.sha256 != "" {
			sum = &m.sha256
		}
		shingles := m.shingles
		if shingles == nil {
			shingles = []string{}
		}
		row, err := q.InsertIntelContribution(ctx, dbq.InsertIntelContributionParams{
			OrgID: c.Org, ID: ids.NewV7(), Kind: string(m.kind), Sha256: sum, Shingles: shingles,
			Severity: string(severity), Techniques: techniques,
		})
		if err != nil {
			return err
		}
		out = Contribution{
			ID: row.ID, Kind: domain.Kind(row.Kind), SHA256: deref(row.Sha256), Shingles: row.Shingles,
			Severity: domain.Severity(row.Severity), Techniques: row.Techniques, CreatedDay: dayOf(row.CreatedDay), State: row.State,
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: auditkind.IntelContributed, Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "intel_contribution", ID: row.ID.String()},
			Details: map[string]string{
				"source": string(src), "source_id": id.String(), "kind": string(m.kind), "severity": string(severity),
			},
		})
		return err
	})
	return out, err
}
