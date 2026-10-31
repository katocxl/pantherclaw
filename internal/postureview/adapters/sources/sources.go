// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package sources holds the ranked posture queue's built-in sources (G0 M24
// D204). Each reads what its own area already keeps, under the viewer, in a
// read-only transaction, and changes nothing. A source whose records need
// more than posture.read returns only what both permissions reach: the queue
// never shows what the source's own read would refuse.
package sources

import (
	"context"
	"time"

	exapp "github.com/katocxl/pantherclaw/internal/exposure/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/posture/domain"
	"github.com/katocxl/pantherclaw/internal/postureview/domain"
	"github.com/katocxl/pantherclaw/internal/postureview/ports"
	recapp "github.com/katocxl/pantherclaw/internal/recommendations/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// discoveryHorizon is how far back a recorded discovery change stays in the
// queue; the operations queue uses the same week.
const discoveryHorizon = 7 * 24 * time.Hour

// maxTitleName bounds a listed name in a title, in characters.
const maxTitleName = 128

// ErrSuggestionsEdition: suggestions stay on the Business edition.
var ErrSuggestionsEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED",
	"policy suggestions need the Business edition or above")

// Reader is what every source reads with.
type Reader struct {
	Pool *db.Pool
	Ents exapp.Entitlements
}

func (r Reader) read(ctx context.Context, org ids.OrgID, fn func(context.Context, *dbq.Queries) error) error {
	return r.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		return fn(ctx, dbq.New(tx))
	}, db.ReadOnly())
}

// both is what posture.read and p reach together. Holding p only where
// posture.read reaches nothing is below the source's scope: RESTRICTED, not
// an empty answer (D255).
func both(ctx context.Context, v ports.Viewer, p td.Permission) (ports.Reach, error) {
	o, err := v.Under(ctx, p)
	if err != nil {
		return ports.Reach{}, err
	}
	r := v.Posture.Intersect(o)
	if r.Empty() && !v.Posture.Empty() {
		return ports.Reach{}, td.ErrPermissionDenied(p)
	}
	return r, nil
}

func agentIDs(r ports.Reach) []ids.UUID {
	if r.Agents == nil {
		return []ids.UUID{}
	}
	return r.Agents
}

// cut keeps the most a source may return, and says whether there was more.
func cut[T any](rows []T) ([]T, bool) {
	if len(rows) > domain.MaxPerSource {
		return rows[:domain.MaxPerSource], true
	}
	return rows, false
}

func maxRows() int32 { return domain.MaxPerSource + 1 }

// Builtin returns every built-in source.
func Builtin(r Reader) []ports.Source {
	return []ports.Source{Posture{r}, Coverage{r}, Suggestions{r}, Discovery{r}, Recommendations{r}, Inventory{r}}
}

// Posture is the posture findings still in the queue. An accepted finding
// comes back when its acceptance ends.
type Posture struct{ Reader }

// Name implements ports.Source.
func (Posture) Name() domain.Source { return domain.SourcePosture }

// Findings implements ports.Source.
func (s Posture) Findings(ctx context.Context, v ports.Viewer, _ domain.Filter) ([]domain.Finding, bool, error) {
	states := []string{string(pdomain.Open), string(pdomain.Assigned), string(pdomain.Testing), string(pdomain.EvidenceIncomplete)}
	var rows []dbq.PcPostureFinding
	err := s.read(ctx, v.Org, func(ctx context.Context, q *dbq.Queries) error {
		var err error
		rows, err = q.ListPostureFindings(ctx, dbq.ListPostureFindingsParams{
			OrgID: v.Org, States: states, MaxRows: maxRows(), AllAgents: v.Posture.All, AgentIds: agentIDs(v.Posture), OrgScope: v.Posture.Org,
		})
		return err
	})
	if err != nil {
		return nil, false, err
	}
	rows, more := cut(rows)
	out := make([]domain.Finding, 0, len(rows))
	for _, r := range rows {
		out = append(out, domain.Finding{
			Source: domain.SourcePosture, SourceID: r.ID.String(), Kind: r.Kind, RootCause: r.RootCause, AgentID: r.AgentID,
			ConnectionID: r.ConnectionID, Title: r.Title, Severity: domain.Severity(r.Severity), State: r.State, Since: r.FirstSeenAt,
			Fix: domain.PostureFix(r.Kind, r.RootCause, r.ID.String()),
		})
	}
	return out, more, nil
}

// Coverage is the open coverage findings no posture finding has imported.
type Coverage struct{ Reader }

// Name implements ports.Source.
func (Coverage) Name() domain.Source { return domain.SourceCoverage }

// Findings implements ports.Source. A finding's subject is untrusted text,
// so its title is fixed.
func (s Coverage) Findings(ctx context.Context, v ports.Viewer, _ domain.Filter) ([]domain.Finding, bool, error) {
	reach, err := both(ctx, v, td.PermCoverageRead)
	if err != nil {
		return nil, false, err
	}
	var rows []dbq.PostureQueueCoverageFindingsRow
	err = s.read(ctx, v.Org, func(ctx context.Context, q *dbq.Queries) error {
		var err error
		rows, err = q.PostureQueueCoverageFindings(ctx, dbq.PostureQueueCoverageFindingsParams{
			OrgID: v.Org, AllAgents: reach.All, AgentIds: agentIDs(reach), OrgScope: reach.Org, MaxRows: maxRows(),
		})
		return err
	})
	if err != nil {
		return nil, false, err
	}
	rows, more := cut(rows)
	out := make([]domain.Finding, 0, len(rows))
	for _, r := range rows {
		root := "coverage_finding:" + r.ID.String()
		if r.ConnectionID != nil {
			root = "connection:" + r.ConnectionID.String()
		}
		out = append(out, domain.Finding{
			Source: domain.SourceCoverage, SourceID: r.ID.String(), Kind: r.Kind, RootCause: root, AgentID: r.AgentID,
			ConnectionID: r.ConnectionID, Title: "Credential holds more than its operations need",
			Severity: domain.Severity(r.Severity), State: "OPEN", Since: r.FirstSeenAt,
			Fix: domain.Fix{Kind: domain.FixNarrowScopes, TargetID: "coverage_finding:" + r.ID.String(), Label: "Narrow the credential to what its operations need"},
		})
	}
	return out, more, nil
}

// Suggestions is the open and drafted policy suggestions, visible where the
// viewer holds both posture.read and grant.read (HR-444), on the editions
// that have them.
type Suggestions struct{ Reader }

// Name implements ports.Source.
func (Suggestions) Name() domain.Source { return domain.SourceSuggestions }

// Findings implements ports.Source.
func (s Suggestions) Findings(ctx context.Context, v ports.Viewer, _ domain.Filter) ([]domain.Finding, bool, error) {
	if s.Ents == nil {
		return nil, false, ErrSuggestionsEdition
	}
	e, err := s.Ents.Current(ctx)
	if err != nil {
		return nil, false, err
	}
	if !e.PostureRemediation() {
		return nil, false, ErrSuggestionsEdition
	}
	reach, err := both(ctx, v, td.PermGrantRead)
	if err != nil {
		return nil, false, err
	}
	var rows []dbq.PcPolicySuggestion
	err = s.read(ctx, v.Org, func(ctx context.Context, q *dbq.Queries) error {
		var err error
		rows, err = q.ListPolicySuggestions(ctx, dbq.ListPolicySuggestionsParams{
			OrgID: v.Org, States: []string{"OPEN", "DRAFTED"}, AllAgents: reach.All, AgentIds: agentIDs(reach), MaxRows: maxRows(),
		})
		return err
	})
	if err != nil {
		return nil, false, err
	}
	rows, more := cut(rows)
	out := make([]domain.Finding, 0, len(rows))
	for _, r := range rows {
		agent := r.AgentID
		out = append(out, domain.Finding{
			Source: domain.SourceSuggestions, SourceID: r.ID.String(), Kind: r.Kind, RootCause: "grant:" + r.GrantID.String(), AgentID: &agent,
			Title: "A narrower policy is suggested for unused authority", State: r.State, Since: r.CreatedAt,
			Fix: domain.Fix{Kind: domain.FixReviewSuggested, TargetID: "suggestion:" + r.ID.String(), Label: "Review the suggested policy"},
		})
	}
	return out, more, nil
}

// Discovery is continuous discovery's open changes: what scans stopped
// seeing and what changed what it may do.
type Discovery struct{ Reader }

// Name implements ports.Source.
func (Discovery) Name() domain.Source { return domain.SourceDiscovery }

// Findings implements ports.Source. What a discovery observed is untrusted,
// so its title is fixed.
func (s Discovery) Findings(ctx context.Context, v ports.Viewer, _ domain.Filter) ([]domain.Finding, bool, error) {
	reach, err := both(ctx, v, td.PermAgentRead)
	if err != nil {
		return nil, false, err
	}
	agents := make([]string, 0, len(reach.Agents))
	for _, a := range reach.Agents {
		agents = append(agents, a.String())
	}
	var rows []dbq.OpsDiscoveryChangesRow
	var now time.Time
	err = s.read(ctx, v.Org, func(ctx context.Context, q *dbq.Queries) error {
		var err error
		if now, err = q.DBNow(ctx); err != nil {
			return err
		}
		rows, err = q.OpsDiscoveryChanges(ctx, dbq.OpsDiscoveryChangesParams{
			OrgID: v.Org, AllAgents: reach.All, Agents: agents, Since: now.Add(-discoveryHorizon), MaxRows: maxRows(),
		})
		return err
	})
	if err != nil {
		return nil, false, err
	}
	rows, more := cut(rows)
	out := make([]domain.Finding, 0, len(rows))
	for _, r := range rows {
		agent := r.AgentID
		f := domain.Finding{
			Source: domain.SourceDiscovery, SourceID: r.ID.String(), Kind: domain.KindDiscoveryVanished, AgentID: &agent,
			RootCause: "agent:" + agent.String(), Title: "Discovery not seen in recent scans", State: r.Change, Since: now,
			Fix: domain.Fix{Kind: domain.FixReviewAgent, TargetID: "agent:" + agent.String(), Label: "Review the agent"},
		}
		if r.Change == "CHANGED" {
			f.Kind, f.Title = domain.KindDiscoveryChanged, "Discovery changed what it may do"
		}
		if r.Since != nil {
			f.Since = *r.Since
		}
		out = append(out, f)
	}
	return out, more, nil
}

// Recommendations is the integrations that would close what discovery
// found. A recommendation names no one agent, so it needs org scope here,
// like a posture finding with no agent, whichever its catalog reach.
type Recommendations struct{ Reader }

// Name implements ports.Source.
func (Recommendations) Name() domain.Source { return domain.SourceRecommendations }

// Findings implements ports.Source.
func (s Recommendations) Findings(ctx context.Context, v ports.Viewer, _ domain.Filter) ([]domain.Finding, bool, error) {
	if !v.Posture.Org {
		return nil, false, td.ErrPermissionDenied(td.PermPostureRead) // RESTRICTED, never empty (D255)
	}
	var items []recapp.Item
	err := s.read(ctx, v.Org, func(ctx context.Context, q *dbq.Queries) error {
		var err error
		items, err = recapp.Open(ctx, q, v.Org, exapp.Visible{All: true}, false)
		return err
	})
	if err != nil {
		return nil, false, err
	}
	out := make([]domain.Finding, 0, len(items))
	for _, it := range items {
		id := string(it.Entry.ID)
		out = append(out, domain.Finding{
			Source: domain.SourceRecommendations, SourceID: id, Kind: id, Title: it.Entry.Title, State: "OPEN",
			Fix: domain.Fix{Kind: domain.FixConnect, TargetID: "recommendation:" + id, Label: it.Entry.Title},
		})
	}
	return out, false, nil
}

// Inventory is what a gateway found behind a connection and nobody has
// reviewed. An item names a connection and no agent, so it needs org scope.
type Inventory struct{ Reader }

// Name implements ports.Source.
func (Inventory) Name() domain.Source { return domain.SourceInventory }

// inventoryKinds maps an inventory kind to its finding kind and label.
var inventoryKinds = map[string]struct{ kind, label string }{
	"TOOL":              {domain.KindNewTool, "tool"},
	"RESOURCE":          {domain.KindNewResource, "resource"},
	"RESOURCE_TEMPLATE": {domain.KindNewResourceTmpl, "resource template"},
}

// Findings implements ports.Source. The name is listed by the upstream
// server: it is cut and shown as plain text, and the description is never
// read.
func (s Inventory) Findings(ctx context.Context, v ports.Viewer, _ domain.Filter) ([]domain.Finding, bool, error) {
	reach, err := both(ctx, v, td.PermConnectionRead)
	if err != nil {
		return nil, false, err
	}
	if !reach.Org {
		return nil, false, td.ErrPermissionDenied(td.PermConnectionRead)
	}
	var rows []dbq.PostureQueueNewInventoryRow
	err = s.read(ctx, v.Org, func(ctx context.Context, q *dbq.Queries) error {
		var err error
		rows, err = q.PostureQueueNewInventory(ctx, v.Org, maxRows())
		return err
	})
	if err != nil {
		return nil, false, err
	}
	rows, more := cut(rows)
	out := make([]domain.Finding, 0, len(rows))
	for _, r := range rows {
		k := inventoryKinds[r.Kind]
		name := []rune(r.Name)
		if len(name) > maxTitleName {
			name = name[:maxTitleName]
		}
		conn := r.ConnectionID
		out = append(out, domain.Finding{
			Source: domain.SourceInventory, SourceID: r.ID.String(), Kind: k.kind, RootCause: "connection:" + conn.String(),
			ConnectionID: &conn, Title: "New " + k.label + " awaits review: " + string(name), State: "NEW", Since: r.FirstSeen,
			Fix: domain.Fix{Kind: domain.FixReviewTool, TargetID: "inventory:" + r.ID.String(), Label: "Review the " + k.label},
		})
	}
	return out, more, nil
}
