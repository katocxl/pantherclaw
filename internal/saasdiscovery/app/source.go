// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pvdomain "github.com/katocxl/pantherclaw/internal/postureview/domain"
	"github.com/katocxl/pantherclaw/internal/postureview/ports"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Kinds of queue finding.
const (
	// KindUnowned is an external agent nobody owns yet (F928).
	KindUnowned = "EXTERNAL_AGENT_UNOWNED"
	// KindNotScanned is a tenant whose last run left something unread: a gap,
	// never a clean bill (HR-637).
	KindNotScanned = "SAAS_NOT_SCANNED"
)

// Source reports SaaS discovery to the ranked queue (D407). A title is fixed
// text and a finding's detail is the source and tenant the server checked:
// nothing a vendor's tenant says reaches the queue (HR-638). What the agents
// are, changed or vanished, the discovery source already reports.
type Source struct {
	Pool     *db.Pool
	Editions Editions
}

var _ ports.Source = (*Source)(nil)

// Name implements ports.Source.
func (s *Source) Name() pvdomain.Source { return pvdomain.SourceSaaS }

// Findings implements ports.Source.
func (s *Source) Findings(ctx context.Context, v ports.Viewer, _ pvdomain.Filter) ([]pvdomain.Finding, bool, error) {
	if s.Editions == nil {
		return nil, false, ErrEdition
	}
	e, err := s.Editions.Current(ctx)
	if err != nil {
		return nil, false, err
	}
	if !e.SaaSDiscovery() {
		return nil, false, ErrEdition
	}
	reach := v.Posture
	if v.Under != nil {
		r, err := v.Under(ctx, td.PermAgentRead)
		if err != nil {
			return nil, false, err
		}
		reach = reach.Intersect(r)
	}
	limit := int32(pvdomain.MaxPerSource + 1)
	var unowned []dbq.PostureQueueSaasUnownedRow
	var gaps []dbq.PostureQueueSaasGapsRow
	err = s.Pool.InTenantTx(ctx, v.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		if unowned, err = q.PostureQueueSaasUnowned(ctx, dbq.PostureQueueSaasUnownedParams{
			OrgID: v.Org, AllAgents: reach.All, AgentIds: reach.Agents, MaxRows: limit,
		}); err != nil {
			return err
		}
		if reach.Has(nil) {
			gaps, err = q.PostureQueueSaasGaps(ctx, v.Org, limit)
		}
		return err
	}, db.ReadOnly())
	if err != nil {
		return nil, false, err
	}
	out := make([]pvdomain.Finding, 0, len(unowned)+len(gaps))
	for _, u := range unowned {
		out = append(out, unownedFinding(u.ID, u.AgentID, u.Source, u.FirstSeenAt))
	}
	for _, g := range gaps {
		out = append(out, gapFinding(g))
	}
	truncated := len(out) > pvdomain.MaxPerSource
	if truncated {
		out = out[:pvdomain.MaxPerSource]
	}
	if !reach.All || !reach.Org {
		// Part of the answer is out of reach, so what is here is not all of it
		// (D277).
		return out, truncated, td.ErrPermissionDenied(td.PermAgentRead)
	}
	return out, truncated, nil
}

func unownedFinding(discovery, agent ids.UUID, source string, since time.Time) pvdomain.Finding {
	return pvdomain.Finding{
		Source: pvdomain.SourceSaaS, SourceID: "discovery:" + discovery.String(), Kind: KindUnowned, AgentID: &agent,
		Title: "An agent in a SaaS tenant has no owner", Detail: map[string]string{"source": source}, State: "OPEN", Since: since,
		Fix: pvdomain.Fix{Kind: pvdomain.FixAssignOwner, TargetID: "agent:" + agent.String(), Label: "Name this agent's owner"},
	}
}

func gapFinding(g dbq.PostureQueueSaasGapsRow) pvdomain.Finding {
	var since time.Time
	if g.FinishedAt != nil {
		since = *g.FinishedAt
	}
	return pvdomain.Finding{
		Source: pvdomain.SourceSaaS, SourceID: "scan:" + g.ID.String(), Kind: KindNotScanned,
		Title: "The last SaaS discovery run left part of a tenant unread", Detail: map[string]string{"source": g.Source, "tenant": g.Tenant},
		State: "OPEN", Since: since,
		Fix: pvdomain.Fix{Kind: pvdomain.FixReviewCoverage, TargetID: "saas_scan:" + g.ID.String(), Label: "See what the run could not read"},
	}
}
