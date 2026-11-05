// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package ports is what the threat map reads and writes through (G0 M28
// D710). Every method runs in the caller's tenant transaction.
package ports

import (
	"context"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/threatmap/domain"
)

// Records are the org-wide records the evaluator reads (D713): everything
// in domain.Inputs but the framework, scope, time, editions and the Seen
// counts, which depend on the scope.
type Records struct {
	ContentMode         string
	MCPCatalogEnforcing bool
	// BrowserExtensionDeployed: an ACTIVE connection pins pc.browser (G0 M33 D987a).
	BrowserExtensionDeployed bool
	Agents                   []domain.Agent
	Routes                   []domain.Route
	Rules                    []domain.Rule
	Cursor                   domain.Cursor
	Automations              []domain.Automation
	Results                  []domain.Result
}

// Seen is the scope's Seen counts' inputs (D713).
type Seen struct {
	Alerts    []domain.AlertGroup
	Decisions []domain.DecisionCount
	// Outcomes are connector refusals by outcome code (G0 M30 D947a).
	Outcomes []domain.OutcomeCount
}

// Snapshot is one stored day of one scope and framework (D719).
type Snapshot struct {
	Day            time.Time
	EvaluatedAt    time.Time
	CatalogVersion string
	CatalogDigest  string
	MappingDigest  string
	// States are each matrix technique's code (domain.Technique.Code).
	States map[string]string
	// Counts are the status counts per tactic id.
	Counts map[string]TacticCounts
}

// TacticCounts are one tactic's techniques by status in a snapshot.
type TacticCounts struct {
	Evidenced int `json:"evidenced"`
	Partial   int `json:"partial"`
	Gap       int `json:"gap"`
	Outside   int `json:"outside"`
}

// Store reads the evaluator's records and keeps the daily snapshots.
type Store interface {
	// Records reads the org-wide records as of now.
	Records(ctx context.Context, tx db.TenantTx, org ids.OrgID, now time.Time) (Records, error)
	// Seen reads the Seen inputs since since: every agent's (all) or only
	// those of agents.
	Seen(ctx context.Context, tx db.TenantTx, org ids.OrgID, since time.Time, all bool, agents []ids.UUID) (Seen, error)
	// EnvironmentPath is the scope path of the org's environment; ok is
	// false when the org has none of that id.
	EnvironmentPath(ctx context.Context, tx db.TenantTx, org ids.OrgID, env ids.UUID) (p td.Path, ok bool, err error)
	// LatestSnapshot is the newest stored day of a scope and framework;
	// ok is false when there is none.
	LatestSnapshot(ctx context.Context, tx db.TenantTx, org ids.OrgID, scopeKey, framework string) (s Snapshot, ok bool, err error)
	// SaveSnapshot stores s as its day's row, replacing an earlier one.
	SaveSnapshot(ctx context.Context, tx db.TenantTx, org ids.OrgID, scopeKey, framework string, s Snapshot) error
	// Snapshots are a scope and framework's days from since on, oldest
	// first.
	Snapshots(ctx context.Context, tx db.TenantTx, org ids.OrgID, scopeKey, framework string, since time.Time) ([]Snapshot, error)
	// DeleteSnapshotsBefore deletes the days before before.
	DeleteSnapshotsBefore(ctx context.Context, tx db.TenantTx, org ids.OrgID, before time.Time) (int64, error)
}
