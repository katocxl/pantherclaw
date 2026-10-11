// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"strings"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// scanRoute is the route an org-scan finding shows (G0 M8 G5; F444, F448,
// F449), or false when it shows none:
//
//   - a GitHub App installation is target-side authority beyond the
//     connection (F449);
//   - a workflow that writes or deploys is an intermediary that can produce
//     the effect (F448);
//   - a committed MCP configuration is an MCP server reaching the target
//     outside the gateway (F444).
//
// The attributes are UNTRUSTED metadata (HR-209): they only describe a
// route, never grant or close one.
func scanRoute(observed map[string]string) (domain.RouteKind, string, bool) {
	where := strings.TrimSpace(observed["repo"] + " " + observed["path"])
	switch observed["kind"] {
	case "github_app":
		return domain.KindTargetSide, strings.TrimSpace("GitHub App " + observed["app_slug"]), true
	case "github_workflow":
		if observed["writes"] == "true" || observed["deploys"] == "true" {
			return domain.KindIntermediary, where, where != ""
		}
	case "github_mcp_config":
		return domain.KindDirectAPI, where, where != ""
	}
	return "", "", false
}

// RefreshScanRoutes records, as observed routes of every agent of their
// connection, the routes the org scan found since they were last recorded,
// and returns the connections it touched. A finding naming no connection
// of the org is left out.
func (s *Service) RefreshScanRoutes(ctx context.Context, tx db.TenantTx) ([]ids.UUID, error) {
	q := dbq.New(tx)
	rows, err := q.CoverageScanFindingsToRecord(ctx, tx.OrgID())
	if err != nil {
		return nil, err
	}
	touched := map[ids.UUID]bool{}
	var out []ids.UUID
	for _, r := range rows {
		var observed map[string]string
		if json.Unmarshal(r.Observed, &observed) != nil {
			continue
		}
		kind, locator, ok := scanRoute(observed)
		conn, err := ids.ParseUUID(observed["connection"])
		if !ok || err != nil {
			continue
		}
		if _, err := q.CoverageBinding(ctx, tx.OrgID(), conn); db.IsNoRows(err) {
			continue
		} else if err != nil {
			return nil, err
		}
		if len(locator) > 512 {
			locator = locator[:512]
		}
		id := r.ID
		if _, err := q.UpsertCoverageRoute(ctx, dbq.UpsertCoverageRouteParams{
			OrgID: tx.OrgID(), ID: ids.NewV7(), ConnectionID: conn, Kind: string(kind), Locator: &locator,
			Observation: "observed", Source: "scan", SourceRef: &id, Attributes: []byte(`{}`),
		}); err != nil {
			return nil, err
		}
		if !touched[conn] {
			touched[conn] = true
			out = append(out, conn)
		}
	}
	return out, nil
}
