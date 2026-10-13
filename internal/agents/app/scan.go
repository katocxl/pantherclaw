// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"maps"
	"path/filepath"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// MaxOpenScanDiscoveries is the cap on open discoveries per org, the same
// as for gateway discoveries (HR-148): the org scans' (github_scan) and
// all others' each have their own, so neither fills the other's room.
const MaxOpenScanDiscoveries = 200

// ScanFinding is one finding of a local `pclaw scan` (PN-001.1). Its
// attributes are UNTRUSTED observations.
type ScanFinding struct {
	Kind       string
	Key        [32]byte
	Attributes map[string]string
}

// ScanResult counts what a submission did.
type ScanResult struct {
	Created, Counted, Dropped int
	// Reopened counts the created that reopened a dismissed finding.
	Reopened int
}

// scanName is a readable name for a discovered agent; nothing binds to it
// (F034).
func scanName(f ScanFinding) string {
	var s string
	switch f.Kind {
	case "mcp_server":
		s = "MCP server " + f.Attributes["name"]
		if c := f.Attributes["client"]; c != "" {
			s += " (" + c + ")"
		}
	case "github_mcp_config":
		s = "MCP configuration " + f.Attributes["repo"] + " " + f.Attributes["path"]
	case "github_workflow":
		s = "GitHub workflow " + f.Attributes["repo"] + " " + f.Attributes["path"]
	case "github_app":
		s = "GitHub App " + f.Attributes["app_slug"]
	default:
		s = "agent project " + filepath.Base(f.Attributes["path"])
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// SubmitScan records scan findings as DISCOVERED agents, each with a
// discovery and an ADMISSION entry (F015); a finding submitted before is
// only counted. The caller needs agent.manage somewhere in the org. At
// most MaxOpenScanDiscoveries discoveries are open per org; past that,
// findings are dropped and counted. Submitting grants nothing.
func (inv *Inventory) SubmitScan(ctx context.Context, host string, findings []ScanFinding) (ScanResult, error) {
	for _, f := range findings {
		if !localKinds[f.Kind] {
			return ScanResult{}, ErrScanKind
		}
	}
	var res ScanResult
	err := inOrg(ctx, inv.pool, func(ctx context.Context, c tenancy.Caller, q *dbq.Queries, tx db.TenantTx) error {
		if !c.CanAnywhere(td.PermAgentManage) {
			return td.ErrPermissionDenied(td.PermAgentManage)
		}
		if err := q.LockDiscoveries(ctx, c.Org.String()); err != nil {
			return err
		}
		open, err := q.CountOpenDiscoveriesOfSource(ctx, c.Org, "scan")
		if err != nil {
			return err
		}
		by := actor(c)
		for _, f := range findings {
			observed := maps.Clone(f.Attributes)
			if observed == nil {
				observed = map[string]string{}
			}
			observed["kind"], observed["submitted_by"] = f.Kind, string(by)
			if host != "" {
				observed["host"] = host
			}
			obs, err := json.Marshal(observed)
			if err != nil {
				return err
			}
			n, err := q.TouchScanDiscovery(ctx, dbq.TouchScanDiscoveryParams{Observed: obs, OrgID: c.Org, ScanKey: f.Key[:], Source: "scan"})
			if err != nil {
				return err
			}
			if n > 0 {
				res.Counted++
				continue
			}
			if open >= MaxOpenScanDiscoveries {
				res.Dropped++
				continue
			}
			if err := insertFinding(ctx, q, c.Org, discoverer{by: c.Principal.String(), actor: actor(c), source: "scan"}, f, obs, observed, ids.UUID{}); err != nil {
				return err
			}
			open++
			res.Created++
		}
		return record(ctx, tx, c, "agents.scan_submitted", ids.UUID{}, map[string]string{
			"created": strconv.Itoa(res.Created), "counted": strconv.Itoa(res.Counted), "dropped": strconv.Itoa(res.Dropped),
		})
	})
	if err != nil {
		return ScanResult{}, err
	}
	return res, nil
}

// discoverer is who submitted a finding: a person or service account
// (local scan) or a gateway (organization scan), and the source it records.
type discoverer struct {
	by     string
	actor  domain.Actor
	source string
	// trusted are more trusted facts for the admission entry (the scan and
	// gateway of an organization scan).
	trusted map[string]string
}

// insertFinding records a new finding as a DISCOVERED agent with its
// discovery, an ADMISSION entry and a history entry. With reopen, the
// finding was dismissed: that discovery reopens for the new agent instead.
func insertFinding(ctx context.Context, q *dbq.Queries, org ids.OrgID, w discoverer, f ScanFinding, obs []byte, observed map[string]string,
	reopen ids.UUID,
) error {
	a, err := q.InsertDiscoveredAgent(ctx, dbq.InsertDiscoveredAgentParams{
		OrgID: org, ID: ids.NewV7(), Name: scanName(f), CreatedBy: w.by,
	})
	if err != nil {
		return err
	}
	d := dbq.PcDiscovery{ID: reopen}
	if reopen.IsZero() {
		if d, err = q.InsertScanDiscovery(ctx, dbq.InsertScanDiscoveryParams{
			OrgID: org, ID: ids.NewV7(), AgentID: a.ID, Source: w.source, ScanKey: f.Key[:], Observed: obs,
		}); err != nil {
			return err
		}
	} else if n, err := q.ReopenScanDiscovery(ctx, dbq.ReopenScanDiscoveryParams{AgentID: a.ID, Observed: obs, OrgID: org, ID: reopen}); err != nil {
		return err
	} else if n != 1 {
		return fmt.Errorf("agents: discovery %s was not dismissed", reopen)
	}
	trusted := maps.Clone(w.trusted)
	if trusted == nil {
		trusted = map[string]string{}
	}
	trusted["source"], trusted["discovery_id"], trusted["submitted_by"] = w.source, d.ID.String(), w.by
	ev, err := json.Marshal(map[string]map[string]string{"trusted": trusted, "untrusted": observed})
	if err != nil {
		return err
	}
	if _, err := q.InsertAgentAdmissionEntry(ctx, dbq.InsertAgentAdmissionEntryParams{
		OrgID: org, ID: ids.NewV7(), AgentID: a.ID, Evidence: ev,
	}); err != nil {
		return err
	}
	details := map[string]string{"discovery_id": d.ID.String(), "source": w.source}
	if !reopen.IsZero() {
		details["reopened"] = "true"
	}
	return RecordChange(ctx, q, org, a.ID, domain.Change{Kind: domain.ChangeDiscovered, Actor: w.actor, Details: details})
}

// Kinds of findings: a local `pclaw scan` reports MCP servers and agent
// projects; a gateway's organization scan reports GitHub Apps, workflows
// and committed MCP configuration (G0 M8, HR-209).
var (
	localKinds  = map[string]bool{"mcp_server": true, "agent_project": true}
	githubKinds = map[string]bool{"github_app": true, "github_workflow": true, "github_mcp_config": true}
	// ErrScanKind refuses a finding of the other kind of scan.
	ErrScanKind = pcerr.New(pcerr.InvalidArgument, "SCAN_KIND",
		"a local scan reports mcp_server and agent_project findings; github_* findings come only from a gateway's organization scan")
)
