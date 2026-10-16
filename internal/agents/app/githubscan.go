// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"maps"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// ErrNoScanLease refuses findings from a gateway that does not hold the
// scan's org_scan lease now.
var ErrNoScanLease = pcerr.New(pcerr.PermissionDenied, "SCAN_LEASE_REQUIRED",
	"only the gateway holding the scan's org_scan lease submits its findings, while it holds it")

// ErrScanConnection refuses a finding that names another connection than
// its scan's.
var ErrScanConnection = pcerr.New(pcerr.InvalidArgument, "SCAN_CONNECTION",
	"a finding names another connection than its scan's; the server records the scan's connection")

// SubmitGitHubScan records a gateway's organization scan findings (G0 M8,
// PN-001.2, HR-209) as DISCOVERED agents, like a local scan's: untrusted
// observations that grant nothing, each tagged with its scan. Only the
// gateway holding the scan's org_scan lease submits, while it holds it;
// the org and the gateway come from its certificate, and lease is the
// lease's secret, whose hash must match. Only github_* kinds.
func (inv *Inventory) SubmitGitHubScan(ctx context.Context, org ids.OrgID, gateway, scan ids.UUID, lease []byte, findings []ScanFinding) (ScanResult, error) {
	for _, f := range findings {
		if !githubKinds[f.Kind] {
			return ScanResult{}, ErrScanKind
		}
	}
	var res ScanResult
	err := inv.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		hash := sha256.Sum256(lease)
		run, err := q.GatewayScanRun(ctx, dbq.GatewayScanRunParams{OrgID: org, ID: scan, GatewayID: gateway, LeaseHash: hash[:]})
		if db.IsNoRows(err) {
			return ErrNoScanLease
		} else if err != nil {
			return err
		}
		// A finding naming another connection than the lease's is refused
		// (the coordinator's decision Q16).
		for _, f := range findings {
			if c, ok := f.Attributes["connection"]; ok && c != run.ConnectionID.String() {
				return ErrScanConnection
			}
		}
		if err := q.LockDiscoveries(ctx, org.String()); err != nil {
			return err
		}
		open, err := q.CountOpenDiscoveriesOfSource(ctx, org, "github_scan")
		if err != nil {
			return err
		}
		w := discoverer{
			by: "gateway:" + gateway.String(), actor: domain.System, source: "github_scan",
			ledger:  evdomain.Actor{Type: "gateway", ID: gateway.String()},
			trusted: map[string]string{"gateway": gateway.String(), "scan": scan.String()},
		}
		for _, f := range findings {
			observed := maps.Clone(f.Attributes)
			if observed == nil {
				observed = map[string]string{}
			}
			observed["kind"], observed["submitted_by"], observed["scan_run"] = f.Kind, w.by, scan.String()
			// The scan's connection, from its lease (G5 review follow-up).
			// A finding naming another was refused above.
			observed["connection"] = run.ConnectionID.String()
			obs, err := json.Marshal(observed)
			if err != nil {
				return err
			}
			var reopen ids.UUID
			prior, err := q.GetScanDiscovery(ctx, org, "github_scan", f.Key[:])
			switch {
			case db.IsNoRows(err):
			case err != nil:
				return err
			case prior.State == "DISMISSED" && riskChanged(f.Kind, prior.Observed, observed):
				reopen = prior.ID // dismissed for what it could do then: people judge it again
			default:
				if _, err := q.TouchScanDiscovery(ctx, dbq.TouchScanDiscoveryParams{Observed: obs, OrgID: org, ScanKey: f.Key[:], Source: "github_scan"}); err != nil {
					return err
				}
				res.Counted++
				continue
			}
			if open >= MaxOpenScanDiscoveries {
				res.Dropped++
				continue
			}
			if err := insertFinding(ctx, tx, q, org, w, f, obs, observed, reopen); err != nil {
				return err
			}
			open++
			res.Created++
			if !reopen.IsZero() {
				res.Reopened++
				if _, err := audit.Record(ctx, tx, audit.Event{
					Name: "agents.discovery_reopened", Actor: evdomain.Actor{Type: "gateway", ID: gateway.String()}, Outcome: audit.Success,
					Object:  &audit.Object{Type: "discovery", ID: reopen.String()},
					Details: map[string]string{"scan": scan.String(), "kind": f.Kind, "previous_agent": prior.AgentID.String()},
				}); err != nil {
					return err
				}
			}
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "agents.github_scan_submitted", Actor: evdomain.Actor{Type: "gateway", ID: gateway.String()}, Outcome: audit.Success,
			Details: map[string]string{
				"scan": scan.String(), "created": strconv.Itoa(res.Created), "counted": strconv.Itoa(res.Counted), "dropped": strconv.Itoa(res.Dropped),
				"reopened": strconv.Itoa(res.Reopened),
			},
		})
		return err
	})
	if err != nil {
		return ScanResult{}, err
	}
	return res, nil
}

// materialKeys are the attributes of an org-scan finding that say what its
// route may do. A finding dismissed for what it could do then reopens when
// any of them changes: newly writable permissions, a new environment, a
// new secret source (HR-209).
var materialKeys = map[string][]string{
	"github_workflow": {
		"agent_actions", "permissions", "permissions_incomplete", "permissions_default", "writes", "deploys", "environments",
		"environments_incomplete",
	},
	"github_mcp_config": {
		"servers", "commands", "transports", "env", "headers", "servers_incomplete", "commands_incomplete", "env_incomplete",
		"headers_incomplete",
	},
	"github_app": {"permissions", "permissions_incomplete", "repository_selection"},
	// A person's local scan (#336 review).
	"mcp_server":    {"transport", "command", "url_host", "env_names", "header_names"},
	"agent_project": {"frameworks", "manifest"},
}

// riskChanged reports whether a finding's material attributes differ from
// those recorded when it was dismissed.
func riskChanged(kind string, recorded []byte, now map[string]string) bool {
	var before map[string]string
	if json.Unmarshal(recorded, &before) != nil {
		return true
	}
	for _, k := range materialKeys[kind] {
		if before[k] != now[k] {
			return true
		}
	}
	return false
}
