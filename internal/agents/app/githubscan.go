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
		if _, err := q.GatewayScanRun(ctx, dbq.GatewayScanRunParams{OrgID: org, ID: scan, GatewayID: gateway, LeaseHash: hash[:]}); db.IsNoRows(err) {
			return ErrNoScanLease
		} else if err != nil {
			return err
		}
		if err := q.LockDiscoveries(ctx, org.String()); err != nil {
			return err
		}
		open, err := q.CountOpenDiscoveriesFrom(ctx, org, true)
		if err != nil {
			return err
		}
		w := discoverer{
			by: "gateway:" + gateway.String(), actor: domain.System, source: "github_scan",
			trusted: map[string]string{"gateway": gateway.String(), "scan": scan.String()},
		}
		for _, f := range findings {
			observed := maps.Clone(f.Attributes)
			if observed == nil {
				observed = map[string]string{}
			}
			observed["kind"], observed["submitted_by"], observed["scan_run"] = f.Kind, w.by, scan.String()
			obs, err := json.Marshal(observed)
			if err != nil {
				return err
			}
			if n, err := q.TouchScanDiscovery(ctx, dbq.TouchScanDiscoveryParams{Observed: obs, OrgID: org, ScanKey: f.Key[:], Source: "github_scan"}); err != nil {
				return err
			} else if n > 0 {
				res.Counted++
				continue
			}
			if open >= MaxOpenScanDiscoveries {
				res.Dropped++
				continue
			}
			if err := insertFinding(ctx, q, org, w, f, obs, observed); err != nil {
				return err
			}
			open++
			res.Created++
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "agents.github_scan_submitted", Actor: evdomain.Actor{Type: "gateway", ID: gateway.String()}, Outcome: audit.Success,
			Details: map[string]string{
				"scan": scan.String(), "created": strconv.Itoa(res.Created), "counted": strconv.Itoa(res.Counted), "dropped": strconv.Itoa(res.Dropped),
			},
		})
		return err
	})
	if err != nil {
		return ScanResult{}, err
	}
	return res, nil
}
