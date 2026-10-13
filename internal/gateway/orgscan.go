// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"log/slog"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/gateway/githubscan"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// ScanSubmitter sends an organization scan's findings to the server,
// under the scan's lease, and returns how many it dropped (its cap on
// open findings).
type ScanSubmitter func(ctx context.Context, scan string, lease []byte, findings []githubscan.Finding) (dropped int32, err error)

// maxSubmission is the most findings one SubmitScanFindings carries.
const maxSubmission = 200

// orgScan runs an organization scan lease claimed at claimed (G0 M8,
// PN-001.2, HR-209): it reads until OrgScanTime after the claim, so the
// findings and the report still reach the server within the lease;
// submits what it found to the scan under the lease; and reports the
// scan's summary, which ends it. What it could not read, or submit, or
// the server dropped, is reported as not scanned.
func (g *Gateway) orgScan(ctx context.Context, conn *control.Connection, l dispatch.Lease, claimed time.Time) {
	var req struct {
		Run string `json:"run"`
	}
	if json.Unmarshal(l.Request, &req) != nil || req.Run == "" {
		g.log.ErrorContext(ctx, "gateway.org_scan_refused", slog.String("task_id", l.Task))
		return
	}
	deadline := claimed.Add(dispatch.OrgScanTime)
	scanCtx, cancel := context.WithDeadline(ctx, deadline)
	r, err := g.engine.ScanOrg(scanCtx, conn, deadline)
	timedOut := scanCtx.Err() != nil
	cancel()
	o := dispatch.Observation{HTTPStatus: 200, Found: true}
	switch {
	case err != nil && timedOut:
		// The lease's time ran out before anything was read: that is no
		// failure of the App.
		r = githubscan.Result{Counts: map[string]int64{}, NotScanned: map[string]string{}}
		for _, s := range []string{"mcp_configs", "org_installations", "repositories", "rulesets", "workflows"} {
			r.NotScanned[s] = "time limit: the lease's time ran out before it was read"
		}
	case err != nil:
		g.log.WarnContext(ctx, "gateway.org_scan_failed", slog.String("task_id", l.Task), slog.String("connection_id", conn.GetId()), pclog.Err(err))
		o.HTTPStatus, o.Found = 0, false
		r.NotScanned = map[string]string{"organization": "the connection's GitHub App could not be used"}
	}
	var dropped int32
	for start := 0; start < len(r.Findings); start += maxSubmission {
		batch := r.Findings[start:min(start+maxSubmission, len(r.Findings))]
		if g.submitScan == nil {
			break
		}
		n, err := g.submitScan(ctx, req.Run, l.Secret, batch)
		if err != nil {
			g.log.WarnContext(ctx, "gateway.org_scan_not_submitted", slog.String("task_id", l.Task), pclog.Err(err))
			r.NotScanned["findings"] = "some findings could not be submitted"
			break
		}
		dropped += n
	}
	if dropped > 0 {
		why := fmt.Sprintf("%d findings dropped: the org's open findings of org scans are at their cap", dropped)
		if r.NotScanned["findings"] != "" {
			why = r.NotScanned["findings"] + "; " + why
		}
		r.NotScanned["findings"] = why
	}
	o.Complete = err == nil && len(r.NotScanned) == 0
	o.Fields = r.Fields()
	if err := g.verifications.Report(ctx, l, o); err != nil {
		g.log.WarnContext(ctx, "gateway.org_scan_not_reported", slog.String("task_id", l.Task), pclog.Err(err))
	}
}

// controlScans submits over the gateway's mTLS identity.
type controlScans struct{ ctl *control.Client }

func (c controlScans) submit(ctx context.Context, scan string, lease []byte, findings []githubscan.Finding) (int32, error) {
	req := &pb.SubmitScanFindingsRequest{ScanId: scan, Lease: lease}
	for _, f := range findings {
		req.Findings = append(req.Findings, &pb.ScanFinding{Kind: f.Kind, Key: hex.EncodeToString(f.Key[:]), Attributes: f.Attributes})
	}
	res, err := c.ctl.Agents.SubmitScanFindings(ctx, req)
	return res.GetDropped(), err
}
