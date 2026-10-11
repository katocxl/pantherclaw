// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"encoding/hex"
	"encoding/json/v2"
	"log/slog"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/gateway/githubscan"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// ScanSubmitter sends an organization scan's findings to the server.
type ScanSubmitter func(ctx context.Context, scan string, findings []githubscan.Finding) error

// maxSubmission is the most findings one SubmitScanFindings carries.
const maxSubmission = 200

// orgScan runs an organization scan lease (G0 M8, PN-001.2, HR-209): it
// scans within the lease, submits what it found to the scan while it
// holds the lease, and reports the scan's summary, which ends it. What it
// could not read, or submit, is reported as not scanned.
func (g *Gateway) orgScan(ctx context.Context, conn *control.Connection, l dispatch.Lease) {
	var req struct {
		Run string `json:"run"`
	}
	if json.Unmarshal(l.Request, &req) != nil || req.Run == "" {
		g.log.ErrorContext(ctx, "gateway.org_scan_refused", slog.String("task_id", l.Task))
		return
	}
	r, err := g.engine.ScanOrg(ctx, conn, time.Now().Add(dispatch.OrgScanTime))
	o := dispatch.Observation{HTTPStatus: 200, Found: true}
	if err != nil {
		g.log.WarnContext(ctx, "gateway.org_scan_failed", slog.String("task_id", l.Task), slog.String("connection_id", conn.GetId()), pclog.Err(err))
		o.HTTPStatus, o.Found = 0, false
		r.NotScanned = map[string]string{"organization": "the connection's GitHub App could not be used"}
	}
	for start := 0; start < len(r.Findings); start += maxSubmission {
		batch := r.Findings[start:min(start+maxSubmission, len(r.Findings))]
		if g.submitScan == nil {
			break
		}
		if err := g.submitScan(ctx, req.Run, batch); err != nil {
			g.log.WarnContext(ctx, "gateway.org_scan_not_submitted", slog.String("task_id", l.Task), pclog.Err(err))
			r.NotScanned["findings"] = "some findings could not be submitted"
			break
		}
	}
	o.Complete = err == nil && len(r.NotScanned) == 0
	o.Fields = r.Fields()
	if err := g.verifications.Report(ctx, l, o); err != nil {
		g.log.WarnContext(ctx, "gateway.org_scan_not_reported", slog.String("task_id", l.Task), pclog.Err(err))
	}
}

// controlScans submits over the gateway's mTLS identity.
type controlScans struct{ ctl *control.Client }

func (c controlScans) submit(ctx context.Context, scan string, findings []githubscan.Finding) error {
	req := &pb.SubmitScanFindingsRequest{ScanId: scan}
	for _, f := range findings {
		req.Findings = append(req.Findings, &pb.ScanFinding{Kind: f.Kind, Key: hex.EncodeToString(f.Key[:]), Attributes: f.Attributes})
	}
	_, err := c.ctl.Agents.SubmitScanFindings(ctx, req)
	return err
}
