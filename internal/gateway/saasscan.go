// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"log/slog"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/gateway/githubscan"
	"github.com/katocxl/pantherclaw/internal/gateway/saascollect"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/saasdiscovery/domain"
)

// saasScan runs a SaaS scan lease claimed at claimed (G0 M26 D407), as an
// organization scan runs: it reads until OrgScanTime after the claim, submits
// what it found under the lease, and reports the run's summary, which ends it.
// What it could not read or submit stays not scanned, never "none found"
// (HR-637).
func (g *Gateway) saasScan(ctx context.Context, conn *control.Connection, l dispatch.Lease, claimed time.Time) {
	var req struct {
		Run    string `json:"run"`
		Source string `json:"source"`
		Tenant string `json:"tenant"`
	}
	if json.Unmarshal(l.Request, &req) != nil || req.Run == "" || domain.KindOf(req.Source) == "" || !domain.TenantOK(req.Tenant) {
		g.log.ErrorContext(ctx, "gateway.saas_scan_refused", slog.String("task_id", l.Task))
		return
	}
	scanCtx, cancel := context.WithDeadline(ctx, claimed.Add(dispatch.OrgScanTime))
	res, err := g.engine.ScanSaaS(scanCtx, conn, req.Source, req.Tenant)
	cancel()
	if err != nil {
		g.log.WarnContext(ctx, "gateway.saas_scan_failed", slog.String("task_id", l.Task), slog.String("connection_id", conn.GetId()), pclog.Err(err))
		res = saascollect.Result{Report: domain.NewReport(req.Source, req.Tenant)}
		res.Report.Note(domain.NoteTenant, "the connection's credential could not be used")
	}
	o := g.submitSaaS(ctx, req.Run, l, res)
	if err := g.verifications.Report(ctx, l, o); err != nil {
		g.log.WarnContext(ctx, "gateway.saas_scan_not_reported", slog.String("task_id", l.Task), pclog.Err(err))
	}
}

// submitSaaS sends a collection's findings under the lease and returns the
// report of what happened.
func (g *Gateway) submitSaaS(ctx context.Context, run string, l dispatch.Lease, res saascollect.Result) dispatch.Observation {
	r := res.Report
	r.MarkUnread()
	var dropped int32
	for start := 0; start < len(r.Findings); start += maxSubmission {
		if g.submitScan == nil {
			r.Note(domain.NoteFindings, "findings could not be submitted")
			break
		}
		part := r.Findings[start:min(start+maxSubmission, len(r.Findings))]
		batch := make([]githubscan.Finding, len(part))
		for i, f := range part {
			batch[i] = githubscan.Finding(f)
		}
		n, err := g.submitScan(ctx, run, l.Secret, batch)
		if err != nil {
			g.log.WarnContext(ctx, "gateway.saas_scan_not_submitted", slog.String("task_id", l.Task), pclog.Err(err))
			r.Note(domain.NoteFindings, "some findings could not be submitted")
			break
		}
		dropped += n
	}
	if dropped > 0 {
		r.Note(domain.NoteFindings, fmt.Sprintf("%d findings dropped: the org's open findings of this source are at their cap", dropped))
	}
	o := dispatch.Observation{HTTPStatus: 200, Found: true, Complete: r.Complete(), Fields: r.Fields()}
	if !res.Reached {
		o.HTTPStatus, o.Found = 0, false
	}
	return o
}
