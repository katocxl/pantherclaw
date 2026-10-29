// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"flag"
	"fmt"
	"strings"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// pclaw run inspect (rows26 D24; F224): one run end to end. Each section
// is read on the server with its own permission; a section the caller may
// not read is listed in omittedSections.

var inspectSections = map[string]pantherclawv1.InspectSection{
	"timeline":  pantherclawv1.InspectSection_INSPECT_SECTION_TIMELINE,
	"lineage":   pantherclawv1.InspectSection_INSPECT_SECTION_LINEAGE,
	"budget":    pantherclawv1.InspectSection_INSPECT_SECTION_BUDGET,
	"approvals": pantherclawv1.InspectSection_INSPECT_SECTION_APPROVALS,
	"coverage":  pantherclawv1.InspectSection_INSPECT_SECTION_COVERAGE,
	"gaps":      pantherclawv1.InspectSection_INSPECT_SECTION_GAPS,
}

// inspectRequest builds the request of run inspect from its arguments.
func inspectRequest(run string, sections []string, n int, tok string) (*pantherclawv1.InspectRunRequest, error) {
	req := &pantherclawv1.InspectRunRequest{RunId: run, TimelinePageSize: int32(min(max(n, 0), 500)), TimelinePageToken: tok}
	for _, s := range sections {
		for _, name := range strings.Split(s, ",") {
			sec, ok := inspectSections[strings.TrimSpace(name)]
			if !ok {
				return nil, fmt.Errorf("--section must be timeline, lineage, budget, approvals, coverage or gaps, not %q", name)
			}
			req.Include = append(req.Include, sec)
		}
	}
	return req, nil
}

func init() {
	usage := "run inspect RUN_ID [--section timeline|lineage|budget|approvals|coverage|gaps]... [--size N] [--page TOKEN]"
	commands["run inspect"] = command{usage: usage, run: func(ctx context.Context, a *app, args []string) error {
		if len(args) < 1 {
			return errUsage
		}
		fs := flag.NewFlagSet(usage, flag.ContinueOnError)
		fs.SetOutput(a.stderr)
		var sections list
		fs.Var(&sections, "section", "only this section (repeatable, or comma-separated; default: all)")
		n := fs.Int("size", 0, "timeline events per page (at most 500; default 200)")
		tok := fs.String("page", "", "the next timeline page's token")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errUsage
		}
		req, err := inspectRequest(args[0], sections, *n, *tok)
		if err != nil {
			return err
		}
		s, err := a.session()
		if err != nil {
			return err
		}
		res, err := pantherclawv1connect.NewInvestigationServiceClient(s.connect()).InspectRun(ctx, req)
		if err != nil {
			return err
		}
		return a.print(res)
	}}
}
