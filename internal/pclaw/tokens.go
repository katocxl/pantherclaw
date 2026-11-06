// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// pclaw tokens report (G0 M29 D825; F988): one UTC month of the org's
// model calls as a table, grouped by team, agent, connection or model, and
// the statement every report carries. Costs are labeled estimates
// (HR-698). The Team edition and budget.read at the org.

var tokenGroupings = map[string]pantherclawv1.TokenReportGroupBy{
	"team":       pantherclawv1.TokenReportGroupBy_TOKEN_REPORT_GROUP_BY_TEAM,
	"agent":      pantherclawv1.TokenReportGroupBy_TOKEN_REPORT_GROUP_BY_AGENT,
	"connection": pantherclawv1.TokenReportGroupBy_TOKEN_REPORT_GROUP_BY_CONNECTION,
	"model":      pantherclawv1.TokenReportGroupBy_TOKEN_REPORT_GROUP_BY_MODEL,
}

func init() {
	usage := "tokens report [--month YYYY-MM] [--by team|agent|connection|model] [--size N] [--page TOKEN] [--json]"
	commands["tokens report"] = command{usage: usage, run: func(ctx context.Context, a *app, args []string) error {
		fs := flag.NewFlagSet(usage, flag.ContinueOnError)
		fs.SetOutput(a.stderr)
		month := fs.String("month", time.Now().UTC().Format("2006-01"), "the UTC month (default: this month)")
		by := fs.String("by", "team", "group by team, agent, connection or model")
		size := fs.Int("size", 0, "rows per page (at most 200; default 50)")
		page := fs.String("page", "", "the next page's token")
		asJSON := fs.Bool("json", false, "print the answer as JSON")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errUsage
		}
		g, ok := tokenGroupings[*by]
		if !ok {
			return fmt.Errorf("--by must be team, agent, connection or model, not %q", *by)
		}
		s, err := a.session()
		if err != nil {
			return err
		}
		res, err := pantherclawv1connect.NewModelUsageServiceClient(s.connect()).GetTokenReport(ctx, &pantherclawv1.GetTokenReportRequest{
			Month: *month, GroupBy: g, PageSize: int32(min(max(*size, 0), 200)), PageToken: *page,
		})
		if err != nil {
			return err
		}
		if *asJSON {
			return a.print(res)
		}
		return printTokenReport(a.stdout, *by, res)
	}}
}

// printTokenReport prints the report as a table, then the statement.
func printTokenReport(w io.Writer, by string, res *pantherclawv1.GetTokenReportResponse) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintf(tw, "%s\tCALLS\tUNREPORTED\tUNKNOWN\tINPUT\tOUTPUT\tCACHE READ\tCACHE WRITE\tTOTAL\tESTIMATE\n", strings.ToUpper(by))
	for _, r := range res.GetRows() {
		label := r.GetLabel()
		if label == "" {
			label = "(none)"
		}
		est := make([]string, 0, len(r.GetEstimates()))
		for _, e := range r.GetEstimates() {
			est = append(est, e.GetAmount()+" "+e.GetCurrency())
		}
		estimate := "-"
		if len(est) > 0 {
			estimate = strings.Join(est, ", ") + " (estimate)"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s\n", label, r.GetCalls(), r.GetUnreportedCalls(), r.GetUnknownCalls(),
			r.GetInputTokens(), r.GetOutputTokens(), r.GetCacheReadTokens(), r.GetCacheWriteTokens(), r.GetTotalTokens(), estimate)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if t := res.GetNextPageToken(); t != "" {
		_, _ = fmt.Fprintln(w, "next page: --page "+strconv.Quote(t))
	}
	_, err := fmt.Fprintln(w, res.GetStatement())
	return err
}
