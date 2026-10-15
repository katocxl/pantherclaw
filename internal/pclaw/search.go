// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// pclaw search (G0 M10 D34; G0 M11 part 2 D45–D48): quick find, plain
// questions, structured, built-in and saved queries, and export. Every
// search runs under the caller's own permissions on the server; a question
// is read by a fixed lexicon there (no model), and the answer shows what it
// understood and what it did not.

type searchCall func(ctx context.Context, c pantherclawv1connect.SearchServiceClient, args []string) (proto.Message, error)

// searchRPC is rpc for SearchService.
func searchRPC(usage string, nargs int, setup func(fs *flag.FlagSet) searchCall) command {
	return command{usage: usage, run: func(ctx context.Context, a *app, args []string) error {
		if len(args) < nargs {
			return errUsage
		}
		fs := flag.NewFlagSet(usage, flag.ContinueOnError)
		fs.SetOutput(a.stderr)
		fn := setup(fs)
		if err := fs.Parse(args[nargs:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errUsage
		}
		s, err := a.session()
		if err != nil {
			return err
		}
		res, err := fn(ctx, pantherclawv1connect.NewSearchServiceClient(s.connect()), args[:nargs])
		if err != nil {
			return err
		}
		if res == nil {
			return nil
		}
		return a.print(res)
	}}
}

// sourceFlags declares the flags that name a search.
func sourceFlags(fs *flag.FlagSet) func() (*pantherclawv1.SearchSource, error) {
	query := fs.String("query", "", `a structured query as JSON, e.g. '{"entity":"transactions","filters":{"decisions":["DENY"]}}'`)
	builtin := fs.String("builtin", "", `a built-in query as JSON, e.g. '{"name":"unused_grants","params":{"days":30}}'`)
	saved := fs.String("saved", "", "a saved query id")
	return func() (*pantherclawv1.SearchSource, error) {
		src := &pantherclawv1.SearchSource{}
		n := 0
		if *query != "" {
			src.Query = &pantherclawv1.Query{}
			if err := protojson.Unmarshal([]byte(*query), src.Query); err != nil {
				return nil, fmt.Errorf("--query: %w", err)
			}
			n++
		}
		if *builtin != "" {
			src.Builtin = &pantherclawv1.BuiltinQuery{}
			if err := protojson.Unmarshal([]byte(*builtin), src.Builtin); err != nil {
				return nil, fmt.Errorf("--builtin: %w", err)
			}
			n++
		}
		if *saved != "" {
			src.SavedQueryId = saved
			n++
		}
		if n != 1 {
			return nil, errors.New("give one of --query, --builtin and --saved")
		}
		return src, nil
	}
}

func searchCommands() map[string]command {
	return map[string]command{
		"find": searchRPC("search find TEXT [--kind KIND]... [--limit N]", 1, func(fs *flag.FlagSet) searchCall {
			var kinds list
			fs.Var(&kinds, "kind", "a kind to match (agents, connections, cases, incidents, alerts, packages, gateways, service_accounts, people, runs, transactions, grants, approvals, findings, policy_versions, audit); repeatable")
			limit := fs.Int("limit", 0, "matches per kind (default 5, at most 10)")
			return func(ctx context.Context, c pantherclawv1connect.SearchServiceClient, a []string) (proto.Message, error) {
				return c.Find(ctx, &pantherclawv1.FindRequest{Text: a[0], Kinds: kinds, Limit: int32(*limit)}) //nolint:gosec // G115: validated by the server
			}
		}),
		"ask": searchRPC(`search ask "QUESTION" [--tz ZONE] [--explain] [--size N] [--page TOKEN]`, 1, func(fs *flag.FlagSet) searchCall {
			tz := fs.String("tz", "", "the IANA time zone dates are read in (default UTC)")
			explain := fs.Bool("explain", false, "only show how the question is read; run nothing")
			size := fs.Int("size", 0, "results per page (default 50, at most 200)")
			token := fs.String("page", "", "page token from a previous answer")
			return func(ctx context.Context, c pantherclawv1connect.SearchServiceClient, a []string) (proto.Message, error) {
				if *explain {
					return c.Interpret(ctx, &pantherclawv1.InterpretRequest{Question: a[0], Timezone: *tz})
				}
				return c.Ask(ctx, &pantherclawv1.AskRequest{Question: a[0], Timezone: *tz, PageSize: int32(*size), PageToken: *token}) //nolint:gosec // G115: validated by the server
			}
		}),
		"run": searchRPC("search run ENTITY [--filters JSON] [--size N] [--page TOKEN]", 1, func(fs *flag.FlagSet) searchCall {
			filters := fs.String("filters", "", `typed filters as JSON, e.g. '{"agentId":"…","states":["ACTIVE"]}'`)
			size := fs.Int("size", 0, "results per page (default 50, at most 200)")
			token := fs.String("page", "", "page token from a previous result")
			return func(ctx context.Context, c pantherclawv1connect.SearchServiceClient, a []string) (proto.Message, error) {
				q := &pantherclawv1.Query{Entity: a[0], Filters: &pantherclawv1.SearchFilters{}}
				if *filters != "" {
					if err := protojson.Unmarshal([]byte(*filters), q.Filters); err != nil {
						return nil, fmt.Errorf("--filters: %w", err)
					}
				}
				return c.Search(ctx, &pantherclawv1.SearchRequest{Query: q, PageSize: int32(*size), PageToken: *token}) //nolint:gosec // G115: validated by the server
			}
		}),
		"builtin": searchRPC("search builtin NAME|list [--params JSON] [--size N] [--page TOKEN]", 1, func(fs *flag.FlagSet) searchCall {
			params := fs.String("params", "", `parameters as JSON, e.g. '{"incidentId":"…","days":7}'`)
			size := fs.Int("size", 0, "results per page (default 50, at most 200)")
			token := fs.String("page", "", "page token from a previous result")
			return func(ctx context.Context, c pantherclawv1connect.SearchServiceClient, a []string) (proto.Message, error) {
				if a[0] == "list" {
					return c.ListBuiltinQueries(ctx, &pantherclawv1.ListBuiltinQueriesRequest{})
				}
				b := &pantherclawv1.BuiltinQuery{Name: a[0], Params: &pantherclawv1.BuiltinParams{}}
				if *params != "" {
					if err := protojson.Unmarshal([]byte(*params), b.Params); err != nil {
						return nil, fmt.Errorf("--params: %w", err)
					}
				}
				return c.RunBuiltinQuery(ctx, &pantherclawv1.RunBuiltinQueryRequest{Query: b, PageSize: int32(*size), PageToken: *token}) //nolint:gosec // G115: validated by the server
			}
		}),
		"saved": group("search saved", map[string]command{
			"list": searchRPC("search saved list [--size N] [--page TOKEN]", 0, func(fs *flag.FlagSet) searchCall {
				size := fs.Int("size", 0, "queries per page (default 50, at most 200)")
				token := fs.String("page", "", "page token from a previous list")
				return func(ctx context.Context, c pantherclawv1connect.SearchServiceClient, _ []string) (proto.Message, error) {
					return c.ListSavedQueries(ctx, &pantherclawv1.ListSavedQueriesRequest{PageSize: int32(*size), PageToken: *token}) //nolint:gosec // G115: validated by the server
				}
			}),
			"save": searchRPC("search saved save NAME (--query JSON | --builtin JSON) [--description TEXT] [--visibility PRIVATE|TEAM|ORG] [--team ID]", 1, func(fs *flag.FlagSet) searchCall {
				src := sourceFlags(fs)
				desc := fs.String("description", "", "what the query is for")
				vis := fs.String("visibility", "PRIVATE", "PRIVATE, TEAM or ORG (whoever runs it runs it under their own permissions)")
				team := fs.String("team", "", "the team a TEAM query is shared with")
				return func(ctx context.Context, c pantherclawv1connect.SearchServiceClient, a []string) (proto.Message, error) {
					s, err := src()
					if err != nil {
						return nil, err
					}
					if s.SavedQueryId != nil {
						return nil, errors.New("save takes --query or --builtin")
					}
					in := &pantherclawv1.SavedQueryInput{Name: a[0], Description: *desc, Visibility: strings.ToUpper(*vis),
						Query: s.GetQuery(), Builtin: s.GetBuiltin()}
					if *team != "" {
						in.TeamId = team
					}
					return c.SaveQuery(ctx, &pantherclawv1.SaveQueryRequest{Input: in})
				}
			}),
			"run": searchRPC("search saved run ID [--size N] [--page TOKEN]", 1, func(fs *flag.FlagSet) searchCall {
				size := fs.Int("size", 0, "results per page (default 50, at most 200)")
				token := fs.String("page", "", "page token from a previous result")
				return func(ctx context.Context, c pantherclawv1connect.SearchServiceClient, a []string) (proto.Message, error) {
					return c.RunSavedQuery(ctx, &pantherclawv1.RunSavedQueryRequest{Id: a[0], PageSize: int32(*size), PageToken: *token}) //nolint:gosec // G115: validated by the server
				}
			}),
		}),
		"export": exportCommand(),
	}
}

// exportCommand writes the exported rows to --out (or stdout) and what the
// export covers to stderr.
func exportCommand() command {
	usage := "search export (--query JSON | --builtin JSON | --saved ID) [--format json|csv] [--out FILE]"
	return command{usage: usage, run: func(ctx context.Context, a *app, args []string) error {
		fs := flag.NewFlagSet(usage, flag.ContinueOnError)
		fs.SetOutput(a.stderr)
		src := sourceFlags(fs)
		format := fs.String("format", "json", "json or csv")
		out := fs.String("out", "", "the file to write (default: stdout)")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errUsage
		}
		s, err := src()
		if err != nil {
			return err
		}
		sess, err := a.session()
		if err != nil {
			return err
		}
		res, err := pantherclawv1connect.NewSearchServiceClient(sess.connect()).ExportResults(ctx,
			&pantherclawv1.ExportResultsRequest{Source: s, Format: strings.ToUpper(*format)})
		if err != nil {
			return err
		}
		if *out != "" {
			if err := os.WriteFile(*out, res.GetData(), 0o600); err != nil {
				return err
			}
		} else if _, err := a.stdout.Write(res.GetData()); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(a.stderr, "exported %d rows (%s) as of %s; audit entry %s\n", res.GetRows(), res.GetScopePermission(),
			res.GetAsOfTime().AsTime().Format("2006-01-02T15:04:05Z07:00"), res.GetAuditEntryId())
		if res.GetTruncated() {
			_, _ = fmt.Fprintln(a.stderr, "truncated: the export stops at 10000 rows")
		}
		for _, o := range res.GetOmissions() {
			_, _ = fmt.Fprintf(a.stderr, "%s: %s\n", o.GetCode(), o.GetDetail())
		}
		return nil
	}}
}

func init() {
	commands["search"] = group("search", searchCommands())
}
