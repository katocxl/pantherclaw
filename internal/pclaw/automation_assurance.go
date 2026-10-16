// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
	"flag"
	"os"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// pclaw automation test|simulate|rollout|status|inspect|blast-radius|
// compare|metrics (G0 M11 part 2 D34–D38, D59): scenario tests and the
// TESTED gate, historical simulation, rollout evidence, status, the
// pre-enable inspection and the authority previews. Tests and simulations
// run in memory or over history and never issue, start, deliver or notify.

type assuranceCall func(ctx context.Context, c pantherclawv1connect.AssuranceServiceClient, args []string) (proto.Message, error)

// assuranceRPC is rpc for AssuranceService.
func assuranceRPC(usage string, nargs int, setup func(fs *flag.FlagSet) assuranceCall) command {
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
		res, err := fn(ctx, pantherclawv1connect.NewAssuranceServiceClient(s.connect()), args[:nargs])
		if err != nil {
			return err
		}
		return a.print(res)
	}}
}

// errCasesFile asks for the cases file.
var errCasesFile = errors.New("--file names a JSON file of test cases ({\"cases\": [...]}, as SetTestCases takes them)")

// automationSimPoll is how often --wait asks for a simulation's state.
var automationSimPoll = 2 * time.Second

func waitAutomationSimulation(ctx context.Context, c pantherclawv1connect.AssuranceServiceClient, id string) (proto.Message, error) {
	t := time.NewTicker(automationSimPoll)
	defer t.Stop()
	for {
		res, err := c.GetAutomationSimulation(ctx, &pantherclawv1.GetAutomationSimulationRequest{Id: id})
		if err != nil {
			return nil, err
		}
		if st := res.GetSimulation().GetState(); st != "QUEUED" && st != "RUNNING" {
			return res, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-t.C:
		}
	}
}

func init() {
	for name, c := range map[string]command{
		"automation test set": assuranceRPC("automation test set VERSION_ID --file CASES.json", 1, func(fs *flag.FlagSet) assuranceCall {
			file := fs.String("file", "", "JSON test cases: {\"cases\": [...]}")
			return func(ctx context.Context, c pantherclawv1connect.AssuranceServiceClient, args []string) (proto.Message, error) {
				if *file == "" {
					return nil, errCasesFile
				}
				raw, err := os.ReadFile(*file)
				if err != nil {
					return nil, err
				}
				req := &pantherclawv1.SetTestCasesRequest{}
				if err := protojson.Unmarshal(raw, req); err != nil {
					return nil, errors.Join(errCasesFile, err)
				}
				req.VersionId = args[0]
				return c.SetTestCases(ctx, req)
			}
		}),
		"automation test list": assuranceRPC("automation test list VERSION_ID", 1, func(*flag.FlagSet) assuranceCall {
			return func(ctx context.Context, c pantherclawv1connect.AssuranceServiceClient, args []string) (proto.Message, error) {
				return c.ListTestCases(ctx, &pantherclawv1.ListTestCasesRequest{VersionId: args[0]})
			}
		}),
		"automation test run": assuranceRPC("automation test run VERSION_ID", 1, func(*flag.FlagSet) assuranceCall {
			return func(ctx context.Context, c pantherclawv1connect.AssuranceServiceClient, args []string) (proto.Message, error) {
				return c.RunTests(ctx, &pantherclawv1.RunTestsRequest{VersionId: args[0]})
			}
		}),
		"automation test get": assuranceRPC("automation test get RUN_ID", 1, func(*flag.FlagSet) assuranceCall {
			return func(ctx context.Context, c pantherclawv1connect.AssuranceServiceClient, args []string) (proto.Message, error) {
				return c.GetTestRun(ctx, &pantherclawv1.GetTestRunRequest{Id: args[0]})
			}
		}),
		"automation simulate": assuranceRPC("automation simulate VERSION_ID [--days N] [--wait]", 1, func(fs *flag.FlagSet) assuranceCall {
			days := fs.Int("days", 7, "the period ending now, in days (at most 30)")
			wait := fs.Bool("wait", false, "wait for the simulation to finish and print it")
			return func(ctx context.Context, c pantherclawv1connect.AssuranceServiceClient, args []string) (proto.Message, error) {
				end := time.Now().UTC()
				res, err := c.StartAutomationSimulation(ctx, &pantherclawv1.StartAutomationSimulationRequest{
					VersionId: args[0], StartTime: timestamppb.New(end.Add(-time.Duration(*days) * 24 * time.Hour)),
					EndTime: timestamppb.New(end),
				})
				if err != nil || !*wait {
					return res, err
				}
				return waitAutomationSimulation(ctx, c, res.GetSimulationId())
			}
		}),
		"automation simulation get": assuranceRPC("automation simulation get SIMULATION_ID", 1, func(*flag.FlagSet) assuranceCall {
			return func(ctx context.Context, c pantherclawv1connect.AssuranceServiceClient, args []string) (proto.Message, error) {
				return c.GetAutomationSimulation(ctx, &pantherclawv1.GetAutomationSimulationRequest{Id: args[0]})
			}
		}),
		"automation rollout": assuranceRPC("automation rollout AUTOMATION_ID", 1, func(*flag.FlagSet) assuranceCall {
			return func(ctx context.Context, c pantherclawv1connect.AssuranceServiceClient, args []string) (proto.Message, error) {
				return c.GetRolloutReport(ctx, &pantherclawv1.GetRolloutReportRequest{AutomationId: args[0]})
			}
		}),
		"automation status": assuranceRPC("automation status AUTOMATION_ID", 1, func(*flag.FlagSet) assuranceCall {
			return func(ctx context.Context, c pantherclawv1connect.AssuranceServiceClient, args []string) (proto.Message, error) {
				return c.GetAutomationStatus(ctx, &pantherclawv1.GetAutomationStatusRequest{AutomationId: args[0]})
			}
		}),
		"automation inspect": assuranceRPC("automation inspect VERSION_ID", 1, func(*flag.FlagSet) assuranceCall {
			return func(ctx context.Context, c pantherclawv1connect.AssuranceServiceClient, args []string) (proto.Message, error) {
				return c.InspectVersion(ctx, &pantherclawv1.InspectVersionRequest{VersionId: args[0]})
			}
		}),
		"automation blast-radius": assuranceRPC("automation blast-radius VERSION_ID", 1, func(*flag.FlagSet) assuranceCall {
			return func(ctx context.Context, c pantherclawv1connect.AssuranceServiceClient, args []string) (proto.Message, error) {
				return c.PreviewBlastRadius(ctx, &pantherclawv1.PreviewBlastRadiusRequest{VersionId: args[0]})
			}
		}),
		"automation compare": assuranceRPC("automation compare VERSION_ID --ceiling CEILING.json", 1, func(fs *flag.FlagSet) assuranceCall {
			file := fs.String("ceiling", "", "the narrowed ceiling as JSON (the version's authority.ceiling)")
			return func(ctx context.Context, c pantherclawv1connect.AssuranceServiceClient, args []string) (proto.Message, error) {
				if *file == "" {
					return nil, errUsage
				}
				raw, err := os.ReadFile(*file)
				if err != nil {
					return nil, err
				}
				return c.CompareRestriction(ctx, &pantherclawv1.CompareRestrictionRequest{VersionId: args[0], NarrowedCeiling: raw})
			}
		}),
		"automation metrics": assuranceRPC("automation metrics [--automation ID] [--hours N]", 0, func(fs *flag.FlagSet) assuranceCall {
			auto := fs.String("automation", "", "one automation (default: all you may read)")
			hours := fs.Int("hours", 24, "the hours ending now (at most 720)")
			return func(ctx context.Context, c pantherclawv1connect.AssuranceServiceClient, _ []string) (proto.Message, error) {
				end := time.Now().UTC()
				return c.GetAutomationMetrics(ctx, &pantherclawv1.GetAutomationMetricsRequest{
					AutomationId: *auto, StartTime: timestamppb.New(end.Add(-time.Duration(*hours) * time.Hour)),
					EndTime: timestamppb.New(end),
				})
			}
		}),
	} {
		commands[name] = c
	}
}
