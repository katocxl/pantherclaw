// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"flag"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// pclaw policy simulate (G0 M11.1 D15, Team edition): what a stored policy
// version would have decided over the org's recorded decisions. The report
// separates newly denied, held, constrained and allowed (expanded
// exposure), changed reasons and unevaluable decisions; it predicts
// decisions, not agent replanning or business outcomes. Samples carry ids,
// decisions and reason codes; `pclaw evidence replay` shows one in full.

type simulationCall func(ctx context.Context, c pantherclawv1connect.PolicySimulationServiceClient, args []string) (proto.Message, error)

// simulationPoll is how often --wait asks for the simulation's state.
var simulationPoll = 2 * time.Second

// simulationRPC is rpc for PolicySimulationService.
func simulationRPC(usage string, nargs int, setup func(fs *flag.FlagSet) simulationCall) command {
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
		res, err := fn(ctx, pantherclawv1connect.NewPolicySimulationServiceClient(s.connect()), args[:nargs])
		if err != nil {
			return err
		}
		return a.print(res)
	}}
}

var simulationCategories = map[string]pantherclawv1.PolicySimulationCategory{
	"unchanged":         pantherclawv1.PolicySimulationCategory_POLICY_SIMULATION_CATEGORY_UNCHANGED,
	"newly_denied":      pantherclawv1.PolicySimulationCategory_POLICY_SIMULATION_CATEGORY_NEWLY_DENIED,
	"newly_held":        pantherclawv1.PolicySimulationCategory_POLICY_SIMULATION_CATEGORY_NEWLY_HELD,
	"newly_constrained": pantherclawv1.PolicySimulationCategory_POLICY_SIMULATION_CATEGORY_NEWLY_CONSTRAINED,
	"newly_allowed":     pantherclawv1.PolicySimulationCategory_POLICY_SIMULATION_CATEGORY_NEWLY_ALLOWED,
	"reason_changed":    pantherclawv1.PolicySimulationCategory_POLICY_SIMULATION_CATEGORY_REASON_CHANGED,
	"unevaluable":       pantherclawv1.PolicySimulationCategory_POLICY_SIMULATION_CATEGORY_UNEVALUABLE,
}

func simulationRunning(s *pantherclawv1.PolicySimulation) bool {
	st := s.GetState()
	return st == pantherclawv1.PolicySimulationState_POLICY_SIMULATION_STATE_QUEUED ||
		st == pantherclawv1.PolicySimulationState_POLICY_SIMULATION_STATE_RUNNING
}

// waitSimulation polls until the simulation finishes or ctx ends.
func waitSimulation(ctx context.Context, c pantherclawv1connect.PolicySimulationServiceClient, s *pantherclawv1.PolicySimulation) (
	*pantherclawv1.PolicySimulation, error,
) {
	t := time.NewTicker(simulationPoll)
	defer t.Stop()
	for simulationRunning(s) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-t.C:
		}
		res, err := c.GetSimulation(ctx, &pantherclawv1.GetSimulationRequest{Id: s.GetId()})
		if err != nil {
			return nil, err
		}
		s = res.GetSimulation()
	}
	return s, nil
}

func init() {
	categoryList := strings.Join(slices.Sorted(maps.Keys(simulationCategories)), ", ")
	for name, c := range map[string]command{
		"policy simulate": simulationRPC("policy simulate VERSION_ID [--days N] [--max N] [--wait]", 1, func(fs *flag.FlagSet) simulationCall {
			days := fs.Int("days", 0, "the window ending now, in days (default 7, at most 30, inside retention)")
			maxN := fs.Int("max", 0, "most recorded decisions to replay (default 10000, at most 50000)")
			wait := fs.Bool("wait", false, "wait for the simulation to finish and print its report")
			return func(ctx context.Context, c pantherclawv1connect.PolicySimulationServiceClient, a []string) (proto.Message, error) {
				if *days < 0 || *days > 30 || *maxN < 0 || *maxN > 50000 {
					return nil, fmt.Errorf("--days must be 1 to 30 and --max 1 to 50000")
				}
				res, err := c.SimulatePolicyVersion(ctx, &pantherclawv1.SimulatePolicyVersionRequest{
					VersionId: a[0], Days: int32(*days), MaxEvaluations: int32(*maxN),
				})
				if err != nil || !*wait {
					return res, err
				}
				s, err := waitSimulation(ctx, c, res.GetSimulation())
				if err != nil {
					return nil, err
				}
				return &pantherclawv1.GetSimulationResponse{Simulation: s}, nil
			}
		}),
		"simulation get": simulationRPC("simulation get ID", 1, func(*flag.FlagSet) simulationCall {
			return func(ctx context.Context, c pantherclawv1connect.PolicySimulationServiceClient, a []string) (proto.Message, error) {
				return c.GetSimulation(ctx, &pantherclawv1.GetSimulationRequest{Id: a[0]})
			}
		}),
		"simulation list": simulationRPC("simulation list [--page-size N] [--page-token T]", 0, func(fs *flag.FlagSet) simulationCall {
			n, tok := paging(fs)
			return func(ctx context.Context, c pantherclawv1connect.PolicySimulationServiceClient, _ []string) (proto.Message, error) {
				return c.ListSimulations(ctx, &pantherclawv1.ListSimulationsRequest{PageSize: size(n), PageToken: *tok})
			}
		}),
		"simulation cancel": simulationRPC("simulation cancel ID", 1, func(*flag.FlagSet) simulationCall {
			return func(ctx context.Context, c pantherclawv1connect.PolicySimulationServiceClient, a []string) (proto.Message, error) {
				return c.CancelSimulation(ctx, &pantherclawv1.CancelSimulationRequest{Id: a[0]})
			}
		}),
		"simulation samples": simulationRPC("simulation samples ID [--category C] [--operation OP] [--page-size N] [--page-token T]", 1,
			func(fs *flag.FlagSet) simulationCall {
				cat := fs.String("category", "", "only this category: "+categoryList)
				op := fs.String("operation", "", "only this operation")
				n, tok := paging(fs)
				return func(ctx context.Context, c pantherclawv1connect.PolicySimulationServiceClient, a []string) (proto.Message, error) {
					req := &pantherclawv1.ListSimulationSamplesRequest{SimulationId: a[0], Operation: *op, PageSize: size(n), PageToken: *tok}
					if *cat != "" {
						v, ok := simulationCategories[*cat]
						if !ok {
							return nil, fmt.Errorf("--category must be one of %s", categoryList)
						}
						req.Category = v
					}
					return c.ListSimulationSamples(ctx, req)
				}
			}),
	} {
		commands[name] = c
	}
}
