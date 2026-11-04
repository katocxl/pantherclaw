// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"google.golang.org/protobuf/proto"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/threatmap/domain"
)

// `pclaw threats` (G0 M28 D720) reads the threat map: the PantherClaw
// controls mapped to each MITRE technique and the evidence for them. Every
// text output ends with the Statement; --json prints the API's response. A
// server error is printed with its message as is (FQ1: an API key or access
// token needs Team or higher).

func threatsClient(c clients) pantherclawv1connect.ThreatMapServiceClient { return c.threatmap }

// threatFrameworkOf maps a --framework value to the API's enum.
func threatFrameworkOf(s string) (pb.ThreatFramework, error) {
	switch strings.ToLower(s) {
	case "atlas":
		return pb.ThreatFramework_THREAT_FRAMEWORK_ATLAS, nil
	case "attack":
		return pb.ThreatFramework_THREAT_FRAMEWORK_ATTACK_ENTERPRISE, nil
	}
	return 0, errors.New("--framework: one of atlas, attack")
}

// threatFrameworkOfID reads the framework from a technique id: ATLAS ids
// start with AML.
func threatFrameworkOfID(id string) pb.ThreatFramework {
	if strings.HasPrefix(id, "AML.") {
		return pb.ThreatFramework_THREAT_FRAMEWORK_ATLAS
	}
	return pb.ThreatFramework_THREAT_FRAMEWORK_ATTACK_ENTERPRISE
}

// threatScope is the --agent and --environment filter (one at most).
type threatScope struct{ agent, environment *string }

func threatScopeFlags(fs *flag.FlagSet) threatScope {
	return threatScope{
		agent:       fs.String("agent", "", "only this agent's routes and signals (Prevent, Seen)"),
		environment: fs.String("environment", "", "only this environment's agents (Prevent, Seen)"),
	}
}

func (s threatScope) check() error {
	if *s.agent != "" && *s.environment != "" {
		return errUsage
	}
	return nil
}

// threatsCommand builds a `pclaw threats` command that prints text, or the
// API's JSON with --json.
func threatsCommand(usage string, nargs int, setup func(fs *flag.FlagSet) func(ctx context.Context, c clients, args []string, w io.Writer, asJSON bool) (proto.Message, error)) command {
	return command{usage: usage, run: func(ctx context.Context, a *app, args []string) error {
		if len(args) < nargs {
			return errUsage
		}
		fs := flag.NewFlagSet(usage, flag.ContinueOnError)
		fs.SetOutput(a.stderr)
		asJSON := fs.Bool("json", false, "print the API's response as JSON")
		fn := setup(fs)
		if err := fs.Parse(args[nargs:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errUsage
		}
		c, err := a.clients()
		if err != nil {
			return err
		}
		res, err := fn(ctx, c, args[:nargs], a.stdout, *asJSON)
		if err != nil {
			return err
		}
		if *asJSON && res != nil {
			return a.print(res)
		}
		return nil
	}}
}

func init() {
	commands["threats matrix"] = threatsCommand("threats matrix [--framework atlas|attack] [--agent ID | --environment ID] [--json]", 0,
		func(fs *flag.FlagSet) func(context.Context, clients, []string, io.Writer, bool) (proto.Message, error) {
			fw := fs.String("framework", "atlas", "atlas or attack")
			sc := threatScopeFlags(fs)
			return func(ctx context.Context, c clients, _ []string, w io.Writer, asJSON bool) (proto.Message, error) {
				f, err := threatFrameworkOf(*fw)
				if err != nil {
					return nil, err
				}
				if err := sc.check(); err != nil {
					return nil, err
				}
				res, err := threatsClient(c).GetThreatMatrix(ctx, &pb.GetThreatMatrixRequest{Framework: f, AgentId: *sc.agent, EnvironmentId: *sc.environment})
				if err != nil || asJSON {
					return res, err
				}
				return nil, writeThreatMatrix(w, res)
			}
		})
	commands["threats technique"] = threatsCommand("threats technique ID [--agent ID | --environment ID] [--json]", 1,
		func(fs *flag.FlagSet) func(context.Context, clients, []string, io.Writer, bool) (proto.Message, error) {
			sc := threatScopeFlags(fs)
			return func(ctx context.Context, c clients, a []string, w io.Writer, asJSON bool) (proto.Message, error) {
				if err := sc.check(); err != nil {
					return nil, err
				}
				res, err := threatsClient(c).GetThreatTechnique(ctx, &pb.GetThreatTechniqueRequest{
					Framework: threatFrameworkOfID(a[0]), TechniqueId: a[0], AgentId: *sc.agent, EnvironmentId: *sc.environment,
				})
				if err != nil || asJSON {
					return res, err
				}
				return nil, writeThreatTechnique(w, res)
			}
		})
	commands["threats gaps"] = threatsCommand("threats gaps [--framework atlas|attack] [--agent ID | --environment ID] [--json]", 0,
		func(fs *flag.FlagSet) func(context.Context, clients, []string, io.Writer, bool) (proto.Message, error) {
			fw := fs.String("framework", "atlas", "atlas or attack")
			sc := threatScopeFlags(fs)
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, _ []string, w io.Writer, asJSON bool) (proto.Message, error) {
				f, err := threatFrameworkOf(*fw)
				if err != nil {
					return nil, err
				}
				if err := sc.check(); err != nil {
					return nil, err
				}
				req := &pb.ListThreatGapsRequest{Framework: f, AgentId: *sc.agent, EnvironmentId: *sc.environment, PageSize: size(n), PageToken: *tok}
				if asJSON {
					return threatsClient(c).ListThreatGaps(ctx, req)
				}
				// Text lists every page.
				var gaps []*pb.ThreatGap
				for {
					res, err := threatsClient(c).ListThreatGaps(ctx, req)
					if err != nil {
						return nil, err
					}
					gaps = append(gaps, res.GetGaps()...)
					if res.GetNextPageToken() == "" {
						break
					}
					req.PageToken = res.GetNextPageToken()
				}
				return nil, writeThreatGaps(w, gaps)
			}
		})
	commands["threats export navigator"] = command{
		usage: "threats export navigator --framework atlas|attack [--agent ID | --environment ID] --out FILE",
		run:   threatsExportNavigator,
	}
	commands["threats export report"] = command{
		usage: "threats export report --framework atlas|attack [--environment ID]",
		run:   threatsExportReport,
	}
	commands["threats history"] = threatsCommand("threats history --framework atlas|attack [--environment ID] [--days N] [--json]", 0,
		func(fs *flag.FlagSet) func(context.Context, clients, []string, io.Writer, bool) (proto.Message, error) {
			fw := fs.String("framework", "", "atlas or attack")
			env := fs.String("environment", "", "only this environment")
			days := fs.Int("days", 30, "days of history (1 to 400)")
			return func(ctx context.Context, c clients, _ []string, w io.Writer, asJSON bool) (proto.Message, error) {
				f, err := threatFrameworkOf(*fw)
				if err != nil {
					return nil, err
				}
				res, err := threatsClient(c).GetThreatMapHistory(ctx, &pb.GetThreatMapHistoryRequest{
					Framework: f, EnvironmentId: *env, Days: int32(min(max(*days, 0), 400)),
				})
				if err != nil || asJSON {
					return res, err
				}
				return nil, writeThreatHistory(w, res)
			}
		})
}

func threatsExportNavigator(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("threats export navigator", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	fw := fs.String("framework", "", "atlas or attack")
	sc := threatScopeFlags(fs)
	out := fs.String("out", "", "file to write (must not exist)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" || fs.NArg() != 0 || sc.check() != nil {
		return errUsage
	}
	f, err := threatFrameworkOf(*fw)
	if err != nil {
		return err
	}
	c, err := a.clients()
	if err != nil {
		return err
	}
	res, err := threatsClient(c).ExportNavigatorLayer(ctx, &pb.ExportNavigatorLayerRequest{Framework: f, AgentId: *sc.agent, EnvironmentId: *sc.environment})
	if err != nil {
		return err
	}
	if err := writeNew(*out, res.GetLayerJson()); err != nil {
		return err
	}
	_, err = fmt.Fprintf(a.stdout, "Wrote the ATT&CK Navigator layer %s (%d bytes) to %s.\n\n%s\n", res.GetFileName(), len(res.GetLayerJson()), *out, domain.Statement)
	return err
}

// threatsExportReport creates a signed pack of scope threat_map, like
// `pclaw pack create`.
func threatsExportReport(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("threats export report", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	fw := fs.String("framework", "", "atlas or attack")
	env := fs.String("environment", "", "only this environment's agents (Prevent, Seen)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errUsage
	}
	f, err := threatFrameworkOf(*fw)
	if err != nil {
		return err
	}
	c, err := a.clients()
	if err != nil {
		return err
	}
	res, err := evidenceClient(c).CreateEvidencePack(ctx, &pb.CreateEvidencePackRequest{
		Scope:   &pb.CreateEvidencePackRequest_ThreatMap{ThreatMap: &pb.PackThreatMap{Framework: f, EnvironmentId: *env}},
		Include: &pb.PackContents{},
	})
	if err != nil {
		return err
	}
	return a.print(res)
}

func threatEnum(v fmt.Stringer, prefix string) string {
	return strings.TrimPrefix(v.String(), prefix)
}

func laneState(s pb.ThreatLaneState) string { return threatEnum(s, "THREAT_LANE_STATE_") }
func testState(s pb.ThreatTestState) string { return threatEnum(s, "THREAT_TEST_STATE_") }
func threatStatus(s pb.ThreatStatus) string { return threatEnum(s, "THREAT_STATUS_") }
func threatLane(s pb.ThreatLane) string     { return threatEnum(s, "THREAT_LANE_") }

// threatStatuses is the order techniques are listed in.
var threatStatuses = []pb.ThreatStatus{
	pb.ThreatStatus_THREAT_STATUS_GAP, pb.ThreatStatus_THREAT_STATUS_PARTIAL,
	pb.ThreatStatus_THREAT_STATUS_EVIDENCED, pb.ThreatStatus_THREAT_STATUS_OUTSIDE,
}

// ew writes formatted lines and keeps the first error.
type ew struct {
	w   io.Writer
	err error
}

func (e *ew) f(format string, args ...any) {
	if e.err == nil {
		_, e.err = fmt.Fprintf(e.w, format, args...)
	}
}

func writeThreatMatrix(w io.Writer, m *pb.GetThreatMatrixResponse) error {
	e := &ew{w: w}
	e.f("%s %s, evaluated %s\n", threatEnum(m.GetFramework(), "THREAT_FRAMEWORK_"), m.GetCatalogVersion(), m.GetEvaluatedAt().AsTime().Format("2006-01-02 15:04 MST"))
	if lanes := m.GetOrgWideLanes(); len(lanes) > 0 {
		names := make([]string, 0, len(lanes))
		for _, l := range lanes {
			names = append(names, threatLane(l))
		}
		e.f("Org-wide lanes (the filter does not apply): %s\n", strings.Join(names, ", "))
	}
	e.f("\nTACTIC                               EVIDENCED  PARTIAL  GAP  OUTSIDE\n")
	for _, t := range m.GetTactics() {
		e.f("%-36s %9d %8d %4d %8d\n", t.GetName(), t.GetEvidenced(), t.GetPartial(), t.GetGap(), t.GetOutside())
	}
	for _, s := range threatStatuses {
		var rows []*pb.ThreatTechniqueCell
		for _, t := range m.GetTechniques() {
			if t.GetStatus() == s {
				rows = append(rows, t)
			}
		}
		if len(rows) == 0 {
			continue
		}
		e.f("\n%s (%d)\n", threatStatus(s), len(rows))
		for _, t := range rows {
			e.f("  %-14s %s  [Prevent %s · Detect %s · Respond %s · Test %s]\n", t.GetTechniqueId(), t.GetName(),
				laneState(t.GetPrevent()), laneState(t.GetDetect()), laneState(t.GetRespond()), testState(t.GetTest()))
		}
	}
	e.f("\n%s\n", m.GetStatement())
	return e.err
}

func writeThreatTechnique(w io.Writer, m *pb.GetThreatTechniqueResponse) error {
	e := &ew{w: w}
	writeTechniqueDetail(e, m.GetTechnique())
	for _, s := range m.GetSubtechniques() {
		e.f("\n")
		writeTechniqueDetail(e, s)
	}
	e.f("\n%s\n", m.GetStatement())
	return e.err
}

func writeTechniqueDetail(e *ew, d *pb.ThreatTechniqueDetail) {
	cell := d.GetCell()
	e.f("%s %s: %s\n", cell.GetTechniqueId(), cell.GetName(), threatStatus(cell.GetStatus()))
	if d.GetParentId() != "" {
		e.f("  sub-technique of %s\n", d.GetParentId())
	}
	if d.GetUrl() != "" {
		e.f("  %s\n", d.GetUrl())
	}
	if o := d.GetOutside(); o != nil {
		e.f("  Outside PantherClaw: %s (covered by %s)\n", o.GetReason(), o.GetCoveredBy())
		if o.GetNote() != "" {
			e.f("    %s\n", o.GetNote())
		}
	}
	if d.GetUnaddressedWhy() != "" {
		e.f("  No PantherClaw control yet: %s\n", d.GetUnaddressedWhy())
	}
	p := d.GetPrevent()
	e.f("  Prevent  %s\n", laneState(p.GetState()))
	writeReasons(e, p.GetReasons())
	for _, c := range p.GetControls() {
		e.f("    control %s %s (%s) applies=%t\n", c.GetControlId(), c.GetTitle(), c.GetSurface(), c.GetApplies())
	}
	if r := p.GetRoutes(); r != nil {
		e.f("    routes: enforced %d, partial %d, observe-only %d, unknown %d, stale %d\n",
			r.GetEnforced(), r.GetPartial(), r.GetObserveOnly(), r.GetUnknown(), r.GetStale())
	}
	dt := d.GetDetect()
	e.f("  Detect   %s\n", laneState(dt.GetState()))
	writeReasons(e, dt.GetReasons())
	for _, r := range dt.GetRules() {
		last := "no input yet"
		if r.GetLastInputTime() != nil {
			last = "last input " + r.GetLastInputTime().AsTime().Format("2006-01-02 15:04 MST")
		}
		e.f("    rule %s %s (%s) licensed=%t disabled=%t suppressed=%t, %s\n", r.GetRuleId(), r.GetTitle(),
			threatEnum(r.GetSource(), "THREAT_RULE_SOURCE_"), r.GetLicensed(), r.GetDisabled(), r.GetSuppressed(), last)
	}
	rs := d.GetRespond()
	e.f("  Respond  %s\n", laneState(rs.GetState()))
	writeReasons(e, rs.GetReasons())
	for _, a := range rs.GetAutomations() {
		name := a.GetName()
		if name == "" {
			name = a.GetHubItem()
		}
		e.f("    automation %s %s state=%s contain=%t\n", a.GetAutomationId(), name, a.GetState(), a.GetHasContain())
	}
	ts := d.GetTest()
	e.f("  Test     %s\n", testState(ts.GetState()))
	writeReasons(e, ts.GetReasons())
	for _, s := range ts.GetScenarios() {
		verdict := s.GetVerdict()
		if verdict == "" {
			verdict = "never run"
		}
		e.f("    scenario %s %s: %s\n", s.GetScenarioId(), s.GetTitle(), verdict)
	}
	if s := d.GetSeen(); s != nil {
		e.f("  Seen in %d days: %d alerts, %d refusals, %d holds\n", s.GetWindowDays(), s.GetAlertsRaised(), s.GetRefusals(), s.GetHolds())
	}
	if len(d.GetCampaigns()) > 0 {
		e.f("  Range campaigns (labels only): %s\n", strings.Join(d.GetCampaigns(), ", "))
	}
	for _, g := range d.GetGaps() {
		writeGap(e, g)
	}
}

func writeReasons(e *ew, reasons []string) {
	for _, r := range reasons {
		e.f("    - %s\n", r)
	}
}

func writeGap(e *ew, g *pb.ThreatGap) {
	e.f("  gap %s %s: %s (%s)\n", g.GetTechniqueId(), threatLane(g.GetLane()), g.GetLabel(), g.GetReason())
	if g.GetCommand() != "" {
		e.f("    fix: %s\n", g.GetCommand())
	}
}

func writeThreatGaps(w io.Writer, gaps []*pb.ThreatGap) error {
	e := &ew{w: w}
	if len(gaps) == 0 {
		e.f("No PARTIAL or GAP lane.\n")
	}
	group := "\x00"
	for _, g := range gaps {
		// A gap with no fix the organization can apply (a lane capped only
		// by its sub-techniques) has no fix line (G0 M28 D720c).
		key := g.GetFixKind().String() + "\x00" + g.GetTargetId()
		if key != group {
			e.f("\n")
			group = key
			if g.GetFixKind() != pb.ThreatFixKind_THREAT_FIX_KIND_UNSPECIFIED {
				e.f("%s %s\n", threatEnum(g.GetFixKind(), "THREAT_FIX_KIND_"), g.GetTargetId())
			}
		}
		writeGap(e, g)
	}
	e.f("\n%s\n", domain.Statement)
	return e.err
}

func writeThreatHistory(w io.Writer, h *pb.GetThreatMapHistoryResponse) error {
	e := &ew{w: w}
	e.f("DAY         EVIDENCED  PARTIAL  GAP  OUTSIDE\n")
	for _, d := range h.GetDays() {
		e.f("%-10s %10d %8d %4d %8d\n", d.GetDay(), d.GetEvidenced(), d.GetPartial(), d.GetGap(), d.GetOutside())
	}
	if len(h.GetDrops()) > 0 {
		e.f("\nDropped lanes\n")
	}
	for _, d := range h.GetDrops() {
		e.f("  %s %s %s: %s -> %s\n", d.GetDay(), d.GetTechniqueId(), threatLane(d.GetLane()), d.GetFrom(), d.GetTo())
	}
	e.f("\n%s\n", domain.Statement)
	return e.err
}
