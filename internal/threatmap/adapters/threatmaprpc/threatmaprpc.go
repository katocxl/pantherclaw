// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package threatmaprpc serves ThreatMapService over Connect (G0 M28 D721).
// Handlers only translate: authentication, the coarse permission check and
// protovalidate have run before a handler is called, and the use cases check
// the credential, edition and scope.
package threatmaprpc

import (
	"context"
	"encoding/base64"
	"strconv"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/threatmap/app"
	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
	"github.com/katocxl/pantherclaw/internal/threatmap/domain"
)

// Handler serves ThreatMapService.
type Handler struct {
	pantherclawv1connect.UnimplementedThreatMapServiceHandler
	svc *app.Service
}

// New returns the ThreatMapService handler.
func New(svc *app.Service) *Handler { return &Handler{svc: svc} }

var frameworks = map[catalog.Framework]pb.ThreatFramework{
	catalog.FrameworkATLAS:  pb.ThreatFramework_THREAT_FRAMEWORK_ATLAS,
	catalog.FrameworkATTACK: pb.ThreatFramework_THREAT_FRAMEWORK_ATTACK_ENTERPRISE,
}

// FrameworkOf is the catalog framework of a proto value, empty for none.
func FrameworkOf(f pb.ThreatFramework) catalog.Framework {
	for k, v := range frameworks {
		if v == f {
			return k
		}
	}
	return ""
}

// ProtoFramework is the proto value of a catalog framework.
func ProtoFramework(f catalog.Framework) pb.ThreatFramework { return frameworks[f] }

var laneStates = map[domain.LaneState]pb.ThreatLaneState{
	domain.LaneEvidenced: pb.ThreatLaneState_THREAT_LANE_STATE_EVIDENCED, domain.LanePartial: pb.ThreatLaneState_THREAT_LANE_STATE_PARTIAL,
	domain.LaneGap: pb.ThreatLaneState_THREAT_LANE_STATE_GAP, domain.LaneStated: pb.ThreatLaneState_THREAT_LANE_STATE_STATED,
	domain.LaneNoneShipped: pb.ThreatLaneState_THREAT_LANE_STATE_NONE_SHIPPED,
}

var testStates = map[domain.TestState]pb.ThreatTestState{
	domain.TestPassed: pb.ThreatTestState_THREAT_TEST_STATE_PASSED, domain.TestFailed: pb.ThreatTestState_THREAT_TEST_STATE_FAILED,
	domain.TestStale: pb.ThreatTestState_THREAT_TEST_STATE_STALE, domain.TestNotRun: pb.ThreatTestState_THREAT_TEST_STATE_NOT_RUN,
}

var statuses = map[domain.Status]pb.ThreatStatus{
	domain.StatusEvidenced: pb.ThreatStatus_THREAT_STATUS_EVIDENCED, domain.StatusPartial: pb.ThreatStatus_THREAT_STATUS_PARTIAL,
	domain.StatusGap: pb.ThreatStatus_THREAT_STATUS_GAP, domain.StatusOutside: pb.ThreatStatus_THREAT_STATUS_OUTSIDE,
}

var lanes = map[domain.Lane]pb.ThreatLane{
	domain.LanePrevent: pb.ThreatLane_THREAT_LANE_PREVENT, domain.LaneDetect: pb.ThreatLane_THREAT_LANE_DETECT,
	domain.LaneRespond: pb.ThreatLane_THREAT_LANE_RESPOND, domain.LaneTest: pb.ThreatLane_THREAT_LANE_TEST,
}

var fixKinds = map[domain.FixKind]pb.ThreatFixKind{
	domain.FixEnableRule: pb.ThreatFixKind_THREAT_FIX_KIND_ENABLE_RULE, domain.FixEndSuppression: pb.ThreatFixKind_THREAT_FIX_KIND_END_SUPPRESSION,
	domain.FixSendEvents: pb.ThreatFixKind_THREAT_FIX_KIND_SEND_EVENTS, domain.FixUpgradeEdition: pb.ThreatFixKind_THREAT_FIX_KIND_UPGRADE_EDITION,
	domain.FixTurnOnSetting:       pb.ThreatFixKind_THREAT_FIX_KIND_TURN_ON_SETTING,
	domain.FixRouteThroughGateway: pb.ThreatFixKind_THREAT_FIX_KIND_ROUTE_THROUGH_GATEWAY,
	domain.FixEnablePlaybook:      pb.ThreatFixKind_THREAT_FIX_KIND_ENABLE_PLAYBOOK,
	domain.FixInstallHubItem:      pb.ThreatFixKind_THREAT_FIX_KIND_INSTALL_HUB_ITEM,
	domain.FixRunScenario:         pb.ThreatFixKind_THREAT_FIX_KIND_RUN_SCENARIO, domain.FixNone: pb.ThreatFixKind_THREAT_FIX_KIND_NONE,
}

var sources = map[domain.RuleSource]pb.ThreatRuleSource{
	domain.SourceBuiltin: pb.ThreatRuleSource_THREAT_RULE_SOURCE_BUILTIN, domain.SourceKind: pb.ThreatRuleSource_THREAT_RULE_SOURCE_KIND,
	domain.SourceHub: pb.ThreatRuleSource_THREAT_RULE_SOURCE_HUB, domain.SourceCustom: pb.ThreatRuleSource_THREAT_RULE_SOURCE_CUSTOM,
}

// scope reads the request's filter; protovalidate has checked the ids.
func scope(agent, env string) (app.Scope, error) {
	var sc app.Scope
	var err error
	if agent != "" {
		if sc.Agent, err = ids.ParseUUID(agent); err != nil {
			return sc, err
		}
	}
	if env != "" {
		if sc.Environment, err = ids.ParseUUID(env); err != nil {
			return sc, err
		}
	}
	return sc, nil
}

func ts(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

func strs[T ~string](in []T) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, string(s))
	}
	return out
}

// ListThreatFrameworks implements ThreatMapServiceHandler.
func (h *Handler) ListThreatFrameworks(ctx context.Context, _ *pb.ListThreatFrameworksRequest) (*pb.ListThreatFrameworksResponse, error) {
	list, err := h.svc.Frameworks(ctx)
	if err != nil {
		return nil, err
	}
	out := &pb.ListThreatFrameworksResponse{}
	for _, f := range list {
		out.Frameworks = append(out.Frameworks, &pb.ThreatFrameworkInfo{
			Framework: frameworks[f.Framework], Title: f.Title, CatalogVersion: f.CatalogVersion, CatalogDigest: f.CatalogDigest,
			TechniqueCount: int32(f.Techniques), TacticCount: int32(f.Tactics), //nolint:gosec // G115: catalog sizes
		})
	}
	return out, nil
}

// Cell is a technique's matrix cell.
func Cell(t domain.Technique) *pb.ThreatTechniqueCell {
	return &pb.ThreatTechniqueCell{
		TechniqueId: t.ID, Name: t.Name, TacticIds: t.Tactics, Status: statuses[t.Status],
		Prevent: laneStates[t.Prevent.State], Detect: laneStates[t.Detect.State], Respond: laneStates[t.Respond.State],
		Test: testStates[t.Test.State], SubtechniqueCount: int32(len(t.Subtechniques)), GapCount: int32(len(t.Gaps)), //nolint:gosec // G115: catalog sizes
	}
}

// Tactic is a tactic column.
func Tactic(t domain.TacticCount) *pb.ThreatTactic {
	return &pb.ThreatTactic{
		TacticId: t.ID, ShortName: t.ShortName, Name: t.Name, Order: int32(t.Order), TechniqueIds: t.TechniqueIDs, //nolint:gosec // G115: catalog sizes
		Evidenced: int32(t.Evidenced), Partial: int32(t.Partial), Gap: int32(t.Gap), Outside: int32(t.Outside), //nolint:gosec // G115: catalog sizes
	}
}

// GetThreatMatrix implements ThreatMapServiceHandler.
func (h *Handler) GetThreatMatrix(ctx context.Context, req *pb.GetThreatMatrixRequest) (*pb.GetThreatMatrixResponse, error) {
	sc, err := scope(req.GetAgentId(), req.GetEnvironmentId())
	if err != nil {
		return nil, err
	}
	m, err := h.svc.Matrix(ctx, FrameworkOf(req.GetFramework()), sc)
	if err != nil {
		return nil, err
	}
	out := &pb.GetThreatMatrixResponse{
		Framework: req.GetFramework(), CatalogVersion: m.CatalogVersion, Statement: m.Statement, EvaluatedAt: ts(m.EvaluatedAt),
		MappingDigest: m.MappingDigest,
	}
	for _, l := range m.OrgWide {
		out.OrgWideLanes = append(out.OrgWideLanes, lanes[l])
	}
	for _, t := range m.Tactics {
		out.Tactics = append(out.Tactics, Tactic(t))
	}
	for _, t := range m.Techniques {
		out.Techniques = append(out.Techniques, Cell(t))
	}
	return out, nil
}

// Gap is one gap.
func Gap(g domain.Gap) *pb.ThreatGap {
	return &pb.ThreatGap{
		Lane: lanes[g.Lane], TechniqueId: g.TechniqueID, Reason: string(g.Reason), FixKind: fixKinds[g.Fix.Kind],
		TargetId: g.Fix.TargetID, Label: g.Fix.Label, Command: g.Fix.Command,
	}
}

// Detail is a technique's page.
func Detail(t domain.Technique) *pb.ThreatTechniqueDetail {
	d := &pb.ThreatTechniqueDetail{
		Cell: Cell(t), Url: t.URL, UnaddressedWhy: t.UnaddressedWhy, Campaigns: t.Campaigns, ParentId: t.Parent,
		Prevent: &pb.ThreatPreventLane{
			State: laneStates[t.Prevent.State], Reasons: strs(t.Prevent.Reasons),
			Routes: &pb.ThreatRouteCounts{
				Enforced: int32(t.Prevent.Routes.Enforced), Partial: int32(t.Prevent.Routes.Partial), //nolint:gosec // G115: route counts
				ObserveOnly: int32(t.Prevent.Routes.ObserveOnly), Unknown: int32(t.Prevent.Routes.Unknown), //nolint:gosec // G115: route counts
				Stale: int32(t.Prevent.Routes.Stale), //nolint:gosec // G115: route counts
			},
		},
		Detect:  &pb.ThreatDetectLane{State: laneStates[t.Detect.State], Reasons: strs(t.Detect.Reasons)},
		Respond: &pb.ThreatRespondLane{State: laneStates[t.Respond.State], Reasons: strs(t.Respond.Reasons)},
		Test:    &pb.ThreatTestLane{State: testStates[t.Test.State], Reasons: strs(t.Test.Reasons)},
		Seen: &pb.ThreatSeen{
			AlertsRaised: t.Seen.AlertsRaised, Refusals: t.Seen.Refusals, Holds: t.Seen.Holds, WindowDays: int32(t.Seen.WindowDays), //nolint:gosec // G115: 30
		},
	}
	for _, c := range t.Prevent.Controls {
		d.Prevent.Controls = append(d.Prevent.Controls, &pb.ThreatControl{
			ControlId: c.ID, Title: c.Title, Surface: c.Surface, HrIds: c.HR, ReasonCodes: c.ReasonCodes, Applies: c.Applies, Why: c.Why,
		})
	}
	for _, r := range t.Detect.Rules {
		d.Detect.Rules = append(d.Detect.Rules, &pb.ThreatRule{
			RuleId: r.RuleID, Title: r.Title, Source: sources[r.Source], Licensed: r.Licensed, Disabled: r.Disabled,
			Suppressed: r.Suppressed, LastInputTime: ts(r.LastInputAt), InputKinds: r.Inputs, InputLiveReason: string(r.InputLive),
		})
	}
	for _, a := range t.Respond.Automations {
		d.Respond.Automations = append(d.Respond.Automations, &pb.ThreatAutomation{
			AutomationId: a.ID, Name: a.Name, State: a.State, TriggerRuleIds: a.TriggerRules, HasContain: a.HasContain, HubItem: a.HubItem,
		})
	}
	for _, s := range t.Test.Scenarios {
		d.Test.Scenarios = append(d.Test.Scenarios, &pb.ThreatScenario{
			ScenarioId: s.ScenarioID, Title: s.Title, Why: s.Why, LastRecordTime: ts(s.RecordedAt), Verdict: s.Verdict,
			ObservedBy: s.ObservedBy, RangeId: s.RangeID,
		})
	}
	if o := t.Outside; o != nil {
		d.Outside = &pb.ThreatOutsideInfo{Reason: string(o.Reason), CoveredBy: string(o.CoveredBy), Note: o.Note}
	}
	for _, g := range t.Gaps {
		d.Gaps = append(d.Gaps, Gap(g))
	}
	return d
}

// GetThreatTechnique implements ThreatMapServiceHandler.
func (h *Handler) GetThreatTechnique(ctx context.Context, req *pb.GetThreatTechniqueRequest) (*pb.GetThreatTechniqueResponse, error) {
	sc, err := scope(req.GetAgentId(), req.GetEnvironmentId())
	if err != nil {
		return nil, err
	}
	m, t, err := h.svc.Technique(ctx, FrameworkOf(req.GetFramework()), req.GetTechniqueId(), sc)
	if err != nil {
		return nil, err
	}
	out := &pb.GetThreatTechniqueResponse{Technique: Detail(t), Statement: m.Statement, EvaluatedAt: ts(m.EvaluatedAt)}
	for _, s := range t.Subtechniques {
		out.Subtechniques = append(out.Subtechniques, Detail(s))
	}
	return out, nil
}

// gapToken is an offset into the derived gap list: base64url of its
// decimal value. The list is evaluated again for every page.
func gapToken(n int) string { return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(n))) }

func gapOffset(token string) (int, error) {
	if token == "" {
		return 0, nil
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil {
		return 0, page.ErrBadToken
	}
	n, err := strconv.Atoi(string(b))
	if err != nil || n <= 0 || strconv.Itoa(n) != string(b) {
		return 0, page.ErrBadToken
	}
	return n, nil
}

// ListThreatGaps implements ThreatMapServiceHandler.
func (h *Handler) ListThreatGaps(ctx context.Context, req *pb.ListThreatGapsRequest) (*pb.ListThreatGapsResponse, error) {
	sc, err := scope(req.GetAgentId(), req.GetEnvironmentId())
	if err != nil {
		return nil, err
	}
	from, err := gapOffset(req.GetPageToken())
	if err != nil {
		return nil, err
	}
	size := page.Default
	if req.GetPageSize() > 0 {
		size = int(min(req.GetPageSize(), page.Max))
	}
	_, gaps, err := h.svc.Gaps(ctx, FrameworkOf(req.GetFramework()), sc)
	if err != nil {
		return nil, err
	}
	if from > len(gaps) {
		return nil, page.ErrBadToken
	}
	to := min(from+size, len(gaps))
	out := &pb.ListThreatGapsResponse{}
	for _, g := range gaps[from:to] {
		out.Gaps = append(out.Gaps, Gap(g))
	}
	if to < len(gaps) {
		out.NextPageToken = gapToken(to)
	}
	return out, nil
}

// ExportNavigatorLayer implements ThreatMapServiceHandler.
func (h *Handler) ExportNavigatorLayer(ctx context.Context, req *pb.ExportNavigatorLayerRequest) (*pb.ExportNavigatorLayerResponse, error) {
	sc, err := scope(req.GetAgentId(), req.GetEnvironmentId())
	if err != nil {
		return nil, err
	}
	b, name, err := h.svc.Navigator(ctx, FrameworkOf(req.GetFramework()), sc)
	if err != nil {
		return nil, err
	}
	return &pb.ExportNavigatorLayerResponse{LayerJson: b, FileName: name}, nil
}

// GetThreatMapHistory implements ThreatMapServiceHandler.
func (h *Handler) GetThreatMapHistory(ctx context.Context, req *pb.GetThreatMapHistoryRequest) (*pb.GetThreatMapHistoryResponse, error) {
	sc, err := scope("", req.GetEnvironmentId())
	if err != nil {
		return nil, err
	}
	hist, err := h.svc.History(ctx, FrameworkOf(req.GetFramework()), sc.Environment, int(req.GetDays()))
	if err != nil {
		return nil, err
	}
	out := &pb.GetThreatMapHistoryResponse{}
	for _, d := range hist.Days {
		out.Days = append(out.Days, &pb.ThreatHistoryDay{
			Day: d.Day.Format(time.DateOnly), Evidenced: int32(d.Evidenced), Partial: int32(d.Partial), //nolint:gosec // G115: catalog sizes
			Gap: int32(d.Gap), Outside: int32(d.Outside), //nolint:gosec // G115: catalog sizes
		})
	}
	for _, d := range hist.Drops {
		out.Drops = append(out.Drops, &pb.ThreatDrop{
			Day: d.Day.Format(time.DateOnly), TechniqueId: d.TechniqueID, Lane: lanes[d.Lane], From: d.From, To: d.To,
		})
	}
	return out, nil
}
