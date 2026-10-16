// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package exposurerpc serves ExposureService and GraphService over Connect
// (G0 M10 D27–D31). Handlers only translate: authentication, the coarse
// permission check and protovalidate have run before a handler is called,
// and the use cases check exposure.read per agent and the edition.
package exposurerpc

import (
	"context"
	"strconv"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/exposure/app"
	"github.com/katocxl/pantherclaw/internal/exposure/domain"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// Handler serves ExposureService and GraphService.
type Handler struct {
	pantherclawv1connect.UnimplementedExposureServiceHandler
	svc *app.Service
}

// Graphs serves GraphService.
type Graphs struct {
	pantherclawv1connect.UnimplementedGraphServiceHandler
	svc *app.Service
}

// New returns the handlers.
func New(svc *app.Service) (*Handler, *Graphs) { return &Handler{svc: svc}, &Graphs{svc: svc} }

var (
	views = map[domain.View]pb.ExposureView{
		domain.Observed: pb.ExposureView_EXPOSURE_VIEW_OBSERVED, domain.Effective: pb.ExposureView_EXPOSURE_VIEW_EFFECTIVE,
		domain.Credential: pb.ExposureView_EXPOSURE_VIEW_CREDENTIAL, domain.IssuanceCeiling: pb.ExposureView_EXPOSURE_VIEW_ISSUANCE_CEILING,
	}
	labels = map[domain.Label]pb.ExposureLabel{
		domain.Usable: pb.ExposureLabel_EXPOSURE_LABEL_USABLE, domain.Conditional: pb.ExposureLabel_EXPOSURE_LABEL_CONDITIONAL,
		domain.Expired: pb.ExposureLabel_EXPOSURE_LABEL_EXPIRED, domain.Uncertain: pb.ExposureLabel_EXPOSURE_LABEL_UNCERTAIN,
	}
	verbs = map[domain.Verb]pb.ExposureVerb{
		domain.VerbRead: pb.ExposureVerb_EXPOSURE_VERB_READ, domain.VerbExport: pb.ExposureVerb_EXPOSURE_VERB_EXPORT,
		domain.VerbUpdate: pb.ExposureVerb_EXPOSURE_VERB_UPDATE, domain.VerbDelete: pb.ExposureVerb_EXPOSURE_VERB_DELETE,
		domain.VerbTransfer: pb.ExposureVerb_EXPOSURE_VERB_TRANSFER, domain.VerbDelegate: pb.ExposureVerb_EXPOSURE_VERB_DELEGATE,
	}
	modes = map[pb.GraphMode]domain.Mode{
		pb.GraphMode_GRAPH_MODE_ACTIVITY: domain.ModeActivity, pb.GraphMode_GRAPH_MODE_CAUSAL: domain.ModeCausal,
		pb.GraphMode_GRAPH_MODE_AUTHORITY: domain.ModeAuthority, pb.GraphMode_GRAPH_MODE_EXPOSURE: domain.ModeExposure,
		pb.GraphMode_GRAPH_MODE_CHANGE: domain.ModeChange,
	}
	edgeStates = map[domain.EdgeState]pb.GraphEdgeState{
		domain.EdgeActive: pb.GraphEdgeState_GRAPH_EDGE_STATE_ACTIVE, domain.EdgeHistorical: pb.GraphEdgeState_GRAPH_EDGE_STATE_HISTORICAL,
		domain.EdgeExpired: pb.GraphEdgeState_GRAPH_EDGE_STATE_EXPIRED, domain.EdgePossible: pb.GraphEdgeState_GRAPH_EDGE_STATE_POSSIBLE,
	}
)

var errPage = pcerr.New(pcerr.InvalidArgument, "PAGE_TOKEN_INVALID", "the page token is not valid")

func viewOf(v pb.ExposureView) domain.View {
	for k, x := range views {
		if x == v {
			return k
		}
	}
	return ""
}

func optID(s string) *ids.UUID {
	if s == "" {
		return nil
	}
	u, err := ids.ParseUUID(s)
	if err != nil {
		return nil
	}
	return &u
}

func str(u *ids.UUID) string {
	if u == nil {
		return ""
	}
	return u.String()
}

func ts(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func snapshotPB(s app.Snapshot) *pb.ExposureSnapshot {
	return &pb.ExposureSnapshot{
		Id: s.ID.String(), ComputeTime: timestamppb.New(s.ComputedAt), Stale: s.Stale, ChangeTime: ts(s.ChangedAt),
		Truncated: s.Truncated, Gaps: s.Gaps, Cause: s.Cause,
	}
}

func rightPB(r domain.Right) *pb.ExposureRight {
	return &pb.ExposureRight{
		View: views[r.View], Label: labels[r.Label], AgentId: str(r.Agent), ConnectionId: str(r.Connection), GrantId: str(r.Grant),
		Operation: r.Operation, ResourceGroup: r.ResourceGroup, Verb: verbs[r.Verb], Coverage: string(r.Coverage), Reasons: r.Reasons,
		Basis: r.Basis, Irreversible: r.Irreversible, DelegationDepth: int32(r.Depth), ExpireTime: ts(r.ExpiresAt), //nolint:gosec // G115: depth ≤ 4
		ObserveTime: ts(r.ObservedAt), Observations: int32(min(r.Observations, 1<<30)), //nolint:gosec // G115: bounded
		AutomationId: str(r.Automation),
	}
}

func rightsPB(rs []domain.Right, limit int) ([]*pb.ExposureRight, bool) {
	cut := len(rs) > limit
	if cut {
		rs = rs[:limit]
	}
	out := make([]*pb.ExposureRight, 0, len(rs))
	for _, r := range rs {
		out = append(out, rightPB(r))
	}
	return out, cut
}

// offset reads an offset page: size (0: 50, at most 200) and token.
func offset(size int32, token string) (int, int, error) {
	n := int(size)
	if n == 0 {
		n = 50
	}
	start := 0
	if token != "" {
		v, err := strconv.Atoi(token)
		if err != nil || v < 0 {
			return 0, 0, errPage
		}
		start = v
	}
	return start, n, nil
}

func next(start, n, total int) string {
	if start+n >= total {
		return ""
	}
	return strconv.Itoa(start + n)
}

// GetExposure implements ExposureServiceHandler.
func (h *Handler) GetExposure(ctx context.Context, req *pb.GetExposureRequest) (*pb.GetExposureResponse, error) {
	start, n, err := offset(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	f := domain.Filter{
		Agent: optID(req.GetAgentId()), Connection: optID(req.GetConnectionId()), View: viewOf(req.GetView()),
		ResourceGroup: req.GetResourceGroup(), Current: req.GetCurrentOnly(),
		Automation: optID(req.GetAutomationId()),
	}
	v, err := h.svc.Exposure(ctx, f)
	if err != nil {
		return nil, err
	}
	out := &pb.GetExposureResponse{Snapshot: snapshotPB(v.Snapshot), Restricted: v.Restricted}
	page := v.Rights[min(start, len(v.Rights)):min(start+n, len(v.Rights))]
	out.Rights, _ = rightsPB(page, n)
	out.NextPageToken = next(start, n, len(v.Rights))
	return out, nil
}

// GetReachMatrix implements ExposureServiceHandler.
func (h *Handler) GetReachMatrix(ctx context.Context, req *pb.GetReachMatrixRequest) (*pb.GetReachMatrixResponse, error) {
	v, m, err := h.svc.Matrix(ctx, domain.Filter{Agent: optID(req.GetAgentId()), Connection: optID(req.GetConnectionId())})
	if err != nil {
		return nil, err
	}
	out := &pb.GetReachMatrixResponse{Snapshot: snapshotPB(v.Snapshot), ResourceGroups: m.Groups, Restricted: v.Restricted}
	for _, a := range m.Agents {
		out.AgentIds = append(out.AgentIds, str(a))
	}
	for _, c := range m.Cells {
		out.Cells = append(out.Cells, &pb.ReachCell{
			AgentId: str(c.Agent), ResourceGroup: c.ResourceGroup, Verb: verbs[c.Verb], View: views[c.View], Label: labels[c.Label],
			Coverage: string(c.Coverage), Bases: c.Bases, Irreversible: c.Irreversible, Rights: int32(min(c.Rights, 1<<30)), //nolint:gosec // G115: bounded
		})
	}
	return out, nil
}

func keysPB(k domain.RankKeys) *pb.RankKeys {
	return &pb.RankKeys{
		Consequence: verbs[k.Consequence], Irreversible: k.Irreversible, ResourceGroups: int32(k.ResourceGroups), //nolint:gosec // G115: bounded by a snapshot
		Connections: int32(k.Connections), Usability: labels[k.Usability], Enforceability: string(k.Enforceability), //nolint:gosec // G115: bounded by a snapshot
		Owned: k.Owned, Revocable: int32(k.Revocable), Unrevocable: int32(k.Unrevocable), //nolint:gosec // G115: bounded by a snapshot
	}
}

// RankExposure implements ExposureServiceHandler.
func (h *Handler) RankExposure(ctx context.Context, req *pb.RankExposureRequest) (*pb.RankExposureResponse, error) {
	v, ranked, autos, err := h.svc.RankWithAutomations(ctx, int(req.GetLimit()), req.GetIncludeAutomations())
	if err != nil {
		return nil, err
	}
	out := &pb.RankExposureResponse{Snapshot: snapshotPB(v.Snapshot), Restricted: v.Restricted}
	for _, r := range ranked {
		out.Agents = append(out.Agents, &pb.RankedAgent{AgentId: str(r.Agent), Keys: keysPB(r.Keys)})
	}
	out.AutomationsNote = autos.Note
	for _, a := range autos.Automations {
		x := &pb.RankedAutomation{
			AutomationId: a.Automation.String(), CeilingAgents: int32(a.Keys.Agents), //nolint:gosec // G115: bounded by a snapshot
			CurrentRights: int32(a.Keys.CurrentRights), ActiveGrants: int32(a.Keys.ActiveGrants), //nolint:gosec // G115: bounded by a snapshot
		}
		if autos.ByCeiling {
			x.CeilingKeys = keysPB(a.Keys.Ceiling)
		}
		out.Automations = append(out.Automations, x)
	}
	return out, nil
}

// ListCredentialDependents implements ExposureServiceHandler.
func (h *Handler) ListCredentialDependents(ctx context.Context, req *pb.ListCredentialDependentsRequest) (*pb.ListCredentialDependentsResponse, error) {
	conn := optID(req.GetConnectionId())
	if conn == nil {
		return nil, app.ErrNotFound
	}
	v, ws, err := h.svc.Dependents(ctx, *conn)
	if err != nil {
		return nil, err
	}
	out := &pb.ListCredentialDependentsResponse{Snapshot: snapshotPB(v.Snapshot)}
	for _, w := range ws {
		x := &pb.CredentialWorkload{AgentId: str(w.Agent), Rights: int32(min(w.Rights, 1<<30)), LastUseTime: ts(w.LastUsed)} //nolint:gosec // G115: bounded
		for _, view := range w.Views {
			x.Views = append(x.Views, views[view])
		}
		out.Workloads = append(out.Workloads, x)
	}
	return out, nil
}

// maxPreviewRights bounds each list of a preview response.
const maxPreviewRights = 500

func countsPB(rights []domain.Right) []*pb.ReachCount {
	by := map[domain.View]*pb.ReachCount{}
	out := []*pb.ReachCount{}
	for _, v := range []domain.View{domain.Effective, domain.Credential} {
		c := &pb.ReachCount{View: views[v]}
		by[v] = c
		out = append(out, c)
	}
	for _, r := range rights {
		c, ok := by[r.View]
		if !ok {
			continue
		}
		//exhaustive:ignore // expired rights are history, never counted
		switch r.Label {
		case domain.Usable:
			c.Usable++
		case domain.Conditional:
			c.Conditional++
		case domain.Uncertain:
			c.Uncertain++
		}
	}
	return out
}

// PreviewReduction implements ExposureServiceHandler.
func (h *Handler) PreviewReduction(ctx context.Context, req *pb.PreviewReductionRequest) (*pb.PreviewReductionResponse, error) {
	c := reflexdomain.ReductionChange{Kind: req.GetKind(), Control: req.GetControl(), Operation: req.GetOperation()}
	for _, s := range req.GetSubjects() {
		c.Subjects = append(c.Subjects, reflexdomain.Subject{Type: reflexdomain.SubjectType(s.GetType()), ID: s.GetId()})
	}
	d, note, err := h.svc.PreviewReduction(ctx, c)
	if err != nil {
		return nil, err
	}
	out := &pb.PreviewReductionResponse{Before: countsPB(d.BeforeRights), After: countsPB(d.AfterRights), Note: note}
	var cut [4]bool
	out.Removed, cut[0] = rightsPB(d.Removed, maxPreviewRights)
	out.Weakened, cut[1] = rightsPB(d.Weakened, maxPreviewRights)
	out.Remaining, cut[2] = rightsPB(d.Remaining, maxPreviewRights)
	out.Disruption, cut[3] = rightsPB(d.Disruption, maxPreviewRights)
	out.Truncated = cut[0] || cut[1] || cut[2] || cut[3]
	return out, nil
}

func filterOf(f *pb.GraphFilter) domain.GraphFilter {
	out := domain.GraphFilter{
		Runs: f.GetRunIds(), Agents: f.GetAgentIds(), Operations: f.GetOperations(), Decisions: f.GetDecisions(),
		Outcomes: f.GetOutcomes(), Principals: f.GetPrincipalIds(),
	}
	if f.GetStartTime() != nil {
		t := f.GetStartTime().AsTime()
		out.Start = &t
	}
	if f.GetEndTime() != nil {
		t := f.GetEndTime().AsTime()
		out.End = &t
	}
	return out
}

func edgePB(e domain.Edge) *pb.GraphEdge {
	return &pb.GraphEdge{
		From: &pb.GraphNode{Type: e.From.Type, Id: e.From.ID}, To: &pb.GraphNode{Type: e.To.Type, Id: e.To.ID}, Kind: e.Kind,
		Verb: verbs[e.Verb], Operation: e.Operation, State: edgeStates[e.State], Decision: e.Decision, Coverage: string(e.Coverage),
		Execution: e.Execution, Effect: e.Effect, Basis: e.Basis, Revision: int32(e.Revision), Time: ts(e.At), //nolint:gosec // G115: revisions are small
		ExpireTime: ts(e.ExpiresAt), Freshness: e.Freshness, Provenance: e.Provenance, Count: int32(min(e.Count, 1<<30)), //nolint:gosec // G115: bounded
	}
}

func (g *Graphs) build(ctx context.Context, mode pb.GraphMode, scope *pb.GraphScope, f *pb.GraphFilter, collapse, table, ceiling bool) (app.GraphResult, error) {
	m, ok := modes[mode]
	if !ok {
		return app.GraphResult{}, app.ErrScope
	}
	return g.svc.Graph(ctx, m, app.GraphScope{Type: scope.GetType(), ID: scope.GetId(), IncludeCeiling: ceiling}, filterOf(f), collapse, table, domain.DefaultLimits)
}

// GetGraph implements GraphServiceHandler.
func (g *Graphs) GetGraph(ctx context.Context, req *pb.GetGraphRequest) (*pb.GetGraphResponse, error) {
	r, err := g.build(ctx, req.GetMode(), req.GetScope(), req.GetFilter(), req.GetCollapse(), false, req.GetIncludeCeiling())
	if err != nil {
		return nil, err
	}
	out := &pb.GetGraphResponse{
		Mode: req.GetMode(), Truncated: r.Graph.Truncated, Restricted: r.Restricted, AsOf: timestamppb.New(r.AsOf),
		Current: map[string]int32{},
	}
	if r.Snapshot != nil {
		out.Snapshot = snapshotPB(*r.Snapshot)
	}
	for _, n := range r.Graph.Nodes {
		out.Nodes = append(out.Nodes, &pb.GraphNode{Type: n.Type, Id: n.ID})
	}
	for _, e := range r.Graph.Edges {
		out.Edges = append(out.Edges, edgePB(e))
	}
	for k, v := range r.Graph.Current {
		out.Current[k] = int32(min(v, 1<<30)) //nolint:gosec // G115: bounded
	}
	return out, nil
}

// ListGraphEdges implements GraphServiceHandler.
func (g *Graphs) ListGraphEdges(ctx context.Context, req *pb.ListGraphEdgesRequest) (*pb.ListGraphEdgesResponse, error) {
	start, n, err := offset(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	r, err := g.build(ctx, req.GetMode(), req.GetScope(), req.GetFilter(), req.GetCollapse(), true, req.GetIncludeCeiling())
	if err != nil {
		return nil, err
	}
	es := r.Graph.Edges
	out := &pb.ListGraphEdgesResponse{Truncated: r.Graph.Truncated, Restricted: r.Restricted, NextPageToken: next(start, n, len(es))}
	for _, e := range es[min(start, len(es)):min(start+n, len(es))] {
		out.Edges = append(out.Edges, edgePB(e))
	}
	return out, nil
}
