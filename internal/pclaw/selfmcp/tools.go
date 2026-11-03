// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package selfmcp

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"regexp"
	"slices"
	"time"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Backend is everything the tools can ask the server: the four reads and no
// other method (HR-656).
type Backend interface {
	WhatHappened(context.Context, *pb.WhatHappenedRequest) (*pb.WhatHappenedResponse, error)
	GetRunTimeline(context.Context, *pb.GetRunTimelineRequest) (*pb.GetRunTimelineResponse, error)
	Search(context.Context, *pb.SearchRequest) (*pb.SearchResponse, error)
	GetGraph(context.Context, *pb.GetGraphRequest) (*pb.GetGraphResponse, error)
}

// reads is the Backend over a Connect client. It keeps the generated clients
// private so no other of their methods can be called from a tool.
type reads struct {
	investigations pantherclawv1connect.InvestigationServiceClient
	search         pantherclawv1connect.SearchServiceClient
	graphs         pantherclawv1connect.GraphServiceClient
}

// NewBackend returns the four reads over c. Give c an AllowList transport.
func NewBackend(c *connect.Client) Backend {
	return reads{
		investigations: pantherclawv1connect.NewInvestigationServiceClient(c),
		search:         pantherclawv1connect.NewSearchServiceClient(c),
		graphs:         pantherclawv1connect.NewGraphServiceClient(c),
	}
}

func (r reads) WhatHappened(ctx context.Context, q *pb.WhatHappenedRequest) (*pb.WhatHappenedResponse, error) {
	return r.investigations.WhatHappened(ctx, q)
}

func (r reads) GetRunTimeline(ctx context.Context, q *pb.GetRunTimelineRequest) (*pb.GetRunTimelineResponse, error) {
	return r.investigations.GetRunTimeline(ctx, q)
}

func (r reads) Search(ctx context.Context, q *pb.SearchRequest) (*pb.SearchResponse, error) {
	return r.search.Search(ctx, q)
}

func (r reads) GetGraph(ctx context.Context, q *pb.GetGraphRequest) (*pb.GetGraphResponse, error) {
	return r.graphs.GetGraph(ctx, q)
}

// Input limits (HR-659). The server validates again.
const (
	maxPageSize  = 50
	defaultPage  = 20
	maxOperation = 200
	maxDecisions = 8
)

var (
	searchEntities = []string{"transactions", "runs", "agents", "grants", "grant_changes", "alerts", "incidents"}
	scopeTypes     = []string{"agent", "run", "incident"}
	operationShape = regexp.MustCompile(`^[A-Za-z0-9._:/-]*$`)
	decisionShape  = regexp.MustCompile(`^[A-Z_]{1,32}$`)
	pageTokenShape = regexp.MustCompile(`^[A-Za-z0-9_-]{0,64}$`)
)

// errInput is a tool argument that failed its limit. Its text is fixed: an
// argument never comes back.
var errInput = errors.New("selfmcp: invalid input")

// tool is one read. Name, description and schema are fixed text (HR-658).
type tool struct {
	Name, Title, Description string
	Schema                   map[string]any
	Procedure                string
	run                      func(context.Context, Backend, jsontext.Value) (proto.Message, error)
}

// args decodes a tool's arguments strictly: an unknown member is refused.
func args[T any](raw jsontext.Value) (T, error) {
	var v T
	if len(raw) == 0 {
		raw = jsontext.Value("{}")
	}
	if err := json.Unmarshal(raw, &v, json.RejectUnknownMembers(true)); err != nil {
		return v, errInput
	}
	return v, nil
}

func uuidArg(s string) (string, error) {
	if _, err := ids.ParseUUID(s); err != nil {
		return "", errInput
	}
	return s, nil
}

// optionalID validates an id filter; empty leaves it unset.
func optionalID(s string) (*string, error) {
	if s == "" {
		return nil, nil
	}
	v, err := uuidArg(s)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func timeArg(s string) (*timestamppb.Timestamp, error) {
	if s == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil, errInput
	}
	return timestamppb.New(t), nil
}

func explainDecision(ctx context.Context, b Backend, raw jsontext.Value) (proto.Message, error) {
	a, err := args[struct {
		TransactionID string `json:"transaction_id"`
	}](raw)
	if err != nil {
		return nil, err
	}
	id, err := uuidArg(a.TransactionID)
	if err != nil {
		return nil, err
	}
	return b.WhatHappened(ctx, &pb.WhatHappenedRequest{TransactionId: id})
}

func runTimeline(ctx context.Context, b Backend, raw jsontext.Value) (proto.Message, error) {
	a, err := args[struct {
		RunID string `json:"run_id"`
	}](raw)
	if err != nil {
		return nil, err
	}
	id, err := uuidArg(a.RunID)
	if err != nil {
		return nil, err
	}
	return b.GetRunTimeline(ctx, &pb.GetRunTimelineRequest{RunId: id})
}

func breachRadius(ctx context.Context, b Backend, raw jsontext.Value) (proto.Message, error) {
	a, err := args[struct {
		ScopeType string `json:"scope_type"`
		ScopeID   string `json:"scope_id"`
	}](raw)
	if err != nil {
		return nil, err
	}
	id, err := uuidArg(a.ScopeID)
	if err != nil || !slices.Contains(scopeTypes, a.ScopeType) {
		return nil, errInput
	}
	return b.GetGraph(ctx, &pb.GetGraphRequest{
		Mode: pb.GraphMode_GRAPH_MODE_EXPOSURE, Scope: &pb.GraphScope{Type: a.ScopeType, Id: id}, Collapse: true,
	})
}

// searchArgs are the search tool's arguments: one entity and typed filters.
type searchArgs struct {
	Entity          string   `json:"entity"`
	AgentID         string   `json:"agent_id"`
	RunID           string   `json:"run_id"`
	GrantID         string   `json:"grant_id"`
	AlertID         string   `json:"alert_id"`
	IncidentID      string   `json:"incident_id"`
	Operation       string   `json:"operation"`
	OperationPrefix string   `json:"operation_prefix"`
	Decisions       []string `json:"decisions"`
	StartTime       string   `json:"start_time"`
	EndTime         string   `json:"end_time"`
	PageSize        int32    `json:"page_size"`
	PageToken       string   `json:"page_token"`
}

func (a searchArgs) request() (*pb.SearchRequest, error) {
	f := &pb.SearchFilters{Operation: a.Operation, OperationPrefix: a.OperationPrefix, Decisions: a.Decisions}
	var err error
	for _, x := range []struct {
		dst **string
		src string
	}{
		{&f.AgentId, a.AgentID}, {&f.RunId, a.RunID}, {&f.GrantId, a.GrantID}, {&f.AlertId, a.AlertID}, {&f.IncidentId, a.IncidentID},
	} {
		if *x.dst, err = optionalID(x.src); err != nil {
			return nil, err
		}
	}
	if f.StartTime, err = timeArg(a.StartTime); err != nil {
		return nil, err
	}
	if f.EndTime, err = timeArg(a.EndTime); err != nil {
		return nil, err
	}
	size := a.PageSize
	if size == 0 {
		size = defaultPage
	}
	switch {
	case !slices.Contains(searchEntities, a.Entity),
		size < 1 || size > maxPageSize,
		!pageTokenShape.MatchString(a.PageToken),
		len(a.Operation) > maxOperation || !operationShape.MatchString(a.Operation),
		len(a.OperationPrefix) > maxOperation || !operationShape.MatchString(a.OperationPrefix),
		len(a.Decisions) > maxDecisions:
		return nil, errInput
	}
	for _, d := range a.Decisions {
		if !decisionShape.MatchString(d) {
			return nil, errInput
		}
	}
	return &pb.SearchRequest{Query: &pb.Query{Entity: a.Entity, Filters: f}, PageSize: size, PageToken: a.PageToken}, nil
}

func searchRecords(ctx context.Context, b Backend, raw jsontext.Value) (proto.Message, error) {
	a, err := args[searchArgs](raw)
	if err != nil {
		return nil, err
	}
	q, err := a.request()
	if err != nil {
		return nil, err
	}
	return b.Search(ctx, q)
}

func schema(required []string, props map[string]any) map[string]any {
	return map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}
}

func uuidProp(description string) map[string]any {
	return map[string]any{"type": "string", "format": "uuid", "description": description}
}

// tools is the whole tool layer: four reads.
var tools = []tool{
	{
		Name: "search", Title: "Search records", Procedure: pantherclawv1connect.SearchServiceSearchProcedure, run: searchRecords,
		Description: "Find transactions, runs, agents, grants, grant changes, alerts or incidents in this service account's scope, " +
			"with typed filters. There is no free text. Results state their scope and what they leave out.",
		Schema: schema([]string{"entity"}, map[string]any{
			"entity":           map[string]any{"type": "string", "enum": searchEntities},
			"agent_id":         uuidProp("Only this agent."),
			"run_id":           uuidProp("Only this run."),
			"grant_id":         uuidProp("Only this grant."),
			"alert_id":         uuidProp("Only this alert."),
			"incident_id":      uuidProp("Only this incident."),
			"operation":        map[string]any{"type": "string", "maxLength": maxOperation, "description": "An exact operation."},
			"operation_prefix": map[string]any{"type": "string", "maxLength": maxOperation, "description": "An operation prefix."},
			"decisions":        map[string]any{"type": "array", "maxItems": maxDecisions, "items": map[string]any{"type": "string", "maxLength": 32}},
			"start_time":       map[string]any{"type": "string", "format": "date-time"},
			"end_time":         map[string]any{"type": "string", "format": "date-time"},
			"page_size":        map[string]any{"type": "integer", "minimum": 1, "maximum": maxPageSize},
			"page_token":       map[string]any{"type": "string", "maxLength": 64},
		}),
	},
	{
		Name: "explain_decision", Title: "Explain a decision", Procedure: pantherclawv1connect.InvestigationServiceWhatHappenedProcedure, run: explainDecision,
		Description: "Say whether one action was allowed, held, denied, observed or dispatched and whether its effect is confirmed, " +
			"with its launcher, principal, grantor chain and delegation chain.",
		Schema: schema([]string{"transaction_id"}, map[string]any{"transaction_id": uuidProp("The action's transaction id.")}),
	},
	{
		Name: "run_timeline", Title: "Run timeline", Procedure: pantherclawv1connect.InvestigationServiceGetRunTimelineProcedure, run: runTimeline,
		Description: "One run's actions, holds, approvals, authority changes, dispatches, results, gaps and child runs, oldest first. " +
			"A gap is evidence the timeline expected and did not find.",
		Schema: schema([]string{"run_id"}, map[string]any{"run_id": uuidProp("The run id.")}),
	},
	{
		Name: "breach_radius", Title: "Breach radius", Procedure: pantherclawv1connect.GraphServiceGetGraphProcedure, run: breachRadius,
		Description: "The exposure graph of an agent, run or incident: what it could reach and through what, with each edge's basis. " +
			"Current reach and history are kept apart, and a cut graph says so.",
		Schema: schema([]string{"scope_type", "scope_id"}, map[string]any{
			"scope_type": map[string]any{"type": "string", "enum": scopeTypes},
			"scope_id":   uuidProp("The agent, run or incident id."),
		}),
	},
}

func toolNamed(name string) (tool, bool) {
	i := slices.IndexFunc(tools, func(t tool) bool { return t.Name == name })
	if i < 0 {
		return tool{}, false
	}
	return tools[i], true
}

// listed is the tools as clients see them.
func listed() []map[string]any {
	out := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		out = append(out, map[string]any{
			"name": t.Name, "title": t.Title, "description": t.Description, "inputSchema": t.Schema,
			"annotations": map[string]any{"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false},
		})
	}
	return out
}
