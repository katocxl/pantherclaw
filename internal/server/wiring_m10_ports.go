// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"strconv"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/billing"
	capp "github.com/katocxl/pantherclaw/internal/cases/app"
	exapp "github.com/katocxl/pantherclaw/internal/exposure/app"
	exdomain "github.com/katocxl/pantherclaw/internal/exposure/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/operations"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	poapp "github.com/katocxl/pantherclaw/internal/posture/app"
	podomain "github.com/katocxl/pantherclaw/internal/posture/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/alerts"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	reflexports "github.com/katocxl/pantherclaw/internal/reflex/ports"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
	"github.com/katocxl/pantherclaw/internal/search"
	"github.com/katocxl/pantherclaw/internal/siem"
)

// The M10 cross-stream ports (G0 M10 D1, D49, D55): each provider is built
// here and injected into its consumers, so no stream imports another's
// adapters.
//
//   - Raiser and FailureSink (core) → response, edges and everyone that
//     raises signals or reports owned failures;
//   - ReachPreviewer (exposure) → response previews; the exposure reads →
//     cases' reach lens and search's who_can_write and widest_exposure;
//   - Container (response) and CaseOpener (cases) → the Shared Signals
//     receiver and identity playbook (edges);
//   - response reads → cases' response lens and the operations queue;
//   - posture findings and SIEM delivery health → the operations queue.
//
// A port left nil reads as "not available" in its consumer, never as empty
// or safe.

// m10Raiser is core's Raiser for pool, with its suppression, incident and
// notification hooks (D14–D17), looked up when a signal is raised: the
// core is built once per pool when the API or the workers start
// (newReflexCore), after some consumers are. Without one (a process that
// builds no core) the plain Raiser records the alert without the hooks.
type m10Raiser struct{ pool *db.Pool }

var _ reflexports.Raiser = m10Raiser{}

func (r m10Raiser) Raise(ctx context.Context, tx pgx.Tx, s reflexdomain.Signal) (ids.UUID, error) {
	reflexCores.Lock()
	c := reflexCores.by[r.pool]
	reflexCores.Unlock()
	if c != nil && c.raiser != nil {
		return c.raiser.Raise(ctx, tx, s)
	}
	return (&alerts.Raiser{}).Raise(ctx, tx, s)
}

// m10Reach is exposure's ReachPreviewer (D27, F259) for response's
// previews; it checks the Team edition itself.
func m10Reach(pool *db.Pool, bill *billing.Service) reflexdomain.ReachPreviewer {
	return &exapp.Previewer{Pool: pool, Ents: exposureEnts(bill)}
}

// m10Exposure is exposure's read service as the other streams read it.
func m10Exposure(pool *db.Pool, bill *billing.Service) *exapp.Service {
	return &exapp.Service{Pool: pool, Ents: exposureEnts(bill)}
}

// m10Response is response's read side (containment.read at the org).
func m10Response(pool *db.Pool, bill *billing.Service) *rapp.Response {
	return &rapp.Response{C: responseContainment(pool, nil, bill)}
}

// m10CaseOpener is cases' CaseOpener (Team edition, D19).
func m10CaseOpener(bill *billing.Service) reflexports.CaseOpener {
	if bill == nil {
		return capp.NewOpener(nil)
	}
	return capp.NewOpener(bill)
}

// m10Container is response's Container (D21).
func m10Container(pool *db.Pool, bill *billing.Service) reflexports.Container {
	return responseContainment(pool, nil, bill)
}

func init() {
	edgesCaseOpener = func(_ *db.Pool, bill *billing.Service) reflexports.CaseOpener { return m10CaseOpener(bill) }
	edgesContainer = m10Container
}

// casesReach is the cases reach lens's ReachView over exposure, read under
// the caller in ctx (exposure.read where each agent lives, and the
// edition).
type casesReach struct{ svc *exapp.Service }

func (r casesReach) AgentReach(ctx context.Context, _ ids.OrgID, agents []ids.UUID) ([]capp.ReachAgent, error) {
	out := make([]capp.ReachAgent, 0, len(agents))
	for _, a := range agents {
		v, err := r.svc.Exposure(ctx, exdomain.Filter{Agent: &a, Current: true})
		if err != nil {
			return nil, err
		}
		ra := capp.ReachAgent{Agent: a, Reach: exapp.ReachOf(v.Rights), Stale: v.Snapshot.Stale}
		if v.Restricted {
			ra.Note = "credential rights shared by several agents need exposure.read across the organization"
		}
		out = append(out, ra)
	}
	return out, nil
}

// casesResponse is the cases response lens's ResponseView over response's
// reads: the actions naming the case and those on its subjects, each with
// its per-path statuses.
type casesResponse struct{ r *rapp.Response }

// maxLensActions bounds the actions a response lens reads.
const maxLensActions = 50

func (x casesResponse) CaseActions(ctx context.Context, _ ids.OrgID, caseID ids.UUID, subjects []reflexdomain.Subject) (
	[]capp.ResponseAction, error,
) {
	seen := map[ids.UUID]bool{}
	var rows []ids.UUID
	add := func(list []ids.UUID) {
		for _, id := range list {
			if !seen[id] && len(rows) < maxLensActions {
				seen[id] = true
				rows = append(rows, id)
			}
		}
	}
	byCase, err := x.r.ListActions(ctx, &caseID, nil, nil, nil, maxLensActions)
	if err != nil {
		return nil, err
	}
	add(actionIDs(byCase))
	for _, s := range subjects {
		byScope, err := x.r.ListActions(ctx, nil, nil, &s, nil, maxLensActions)
		if err != nil {
			return nil, err
		}
		add(actionIDs(byScope))
	}
	out := make([]capp.ResponseAction, 0, len(rows))
	for _, id := range rows {
		v, err := x.r.GetAction(ctx, id)
		if err != nil {
			return nil, err
		}
		a := capp.ResponseAction{
			ID: v.Action.ID, Scope: reflexdomain.Subject{Type: reflexdomain.SubjectType(v.Action.ScopeType), ID: v.Action.ScopeID},
			Status: v.Action.Status, Requested: v.Action.RequestedAt,
		}
		if v.Action.Control != nil {
			a.Control = *v.Action.Control
		}
		for _, p := range v.Paths {
			a.Paths = append(a.Paths, capp.ResponsePath{Kind: p.Type, Status: p.Status})
		}
		out = append(out, a)
	}
	return out, nil
}

func actionIDs(rows []dbq.PcResponseAction) []ids.UUID {
	out := make([]ids.UUID, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.ID)
	}
	return out
}

// opsContainment is the operations queue's ContainmentReader: the latest
// actions not confirmed on every material path.
type opsContainment struct{ r *rapp.Response }

// maxQueueActions bounds the actions the queue reads.
const maxQueueActions = 200

func (x opsContainment) Unconfirmed(ctx context.Context) ([]operations.ContainmentAction, error) {
	rows, err := x.r.ListActions(ctx, nil, nil, nil, nil, maxQueueActions)
	if err != nil {
		return nil, err
	}
	var out []operations.ContainmentAction
	for _, a := range rows {
		if a.Status == "CONFIRMED" {
			continue
		}
		c := operations.ContainmentAction{
			ID: a.ID, Kind: a.Kind, ScopeType: a.ScopeType, ScopeID: a.ScopeID, Status: a.Status,
			Requested: a.RequestedAt, Incident: a.IncidentID, Case: a.CaseID,
		}
		if a.Control != nil {
			c.Control = *a.Control
		}
		out = append(out, c)
	}
	return out, nil
}

// opsFindings is the operations queue's FindingReader: posture findings
// still open, as the caller may read them (posture.read, Business).
type opsFindings struct{ svc *poapp.Service }

var openFindingStates = []podomain.State{podomain.Open, podomain.Assigned, podomain.Testing, podomain.EvidenceIncomplete}

func (x opsFindings) OpenFindings(ctx context.Context) ([]operations.PostureFinding, error) {
	rows, _, _, err := x.svc.List(ctx, openFindingStates, "", "", 200, "")
	if err != nil {
		return nil, err
	}
	out := make([]operations.PostureFinding, 0, len(rows))
	for _, f := range rows {
		out = append(out, operations.PostureFinding{
			ID: f.ID, Kind: f.Kind, Title: f.Title, Severity: f.Severity, State: f.State, Agent: f.AgentID, Since: f.FirstSeenAt,
		})
	}
	return out, nil
}

// opsExports is the evidence status's ExportReader over SIEM destinations
// (siem.read at the org).
type opsExports struct{ svc *siem.Service }

func (x opsExports) Destinations(ctx context.Context) ([]operations.ExportDestination, error) {
	var out []operations.ExportDestination
	token := ""
	for range 10 { // at most 2000 destinations
		ds, next, err := x.svc.List(ctx, 200, token)
		if err != nil {
			return nil, err
		}
		for _, d := range ds {
			out = append(out, operations.ExportDestination{
				ID: d.ID, Name: d.Name, State: d.State, Health: d.Health, LastDelivered: d.LastDeliveredAt, FailingSince: d.FailingSince,
			})
		}
		if next == "" {
			break
		}
		token = next
	}
	return out, nil
}

// searchExposure is search's ExposureReader over exposure's reads.
type searchExposure struct{ svc *exapp.Service }

// writeVerbs are the verbs that change a resource (F308).
var writeVerbs = map[exdomain.Verb]bool{exdomain.VerbUpdate: true, exdomain.VerbDelete: true, exdomain.VerbTransfer: true}

func exposureView(v exapp.View, items []search.Item) search.ExposureView {
	return search.ExposureView{
		Items: items, Restricted: v.Restricted, ComputedAt: v.Snapshot.ComputedAt, Stale: v.Snapshot.Stale,
		ChangedAt: v.Snapshot.ChangedAt, Gaps: v.Snapshot.Gaps, Truncated: v.Snapshot.Truncated,
	}
}

func idString(u *ids.UUID) string {
	if u == nil {
		return ""
	}
	return u.String()
}

func (x searchExposure) WhoCanWrite(ctx context.Context, group string, connection *ids.UUID) (search.ExposureView, error) {
	v, err := x.svc.Exposure(ctx, exdomain.Filter{ResourceGroup: group, Connection: connection, Current: true})
	if err != nil {
		return search.ExposureView{}, err
	}
	var items []search.Item
	for _, r := range v.Rights {
		// Observed use is history, not current authority (D31).
		if !writeVerbs[r.Verb] || r.View == exdomain.Observed {
			continue
		}
		it := search.Item{
			Entity: "exposure", ID: r.Key(), Label: string(r.View) + "/" + string(r.Label),
			Fields: map[string]string{
				"agent": idString(r.Agent), "connection": idString(r.Connection), "grant": idString(r.Grant),
				"operation": r.Operation, "resource_group": r.ResourceGroup, "verb": string(r.Verb), "view": string(r.View),
				"label": string(r.Label), "coverage": string(r.Coverage), "basis": r.Basis,
				"irreversible": strconv.FormatBool(r.Irreversible),
			},
		}
		if r.Agent != nil {
			it.Evidence = append(it.Evidence, "agent:"+r.Agent.String())
		}
		if r.Grant != nil {
			it.Evidence = append(it.Evidence, "grant:"+r.Grant.String())
		}
		if r.Connection != nil {
			it.Evidence = append(it.Evidence, "connection:"+r.Connection.String())
		}
		items = append(items, it)
	}
	return exposureView(v, items), nil
}

func (x searchExposure) Widest(ctx context.Context, limit int) (search.ExposureView, error) {
	v, ranked, err := x.svc.Rank(ctx, limit)
	if err != nil {
		return search.ExposureView{}, err
	}
	items := make([]search.Item, 0, len(ranked))
	for i, r := range ranked {
		k := r.Keys
		id := "credential"
		if r.Agent != nil {
			id = r.Agent.String()
		}
		it := search.Item{
			Entity: "exposure_rank", ID: id, Label: "RANK_" + strconv.Itoa(i+1),
			Fields: map[string]string{
				"agent": idString(r.Agent), "consequence": string(k.Consequence), "irreversible": strconv.FormatBool(k.Irreversible),
				"resource_groups": strconv.Itoa(k.ResourceGroups), "connections": strconv.Itoa(k.Connections),
				"usability": string(k.Usability), "enforceability": string(k.Enforceability), "owned": strconv.FormatBool(k.Owned),
				"revocable": strconv.Itoa(k.Revocable), "unrevocable": strconv.Itoa(k.Unrevocable),
			},
		}
		if r.Agent != nil {
			it.Evidence = []string{"agent:" + r.Agent.String()}
		}
		items = append(items, it)
	}
	return exposureView(v, items), nil
}

// opsSources builds the operations queue's ports from apiDeps.
func opsSources(d apiDeps) operations.Sources {
	s := operations.Sources{
		Containment: opsContainment{r: m10Response(d.pool, d.billing)},
		Findings:    opsFindings{svc: &poapp.Service{Pool: d.pool, Ents: exposureEnts(d.billing)}},
	}
	if sv, err := newSIEM(d.pool, d.kp, d.billing, nil, d.publicURL, d.log); err == nil {
		s.Exports = opsExports{svc: sv}
	}
	return s
}
