// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package templatesrpc serves TemplateService and ProposalService over
// Connect (G0 M11 part 2 D31, D32; HR-286). Creating from a template only
// drafts: a DRAFT automation, a DRAFT version rendered from typed
// parameters and the template's baseline tests. Deciding a proposal only
// records the decision. Every call is a person's.
package templatesrpc

import (
	"context"
	"encoding/json/v2"
	"errors"
	"strings"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/automations/templates"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors.
var (
	ErrNotFound    = pcerr.New(pcerr.NotFound, "NOT_FOUND", "not found")
	ErrHumanOnly   = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person may do this")
	ErrDecided     = pcerr.New(pcerr.FailedPrecondition, "PROPOSAL_DECIDED", "the proposal is no longer open")
	ErrUnavailable = pcerr.New(pcerr.FailedPrecondition, "UNAVAILABLE", "automations are not available on this server yet")
	ErrInvalidID   = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")
)

// Draft is an automation to create from a rendered template.
type Draft struct {
	Name    string
	Purpose string
	// Kind is AGENT_WORK or SECURITY_WORK.
	Kind  string
	Owner ids.UUID
	// Definition is the rendered definition document (YAML).
	Definition []byte
}

// Drafts creates a DRAFT automation, its execution identity and its first
// DRAFT version in the caller's transaction, as the caller (core
// CreateDraftTx, D5, D103 T1).
type Drafts interface {
	CreateDraftTx(ctx context.Context, tx db.TenantTx, d Draft) (automation, version ids.UUID, err error)
}

// TestStore stores a version's test cases in the caller's transaction, as
// the caller (assurance SetTestCasesTx, D34, D103 T1).
type TestStore interface {
	SetTestCasesTx(ctx context.Context, tx db.TenantTx, version ids.UUID, cases []templates.TestCase) (int, error)
}

// TemplateHandler serves TemplateService.
type TemplateHandler struct {
	pantherclawv1connect.UnimplementedTemplateServiceHandler
	Pool   *db.Pool
	Drafts Drafts
	Tests  TestStore
}

var _ pantherclawv1connect.TemplateServiceHandler = (*TemplateHandler)(nil)

func caller(ctx context.Context, p td.Permission, human bool) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if human && !c.Human() {
		return c, ErrHumanOnly
	}
	return c, c.Require(p, td.OrgPath(c.Org))
}

func templateOf(t templates.Template) *pantherclawv1.AutomationTemplate {
	out := &pantherclawv1.AutomationTemplate{
		Id: t.ID, Title: t.Title, Summary: t.Summary, Kind: t.Kind, Edition: strings.ToUpper(string(t.Edition)),
	}
	for _, p := range t.Params {
		out.Params = append(out.Params, &pantherclawv1.AutomationTemplateParam{
			Name: p.Name, Type: string(p.Type), Description: p.Description, Required: p.Required == nil || *p.Required,
			Values: p.Values, DefaultValue: p.Default,
		})
	}
	return out
}

// ListTemplates implements TemplateService.
func (h *TemplateHandler) ListTemplates(ctx context.Context, _ *pantherclawv1.ListTemplatesRequest) (*pantherclawv1.ListTemplatesResponse, error) {
	if _, err := caller(ctx, td.PermAutomationRead, false); err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListTemplatesResponse{}
	for _, t := range templates.List() {
		out.Templates = append(out.Templates, templateOf(t))
	}
	return out, nil
}

// GetTemplate implements TemplateService: the definition as shipped and
// the baseline tests rendered from the template's example parameters.
func (h *TemplateHandler) GetTemplate(ctx context.Context, req *pantherclawv1.GetTemplateRequest) (*pantherclawv1.GetTemplateResponse, error) {
	if _, err := caller(ctx, td.PermAutomationRead, false); err != nil {
		return nil, err
	}
	t, ok := templates.Get(req.GetId())
	if !ok {
		return nil, ErrNotFound
	}
	src, _ := templates.Source(t.ID)
	_, tests, err := templates.Render(t.ID, t.Example())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetTemplateResponse{Template: templateOf(t), DefinitionYaml: string(src)}
	for _, tc := range tests {
		b, err := json.Marshal(tc, json.Deterministic(true))
		if err != nil {
			return nil, err
		}
		out.Tests = append(out.Tests, &pantherclawv1.AutomationTemplateTest{Name: tc.Name, Kind: tc.Kind, CaseJson: b})
	}
	return out, nil
}

// CreateFromTemplate implements TemplateService.
func (h *TemplateHandler) CreateFromTemplate(ctx context.Context, req *pantherclawv1.CreateFromTemplateRequest) (*pantherclawv1.CreateFromTemplateResponse, error) {
	c, err := caller(ctx, td.PermAutomationManage, true)
	if err != nil {
		return nil, err
	}
	// The automation, its version and its baseline tests are one unit
	// (D103 T1): without both ports nothing is created.
	if h.Pool == nil || h.Drafts == nil || h.Tests == nil {
		return nil, ErrUnavailable
	}
	t, ok := templates.Get(req.GetTemplateId())
	if !ok {
		return nil, ErrNotFound
	}
	doc, tests, err := templates.Render(t.ID, req.GetParams())
	if err != nil {
		if errors.Is(err, templates.ErrParams) {
			return nil, pcerr.Wrap(err, pcerr.InvalidArgument, "TEMPLATE_PARAMS", err.Error())
		}
		return nil, err
	}
	owner := c.Principal.ID
	if req.GetOwnerUserId() != "" {
		if owner, err = ids.ParseUUID(req.GetOwnerUserId()); err != nil {
			return nil, ErrInvalidID
		}
	}
	purpose := req.GetPurpose()
	if purpose == "" {
		purpose = t.Summary
	}
	var automation, version ids.UUID
	var n int
	err = h.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		automation, version, err = h.Drafts.CreateDraftTx(ctx, tx, Draft{Name: req.GetName(), Purpose: purpose, Kind: t.Kind, Owner: owner, Definition: doc})
		if err != nil {
			return err
		}
		n, err = h.Tests.SetTestCasesTx(ctx, tx, version, tests)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateFromTemplateResponse{
		AutomationId: automation.String(), VersionId: version.String(), Tests: int32(n), //nolint:gosec // G115: a template has a few cases
	}, nil
}

// ProposalHandler serves ProposalService.
type ProposalHandler struct {
	pantherclawv1connect.UnimplementedProposalServiceHandler
	Pool *db.Pool
}

var _ pantherclawv1connect.ProposalServiceHandler = (*ProposalHandler)(nil)

func proposalOf(p dbq.PcAutomationProposal, automation ids.UUID) *pantherclawv1.AutomationProposal {
	out := &pantherclawv1.AutomationProposal{
		Id: p.ID.String(), ExecutionId: p.ExecutionID.String(), AutomationId: automation.String(), StepId: p.StepID,
		Kind: p.Kind, SubjectType: p.SubjectType, SubjectId: p.SubjectID.String(), Body: p.Body, State: p.State,
		CreatedAt: timestamppb.New(p.CreatedAt),
	}
	if p.DecidedBy != nil {
		out.DecidedBy = p.DecidedBy.String()
	}
	if p.DecidedAt != nil {
		out.DecidedAt = timestamppb.New(*p.DecidedAt)
	}
	return out
}

func optID(s string) (*ids.UUID, error) {
	if s == "" {
		return nil, nil //nolint:nilnil // unset
	}
	id, err := ids.ParseUUID(s)
	if err != nil {
		return nil, ErrInvalidID
	}
	return &id, nil
}

func optStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// ListProposals implements ProposalService.
func (h *ProposalHandler) ListProposals(ctx context.Context, req *pantherclawv1.ListProposalsRequest) (*pantherclawv1.ListProposalsResponse, error) {
	c, err := caller(ctx, td.PermAutomationRead, false)
	if err != nil {
		return nil, err
	}
	p := dbq.ListAutomationProposalsParams{OrgID: c.Org, State: optStr(req.GetState()), Kind: optStr(req.GetKind()), MaxRows: req.GetPageSize()}
	if p.MaxRows == 0 {
		p.MaxRows = 50
	}
	if p.SubjectID, err = optID(req.GetSubjectId()); err != nil {
		return nil, err
	}
	if p.AutomationID, err = optID(req.GetAutomationId()); err != nil {
		return nil, err
	}
	if p.After, err = optID(req.GetPageToken()); err != nil {
		return nil, err
	}
	p.MaxRows++
	out := &pantherclawv1.ListProposalsResponse{}
	err = h.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListAutomationProposals(ctx, p)
		if err != nil {
			return err
		}
		for i, r := range rows {
			if int32(i) == p.MaxRows-1 {
				out.NextPageToken = rows[i-1].ID.String()
				break
			}
			out.Proposals = append(out.Proposals, proposalOf(dbq.PcAutomationProposal{
				OrgID: r.OrgID, ID: r.ID, ExecutionID: r.ExecutionID, StepID: r.StepID, Kind: r.Kind, SubjectType: r.SubjectType,
				SubjectID: r.SubjectID, Body: r.Body, State: r.State, CreatedAt: r.CreatedAt, DecidedBy: r.DecidedBy, DecidedAt: r.DecidedAt,
			}, r.AutomationID))
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// DecideProposal implements ProposalService: it records the decision and
// nothing else (HR-286).
func (h *ProposalHandler) DecideProposal(ctx context.Context, req *pantherclawv1.DecideProposalRequest) (*pantherclawv1.DecideProposalResponse, error) {
	c, err := caller(ctx, td.PermAutomationManage, true)
	if err != nil {
		return nil, err
	}
	id, err := ids.ParseUUID(req.GetId())
	if err != nil {
		return nil, ErrInvalidID
	}
	state := "DECLINED"
	if req.GetDecision() == "ACCEPT" {
		state = "ACCEPTED"
	}
	who := c.Principal.ID
	var out *pantherclawv1.AutomationProposal
	err = h.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		p, err := q.DecideAutomationProposal(ctx, dbq.DecideAutomationProposalParams{State: state, DecidedBy: &who, OrgID: c.Org, ID: id})
		if db.IsNoRows(err) {
			if _, gerr := q.GetAutomationProposal(ctx, c.Org, id); db.IsNoRows(gerr) {
				return ErrNotFound
			}
			return ErrDecided
		} else if err != nil {
			return err
		}
		e, err := q.GetAutomationExecution(ctx, c.Org, p.ExecutionID)
		if err != nil {
			return err
		}
		out = proposalOf(p, e.AutomationID)
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "automation.proposal_decided", Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "automation_proposal", ID: p.ID.String()},
			Details: map[string]string{
				"automation": e.AutomationID.String(), "execution": p.ExecutionID.String(), "kind": p.Kind,
				"subject_type": p.SubjectType, "subject": p.SubjectID.String(), "decision": state,
			},
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.DecideProposalResponse{Proposal: out}, nil
}
