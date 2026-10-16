// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package securitysteps

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Proposal kinds and subject types (00143). A RESTRICTION is about the
// policy draft it was written into; the others about the trigger's agent.
const (
	ProposalOwner       = "OWNER"
	ProposalBaseline    = "BASELINE"
	ProposalTests       = "TESTS"
	ProposalRestriction = "RESTRICTION"

	ProposalAboutAgent  = "agent"
	ProposalAboutPolicy = "policy_version"
)

// MaxProposalBody is the largest proposal body, as the table checks it
// (octet_length(body::text) ≤ 16 KiB).
const MaxProposalBody = 16 << 10

// OutProposal is the output key of a recorded proposal's id.
const OutProposal = "proposal_id"

// ErrProposalBody reports a body that is not a JSON object of at most
// MaxProposalBody bytes.
var ErrProposalBody = errors.New("securitysteps: a proposal body is a JSON object of at most 16 KiB")

// Proposals records the intake and review kinds' proposals (HR-286): what
// an automation finds is written down for a person to decide, never acted
// on. A nil Proposals in IntakeDeps or ReviewDeps is the table itself.
type Proposals interface {
	// Propose records one proposal per execution, step and subject and
	// supersedes the open proposals of the same kind about the same
	// subject; a repeat of the step returns the first.
	Propose(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext, kind, about string, subject ids.UUID, body any) (ids.UUID, error)
	// Body returns a proposal's kind and body.
	Body(ctx context.Context, tx pgx.Tx, org ids.OrgID, id ids.UUID) (string, []byte, error)
}

// TableProposals is Proposals over pc.automation_proposals.
type TableProposals struct{}

// Propose implements Proposals.
func (TableProposals) Propose(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext, kind, about string, subject ids.UUID, body any) (ids.UUID, error) {
	return propose(ctx, tx, sc, kind, about, subject, body)
}

// Body implements Proposals.
func (TableProposals) Body(ctx context.Context, tx pgx.Tx, org ids.OrgID, id ids.UUID) (string, []byte, error) {
	p, err := dbq.New(tx).GetAutomationProposal(ctx, org, id)
	if err != nil {
		return "", nil, err
	}
	return p.Kind, p.Body, nil
}

func proposalsOr(p Proposals) Proposals {
	if p == nil {
		return TableProposals{}
	}
	return p
}

// propose records a proposal of the step about subject, once per
// execution, step and subject: a repeat (a retried attempt, a replayed
// poll) finds the first, whose body never changes. A new proposal
// supersedes the older open ones of its kind about the same subject, so a
// person decides only the latest.
func propose(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext, kind, about string, subject ids.UUID, body any) (ids.UUID, error) {
	raw, err := json.Marshal(body, json.Deterministic(true))
	if err != nil {
		return ids.UUID{}, err
	}
	// jsonb renders ": " and ", ", so count every separator once more.
	if len(raw) < 2 || raw[0] != '{' || len(raw)+bytes.Count(raw, []byte{':'})+bytes.Count(raw, []byte{','}) > MaxProposalBody {
		return ids.UUID{}, ErrProposalBody
	}
	q := dbq.New(tx)
	row, err := q.InsertAutomationProposal(ctx, dbq.InsertAutomationProposalParams{
		OrgID: sc.Org, ID: ids.NewV7(), ExecutionID: sc.Execution.ID, StepID: sc.Spec.ID, Kind: kind,
		SubjectType: about, SubjectID: subject, Body: raw,
	})
	if db.IsNoRows(err) {
		// ON CONFLICT … WHERE false returns no row: the step proposed
		// already.
		row, err = q.GetAutomationProposalByStep(ctx, dbq.GetAutomationProposalByStepParams{
			OrgID: sc.Org, ExecutionID: sc.Execution.ID, StepID: sc.Spec.ID, SubjectID: subject,
		})
		if err != nil {
			return ids.UUID{}, err
		}
		if row.Kind != kind || row.SubjectType != about {
			return ids.UUID{}, fmt.Errorf("securitysteps: step %s proposed a %s about %s before", sc.Spec.ID, row.Kind, row.SubjectType)
		}
		return row.ID, nil
	}
	if err != nil {
		return ids.UUID{}, err
	}
	if _, err := q.SupersedeAutomationProposals(ctx, dbq.SupersedeAutomationProposalsParams{
		OrgID: sc.Org, Kind: kind, SubjectID: subject, Keep: row.ID,
	}); err != nil {
		return ids.UUID{}, err
	}
	return row.ID, nil
}
