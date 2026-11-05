// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package partners

import (
	"context"
	"encoding/json/v2"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	"github.com/katocxl/pantherclaw/internal/policy/packs"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Proposal kinds (D1102).
const (
	KindPolicyVersion = "POLICY_VERSION"
	KindPack          = "PACK"
)

// Proposal states.
const (
	ProposalProposed  = "PROPOSED"
	ProposalAccepted  = "ACCEPTED"
	ProposalDeclined  = "DECLINED"
	ProposalWithdrawn = "WITHDRAWN"
	ProposalExpired   = "EXPIRED"
)

// OriginPrefix marks a draft that came from a partner: origin =
// partner:<partner org> (D1102).
const OriginPrefix = "partner:"

// Proposal errors.
var (
	ErrProposalInvalid = pcerr.New(pcerr.InvalidArgument, "INVALID_PARTNER_PROPOSAL",
		"a proposal needs 1 to 100 linked customers, a kind, a title of 1 to 200 characters of plain text and a body "+
			"of at most 256 KiB: a policy document, or {pack, environment, agents, cohort, parameters}")
	ErrProposalNotFound = pcerr.New(pcerr.NotFound, "PARTNER_PROPOSAL_NOT_FOUND", "partner proposal not found")
	ErrNotProposed      = pcerr.New(pcerr.FailedPrecondition, "PARTNER_PROPOSAL_NOT_PROPOSED",
		"the proposal was already decided, withdrawn or has expired")
	ErrDraftsUnavailable = pcerr.New(pcerr.FailedPrecondition, "PARTNER_PROPOSAL_DRAFTS_UNAVAILABLE",
		"this server cannot draft proposals")
)

// Drafts stores a policy document as a DRAFT version through the existing
// draft path (policyapp.Versions).
type Drafts interface {
	CreateExpectingWith(ctx context.Context, raw []byte, expected *ids.UUID, details map[string]string) (policyapp.VersionInfo, error)
}

// Packs drafts a reference pack (packs.Service).
type Packs interface {
	ApplyPack(ctx context.Context, in packs.Apply) (packs.Applied, error)
}

// WithDrafts sets the draft paths acceptance uses.
func (s *Service) WithDrafts(d Drafts, p Packs) *Service {
	s.drafts, s.packs = d, p
	return s
}

// Proposal is one proposal to one customer.
type Proposal struct {
	ID            ids.UUID
	Link          ids.UUID
	PartnerOrg    ids.UUID
	CustomerOrg   ids.UUID
	Kind          string
	Title         string
	Body          []byte
	Template      *ids.UUID
	State         string
	ProposedBy    string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	DecidedBy     string
	DecidedAt     *time.Time
	DeclineReason string
	Draft         *ids.UUID
}

func proposalOf(r dbq.GetPartnerProposalRow) Proposal {
	p := Proposal{
		ID: r.ID, Link: r.LinkID, PartnerOrg: r.PartnerOrg, CustomerOrg: r.CustomerOrg, Kind: r.Kind, Title: r.Title,
		Body: r.Body, Template: r.TemplateID, State: r.State, ProposedBy: r.ProposedBy, CreatedAt: r.CreatedAt,
		ExpiresAt: r.ExpiresAt, DecidedAt: r.DecidedAt, Draft: r.DraftRef,
	}
	if r.Expired {
		p.State = ProposalExpired
	}
	if r.DecidedBy != nil {
		p.DecidedBy = *r.DecidedBy
	}
	if r.DeclineReason != nil {
		p.DeclineReason = *r.DeclineReason
	}
	return p
}

// packBody is a PACK proposal's body.
type packBody struct {
	Pack        string            `json:"pack"`
	Environment ids.UUID          `json:"environment"`
	Agents      []ids.UUID        `json:"agents,omitzero"`
	Cohort      *ids.UUID         `json:"cohort,omitzero"`
	Parameters  map[string]string `json:"parameters,omitzero"`
}

// checkBody decodes a body as its kind needs, without compiling it: the
// customer's draft path compiles it against the customer's definitions on
// acceptance.
func checkBody(kind string, body []byte) error {
	if len(body) < 2 || len(body) > MaxBodyBytes {
		return ErrProposalInvalid
	}
	switch kind {
	case KindPolicyVersion:
		if _, err := policyapp.DecodeBundle(body); err != nil {
			return pcerr.Wrap(err, pcerr.InvalidArgument, "INVALID_PARTNER_PROPOSAL", "the policy document does not decode: "+err.Error())
		}
	case KindPack:
		var b packBody
		if err := json.Unmarshal(body, &b, json.RejectUnknownMembers(true)); err != nil {
			return ErrProposalInvalid
		}
		if _, err := packs.Get(b.Pack); err != nil {
			return err
		}
	default:
		return ErrProposalInvalid
	}
	return nil
}

// NewProposal is one change proposed to customers.
type NewProposal struct {
	Customers []ids.UUID
	Kind      string
	Title     string
	Body      []byte
}

// Propose creates one PROPOSED row per customer (D1102). From a partner
// session it proposes to the session's customer only, over the session's
// link, which needs the PROPOSE scope. From the partner org it needs a
// person holding partner.manage, the org on Enterprise, and an ACTIVE link
// with the PROPOSE scope to each customer; one template id groups the
// rows. Nothing else happens: only a customer person's acceptance makes a
// draft (HR-814). Each proposal is recorded in both orgs.
func (s *Service) Propose(ctx context.Context, in NewProposal) ([]Proposal, ids.UUID, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return nil, ids.UUID{}, err
	}
	if len(in.Customers) == 0 || len(in.Customers) > MaxCustomers || in.Title == "" || !plainText(in.Title, MaxTitleRunes) {
		return nil, ids.UUID{}, ErrProposalInvalid
	}
	if err := checkBody(in.Kind, in.Body); err != nil {
		return nil, ids.UUID{}, err
	}
	if c.PartnerSession() {
		p, err := s.proposeFromSession(ctx, c, in)
		if err != nil {
			return nil, ids.UUID{}, err
		}
		return []Proposal{p}, ids.UUID{}, nil
	}
	if c, err = person(ctx, PermManage); err != nil {
		return nil, ids.UUID{}, err
	}
	if err := s.partnerAccess(ctx, c.Org); err != nil {
		return nil, ids.UUID{}, err
	}
	var template *ids.UUID
	if len(in.Customers) > 1 {
		t := ids.NewV7()
		template = &t
	}
	actor := partnerActor(c.Org.UUID(), c.Principal.ID)
	var out []Proposal
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		for _, customer := range in.Customers {
			l, err := q.LivePartnerLink(ctx, c.Org.UUID(), customer)
			if db.IsNoRows(err) {
				return ErrNoLink
			} else if err != nil {
				return err
			}
			if !slices.Contains(l.Scopes, ScopePropose) {
				return ErrNoPropose
			}
			p, err := insertProposal(ctx, tx, q, l.ID, c.Org.UUID(), customer, in, template, actor)
			if err != nil {
				return err
			}
			out = append(out, p)
		}
		return nil
	})
	if err != nil {
		return nil, ids.UUID{}, err
	}
	for _, p := range out {
		if err := s.mirror(ctx, p.CustomerOrg, actor, auditkind.PartnerProposalCreated, "partner_proposal", p.ID,
			proposalDetails(p)); err != nil {
			return nil, ids.UUID{}, err
		}
	}
	var t ids.UUID
	if template != nil {
		t = *template
	}
	return out, t, nil
}

func (s *Service) proposeFromSession(ctx context.Context, c tapp.Caller, in NewProposal) (Proposal, error) {
	if len(in.Customers) != 1 || in.Customers[0] != c.Org.UUID() {
		return Proposal{}, ErrProposalInvalid
	}
	var out Proposal
	var actor evdomain.Actor
	err := s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		sess, err := q.GetPartnerSession(ctx, c.Org, c.Session)
		if db.IsNoRows(err) {
			return ErrNotSession
		} else if err != nil {
			return err
		}
		if sess.State != "ACTIVE" {
			return ErrNotSession
		}
		if !slices.Contains(sess.Scopes, ScopePropose) {
			return ErrNoPropose
		}
		actor = partnerActor(sess.PartnerOrg, sess.PartnerUser)
		out, err = insertProposal(ctx, tx, q, sess.LinkID, sess.PartnerOrg, c.Org.UUID(), in, nil, actor)
		return err
	})
	if err != nil {
		return Proposal{}, err
	}
	return out, s.mirror(ctx, out.PartnerOrg, actor, auditkind.PartnerProposalCreated, "partner_proposal", out.ID,
		proposalDetails(out))
}

func proposalDetails(p Proposal) map[string]string {
	d := map[string]string{
		"kind": p.Kind, "link": p.Link.String(), "partner_org": p.PartnerOrg.String(), "customer_org": p.CustomerOrg.String(),
	}
	if p.Template != nil {
		d["template"] = p.Template.String()
	}
	return d
}

func insertProposal(ctx context.Context, tx db.TenantTx, q *dbq.Queries, link, partner, customer ids.UUID, in NewProposal,
	template *ids.UUID, actor evdomain.Actor,
) (Proposal, error) {
	id := ids.NewV7()
	if err := q.InsertPartnerProposal(ctx, dbq.InsertPartnerProposalParams{
		ID: id, LinkID: link, PartnerOrg: partner, CustomerOrg: customer, Kind: in.Kind, Title: in.Title, Body: in.Body,
		TemplateID: template, ProposedBy: actorString(actor),
	}); err != nil {
		return Proposal{}, err
	}
	r, err := q.GetPartnerProposal(ctx, id, customer)
	if err != nil {
		return Proposal{}, err
	}
	p := proposalOf(r)
	return p, record(ctx, tx, actor, auditkind.PartnerProposalCreated, "partner_proposal", id, proposalDetails(p))
}

func (s *Service) getProposal(ctx context.Context, org ids.OrgID, id ids.UUID) (Proposal, error) {
	var out Proposal
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		r, err := dbq.New(tx).GetPartnerProposal(ctx, id, org.UUID())
		if db.IsNoRows(err) {
			return ErrProposalNotFound
		} else if err != nil {
			return err
		}
		out = proposalOf(r)
		return nil
	}, db.ReadOnly())
	return out, err
}

// GetProposal returns one proposal of the caller's org with its body
// (partner.read).
func (s *Service) GetProposal(ctx context.Context, id ids.UUID) (Proposal, error) {
	c, err := reader(ctx)
	if err != nil {
		return Proposal{}, err
	}
	return s.getProposal(ctx, c.Org, id)
}

// ListProposals returns one page of the caller's org's proposals by id,
// without bodies (partner.read).
func (s *Service) ListProposals(ctx context.Context, size int32, token string) ([]Proposal, string, error) {
	c, err := reader(ctx)
	if err != nil {
		return nil, "", err
	}
	pr, err := page.Parse(size, token)
	if err != nil {
		return nil, "", err
	}
	var after *ids.UUID
	if !pr.After.IsZero() {
		after = &pr.After
	}
	var out []Proposal
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListPartnerProposals(ctx, c.Org.UUID(), after, pr.Limit())
		if err != nil {
			return err
		}
		for _, r := range rows {
			out = append(out, proposalOf(dbq.GetPartnerProposalRow{
				ID: r.ID, LinkID: r.LinkID, PartnerOrg: r.PartnerOrg, CustomerOrg: r.CustomerOrg, Kind: r.Kind, Title: r.Title,
				TemplateID: r.TemplateID, State: r.State, ProposedBy: r.ProposedBy, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt,
				DecidedBy: r.DecidedBy, DecidedAt: r.DecidedAt, DeclineReason: r.DeclineReason, DraftRef: r.DraftRef,
				Expired: r.Expired,
			}))
		}
		return nil
	}, db.ReadOnly())
	if err != nil {
		return nil, "", err
	}
	out, next := page.Finish(pr, out, func(p Proposal) ids.UUID { return p.ID })
	return out, next, nil
}

// customerProposal returns a PROPOSED proposal to the caller's org, for a
// customer person holding policy.author.
func (s *Service) customerProposal(ctx context.Context) (tapp.Caller, error) {
	return person(ctx, td.PermPolicyAuthor)
}

// Accept makes a proposal a DRAFT (HR-814): a customer person holding
// policy.author. A POLICY_VERSION goes through the existing draft path
// with origin partner:<partner org> in its policy.version_created record;
// a PACK through ApplyPack. Nothing is published: the existing publish and
// rollout flow applies, and a loosening of a version from a partner always
// needs two customer people (HR-815). The proposal records the draft.
func (s *Service) Accept(ctx context.Context, id ids.UUID) (Proposal, error) {
	c, err := s.customerProposal(ctx)
	if err != nil {
		return Proposal{}, err
	}
	p, err := s.getProposal(ctx, c.Org, id)
	if err != nil {
		return Proposal{}, err
	}
	if p.CustomerOrg != c.Org.UUID() {
		return Proposal{}, ErrProposalNotFound
	}
	if p.State != ProposalProposed {
		return Proposal{}, ErrNotProposed
	}
	origin := OriginPrefix + p.PartnerOrg.String()
	var draft ids.UUID
	switch p.Kind {
	case KindPolicyVersion:
		if s.drafts == nil {
			return Proposal{}, ErrDraftsUnavailable
		}
		v, err := s.drafts.CreateExpectingWith(ctx, p.Body, nil, map[string]string{"origin": origin, "partner_proposal": id.String()})
		if err != nil {
			return Proposal{}, err
		}
		draft = v.ID
	case KindPack:
		if s.packs == nil {
			return Proposal{}, ErrDraftsUnavailable
		}
		var b packBody
		if err := json.Unmarshal(p.Body, &b, json.RejectUnknownMembers(true)); err != nil {
			return Proposal{}, ErrProposalInvalid
		}
		a, err := s.packs.ApplyPack(ctx, packs.Apply{
			Pack: b.Pack, Environment: b.Environment, Agents: b.Agents, Cohort: b.Cohort, Parameters: b.Parameters,
		})
		if err != nil {
			return Proposal{}, err
		}
		draft = a.Version.ID
	default:
		return Proposal{}, ErrProposalInvalid
	}
	actor := c.Actor()
	details := proposalDetails(p)
	details["draft_version"] = draft.String()
	details["origin"] = origin
	var out Proposal
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		by := actorString(actor)
		n, err := q.AcceptPartnerProposal(ctx, dbq.AcceptPartnerProposalParams{
			DecidedBy: &by, DraftRef: &draft, ID: id, CustomerOrg: c.Org.UUID(),
		})
		if err != nil {
			return err
		}
		if n == 0 {
			// The draft stays a draft: nothing is published from it.
			return ErrNotProposed
		}
		r, err := q.GetPartnerProposal(ctx, id, c.Org.UUID())
		if err != nil {
			return err
		}
		out = proposalOf(r)
		return record(ctx, tx, actor, auditkind.PartnerProposalAccepted, "partner_proposal", id, details)
	})
	if err != nil {
		return Proposal{}, err
	}
	return out, s.mirror(ctx, p.PartnerOrg, actor, auditkind.PartnerProposalAccepted, "partner_proposal", id, details)
}

// Decline declines a proposal (a customer person holding policy.author).
func (s *Service) Decline(ctx context.Context, id ids.UUID, reason string) (Proposal, error) {
	c, err := s.customerProposal(ctx)
	if err != nil {
		return Proposal{}, err
	}
	if !plainText(reason, MaxReasonRunes) {
		return Proposal{}, ErrProposalInvalid
	}
	actor := c.Actor()
	var out Proposal
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		by := actorString(actor)
		var why *string
		if reason != "" {
			why = &reason
		}
		n, err := q.DeclinePartnerProposal(ctx, dbq.DeclinePartnerProposalParams{
			DecidedBy: &by, DeclineReason: why, ID: id, CustomerOrg: c.Org.UUID(),
		})
		if err != nil {
			return err
		}
		r, err := q.GetPartnerProposal(ctx, id, c.Org.UUID())
		if db.IsNoRows(err) || (err == nil && r.CustomerOrg != c.Org.UUID()) {
			return ErrProposalNotFound
		} else if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotProposed
		}
		out = proposalOf(r)
		return record(ctx, tx, actor, auditkind.PartnerProposalDeclined, "partner_proposal", id, proposalDetails(out))
	})
	if err != nil {
		return Proposal{}, err
	}
	return out, s.mirror(ctx, out.PartnerOrg, actor, auditkind.PartnerProposalDeclined, "partner_proposal", id,
		proposalDetails(out))
}

// Withdraw withdraws a proposal (partner side, partner.manage, a person).
func (s *Service) Withdraw(ctx context.Context, id ids.UUID) (Proposal, error) {
	c, err := person(ctx, PermManage)
	if err != nil {
		return Proposal{}, err
	}
	actor := partnerActor(c.Org.UUID(), c.Principal.ID)
	var out Proposal
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		by := actorString(actor)
		n, err := q.WithdrawPartnerProposal(ctx, &by, id, c.Org.UUID())
		if err != nil {
			return err
		}
		r, err := q.GetPartnerProposal(ctx, id, c.Org.UUID())
		if db.IsNoRows(err) || (err == nil && r.PartnerOrg != c.Org.UUID()) {
			return ErrProposalNotFound
		} else if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotProposed
		}
		out = proposalOf(r)
		return record(ctx, tx, actor, auditkind.PartnerProposalWithdrawn, "partner_proposal", id, proposalDetails(out))
	})
	if err != nil {
		return Proposal{}, err
	}
	return out, s.mirror(ctx, out.CustomerOrg, actor, auditkind.PartnerProposalWithdrawn, "partner_proposal", id,
		proposalDetails(out))
}
