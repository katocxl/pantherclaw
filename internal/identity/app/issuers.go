// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"strconv"
	"strings"
	"time"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors of the issuer-entry use cases.
var (
	ErrEntryNotFound = pcerr.New(pcerr.NotFound, "ISSUER_ENTRY_NOT_FOUND", "trusted-issuer entry not found")
	ErrEntryState    = pcerr.New(pcerr.FailedPrecondition, "ISSUER_ENTRY_STATE",
		"the entry or revision is not in a state that allows this change")
	ErrProposalOpen = pcerr.New(pcerr.FailedPrecondition, "ISSUER_PROPOSAL_OPEN",
		"the entry already has a proposed revision; withdraw or activate it first")
	ErrContextMismatch = pcerr.New(pcerr.InvalidArgument, "ISSUER_CONTEXT",
		"the GitHub and GitLab presets are for ci agents, the Kubernetes preset for kubernetes agents and the SPIFFE and cloud presets for service agents; desktop agents stay at L1")
	ErrUnknownCluster = pcerr.New(pcerr.InvalidArgument, "ISSUER_CLUSTER",
		"the cluster is not configured for this organization (identity.kubernetes_clusters)")
	ErrUnknownIssuer = pcerr.New(pcerr.InvalidArgument, "ISSUER_NOT_CONFIGURED",
		"the issuer is not configured for this organization (identity.gitlab_issuers, identity.spiffe_trust_domains)")
	ErrConfirmReusable = pcerr.New(pcerr.FailedPrecondition, "CONFIRM_REUSABLE_REFS",
		"confirm that every reusable workflow ref is a protected branch or tag of its repository")
)

// Clusters tells which configured Kubernetes clusters an org may use
// (founder decision 3: clusters are operator configuration).
type Clusters interface {
	Allowed(cluster string, org ids.OrgID) bool
}

// Binding is the binding of one preset: exactly one field is set.
type Binding struct {
	GitHub     *issuers.GitHubBinding     `json:"github,omitzero"`
	Kubernetes *issuers.KubernetesBinding `json:"kubernetes,omitzero"`
	GitLab     *issuers.GitLabBinding     `json:"gitlab,omitzero"`
	SPIFFE     *issuers.SPIFFEBinding     `json:"spiffe,omitzero"`
	GCP        *issuers.GCPBinding        `json:"gcp,omitzero"`
}

// presetContext is the execution context each preset attests (D119-D121).
var presetContext = map[issuers.Kind]adomain.ExecutionContext{
	issuers.KindGitHub: adomain.ContextCI, issuers.KindKubernetes: adomain.ContextKubernetes, issuers.KindGitLab: adomain.ContextCI,
	issuers.KindSPIFFE: adomain.ContextService,
	issuers.KindGCP:    adomain.ContextService,
}

// kinds lists the kind of every field that is set.
func (b Binding) kinds() []issuers.Kind {
	var out []issuers.Kind
	for k, set := range map[issuers.Kind]bool{
		issuers.KindGitHub: b.GitHub != nil, issuers.KindKubernetes: b.Kubernetes != nil, issuers.KindGitLab: b.GitLab != nil,
		issuers.KindSPIFFE: b.SPIFFE != nil,
		issuers.KindGCP:    b.GCP != nil,
	} {
		if set {
			out = append(out, k)
		}
	}
	return out
}

func (b Binding) kind() issuers.Kind {
	if k := b.kinds(); len(k) == 1 {
		return k[0]
	}
	return ""
}

func (b Binding) validate() error {
	var err error
	switch b.kind() {
	case issuers.KindGitHub:
		err = b.GitHub.Validate()
	case issuers.KindKubernetes:
		err = b.Kubernetes.Validate()
	case issuers.KindGitLab:
		err = b.GitLab.Validate()
	case issuers.KindSPIFFE:
		err = b.SPIFFE.Validate()
	case issuers.KindGCP:
		err = b.GCP.Validate()
	default:
		return pcerr.New(pcerr.InvalidArgument, "ISSUER_BINDING", "exactly one preset binding is required")
	}
	if err != nil {
		return pcerr.Wrap(err, pcerr.InvalidArgument, "ISSUER_BINDING", err.Error())
	}
	return nil
}

func (b Binding) issuer() string {
	switch b.kind() {
	case issuers.KindGitHub:
		return issuers.GitHubIssuer
	case issuers.KindGitLab:
		return strings.TrimSuffix(b.GitLab.Issuer, "/")
	case issuers.KindSPIFFE:
		return b.SPIFFE.Issuer()
	case issuers.KindGCP:
		return issuers.GCPIssuer
	default:
		return b.Kubernetes.Issuer()
	}
}

func (b Binding) algorithms() []string {
	switch b.kind() {
	case issuers.KindGitHub:
		return issuers.GitHubAlgorithms
	case issuers.KindGitLab:
		return issuers.GitLabAlgorithms
	case issuers.KindSPIFFE:
		return issuers.SPIFFEAlgorithms
	case issuers.KindGCP:
		return issuers.GCPAlgorithms
	default:
		return []string{"TokenReview"}
	}
}

// widening lists what b accepts that prev did not; a kind change replaces
// the whole binding.
func (b Binding) widening(prev *Binding) []string {
	switch {
	case prev == nil:
		return []string{"new trusted issuer entry"}
	case b.kind() != prev.kind():
		return []string{"preset changed"}
	case b.GitHub != nil:
		return b.GitHub.Widening(prev.GitHub)
	case b.GitLab != nil:
		return b.GitLab.Widening(prev.GitLab)
	case b.SPIFFE != nil:
		return b.SPIFFE.Widening(prev.SPIFFE)
	case b.GCP != nil:
		return b.GCP.Widening(prev.GCP)
	default:
		return b.Kubernetes.Widening(prev.Kubernetes)
	}
}

// Revision is one revision of an issuer entry.
type Revision struct {
	ID          ids.UUID
	EntryID     ids.UUID
	Revision    int
	AgentID     ids.UUID
	Kind        issuers.Kind
	Issuer      string
	Audience    string
	Algorithms  []string
	Binding     Binding
	AutoAdmit   bool
	Widening    []string
	State       string
	ProposedBy  string
	ProposedAt  time.Time
	ActivatedBy string
	ActivatedAt *time.Time
	ClosedBy    string
	ClosedAt    *time.Time
}

func revisionView(r dbq.PcTrustedIssuer) (Revision, error) {
	out := Revision{
		ID: r.ID, EntryID: r.EntryID, Revision: int(r.Revision), AgentID: r.AgentID, Kind: issuers.Kind(r.Kind),
		Issuer: r.Issuer, Audience: r.Audience, Algorithms: r.Algorithms, AutoAdmit: r.AutoAdmit, State: r.State,
		ProposedBy: r.ProposedBy, ProposedAt: r.ProposedAt, ActivatedBy: deref(r.ActivatedBy), ActivatedAt: r.ActivatedAt,
		ClosedBy: deref(r.ClosedBy), ClosedAt: r.ClosedAt,
	}
	if err := json.Unmarshal(r.Binding, &out.Binding); err != nil {
		return out, err
	}
	return out, json.Unmarshal(r.Widening, &out.Widening)
}

// issuerAgent loads the agent an entry binds to and checks p where it
// lives; the agent must be claimed and not retired.
func issuerAgent(ctx context.Context, c tenancy.Caller, q *dbq.Queries, id ids.UUID, p td.Permission) (dbq.PcAgent, error) {
	a, err := q.LockAgent(ctx, c.Org, id)
	if db.IsNoRows(err) {
		return a, ErrAgentNotFound
	} else if err != nil {
		return a, err
	}
	path, err := agents.PathOf(ctx, q, a)
	if err != nil {
		return a, err
	}
	if err := c.Require(p, path); err != nil {
		return a, err
	}
	if a.ClaimedAt == nil || adomain.State(a.State) == adomain.StateRetired {
		return a, ErrAgentUnusable
	}
	return a, nil
}

// entry is the locked state of one issuer entry.
type entry struct {
	revisions []dbq.PcTrustedIssuer
	active    *dbq.PcTrustedIssuer
	proposed  *dbq.PcTrustedIssuer
}

func lockEntry(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID) (entry, error) {
	rows, err := q.LockIssuerEntry(ctx, org, id)
	if err != nil {
		return entry{}, err
	}
	if len(rows) == 0 {
		return entry{}, ErrEntryNotFound
	}
	e := entry{revisions: rows}
	for i := range rows {
		switch rows[i].State {
		case "ACTIVE":
			e.active = &rows[i]
		case "PROPOSED":
			e.proposed = &rows[i]
		}
	}
	return e, nil
}

// ProposeInput proposes a new entry or a new revision of an entry.
type ProposeInput struct {
	// EntryID is zero for a new entry.
	EntryID   ids.UUID
	AgentID   ids.UUID
	Binding   Binding
	AutoAdmit bool
	Reason    string
}

// ProposeIssuer creates an entry or a revision (HR-140, HR-141). A
// revision that adds or widens anything, turning on auto-admission
// included, is PROPOSED and changes nothing until a human activates it; a
// revision that only narrows replaces the active one at once. The preset
// must match the agent's execution context, and a Kubernetes cluster must be
// configured for the org.
func (s *Service) ProposeIssuer(ctx context.Context, in ProposeInput, clusters Clusters) (Revision, error) {
	if err := in.Binding.validate(); err != nil {
		return Revision{}, err
	}
	if err := adomain.ValidateReason(in.Reason); err != nil {
		return Revision{}, pcerr.Wrap(err, pcerr.InvalidArgument, "REASON", err.Error())
	}
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Revision{}, err
	}
	if k := in.Binding.Kubernetes; k != nil && (clusters == nil || !clusters.Allowed(k.Cluster, c.Org)) {
		return Revision{}, ErrUnknownCluster
	}
	if g := in.Binding.GitLab; g != nil && (s.att.GitLab == nil || !s.att.GitLab.Allowed(strings.TrimSuffix(g.Issuer, "/"), c.Org)) {
		return Revision{}, ErrUnknownIssuer
	}
	if sp := in.Binding.SPIFFE; sp != nil && (s.att.SPIFFE == nil || !s.att.SPIFFE.Allowed(sp.TrustDomain, c.Org)) {
		return Revision{}, ErrUnknownIssuer
	}
	var out Revision
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		a, err := issuerAgent(ctx, c, q, in.AgentID, td.PermIssuerManage)
		if err != nil {
			return err
		}
		if want := presetContext[in.Binding.kind()]; deref(a.ExecutionContext) != string(want) {
			return ErrContextMismatch
		}
		entryID, number := in.EntryID, int32(1)
		var prev *Binding
		var prevAuto bool
		var active *dbq.PcTrustedIssuer
		if !entryID.IsZero() {
			e, err := lockEntry(ctx, q, c.Org, entryID)
			if err != nil {
				return err
			}
			if e.revisions[0].AgentID != in.AgentID {
				return pcerr.New(pcerr.InvalidArgument, "ISSUER_AGENT", "an entry always binds the same agent")
			}
			if e.proposed != nil {
				return ErrProposalOpen
			}
			number = e.revisions[len(e.revisions)-1].Revision + 1
			if e.active != nil {
				active = e.active
				pr, err := revisionView(*e.active)
				if err != nil {
					return err
				}
				prev, prevAuto = &pr.Binding, pr.AutoAdmit
			}
		} else {
			entryID = ids.NewV7()
		}
		widening := in.Binding.widening(prev)
		if in.AutoAdmit && (prev == nil || !prevAuto) {
			widening = append(widening, "auto-admission turned on")
		}
		state := "PROPOSED"
		var activatedBy *string
		if len(widening) == 0 && active != nil {
			// Narrowing only: replace the active revision at once.
			state, activatedBy = "ACTIVE", ptr(c.Principal.String())
			if _, err := q.SetIssuerRevisionState(ctx, dbq.SetIssuerRevisionStateParams{
				OrgID: c.Org, ID: active.ID, FromState: "ACTIVE", ToState: "SUPERSEDED", ClosedBy: activatedBy,
			}); err != nil {
				return notFoundAs(err, ErrEntryState)
			}
		}
		binding, err := json.Marshal(in.Binding)
		if err != nil {
			return err
		}
		wjson, err := json.Marshal(nonNil(widening))
		if err != nil {
			return err
		}
		r, err := q.InsertIssuerRevision(ctx, dbq.InsertIssuerRevisionParams{
			OrgID: c.Org, ID: ids.NewV7(), EntryID: entryID, Revision: number, AgentID: a.ID, Kind: string(in.Binding.kind()),
			Issuer: in.Binding.issuer(), Audience: issuers.Audience(c.Org), Algorithms: in.Binding.algorithms(), Binding: binding,
			AutoAdmit: in.AutoAdmit, Widening: wjson, State: state, ProposedBy: c.Principal.String(), ActivatedBy: activatedBy,
		})
		if err != nil {
			return err
		}
		if out, err = revisionView(r); err != nil {
			return err
		}
		return recordAs(ctx, tx, c.Actor(), "identity.issuer_"+map[string]string{"PROPOSED": "proposed", "ACTIVE": "narrowed"}[state],
			"issuer_entry", entryID, map[string]string{
				"agent_id": a.ID.String(), "revision": strconv.Itoa(int(number)), "kind": string(in.Binding.kind()),
				"widening": strings.Join(widening, "; "),
			})
	})
	return out, err
}

// ActivateIssuer activates a proposed revision (HR-141): a person holding
// identity.issuer.activate where the agent lives, never a service account
// or API key. For a GitHub reusable-workflow binding the activator must
// confirm that each workflow ref is protected in its own repository, which
// the token cannot show (G0 M3 constraint 10).
func (s *Service) ActivateIssuer(ctx context.Context, entryID ids.UUID, revision int, confirmReusable bool) (Revision, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Revision{}, err
	}
	if !c.Human() {
		return Revision{}, td.ErrPermissionDenied(td.PermIssuerActivate)
	}
	var out Revision
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		e, err := lockEntry(ctx, q, c.Org, entryID)
		if err != nil {
			return err
		}
		if _, err := issuerAgent(ctx, c, q, e.revisions[0].AgentID, td.PermIssuerActivate); err != nil {
			return err
		}
		if e.proposed == nil || int(e.proposed.Revision) != revision {
			return ErrEntryState
		}
		pr, err := revisionView(*e.proposed)
		if err != nil {
			return err
		}
		if g := pr.Binding.GitHub; g != nil && g.JobType == issuers.JobReusable && !confirmReusable {
			return ErrConfirmReusable
		}
		by := ptr(c.Principal.String())
		if e.active != nil {
			if _, err := q.SetIssuerRevisionState(ctx, dbq.SetIssuerRevisionStateParams{
				OrgID: c.Org, ID: e.active.ID, FromState: "ACTIVE", ToState: "SUPERSEDED", ClosedBy: by,
			}); err != nil {
				return notFoundAs(err, ErrEntryState)
			}
		}
		r, err := q.ActivateIssuerRevision(ctx, by, c.Org, e.proposed.ID)
		if err != nil {
			return notFoundAs(err, ErrEntryState)
		}
		if out, err = revisionView(r); err != nil {
			return err
		}
		return recordAs(ctx, tx, c.Actor(), "identity.issuer_activated", "issuer_entry", entryID, map[string]string{
			"revision": strconv.Itoa(revision), "widening": strings.Join(pr.Widening, "; "),
			"confirmed_reusable_refs": strconv.FormatBool(confirmReusable),
		})
	})
	return out, err
}

// WithdrawIssuer withdraws a proposed revision.
func (s *Service) WithdrawIssuer(ctx context.Context, entryID ids.UUID, revision int) (Revision, error) {
	return s.closeIssuer(ctx, entryID, func(e entry) (*dbq.PcTrustedIssuer, string, error) {
		if e.proposed == nil || int(e.proposed.Revision) != revision {
			return nil, "", ErrEntryState
		}
		return e.proposed, "WITHDRAWN", nil
	}, "identity.issuer_withdrawn", "")
}

// DisableIssuer disables an entry at once (narrowing needs no activation):
// no more auto-admission, and its instances lose L2 at their next token
// refresh. An open proposal is withdrawn with it.
func (s *Service) DisableIssuer(ctx context.Context, entryID ids.UUID, reason string) (Revision, error) {
	if err := adomain.ValidateReason(reason); err != nil {
		return Revision{}, pcerr.Wrap(err, pcerr.InvalidArgument, "REASON", err.Error())
	}
	return s.closeIssuer(ctx, entryID, func(e entry) (*dbq.PcTrustedIssuer, string, error) {
		if e.active == nil {
			return nil, "", ErrEntryState
		}
		return e.active, "DISABLED", nil
	}, "identity.issuer_disabled", reason)
}

func (s *Service) closeIssuer(ctx context.Context, entryID ids.UUID, pick func(entry) (*dbq.PcTrustedIssuer, string, error), event, reason string) (Revision, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Revision{}, err
	}
	var out Revision
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		e, err := lockEntry(ctx, q, c.Org, entryID)
		if err != nil {
			return err
		}
		if _, err := issuerAgent(ctx, c, q, e.revisions[0].AgentID, td.PermIssuerManage); err != nil && !errors.Is(err, ErrAgentUnusable) {
			return err
		}
		target, to, err := pick(e)
		if err != nil {
			return err
		}
		by := ptr(c.Principal.String())
		if to == "DISABLED" && e.proposed != nil {
			if _, err := q.SetIssuerRevisionState(ctx, dbq.SetIssuerRevisionStateParams{
				OrgID: c.Org, ID: e.proposed.ID, FromState: "PROPOSED", ToState: "WITHDRAWN", ClosedBy: by,
			}); err != nil {
				return notFoundAs(err, ErrEntryState)
			}
		}
		r, err := q.SetIssuerRevisionState(ctx, dbq.SetIssuerRevisionStateParams{
			OrgID: c.Org, ID: target.ID, FromState: target.State, ToState: to, ClosedBy: by,
		})
		if err != nil {
			return notFoundAs(err, ErrEntryState)
		}
		if out, err = revisionView(r); err != nil {
			return err
		}
		return recordAs(ctx, tx, c.Actor(), event, "issuer_entry", entryID, map[string]string{
			"revision": strconv.Itoa(int(r.Revision)), "reason": reason,
		})
	})
	return out, err
}

// ListIssuers lists the current revision of each entry the caller may read.
func (s *Service) ListIssuers(ctx context.Context, agent ids.UUID, pr page.Request) ([]Revision, string, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, "", err
	}
	var out []Revision
	var next string
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var agentID *ids.UUID
		if !agent.IsZero() {
			agentID = &agent
		}
		rows, err := q.ListCurrentIssuerRevisions(ctx, dbq.ListCurrentIssuerRevisionsParams{
			OrgID: c.Org, AgentID: agentID, After: pr.After, PageLimit: pr.Limit(),
		})
		if err != nil {
			return err
		}
		rows, next = page.Finish(pr, rows, func(r dbq.PcTrustedIssuer) ids.UUID { return r.EntryID })
		for _, r := range rows {
			if ok, err := canRead(ctx, c, q, r.AgentID); err != nil {
				return err
			} else if !ok {
				continue
			}
			v, err := revisionView(r)
			if err != nil {
				return err
			}
			out = append(out, v)
		}
		return nil
	}, db.ReadOnly())
	return out, next, err
}

// GetIssuer returns every revision of one entry, newest first.
func (s *Service) GetIssuer(ctx context.Context, entryID ids.UUID) ([]Revision, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	var out []Revision
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.ListIssuerRevisions(ctx, c.Org, entryID)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return ErrEntryNotFound
		}
		if ok, err := canRead(ctx, c, q, rows[0].AgentID); err != nil {
			return err
		} else if !ok {
			return td.ErrPermissionDenied(td.PermIssuerRead)
		}
		for _, r := range rows {
			v, err := revisionView(r)
			if err != nil {
				return err
			}
			out = append(out, v)
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

func canRead(ctx context.Context, c tenancy.Caller, q *dbq.Queries, agent ids.UUID) (bool, error) {
	a, err := q.GetAgent(ctx, c.Org, agent)
	if err != nil {
		return false, err
	}
	path, err := agents.PathOf(ctx, q, a)
	if err != nil {
		return false, err
	}
	return c.Can(td.PermIssuerRead, path), nil
}

func notFoundAs(err, nf error) error {
	if db.IsNoRows(err) {
		return nf
	}
	return err
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
