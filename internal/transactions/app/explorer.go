// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// ErrTransactionNotFound is returned for an unknown transaction.
var ErrTransactionNotFound = pcerr.New(pcerr.NotFound, "TRANSACTION_NOT_FOUND", "transaction not found")

// Explorer serves the evidence explorer (G0 M7 track A, F466–F479). Every
// read is scoped like run.read: evidence.read where the run's agent lives.
type Explorer struct {
	Pool *db.Pool
}

// Filter narrows ListTransactions; empty fields match everything.
type Filter struct {
	Run, Agent, Connection *ids.UUID
	Decisions              []string
	Executions             []domain.ExecutionState
	Effects                []domain.EffectState
	Start, End             *time.Time
}

// Summary is one transaction, its execution state beside its effect state
// (F479).
type Summary struct {
	ID, Run, Agent ids.UUID
	Operation      string
	Connection     *ids.UUID
	Decision       string
	Reason         string
	Execution      domain.ExecutionState
	// Effect is empty until the first effect receipt.
	Effect             domain.EffectState
	Required, Achieved defs.Level
	Monitor            bool
	Evaluations        int
	Created            time.Time
}

// TransactionPage is one page of transactions, newest first.
type TransactionPage struct {
	Items []Summary
	Next  string
}

// Integrity is an evidence item's ledger entry and its place in the org's
// hash chain (0 while the entry waits to be chained).
type Integrity struct {
	Entry ids.UUID
	Seq   int64
}

// DecisionRecord is one evaluation's decision receipt.
type DecisionRecord struct {
	Evaluation int
	JWS        string
	Integrity  Integrity
	Created    time.Time
}

// Level is one level of authority a decision used.
type Level struct {
	Kind, ID string
	Revision int
}

// DecisionBasis is what the latest decision was made on, read from its
// signed receipt.
type DecisionBasis struct {
	Policy, Definition, Facts, Digest string
	Levels                            []Level
	Approval                          string
	Connection                        string
}

// ExecutionRecord is the dispatch attempt and its execution receipt.
type ExecutionRecord struct {
	Attempt, Permit ids.UUID
	Outcome         string
	TargetStatus    int
	RecordedBy      string
	TargetRef       string
	DispatchMS      int
	Dispatched      *time.Time
	Recorded        time.Time
	JWS             string
	Integrity       Integrity
}

// ObservationRecord is one read at the target. Fields are target data.
type ObservationRecord struct {
	ID             ids.UUID
	Source         string
	Verification   *ids.UUID
	Gateway        ids.UUID
	HTTPStatus     int
	Outcome        string
	Found          *bool
	Complete       *bool
	Fields         map[string]string
	ResponseDigest []byte
	Observed       time.Time
}

// EffectRecord is one effect receipt.
type EffectRecord struct {
	Seq                int
	State              domain.EffectState
	Required, Achieved defs.Level
	Basis              string
	JWS                string
	Integrity          Integrity
	Created            time.Time
}

// Reconciliation is one reconciliation task. Basis is the person's
// untrusted text.
type Reconciliation struct {
	ID, Transaction ids.UUID
	Kind            domain.TaskKind
	State           domain.TaskState
	Via             domain.Via
	Observation     *ids.UUID
	User            *ids.UUID
	Basis           string
	Evidence        []ids.UUID
	WaitlistEntry   *ids.UUID
	Opened          time.Time
	Resolved        *time.Time
}

// Link links a later transaction (From) to an earlier one (To).
type Link struct {
	From, To  ids.UUID
	Kind      domain.LinkKind
	CreatedBy string
	Created   time.Time
}

// Evidence is everything recorded about one transaction.
type Evidence struct {
	Transaction     Summary
	Decisions       []DecisionRecord
	Basis           *DecisionBasis
	Execution       *ExecutionRecord
	Observations    []ObservationRecord
	Effects         []EffectRecord
	Reconciliations []Reconciliation
	Links           []Link
}

// readers caches, per agent, whether the caller holds evidence.read where
// it lives.
type readers struct {
	c       tenancy.Caller
	q       *dbq.Queries
	allowed map[ids.UUID]bool
}

func newReaders(c tenancy.Caller, q *dbq.Queries) *readers {
	return &readers{c: c, q: q, allowed: map[ids.UUID]bool{}}
}

func (r *readers) can(ctx context.Context, agent ids.UUID) (bool, error) {
	if ok, seen := r.allowed[agent]; seen {
		return ok, nil
	}
	a, err := r.q.GetAgent(ctx, r.c.Org, agent)
	if err != nil {
		return false, err
	}
	path, err := agents.PathOf(ctx, r.q, a)
	if err != nil {
		return false, err
	}
	ok := r.c.Can(td.PermEvidenceRead, path)
	r.allowed[agent] = ok
	return ok, nil
}

// ListTransactions lists the transactions the caller may read, newest
// first. A page holds fewer than its size when some are not readable.
func (e *Explorer) ListTransactions(ctx context.Context, pr page.Request, f Filter) (TransactionPage, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return TransactionPage{}, err
	}
	execs := make([]string, len(f.Executions))
	for i, s := range f.Executions {
		execs[i] = string(s)
	}
	effects := make([]string, len(f.Effects))
	for i, s := range f.Effects {
		effects[i] = string(s)
	}
	decisions := f.Decisions
	if decisions == nil {
		decisions = []string{}
	}
	var out TransactionPage
	err = e.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.ListTransactions(ctx, dbq.ListTransactionsParams{
			OrgID: c.Org, Before: pr.After, RunID: f.Run, AgentID: f.Agent, ConnectionID: f.Connection,
			Decisions: decisions, ExecutionStates: execs, EffectStates: effects, StartTime: f.Start, EndTime: f.End,
			PageLimit: pr.Limit(),
		})
		if err != nil {
			return err
		}
		rows, out.Next = page.Finish(pr, rows, func(r dbq.ListTransactionsRow) ids.UUID { return r.ID })
		rd := newReaders(c, q)
		for _, r := range rows {
			ok, err := rd.can(ctx, r.AgentID)
			if err != nil {
				return err
			}
			if ok {
				out.Items = append(out.Items, summary(dbq.TransactionSummaryRow{
					ID: r.ID, RunID: r.RunID, AgentID: r.AgentID, Operation: r.Operation, ConnectionID: r.ConnectionID,
					Decision: r.Decision, ReasonCode: r.ReasonCode, EffectState: r.EffectState,
					EffectLevelRequired: r.EffectLevelRequired, EffectLevelAchieved: r.EffectLevelAchieved, Mode: r.Mode,
					Evaluations: r.Evaluations, CreatedAt: r.CreatedAt, PermitState: r.PermitState, Outcome: r.Outcome,
				}))
			}
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// TransactionEvidence returns everything recorded about one transaction
// (evidence.read where its run's agent lives). Links to a transaction the
// caller may not read are left out.
func (e *Explorer) TransactionEvidence(ctx context.Context, id ids.UUID) (Evidence, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Evidence{}, err
	}
	var out Evidence
	err = e.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		t, err := q.TransactionSummary(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrTransactionNotFound
		} else if err != nil {
			return err
		}
		rd := newReaders(c, q)
		if ok, err := rd.can(ctx, t.AgentID); err != nil {
			return err
		} else if !ok {
			return td.ErrPermissionDenied(td.PermEvidenceRead)
		}
		out.Transaction = summary(t)

		decisions, err := q.DecisionReceiptsOf(ctx, c.Org, id)
		if err != nil {
			return err
		}
		for _, d := range decisions {
			out.Decisions = append(out.Decisions, DecisionRecord{
				Evaluation: int(d.Evaluation), JWS: d.ReceiptJws, Integrity: integrity(d.LedgerEntryID, d.ChainSeq), Created: d.CreatedAt,
			})
		}
		if n := len(decisions); n > 0 {
			out.Basis = decisionBasis(decisions[n-1].ReceiptJws)
		}

		x, err := q.ExecutionOf(ctx, c.Org, id)
		switch {
		case db.IsNoRows(err):
		case err != nil:
			return err
		default:
			out.Execution = &ExecutionRecord{
				Attempt: x.AttemptID, Permit: x.PermitID, Outcome: x.Outcome, TargetStatus: int(deref(x.TargetStatus)),
				RecordedBy: x.RecordedBy, TargetRef: deref(x.TargetRef), DispatchMS: int(deref(x.DispatchMs)),
				Dispatched: x.DispatchingAt, Recorded: x.RecordedAt, JWS: x.ReceiptJws, Integrity: integrity(x.LedgerEntryID, x.ChainSeq),
			}
		}

		effects, err := q.EffectReceiptsOf(ctx, c.Org, id)
		if err != nil {
			return err
		}
		named := []ids.UUID{}
		for _, f := range effects {
			out.Effects = append(out.Effects, EffectRecord{
				Seq: int(f.Seq), State: domain.EffectState(f.State), Required: defs.Level(f.LevelRequired),
				Achieved: defs.Level(deref(f.LevelAchieved)), Basis: f.Basis, JWS: f.ReceiptJws,
				Integrity: integrity(f.LedgerEntryID, f.ChainSeq), Created: f.CreatedAt,
			})
			named = append(named, ReceiptObservations(f.ReceiptJws)...)
		}

		obs, err := q.ObservationsOf(ctx, c.Org, &id, named)
		if err != nil {
			return err
		}
		for _, o := range obs {
			r := ObservationRecord{
				ID: o.ID, Source: o.Source, Verification: o.VerificationID, Gateway: o.GatewayID, HTTPStatus: int(deref(o.HttpStatus)),
				Outcome: deref(o.Outcome), Found: boolPtr(o.Found), Complete: boolPtr(o.Complete), ResponseDigest: o.ResponseDigest,
				Observed: o.ObservedAt,
			}
			if len(o.Fields) > 0 {
				if err := json.Unmarshal(o.Fields, &r.Fields); err != nil {
					return err
				}
			}
			out.Observations = append(out.Observations, r)
		}

		recs, err := q.ReconciliationsOf(ctx, c.Org, id)
		if err != nil {
			return err
		}
		for _, k := range recs {
			out.Reconciliations = append(out.Reconciliations, reconciliation(k))
		}

		links, err := q.LinksOf(ctx, c.Org, id)
		if err != nil {
			return err
		}
		for _, l := range links {
			other := l.FromTransactionID
			if other == id {
				other = l.ToTransactionID
			}
			o, err := q.TransactionSummary(ctx, c.Org, other)
			if err != nil {
				return err
			}
			if ok, err := rd.can(ctx, o.AgentID); err != nil {
				return err
			} else if !ok {
				continue
			}
			out.Links = append(out.Links, Link{
				From: l.FromTransactionID, To: l.ToTransactionID, Kind: domain.LinkKind(l.Kind), CreatedBy: l.CreatedBy, Created: l.CreatedAt,
			})
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// summary converts a transaction row, deriving its execution state.
func summary(t dbq.TransactionSummaryRow) Summary {
	return Summary{
		ID: t.ID, Run: t.RunID, Agent: t.AgentID, Operation: t.Operation, Connection: t.ConnectionID, Decision: t.Decision,
		Reason: t.ReasonCode, Effect: domain.EffectState(deref(t.EffectState)), Required: defs.Level(deref(t.EffectLevelRequired)),
		Achieved: defs.Level(deref(t.EffectLevelAchieved)), Monitor: t.Mode == "monitor", Evaluations: int(t.Evaluations),
		Created: t.CreatedAt,
		Execution: domain.Execution(domain.Record{
			Decision: t.Decision, Reason: t.ReasonCode, PermitState: deref(t.PermitState), Outcome: deref(t.Outcome),
		}),
	}
}

// ReconciliationOf converts a stored reconciliation.
func ReconciliationOf(k dbq.ReconciliationOfRow) Reconciliation {
	return reconciliation(dbq.ReconciliationsOfRow(k))
}

func reconciliation(k dbq.ReconciliationsOfRow) Reconciliation {
	return Reconciliation{
		ID: k.ID, Transaction: k.TransactionID, Kind: domain.TaskKind(k.Kind), State: domain.TaskState(k.State),
		Via: domain.Via(deref(k.ResolvedVia)), Observation: k.ObservationID, User: k.UserID, Basis: deref(k.Basis),
		Evidence: k.Evidence, WaitlistEntry: k.WaitlistEntryID, Opened: k.OpenedAt, Resolved: k.ResolvedAt,
	}
}

func integrity(entry ids.UUID, seq pgtype.Int8) Integrity {
	i := Integrity{Entry: entry}
	if seq.Valid {
		i.Seq = seq.Int64
	}
	return i
}

func boolPtr(b pgtype.Bool) *bool {
	if !b.Valid {
		return nil
	}
	v := b.Bool
	return &v
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

// payload decodes the claims of a compact JWS this server signed and
// stored. It is never used to verify anything: pclaw verify does that.
func payload(jws string, v any) bool {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	return json.Unmarshal(raw, v) == nil
}

// decisionBasis reads what a decision was made on from its receipt.
func decisionBasis(jws string) *DecisionBasis {
	var claims struct {
		Pap struct {
			Basis struct {
				Policy string `json:"policy"`
				Levels []struct {
					Kind     string `json:"kind"`
					ID       string `json:"id"`
					Revision int    `json:"revision"`
				} `json:"levels"`
				Definition string `json:"definition"`
				Facts      string `json:"facts"`
			} `json:"basis"`
			BasisDigest string `json:"basis_digest"`
			Connection  string `json:"connection"`
			Approval    *struct {
				Request string `json:"request"`
			} `json:"approval"`
		} `json:"pap"`
	}
	if !payload(jws, &claims) {
		return nil
	}
	b := claims.Pap.Basis
	out := &DecisionBasis{
		Policy: b.Policy, Definition: b.Definition, Facts: b.Facts, Digest: claims.Pap.BasisDigest, Connection: claims.Pap.Connection,
	}
	for _, l := range b.Levels {
		out.Levels = append(out.Levels, Level{Kind: l.Kind, ID: l.ID, Revision: l.Revision})
	}
	if claims.Pap.Approval != nil {
		out.Approval = claims.Pap.Approval.Request
	}
	return out
}

// ReceiptObservations returns the observations an effect receipt's basis
// names.
func ReceiptObservations(jws string) []ids.UUID {
	var claims struct {
		Pap struct {
			Basis struct {
				Observations []string `json:"observations"`
			} `json:"basis"`
		} `json:"pap"`
	}
	if !payload(jws, &claims) {
		return nil
	}
	var out []ids.UUID
	for _, s := range claims.Pap.Basis.Observations {
		if id, err := ids.ParseUUID(s); err == nil {
			out = append(out, id)
		}
	}
	return out
}

// ReconciliationFilter narrows ListReconciliations; empty fields match
// everything.
type ReconciliationFilter struct {
	States      []domain.TaskState
	Kinds       []domain.TaskKind
	Transaction *ids.UUID
}

// ReconciliationPage is one page of reconciliations, newest first.
type ReconciliationPage struct {
	Items []Reconciliation
	Next  string
}

// ListReconciliations lists the reconciliations the caller may read,
// newest first.
func (e *Explorer) ListReconciliations(ctx context.Context, pr page.Request, f ReconciliationFilter) (ReconciliationPage, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return ReconciliationPage{}, err
	}
	states, kinds := make([]string, len(f.States)), make([]string, len(f.Kinds))
	for i, s := range f.States {
		states[i] = string(s)
	}
	for i, k := range f.Kinds {
		kinds[i] = string(k)
	}
	var out ReconciliationPage
	err = e.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.ListReconciliations(ctx, dbq.ListReconciliationsParams{
			OrgID: c.Org, Before: pr.After, States: states, Kinds: kinds, TransactionID: f.Transaction, PageLimit: pr.Limit(),
		})
		if err != nil {
			return err
		}
		rows, out.Next = page.Finish(pr, rows, func(r dbq.ListReconciliationsRow) ids.UUID { return r.ID })
		rd := newReaders(c, q)
		for _, k := range rows {
			ok, err := rd.can(ctx, k.AgentID)
			if err != nil {
				return err
			}
			if ok {
				out.Items = append(out.Items, reconciliation(dbq.ReconciliationsOfRow{
					ID: k.ID, TransactionID: k.TransactionID, Kind: k.Kind, State: k.State, ResolvedVia: k.ResolvedVia,
					ObservationID: k.ObservationID, UserID: k.UserID, Basis: k.Basis, Evidence: k.Evidence,
					WaitlistEntryID: k.WaitlistEntryID, OpenedAt: k.OpenedAt, ResolvedAt: k.ResolvedAt,
				}))
			}
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// Reconciliation returns one reconciliation and its transaction
// (evidence.read where the run's agent lives).
func (e *Explorer) Reconciliation(ctx context.Context, id ids.UUID) (Reconciliation, Summary, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Reconciliation{}, Summary{}, err
	}
	var k Reconciliation
	var s Summary
	err = e.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.ReconciliationOf(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrReconciliationNotFound
		} else if err != nil {
			return err
		}
		t, err := q.TransactionSummary(ctx, c.Org, row.TransactionID)
		if err != nil {
			return err
		}
		if ok, err := newReaders(c, q).can(ctx, t.AgentID); err != nil {
			return err
		} else if !ok {
			return td.ErrPermissionDenied(td.PermEvidenceRead)
		}
		k, s = reconciliation(dbq.ReconciliationsOfRow(row)), summary(t)
		return nil
	}, db.ReadOnly())
	return k, s, err
}
