// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package store reads and writes cases inside the caller's tenant
// transaction (G0 M10 D19). Appending an entry records its canonical body
// as a reflex.case ledger entry and inserts it; migration 00122 chains it,
// moves the case and enforces the closure rules (HR-245, HR-246). Callers
// check permissions and editions before they call in.
package store

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"

	"github.com/katocxl/pantherclaw/internal/cases/domain"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// MaxEntriesPage caps one read of a case's entries.
const MaxEntriesPage = 500

// Errors of the case store.
var (
	ErrNotFound = pcerr.New(pcerr.NotFound, "CASE_NOT_FOUND", "case not found")
	ErrInvalid  = pcerr.New(pcerr.InvalidArgument, "INVALID_CASE_ENTRY",
		"the case entry does not fit its kind, or names evidence, a question or an entry that is not in this case or organization")
	ErrClosureRules = pcerr.New(pcerr.FailedPrecondition, "CASE_CLOSURE_RULES",
		"closing needs an impact, a disposition, at least one standing fact, and a follow-up owner while questions are open")
	ErrNotContained = pcerr.New(pcerr.FailedPrecondition, "CASE_NOT_CONTAINED",
		"every linked containment action must be confirmed, or the entry must say why no containment is needed")
	ErrTransition = pcerr.New(pcerr.FailedPrecondition, "CASE_TRANSITION",
		"the case cannot move to that state, or a closed case takes only facts, answers, notes and a follow-up owner")
	ErrSuperseded   = pcerr.New(pcerr.FailedPrecondition, "CASE_ENTRY_SUPERSEDED", "that entry was already superseded")
	ErrTooManyLinks = pcerr.New(pcerr.ResourceExhausted, "CASE_LINKS_EXHAUSTED", "a case links at most 1000 subjects")
)

// Open inserts a new OPEN case.
func Open(ctx context.Context, tx db.TenantTx, n domain.NewCase) (domain.Case, error) {
	if err := n.Validate(); err != nil {
		return domain.Case{}, invalid(err)
	}
	row, err := dbq.New(tx).InsertCase(ctx, dbq.InsertCaseParams{
		OrgID: tx.OrgID(), ID: ids.NewV7(), Title: n.Title, Source: n.Source,
		OpenedByType: n.OpenedBy.Type, OpenedByID: n.OpenedBy.ID, AlertID: n.Alert, IncidentID: n.Incident,
	})
	if err != nil {
		return domain.Case{}, fmt.Errorf("cases: open: %w", err)
	}
	return FromRow(row), nil
}

// Append adds d to case c as author: it numbers the entry after the case's
// head, records it in the ledger and inserts it.
func Append(ctx context.Context, tx db.TenantTx, c ids.UUID, author domain.Author, d domain.Draft) (domain.Entry, error) {
	q := dbq.New(tx)
	head, err := q.LockCase(ctx, tx.OrgID(), c)
	if db.IsNoRows(err) {
		return domain.Entry{}, ErrNotFound
	} else if err != nil {
		return domain.Entry{}, err
	}
	id := ids.NewV7()
	body, err := d.Body(c, id, head.HeadSeq+1, author)
	if err != nil {
		return domain.Entry{}, invalid(err)
	}
	le, err := ledger.Append(ctx, tx, domain.LedgerKind, evdomain.Actor{Type: author.Type, ID: author.ID}, body)
	if err != nil {
		return domain.Entry{}, err
	}
	row, err := q.InsertCaseEntry(ctx, dbq.InsertCaseEntryParams{
		OrgID: tx.OrgID(), CaseID: c, ID: id, Body: body, LedgerEntryID: le.ID,
	})
	if err != nil {
		return domain.Entry{}, mapWriteError(err)
	}
	return EntryFromRow(row)
}

// mapWriteError turns the refusals of migration 00122 into API errors.
func mapWriteError(err error) error {
	switch {
	case db.IsUniqueViolation(err):
		return ErrSuperseded
	case db.IsForeignKeyViolation(err):
		return ErrInvalid
	case db.IsCheckViolation(err):
		msg := err.Error()
		switch {
		case strings.Contains(msg, "CASE_LINKS_EXHAUSTED"):
			return ErrTooManyLinks
		case strings.Contains(msg, "CASE_CLOSURE_RULES"):
			return ErrClosureRules
		case strings.Contains(msg, "CASE_NOT_CONTAINED"):
			return ErrNotContained
		case strings.Contains(msg, "cannot go from"), strings.Contains(msg, "a closed case"):
			return ErrTransition
		}
		return ErrInvalid
	}
	return err
}

// Get returns case c.
func Get(ctx context.Context, tx db.TenantTx, c ids.UUID) (domain.Case, error) {
	row, err := dbq.New(tx).GetCase(ctx, tx.OrgID(), c)
	if db.IsNoRows(err) {
		return domain.Case{}, ErrNotFound
	} else if err != nil {
		return domain.Case{}, err
	}
	return FromRow(row), nil
}

// Entries returns up to limit entries of case c after seq, in order.
func Entries(ctx context.Context, tx db.TenantTx, c ids.UUID, after int64, limit int) ([]domain.Entry, error) {
	if limit < 1 || limit > MaxEntriesPage {
		limit = MaxEntriesPage
	}
	rows, err := dbq.New(tx).ListCaseEntries(ctx, dbq.ListCaseEntriesParams{
		OrgID: tx.OrgID(), CaseID: c, AfterSeq: after, MaxRows: int32(limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Entry, 0, len(rows))
	for _, r := range rows {
		e, err := EntryFromRow(r)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// Superseded returns the ids of the entries of case c that a later entry
// superseded.
func Superseded(ctx context.Context, tx db.TenantTx, c ids.UUID) (map[ids.UUID]bool, error) {
	rows, err := dbq.New(tx).SupersededCaseEntries(ctx, tx.OrgID(), c)
	if err != nil {
		return nil, err
	}
	out := make(map[ids.UUID]bool, len(rows))
	for _, id := range rows {
		out[id] = true
	}
	return out, nil
}

// OpenQuestions counts the case's questions no standing answer resolves.
func OpenQuestions(ctx context.Context, tx db.TenantTx, c ids.UUID) (int64, error) {
	return dbq.New(tx).CaseOpenQuestions(ctx, tx.OrgID().UUID(), c)
}

// ErrChainBroken reports a case whose entries do not chain to its head.
var ErrChainBroken = errors.New("cases: entry chain broken")

// VerifyChain recomputes the hash chain of case c from its genesis to its
// head (T-107).
func VerifyChain(ctx context.Context, tx db.TenantTx, c ids.UUID) error {
	k, err := Get(ctx, tx, c)
	if err != nil {
		return err
	}
	prev, seq := domain.GenesisHash(c), int64(0)
	for {
		es, err := Entries(ctx, tx, c, seq, MaxEntriesPage)
		if err != nil {
			return err
		}
		for _, e := range es {
			if e.Seq != seq+1 || !bytes.Equal(e.PrevHash, prev) || !bytes.Equal(e.Hash, domain.ChainHash(prev, e.Body)) {
				return fmt.Errorf("%w at entry %d", ErrChainBroken, e.Seq)
			}
			prev, seq = e.Hash, e.Seq
		}
		if len(es) < MaxEntriesPage {
			break
		}
	}
	if seq != k.HeadSeq || !bytes.Equal(prev, k.HeadHash) {
		return fmt.Errorf("%w: head %d does not match the entries (%d)", ErrChainBroken, k.HeadSeq, seq)
	}
	return nil
}

func deref[T ~string](p *string) T {
	if p == nil {
		return ""
	}
	return T(*p)
}

// FromRow maps a case row.
func FromRow(r dbq.PcCase) domain.Case {
	return domain.Case{
		Org: r.OrgID, ID: r.ID, Title: r.Title, Source: r.Source,
		OpenedBy: domain.Author{Type: r.OpenedByType, ID: r.OpenedByID}, Alert: r.AlertID, Incident: r.IncidentID,
		State: domain.State(r.State), Owner: r.OwnerID, FollowUpOwner: r.FollowUpOwnerID,
		Disposition: deref[domain.Disposition](r.Disposition), Impact: deref[domain.Impact](r.Impact),
		HeadSeq: r.HeadSeq, HeadHash: r.HeadHash, Created: r.CreatedAt, Updated: r.UpdatedAt,
		OperationalClosed: r.OperationalClosedAt, Closed: r.ClosedAt,
	}
}

// EntryFromRow maps an entry row.
func EntryFromRow(r dbq.PcCaseEntry) (domain.Entry, error) {
	var refs []struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	}
	if err := json.Unmarshal(r.Evidence, &refs); err != nil {
		return domain.Entry{}, fmt.Errorf("cases: entry %s evidence: %w", r.ID, err)
	}
	d := domain.Draft{
		Kind: domain.Kind(r.Kind), Text: deref[string](r.Text), Basis: deref[domain.Basis](r.Basis),
		Confidence: deref[domain.Confidence](r.Confidence), Alternatives: r.Alternatives, Question: r.QuestionID,
		Unresolved: r.Unresolved, Owner: r.OwnerID, OwnerRole: deref[domain.OwnerRole](r.OwnerRole),
		Impact: deref[domain.ImpactKind](r.ImpactKind), State: deref[domain.State](r.ToState),
		NoContainmentNeeded: r.NoContainmentNeeded, Disposition: deref[domain.Disposition](r.Disposition),
		CaseImpact: deref[domain.Impact](r.CaseImpact), Reason: deref[string](r.Reason), Supersedes: r.Supersedes,
	}
	if len(d.Alternatives) == 0 {
		d.Alternatives = nil
	}
	for _, x := range refs {
		u, err := ids.ParseUUID(x.ID)
		if err != nil {
			return domain.Entry{}, fmt.Errorf("cases: entry %s evidence: %w", r.ID, err)
		}
		d.Evidence = append(d.Evidence, domain.EvidenceRef{Kind: x.Kind, ID: u})
	}
	if r.RefKind != nil && r.RefID != nil {
		d.Ref = &domain.Ref{Kind: *r.RefKind, ID: *r.RefID}
	}
	return domain.Entry{
		Draft: d, Case: r.CaseID, ID: r.ID, LedgerEntry: r.LedgerEntryID, Seq: r.Seq,
		Author: domain.Author{Type: r.AuthorType, ID: r.AuthorID}, Body: r.Body,
		PrevHash: r.PrevHash, Hash: r.EntryHash, Created: r.CreatedAt,
	}, nil
}

// invalid wraps a validation error as INVALID_CASE_ENTRY with its detail.
func invalid(err error) error {
	return pcerr.Wrap(err, pcerr.InvalidArgument, "INVALID_CASE_ENTRY", err.Error())
}

// UnownedOpenQuestions returns the open questions of case c that name no
// owner (D66).
func UnownedOpenQuestions(ctx context.Context, tx db.TenantTx, c ids.UUID) (map[ids.UUID]bool, error) {
	rows, err := dbq.New(tx).UnownedOpenQuestions(ctx, tx.OrgID(), c)
	if err != nil {
		return nil, err
	}
	out := make(map[ids.UUID]bool, len(rows))
	for _, id := range rows {
		out[id] = true
	}
	return out, nil
}
