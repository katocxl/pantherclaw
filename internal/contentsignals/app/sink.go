// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/contentsignals/domain"
	"github.com/katocxl/pantherclaw/internal/contentsignals/ports"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	reflexports "github.com/katocxl/pantherclaw/internal/reflex/ports"
)

// Sink takes what a gateway found (G0 M27 D507, D512; HR-648, HR-650, HR-651)
// and keeps kinds and locations, never a value. It reads the org's mode
// itself: at OFF it keeps nothing, whatever a gateway with an old
// configuration sent.
type Sink struct {
	Raiser   reflexports.Raiser
	Failures reflexports.FailureSink
}

// Observed is what one body held.
type Observed struct {
	Org              ids.OrgID
	Run, Transaction ids.UUID
	Surface          ports.Surface
	Findings         []domain.Finding
}

// ownedFailureKind is the owned failure of a scan that could not finish.
const ownedFailureKind = "content.scan_incomplete"

// flagDeclaration is the built-in provider's fact about a run.
var flagDeclaration = fdomain.Declaration{
	Name: fdomain.NameContentFlag, Type: fdomain.TypeObject, SubjectType: fdomain.SubjectRun, MaxLag: fdomain.MaxLagCeiling,
}

// Observe records one body's findings in the caller's transaction: a tool
// result's flags on the root of the run's tree for later decisions, what
// WATCHING would have held, inference alerts, and an owned failure for a scan
// that could not finish, in WATCHING as in ACTIVE.
func (s *Sink) Observe(ctx context.Context, tx db.TenantTx, o Observed) error {
	if len(o.Findings) == 0 {
		return nil
	}
	q := dbq.New(tx)
	mode, err := q.ContentSignalMode(ctx, o.Org)
	if err != nil {
		return err
	}
	if !domain.Mode(mode).Scans() {
		return nil
	}
	found := normal(o.Findings)
	now, err := q.DBNow(ctx)
	if err != nil {
		return err
	}
	if o.Surface == ports.SurfaceResult && !o.Run.IsZero() {
		if err := s.flag(ctx, q, o, found, now); err != nil {
			return err
		}
	}
	if domain.Mode(mode) == domain.ModeWatching {
		if err := count(ctx, q, o.Org, found); err != nil {
			return err
		}
	}
	return s.tell(ctx, tx, o, found, now)
}

// normal keeps a finding a gateway sent only as what it is allowed to say: an
// unknown kind is a classifier's flag, so it still restricts.
func normal(in []domain.Finding) []domain.Finding {
	out := make([]domain.Finding, 0, len(in))
	for _, f := range in {
		if !domain.ValidKind(f.Kind) {
			f.Kind = domain.KindClassifierFlag
		}
		out = append(out, f)
	}
	return domain.Pick(out)
}

// flag merges the findings' kinds into the fact on the root of the run's
// tree, written only through the built-in provider (HR-648). Two first
// writers at once can lose a kind, never the flag.
func (s *Sink) flag(ctx context.Context, q *dbq.Queries, o Observed, found []domain.Finding, now time.Time) error {
	if err := q.EnsureBuiltinFactProvider(ctx, o.Org, ids.NewV7()); err != nil {
		return err
	}
	p, err := q.GetBuiltinFactProvider(ctx, o.Org)
	if err != nil {
		return err
	}
	if err := q.EnsureBuiltinFactDeclaration(ctx, dbq.EnsureBuiltinFactDeclarationParams{
		OrgID: o.Org, ProviderID: p.ID, Name: flagDeclaration.Name, ValueType: string(flagDeclaration.Type),
		SubjectType: flagDeclaration.SubjectType, MaxLagS: int32(flagDeclaration.MaxLag / time.Second), //nolint:gosec // G115: at most a day
	}); err != nil {
		return err
	}
	st, err := q.ContentRunState(ctx, o.Org, o.Run)
	if err != nil {
		return err
	}
	kinds, n := domain.ParseFlag(st.Flag)
	for _, f := range found {
		kinds = append(kinds, f.Kind)
	}
	slices.Sort(kinds)
	v, err := fdomain.EncodeValue(fdomain.Value{Type: fdomain.TypeObject, Object: map[string]any{
		"kinds": strings.Join(slices.Compact(kinds), ","), "count": n + int64(len(found)), "at": now.Unix(),
	}})
	if err != nil {
		return err
	}
	source, method := fdomain.BuiltinProvider, "rule"
	_, err = q.PutFact(ctx, dbq.PutFactParams{
		OrgID: o.Org, ID: ids.NewV7(), Name: fdomain.NameContentFlag, SubjectType: fdomain.SubjectRun, SubjectID: st.Root.String(),
		ProviderID: p.ID, Value: v, ObservedAt: now, Source: &source, Method: &method,
	})
	return err
}


// count adds to what WATCHING would have held, once per reason per body.
func count(ctx context.Context, q *dbq.Queries, org ids.OrgID, found []domain.Finding) error {
	var reasons []string
	for _, f := range found {
		reasons = append(reasons, f.Reason())
	}
	slices.Sort(reasons)
	for _, r := range slices.Compact(reasons) {
		if err := q.CountContentWouldHold(ctx, org, r, 1); err != nil {
			return err
		}
	}
	return nil
}

// tell raises the people's side: an INFERRED alert per run and kind (HR-651),
// and an owned failure per reason a scan could not finish, open until someone
// closes it, so one stopped classifier is one failure and not a flood.
func (s *Sink) tell(ctx context.Context, tx db.TenantTx, o Observed, found []domain.Finding, now time.Time) error {
	seen := map[string]bool{}
	for _, f := range found {
		if f.Kind == domain.KindScanIncomplete {
			if s.Failures == nil {
				continue
			}
			if _, err := s.Failures.Report(ctx, tx.Pgx(), reflexdomain.Failure{
				Org: o.Org, Kind: ownedFailureKind, DedupeKey: ownedFailureKind + ":" + f.Reason(),
				Summary:  "A content scan could not finish (" + f.Reason() + "): the body is not known to have no flags.",
				NextStep: "Check the content classifier and the gateway's logs; in ACTIVE, writes on flagged runs stay held until a person approves them.",
			}); err != nil {
				return err
			}
			continue
		}
		if s.Raiser == nil || seen[f.Kind] {
			continue
		}
		seen[f.Kind] = true
		sig := reflexdomain.Signal{
			Org: o.Org, Source: reflexdomain.SourceSystem, Title: "Content flag (inference): " + f.Kind,
			Summary:  "A content pattern matched on a " + string(o.Surface) + " at " + f.Location + ". This is inference, not proof, and no value is kept.",
			Severity: reflexdomain.SeverityMedium, Attention: reflexdomain.AttentionAlert, Basis: reflexdomain.BasisInferred,
			GroupKey: "content.flag", DedupeKey: "content.flag:" + o.Run.String() + ":" + f.Kind, OccurredAt: now,
			Facts: map[string]string{"kind": f.Kind, "surface": string(o.Surface), "body_findings": strconv.Itoa(len(found))},
		}
		if !o.Run.IsZero() {
			sig.Subjects = []reflexdomain.Subject{{Type: reflexdomain.SubjectRun, ID: o.Run.String()}}
		}
		if !o.Transaction.IsZero() {
			sig.Subjects = append(sig.Subjects, reflexdomain.Subject{Type: reflexdomain.SubjectTransaction, ID: o.Transaction.String()})
		}
		if _, err := s.Raiser.Raise(ctx, tx.Pgx(), sig); err != nil {
			return err
		}
	}
	return nil
}
