// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package signals

import (
	"context"
	"log/slog"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/approvals/adapters/pgapprovals"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	reflexports "github.com/katocxl/pantherclaw/internal/reflex/ports"
)

// Notifier enqueues notifications in the caller's transaction (M5).
type Notifier interface {
	Enqueue(ctx context.Context, tx db.TenantTx, m napp.Message) (napp.Enqueued, error)
}

// WithCases sets the case opener (cases, D19). Without one an accepted
// event is recorded with the note NoCaseNote.
func (s *Service) WithCases(o reflexports.CaseOpener) *Service {
	s.cases = o
	return s
}

// WithContainer sets the containment port (response, D21). Without one
// the identity playbook cannot be enabled (fail closed).
func (s *Service) WithContainer(c reflexports.Container) *Service {
	s.container = c
	return s
}

// WithRaiser sets the signal raiser (core, D14).
func (s *Service) WithRaiser(r reflexports.Raiser) *Service {
	s.raiser = r
	return s
}

// WithNotifier sets the notifier (M5).
func (s *Service) WithNotifier(n Notifier) *Service {
	s.notify = n
	return s
}

// NoCaseNote is recorded on an accepted event when no case could be
// opened (D49).
const NoCaseNote = "case not opened: cases unavailable"

// PlaybookReason prefixes the reason of the playbook's containment
// requests; PlaybookActor is the actor they name (D50).
const PlaybookReason = "PLAYBOOK: "

// PlaybookActor is the actor of the playbook's containment requests.
var PlaybookActor = reflexdomain.Subject{Type: reflexdomain.SubjectSystem, ID: reflexdomain.SystemIdentityPlaybook}

// maxCaseGrants bounds the grants a case lists as subjects.
const maxCaseGrants = reflexdomain.MaxSubjects - 1

// severityOf is how much an event type says about a person's account.
func severityOf(eventType string) reflexdomain.Severity {
	switch eventType {
	case TypeCredentialCompromise, TypeAccountPurged, TypeAccountDisabled:
		return reflexdomain.SeverityHigh
	}
	return reflexdomain.SeverityMedium
}

// accepted handles an accepted event in the receiver's transaction (D37):
// a signals alert, a case listing the person's grants and waiting
// approvals (or a note when cases are unavailable), a notice, and the
// identity playbook when it is enabled for this event type and the person
// was matched by issuer and subject. The playbook runs in a savepoint: a
// containment failure is reported as an owned failure and never loses the
// event or its case.
func (s *Service) accepted(ctx context.Context, tx db.TenantTx, r Received, entry ids.UUID) error {
	q := dbq.New(tx)
	user := r.User
	grants, err := q.SSFPersonGrants(ctx, user, r.Org)
	if err != nil {
		return err
	}
	counts, err := q.SSFPersonCounts(ctx, r.Org, user)
	if err != nil {
		return err
	}
	person := reflexdomain.Subject{Type: reflexdomain.SubjectUser, ID: user.String()}
	subjects := []reflexdomain.Subject{person}
	for _, g := range grants {
		if len(subjects) > maxCaseGrants {
			break
		}
		subjects = append(subjects, reflexdomain.Subject{Type: reflexdomain.SubjectGrant, ID: g.ID.String()})
	}
	evidence := []reflexdomain.EvidenceRef{{Kind: reflexdomain.EvidenceLedger, ID: entry}}
	short := ShortName(r.EventType)
	// The identity-risk fact first, so its case can say when it failed (G0
	// M16 D82, risk.go).
	riskRecorded := s.identityRisk(ctx, tx, r)
	if !riskRecorded {
		if err := s.riskNotRecorded(ctx, tx, r, evidence, person); err != nil {
			return err
		}
	}
	var alert *ids.UUID
	if s.raiser != nil {
		id, err := s.raiser.Raise(ctx, tx.Pgx(), reflexdomain.Signal{
			Org: r.Org, Source: reflexdomain.SourceSignals, Title: "Identity provider reported " + short,
			Summary: "The Shared Signals transmitter " + r.Transmitter.String() + " reported " + short + " for person " + user.String() +
				" (matched by " + r.MatchBasis + ").",
			Severity: severityOf(r.EventType), Attention: reflexdomain.AttentionAlert, Basis: reflexdomain.BasisObserved,
			Subjects: []reflexdomain.Subject{person}, Evidence: evidence, GroupKey: person.String(),
			DedupeKey: "signals:" + r.Event.String(), OccurredAt: r.IssuedAt,
			Facts: map[string]string{
				"event_type": short, "transmitter": r.Transmitter.String(), "match_basis": r.MatchBasis, "event": r.Event.String(),
			},
		})
		if err != nil {
			return err
		}
		if !id.IsZero() {
			alert = &id
		}
	}
	caseID := ids.UUID{}
	if s.cases != nil {
		questions := []string{
			"Is this person's account compromised? The identity provider reported " + short + "; the person was matched by " + r.MatchBasis + ".",
			"Which actions under the listed grants since " + r.IssuedAt.UTC().Format(time.RFC3339) + " did this person really take?",
		}
		if listed := len(subjects) - 1; int(counts.Grants) > listed {
			questions = append(questions, "The person has "+strconv.Itoa(int(counts.Grants))+" active grants; the case lists "+
				strconv.Itoa(listed)+". Which of the others matter?")
		}
		if !riskRecorded {
			questions = append(questions, RiskNotRecordedNote)
		}
		if counts.Approvals > 0 {
			questions = append(questions, "Should the person's "+strconv.Itoa(int(counts.Approvals))+" waiting approvals stand?")
		}
		caseID, err = s.cases.Open(ctx, tx.Pgx(), reflexdomain.CaseSeed{
			Org: r.Org, Title: "Identity provider reported " + short, Source: reflexdomain.SourceSignals, Subjects: subjects,
			Evidence: evidence, Questions: questions, AlertID: alert,
			Opener: reflexdomain.Subject{Type: reflexdomain.SubjectResource, ID: "ssf_transmitter:" + r.Transmitter.String()},
		})
		if err != nil {
			return err
		}
		if _, err := q.SetSSFEventCase(ctx, &caseID, r.Org, r.Event); err != nil {
			return err
		}
	} else if _, err := q.SetSSFEventCaseNote(ctx, noCaseNote(riskRecorded), r.Org, r.Event); err != nil {
		return err
	}
	if s.notify != nil {
		c := "none"
		if !caseID.IsZero() {
			c = caseID.String()
		}
		if _, err := s.notify.Enqueue(ctx, tx, napp.Message{
			Org: r.Org, Type: "signals.event_received", DedupeKey: "signals.event_received:" + r.Event.String(),
			Params: map[string]string{
				"transmitter": r.Transmitter.String(), "event": short, "user": user.String(),
				"basis": r.MatchBasis, "case": c,
			},
		}); err != nil {
			return err
		}
	}
	return s.playbookActs(ctx, tx, r, caseID)
}

// playbookActs runs the identity playbook for an accepted event (D38,
// HR-262).
func (s *Service) playbookActs(ctx context.Context, tx db.TenantTx, r Received, caseID ids.UUID) error {
	pb, err := playbookOf(ctx, dbq.New(tx), r.Org)
	if err != nil {
		return err
	}
	if !pb.Enabled || !slices.Contains(pb.Events, r.EventType) {
		return nil
	}
	if r.MatchBasis != BasisIssSub {
		// An email or foreign issuer match never acts (D46, D64): the case
		// states the basis.
		return s.playbookNote(ctx, tx, r, "skipped", "MATCH_NOT_ISS_SUB")
	}
	if s.container == nil {
		return s.playbookFailed(ctx, tx, r, "containment is unavailable on this server")
	}
	res, err := s.contain(ctx, tx, r, caseID)
	if err != nil {
		return err
	}
	if _, err := audit.Record(ctx, tx, audit.Event{
		Name: "signals.playbook_acted", Actor: evdomain.Actor{Type: "system", ID: PlaybookActor.ID}, Outcome: audit.Success,
		Object: &audit.Object{Type: "ssf_event", ID: r.Event.String()},
		Details: map[string]string{
			"user": r.User.String(), "event_type": ShortName(r.EventType), "principal_contained": strconv.FormatBool(res.principal),
			"grants_contained": strconv.Itoa(res.grants), "grants_not_contained": strconv.Itoa(res.grantsMissed),
			"approvals_voided": strconv.Itoa(res.approvals), "approvals_not_voided": strconv.Itoa(res.approvalsMissed),
		},
	}); err != nil {
		return err
	}
	if res.complete() {
		return nil
	}
	return s.playbookFailed(ctx, tx, r, res.shortfall())
}

// containResult counts what the playbook did and did not do.
type containResult struct {
	principal                  bool
	grants, grantsMissed       int
	approvals, approvalsMissed int
}

func (c containResult) complete() bool {
	return c.principal && c.grantsMissed == 0 && c.approvalsMissed == 0
}

func (c containResult) shortfall() string {
	out := ""
	if !c.principal {
		out = "the person was not contained; "
	}
	return out + strconv.Itoa(c.grantsMissed) + " of " + strconv.Itoa(c.grants+c.grantsMissed) + " issued grants not contained and " +
		strconv.Itoa(c.approvalsMissed) + " of " + strconv.Itoa(c.approvals+c.approvalsMissed) + " waiting approvals not voided; contain by hand"
}

// playbookPage is how many grants or approvals one query reads.
const playbookPage = 500

// contain asks Response for a principal DENY_ALL on the person, then a
// DENY_ALL on every grant they issued (the only scopes the playbook may
// ask for, D50), then voids every waiting approval of theirs, paging with
// no cap (D64). The principal control commits in its own savepoint first,
// and every later request in its own, so one failure never undoes the
// others (D64 L3); failures are counted. Each request is idempotent per
// event and scope; no preview digest is sent (Response records its own).
func (s *Service) contain(ctx context.Context, tx db.TenantTx, r Received, caseID ids.UUID) (containResult, error) {
	var caseRef *ids.UUID
	if !caseID.IsZero() {
		caseRef = &caseID
	}
	reason := PlaybookReason + ShortName(r.EventType) + " reported by transmitter " + r.Transmitter.String()
	req := func(scope reflexdomain.Subject) reflexdomain.ContainRequest {
		return reflexdomain.ContainRequest{
			Org: r.Org, Scope: scope, Control: reflexdomain.ControlDenyAll, Reason: reason, CaseID: caseRef, Actor: PlaybookActor,
			Idempotency: "playbook:" + r.Event.String() + ":" + scope.String(),
		}
	}
	contain := func(scope reflexdomain.Subject) func(pgx.Tx) error {
		return func(sp pgx.Tx) error {
			_, err := s.container.Contain(ctx, sp, req(scope))
			return err
		}
	}
	var res containResult
	res.principal = s.attempt(ctx, tx, r, contain(reflexdomain.Subject{Type: reflexdomain.SubjectUser, ID: r.User.String()}))
	q := dbq.New(tx)
	for after := (*ids.UUID)(nil); ; {
		page, err := q.SSFIssuedGrantsPage(ctx, dbq.SSFIssuedGrantsPageParams{OrgID: r.Org, UserID: r.User, AfterID: after, MaxRows: playbookPage})
		if err != nil {
			return res, err
		}
		for _, g := range page {
			if s.attempt(ctx, tx, r, contain(reflexdomain.Subject{Type: reflexdomain.SubjectGrant, ID: g.String()})) {
				res.grants++
			} else {
				res.grantsMissed++
			}
		}
		if len(page) < playbookPage {
			break
		}
		last := page[len(page)-1]
		after = &last
	}
	for after := (*ids.UUID)(nil); ; {
		page, err := q.SSFPersonApprovalsPage(ctx, dbq.SSFPersonApprovalsPageParams{OrgID: r.Org, UserID: r.User, AfterID: after, MaxRows: playbookPage})
		if err != nil {
			return res, err
		}
		for _, a := range page {
			if s.attempt(ctx, tx, r, func(sp pgx.Tx) error {
				stx, err := db.AdoptTenantTx(ctx, sp, r.Org)
				if err != nil {
					return err
				}
				return pgapprovals.Invalidate(ctx, stx, r.Org, a, "IDENTITY_PLAYBOOK")
			}) {
				res.approvals++
			} else {
				res.approvalsMissed++
			}
		}
		if len(page) < playbookPage {
			break
		}
		last := page[len(page)-1]
		after = &last
	}
	return res, nil
}

// attempt runs f in its own savepoint and reports whether it committed.
func (s *Service) attempt(ctx context.Context, tx db.TenantTx, r Received, f func(pgx.Tx) error) bool {
	sp, err := tx.Pgx().Begin(ctx)
	if err != nil {
		return false
	}
	if err := f(sp); err != nil {
		_ = sp.Rollback(ctx)
		s.log.WarnContext(ctx, "signals.playbook_step_failed", slog.String("event", r.Event.String()), pclog.Err(err))
		return false
	}
	return sp.Commit(ctx) == nil
}

// playbookNote records what the playbook did (or why it did not act).
func (s *Service) playbookNote(ctx context.Context, tx db.TenantTx, r Received, what, reason string) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: "signals.playbook_" + what, Actor: evdomain.Actor{Type: "system", ID: PlaybookActor.ID}, Outcome: audit.Success,
		ReasonCode: reason, Object: &audit.Object{Type: "ssf_event", ID: r.Event.String()},
		Details: map[string]string{"user": r.User.String(), "event_type": ShortName(r.EventType)},
	})
	return err
}

// playbookFailed reports a playbook that could not act as an owned
// failure and a non-suppressible audit record.
func (s *Service) playbookFailed(ctx context.Context, tx db.TenantTx, r Received, summary string) error {
	if err := s.playbookNote(ctx, tx, r, "failed", "CONTAINMENT_FAILED"); err != nil {
		return err
	}
	if s.failures == nil {
		return nil
	}
	_, err := s.failures.Report(ctx, tx.Pgx(), reflexdomain.Failure{
		Org: r.Org, Kind: "signals.playbook_failed",
		Summary:   "The identity playbook could not contain person " + r.User.String() + ": " + summary + ".",
		NextStep:  "Contain the person and the grants they issued by hand from the case, then check containment.",
		Scope:     []reflexdomain.Subject{{Type: reflexdomain.SubjectUser, ID: r.User.String()}},
		DedupeKey: "signals.playbook_failed:" + r.Event.String(),
	})
	return err
}

func noCaseNote(riskRecorded bool) *string {
	n := NoCaseNote
	if !riskRecorded {
		n += "; " + RiskNotRecordedNote
	}
	return &n
}
