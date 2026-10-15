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
	approvals, err := q.SSFPersonApprovals(ctx, r.Org, &user)
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
		if len(approvals) > 0 {
			questions = append(questions, "Should the person's "+strconv.Itoa(len(approvals))+" waiting approvals stand?")
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
	} else if _, err := q.SetSSFEventCaseNote(ctx, noCaseNote(), r.Org, r.Event); err != nil {
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
	return s.playbookActs(ctx, tx, r, grants, approvals, caseID)
}

// playbookActs runs the identity playbook for an accepted event (D38,
// HR-262), in a savepoint.
func (s *Service) playbookActs(ctx context.Context, tx db.TenantTx, r Received, grants []dbq.SSFPersonGrantsRow, approvals []ids.UUID,
	caseID ids.UUID,
) error {
	pb, err := playbookOf(ctx, dbq.New(tx), r.Org)
	if err != nil {
		return err
	}
	if !pb.Enabled || !slices.Contains(pb.Events, r.EventType) {
		return nil
	}
	if r.MatchBasis != "iss_sub" {
		// An email match never acts (D46): the case states the basis.
		return s.playbookNote(ctx, tx, r, "skipped", "MATCH_BY_EMAIL")
	}
	if s.container == nil {
		return s.playbookFailed(ctx, tx, r, "containment is unavailable on this server")
	}
	sp, err := tx.Pgx().Begin(ctx)
	if err != nil {
		return err
	}
	if err := s.contain(ctx, sp, r, grants, approvals, caseID); err != nil {
		_ = sp.Rollback(ctx)
		s.log.WarnContext(ctx, "signals.playbook_failed", slog.String("event", r.Event.String()), pclog.Err(err))
		return s.playbookFailed(ctx, tx, r, "a containment request failed")
	}
	return sp.Commit(ctx)
}

// contain asks Response for a principal DENY_ALL on the person and a
// DENY_ALL on each grant they issued (the only scopes the playbook may
// ask for, D50), then voids the person's waiting approvals. Each request
// is idempotent per event and scope; no preview digest is sent (Response
// records its own preview).
func (s *Service) contain(ctx context.Context, sp pgx.Tx, r Received, grants []dbq.SSFPersonGrantsRow, approvals []ids.UUID,
	caseID ids.UUID,
) error {
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
	contained := 0
	if _, err := s.container.Contain(ctx, sp, req(reflexdomain.Subject{Type: reflexdomain.SubjectUser, ID: r.User.String()})); err != nil {
		return err
	}
	contained++
	for _, g := range grants {
		if !g.Issued {
			continue
		}
		if _, err := s.container.Contain(ctx, sp, req(reflexdomain.Subject{Type: reflexdomain.SubjectGrant, ID: g.ID.String()})); err != nil {
			return err
		}
		contained++
	}
	tx, err := db.AdoptTenantTx(ctx, sp, r.Org)
	if err != nil {
		return err
	}
	for _, a := range approvals {
		if err := pgapprovals.Invalidate(ctx, tx, r.Org, a, "IDENTITY_PLAYBOOK"); err != nil {
			return err
		}
	}
	_, err = audit.Record(ctx, tx, audit.Event{
		Name: "signals.playbook_acted", Actor: evdomain.Actor{Type: "system", ID: PlaybookActor.ID}, Outcome: audit.Success,
		Object: &audit.Object{Type: "ssf_event", ID: r.Event.String()},
		Details: map[string]string{
			"user": r.User.String(), "event_type": ShortName(r.EventType), "controls": strconv.Itoa(contained),
			"approvals_voided": strconv.Itoa(len(approvals)),
		},
	})
	return err
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

func noCaseNote() *string {
	n := NoCaseNote
	return &n
}
