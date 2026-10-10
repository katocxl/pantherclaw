// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/transactions/domain"
)

var (
	dispatched = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	inWindow   = dispatched.Add(time.Minute)
	afterIt    = dispatched.Add(11 * time.Minute)
)

func refundVerifier() *defs.VerifierSpec {
	return &defs.VerifierSpec{
		Operation: "payments.refund.get", Establishes: "refund.exists", WithinSeconds: 600,
		States: &defs.StateMap{
			Field: "/status", Confirmed: []string{"succeeded"}, Pending: []string{"pending"},
			None: []string{"failed", "canceled"},
		},
	}
}

var want = domain.Expected{"/charge": "ch_1", "/amount": "30.00", "/currency": "USD"}

func uuid(s string) ids.UUID {
	u, err := ids.ParseUUID(s)
	if err != nil {
		panic(err)
	}
	return u
}

func fields(status string) map[string]string {
	return map[string]string{"/charge": "ch_1", "/amount": "30.00", "/currency": "USD", "/status": status}
}

// TestHR191_ObservationsMapToEffectStates walks G0 M7 design decision 2.
func TestHR191_ObservationsMapToEffectStates(t *testing.T) {
	differs := fields("succeeded")
	differs["/amount"] = "300.00"
	cases := []struct {
		name     string
		p        domain.Purpose
		o        domain.Observation
		state    domain.EffectState
		final    bool
		occurred bool
	}{
		{"read failed", domain.PurposeFollowUp, domain.Observation{HTTPStatus: 0, At: inWindow}, "", false, false},
		{"server error", domain.PurposeReconcile, domain.Observation{HTTPStatus: 503, At: afterIt}, "", false, false},
		{"refused read", domain.PurposeFollowUp, domain.Observation{HTTPStatus: 401, At: inWindow}, "", false, false},
		{"confirmed", domain.PurposeFollowUp, domain.Observation{HTTPStatus: 200, Found: true, Fields: fields("succeeded"), At: inWindow}, domain.Confirmed, true, true},
		{"pending", domain.PurposeFollowUp, domain.Observation{HTTPStatus: 200, Found: true, Fields: fields("pending"), At: inWindow}, domain.PropagationPending, false, true},
		{"none", domain.PurposeFollowUp, domain.Observation{HTTPStatus: 200, Found: true, Fields: fields("failed"), At: inWindow}, domain.NoneConfirmed, true, false},
		{"unrecognized status", domain.PurposeFollowUp, domain.Observation{HTTPStatus: 200, Found: true, Fields: fields("weird"), At: inWindow}, "", false, true},
		{"differs", domain.PurposeFollowUp, domain.Observation{HTTPStatus: 200, Found: true, Fields: differs, At: inWindow}, domain.Conflicting, true, false},
		{"missing field", domain.PurposeFollowUp, domain.Observation{HTTPStatus: 200, Found: true, Fields: map[string]string{"/status": "succeeded"}, At: inWindow}, domain.Conflicting, true, false},
		{"accepted but not found yet", domain.PurposeFollowUp, domain.Observation{HTTPStatus: 404, At: inWindow}, domain.PropagationPending, false, false},
		{"accepted but never found", domain.PurposeFollowUp, domain.Observation{HTTPStatus: 404, At: afterIt}, domain.Conflicting, true, false},
		{"found in listing", domain.PurposeReconcile, domain.Observation{HTTPStatus: 200, Found: true, Complete: true, Fields: fields("succeeded"), At: inWindow}, domain.Confirmed, true, true},
		{"listing cut short", domain.PurposeReconcile, domain.Observation{HTTPStatus: 200, Complete: false, At: afterIt}, "", false, false},
		{"absent too early", domain.PurposeReconcile, domain.Observation{HTTPStatus: 200, Complete: true, At: inWindow}, "", false, false},
		{"absent from a complete listing", domain.PurposeReconcile, domain.Observation{HTTPStatus: 200, Complete: true, At: afterIt}, domain.NoneConfirmed, true, false},
	}
	for _, c := range cases {
		a := domain.Assess(refundVerifier(), c.p, want, c.o, dispatched)
		if a.State != c.state || a.Final != c.final || a.Occurred() != c.occurred {
			t.Errorf("%s: state %q final %v occurred %v; want %q %v %v (%s)", c.name, a.State, a.Final, a.Occurred(),
				c.state, c.final, c.occurred, a.Reason)
		}
	}
}

func TestHR191_ConfirmationReachesOnlyTheVerifiersLevel(t *testing.T) {
	v := refundVerifier()
	o := domain.Observation{HTTPStatus: 200, Found: true, Fields: fields("succeeded"), At: inWindow}
	if a := domain.Assess(v, domain.PurposeFollowUp, want, o, dispatched); a.Level != defs.LevelFollowUp {
		t.Fatalf("level %q, want follow_up", a.Level)
	}
	v.Level = defs.LevelDomainEffect
	if a := domain.Assess(v, domain.PurposeFollowUp, want, o, dispatched); a.Level != defs.LevelDomainEffect {
		t.Fatalf("level %q, want domain_effect", a.Level)
	}
	v.States = nil // without a status map, finding the object is the confirmation
	if a := domain.Assess(v, domain.PurposeFollowUp, want, o, dispatched); a.State != domain.Confirmed {
		t.Fatalf("state %q, want CONFIRMED", a.State)
	}
}

func TestHR191_DeadlinesEndInTheLastConclusiveStateOrUnknown(t *testing.T) {
	if s := domain.AtDeadline(domain.Assessment{State: domain.PropagationPending}); s != domain.Unknown {
		t.Fatalf("pending at the deadline: %q, want UNKNOWN", s)
	}
	if s := domain.AtDeadline(domain.Assessment{}); s != domain.Unknown {
		t.Fatalf("nothing conclusive: %q, want UNKNOWN", s)
	}
	if s := domain.AtDeadline(domain.Assessment{State: domain.Conflicting, Final: true}); s != domain.Conflicting {
		t.Fatalf("conflicting: %q", s)
	}
}

func TestINV07_ExecutionStatesNeverReadAsEffects(t *testing.T) {
	cases := []struct {
		r    domain.Record
		want domain.ExecutionState
	}{
		{domain.Record{}, domain.Requested},
		{domain.Record{Decision: "REQUIRE_APPROVAL"}, domain.Waiting},
		{domain.Record{Decision: "DENY", Reason: "GRANT_AMOUNT_EXCEEDED"}, domain.Blocked},
		{domain.Record{Decision: "DENY", Reason: "APPROVAL_DECLINED"}, domain.Canceled},
		{domain.Record{Decision: "CANNOT_AUTHORIZE"}, domain.Blocked},
		{domain.Record{Decision: "ALLOW", PermitState: "ISSUED"}, domain.Authorized},
		{domain.Record{Decision: "ALLOW", PermitState: "RELEASED"}, domain.Canceled},
		{domain.Record{Decision: "ALLOW", PermitState: "DISPATCHING"}, domain.Dispatched},
		{domain.Record{Decision: "ALLOW", PermitState: "UNKNOWN", Outcome: "unknown"}, domain.Dispatched},
		{domain.Record{Decision: "ALLOW_WITH_OBLIGATIONS", PermitState: "DISPATCHED", Outcome: "accepted"}, domain.Accepted},
		{domain.Record{Decision: "ALLOW", PermitState: "DISPATCHED", Outcome: "failed"}, domain.Failed},
		{domain.Record{Decision: "ALLOW", PermitState: "DISPATCHED", Outcome: "delegated"}, domain.Dispatched},
	}
	for _, c := range cases {
		if got := domain.Execution(c.r); got != c.want {
			t.Errorf("%+v: %q, want %q", c.r, got, c.want)
		}
	}
}

func TestHR192_EvidenceResolvesOnlyTowardsOccurred(t *testing.T) {
	cases := []struct {
		from, to domain.TaskState
		via      domain.Via
		want     error
	}{
		{domain.TaskOpen, domain.TaskOccurred, domain.ViaVerifier, nil},
		{domain.TaskOpen, domain.TaskOccurred, domain.ViaLateReport, nil},
		{domain.TaskOpen, domain.TaskOccurred, domain.ViaTargetLog, nil},
		{domain.TaskOpen, domain.TaskNotOccurred, domain.ViaVerifier, domain.ErrEvidenceReleases},
		{domain.TaskOpen, domain.TaskNotOccurred, domain.ViaTargetLog, domain.ErrEvidenceReleases},
		{domain.TaskOpen, domain.TaskNotOccurred, domain.ViaPerson, nil},
		{domain.TaskOccurred, domain.TaskNotOccurred, domain.ViaPerson, domain.ErrNotOpen},
		{domain.TaskNotOccurred, domain.TaskOccurred, domain.ViaVerifier, domain.ErrNotOpen},
	}
	for _, c := range cases {
		if err := domain.CheckResolution(c.from, c.to, c.via); !errors.Is(err, c.want) {
			t.Errorf("%s -> %s by %s: %v, want %v", c.from, c.to, c.via, err, c.want)
		}
	}
}

func TestHR192_OnlyAnIndependentPersonResolves(t *testing.T) {
	p := domain.Party{Launcher: ids.NewV7(), Principal: ids.NewV7(), Owner: ids.NewV7(), BackupOwner: ids.NewV7()}
	other := ids.NewV7()
	for _, u := range []ids.UUID{p.Launcher, p.Principal, p.Owner, p.BackupOwner} {
		if err := domain.CheckResolver(true, u, p, "basis", nil); !errors.Is(err, domain.ErrNotIndependent) {
			t.Errorf("a party to the run resolved: %v", err)
		}
	}
	if err := domain.CheckResolver(false, other, p, "basis", nil); !errors.Is(err, domain.ErrNotAPerson) {
		t.Errorf("a service resolved: %v", err)
	}
	if err := domain.CheckResolver(true, other, p, "", nil); !errors.Is(err, domain.ErrBasisRequired) {
		t.Errorf("no basis: %v", err)
	}
	if err := domain.CheckResolver(true, other, p, strings.Repeat("é", domain.MaxBasis+1), nil); !errors.Is(err, domain.ErrBasisTooLong) {
		t.Errorf("a long basis: %v", err)
	}
	if err := domain.CheckResolver(true, other, p, strings.Repeat("é", domain.MaxBasis), nil); err != nil {
		t.Errorf("2000 characters: %v", err)
	}
}

// TestHR192_APersonRecordsOccurredWithABasis: "occurred" only commits, so
// any person holding transaction.reconcile records it, with a basis, naming
// the authoritative observation among their evidence.
func TestHR192_APersonRecordsOccurredWithABasis(t *testing.T) {
	seen := ids.NewV7()
	cases := []struct {
		name          string
		human         bool
		basis         string
		evidence      []ids.UUID
		authoritative *ids.UUID
		want          error
	}{
		{"a person with a basis", true, "the refund is in the processor's dashboard", nil, nil, nil},
		{"naming the authoritative observation", true, "basis", []ids.UUID{seen}, &seen, nil},
		{"a service", false, "basis", nil, nil, domain.ErrNotAPerson},
		{"no basis", true, "", nil, nil, domain.ErrBasisRequired},
		{"a long basis", true, strings.Repeat("é", domain.MaxBasis+1), nil, nil, domain.ErrBasisTooLong},
		{"too much evidence", true, "basis", make([]ids.UUID, 65), nil, domain.ErrTooMuchEvidence},
		{"an authoritative observation not shown", true, "basis", []ids.UUID{seen}, new(ids.NewV7()), domain.ErrNotEvidence},
	}
	for _, c := range cases {
		if err := domain.CheckOccurred(c.human, c.basis, c.evidence, c.authoritative); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
}

// TestHR192_ReleaseBindingIsStable pins the release binding: a change to its
// inputs or encoding changes the challenge a person's key signed.
func TestHR192_ReleaseBindingIsStable(t *testing.T) {
	r := domain.Release{
		Reconciliation: uuid("0192a000-0000-7000-8000-000000000001"),
		Transaction:    uuid("0192a000-0000-7000-8000-000000000002"),
		Basis:          "No refund for this charge in a complete listing 12 minutes after dispatch.",
		Evidence:       []ids.UUID{uuid("0192a000-0000-7000-8000-000000000004"), uuid("0192a000-0000-7000-8000-000000000003")},
		ExpiresAt:      time.Date(2026, 10, 10, 12, 30, 0, 500, time.UTC),
	}
	// Written by hand in JCS order, and hashed independently of this code.
	const document = `{"basis_sha256":"btv2722-gW-hzNPmyZnMYl3B7N0dcu9YepFIfMVpQRA",` +
		`"evidence":["0192a000-0000-7000-8000-000000000003","0192a000-0000-7000-8000-000000000004"],` +
		`"expires_at":"2026-10-10T12:30:00Z","reconciliation":"0192a000-0000-7000-8000-000000000001",` +
		`"resolution":"not_occurred","transaction":"0192a000-0000-7000-8000-000000000002","v":1}`
	const golden = "4a26fde70d121f4e0712d6e924c07e1b36276f68d252397f95c1e5e49253cc77"
	doc, err := r.Document()
	if err != nil || string(doc) != document {
		t.Fatalf("document %s (%v), want %s", doc, err, document)
	}
	b, err := r.Binding()
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(b[:]); got != golden {
		t.Fatalf("binding %s, want %s", got, golden)
	}
	swapped := r
	swapped.Evidence = slices.Clone(r.Evidence)
	slices.Reverse(swapped.Evidence)
	if b2, _ := swapped.Binding(); b2 != b {
		t.Fatal("evidence order changed the binding")
	}
	for _, m := range []func(*domain.Release){
		func(x *domain.Release) { x.Basis += "." },
		func(x *domain.Release) { x.Transaction = ids.NewV7() },
		func(x *domain.Release) { x.Evidence = x.Evidence[:1] },
		func(x *domain.Release) { x.ExpiresAt = x.ExpiresAt.Add(time.Second) },
	} {
		c := r
		c.Evidence = slices.Clone(r.Evidence)
		m(&c)
		if b2, _ := c.Binding(); b2 == b {
			t.Fatal("a changed input kept the binding")
		}
	}
}

func TestHR193_LinksFollowTheOriginalAndCompensateOnlyConfirmedEffects(t *testing.T) {
	a, b := ids.NewV7(), ids.NewV7()
	if err := domain.CheckLink(a, a, afterIt, dispatched); !errors.Is(err, domain.ErrLinkSelf) {
		t.Errorf("self link: %v", err)
	}
	if err := domain.CheckLink(a, b, dispatched.Add(-time.Second), dispatched); !errors.Is(err, domain.ErrLinkOrder) {
		t.Errorf("decided before the original was sent: %v", err)
	}
	if err := domain.CheckLink(a, b, afterIt, time.Time{}); !errors.Is(err, domain.ErrLinkOrder) {
		t.Errorf("the original never dispatched: %v", err)
	}
	if err := domain.CheckLink(a, b, afterIt, dispatched); err != nil {
		t.Errorf("a later compensation: %v", err)
	}
	for _, s := range domain.EffectStates {
		err := domain.CompensatedFrom(s)
		if (s == domain.Confirmed) != (err == nil) {
			t.Errorf("COMPENSATED from %s: %v", s, err)
		}
	}
}
