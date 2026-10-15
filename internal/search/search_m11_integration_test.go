// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package search

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	capp "github.com/katocxl/pantherclaw/internal/cases/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type edition billing.Edition

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Edition(e)}, nil
}

// m11fx is fx with a run per agent the test can name, an incident per
// agent and the M11 search wiring.
type m11fx struct {
	*fx
	runA, runB           ids.UUID
	incidentA, incidentB ids.UUID
	auditor, responder   tenancy.Caller
}

// run adds a run of agent with one transaction per decision, all the same
// operation, and returns it.
func (f *fx) run(agent ids.UUID, decisions ...string) ids.UUID {
	var env ids.UUID
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT environment_id FROM pc.agents WHERE org_id = $1 AND id = $2", f.org, agent).Scan(&env)
	}); err != nil {
		f.t.Fatal(err)
	}
	run := ids.NewV7()
	f.exec(`INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_user_id, principal_user_id, principal_source, expires_at)
		VALUES ($1, $2, $3, $4, $5, $5, 'launcher', now() + interval '8 hours')`, f.org, run, agent, env, f.user)
	for _, d := range decisions {
		f.exec(`INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id, state)
			VALUES ($1, $2, $3, $4, $5, 'payments.refund.create', $6, 'R', 'gw', 'OPEN')`,
			f.org, ids.NewV7(), run, ids.NewV7(), make([]byte, 32), d)
	}
	return run
}

// incident opens an incident with one alert about agent and run.
func (f *fx) incident(title string, agent, run ids.UUID) ids.UUID {
	inc := ids.NewV7()
	f.exec(`INSERT INTO pc.incidents (org_id, id, title, severity, opened_by) VALUES ($1, $2, $3, 'HIGH', 'user:test')`, f.org, inc, title)
	f.exec(`INSERT INTO pc.alerts (org_id, id, source, title, severity, attention, basis, subjects, dedupe_key, incident_id,
		first_seen, last_seen) VALUES ($1, $2, 'detection', $3, 'HIGH', 'INCIDENT', 'RULE_MATCH',
		jsonb_build_array(jsonb_build_object('type', 'agent', 'id', $4::text), jsonb_build_object('type', 'run', 'id', $5::text)),
		$6, $7, now(), now())`, f.org, ids.NewV7(), title, agent.String(), run.String(), ids.NewV7().String(), inc)
	return inc
}

func newM11Fx(t *testing.T) *m11fx {
	t.Helper()
	f := &m11fx{fx: newFx(t)}
	f.runA = f.run(f.agentA, "ALLOW", "ALLOW", "ALLOW")
	f.runB = f.run(f.agentB, "ALLOW", "ALLOW", "ALLOW")
	f.incidentA = f.incident("Exfil from alpha", f.agentA, f.runA)
	f.incidentB = f.incident("Exfil from bravo", f.agentB, f.runB)
	f.s.Editions = edition(billing.Team)
	f.s.Cases = capp.NewOpener(edition(billing.Team))
	f.auditor = f.caller(td.RoleAuditor, td.Scope{Type: td.ScopeOrg, ID: f.fx.org.UUID()})
	f.responder = f.caller(td.RoleResponder, td.Scope{Type: td.ScopeTeam, ID: f.teamA})
	return f
}

func as(c tenancy.Caller) context.Context { return tenancy.WithCaller(context.Background(), c) }

func kindOf(r FindResult, k FindKind) (KindResult, bool) {
	for _, x := range r.Kinds {
		if x.Kind == k {
			return x, true
		}
	}
	return KindResult{}, false
}

func hasOmission(os []Omission, code, part string) bool {
	return slices.ContainsFunc(os, func(o Omission) bool { return o.Code == code && strings.Contains(o.Detail, part) })
}

// TestHR257_NewEntitiesReadOnlyTheViewersScope (D44): alerts and
// incidents are read and counted at the viewer's agent scope; org-level
// entities the viewer may not read are RESTRICTED, never empty.
func TestHR257_NewEntitiesReadOnlyTheViewersScope(t *testing.T) {
	f := newM11Fx(t)
	for _, e := range []Entity{EntityAlerts, EntityIncidents} {
		all := f.search(f.auditor, Query{Entity: e})
		mine := f.search(f.responder, Query{Entity: e})
		if all.Count != 2 || mine.Count != 1 || mine.Items[0].Fields["agents"] != f.agentA.String() {
			t.Fatalf("%s: org %d, team %d %+v", e, all.Count, mine.Count, mine.Items)
		}
		hidden := f.search(f.responder, Query{Entity: e, Filters: Filters{Agent: &f.agentB}})
		if hidden.Count != 0 || hidden.Empty != EmptyNothingInScope {
			t.Fatalf("%s for the hidden agent: %+v", e, hidden)
		}
	}
	if r := f.search(f.responder, Query{Entity: EntityIncidents, Filters: Filters{Severities: []string{"LOW"}}}); r.Count != 0 {
		t.Fatalf("severity filter: %d", r.Count)
	}
	if r := f.search(f.responder, Query{Entity: EntityGateways}); r.Empty != EmptyRestricted || len(r.Items) != 0 {
		t.Fatalf("gateways for a responder: %+v", r)
	}
	for _, e := range []Entity{EntityCases, EntityFindings, EntityPolicyVersions, EntityPackages, EntityGateways} {
		_ = f.search(f.auditor, Query{Entity: e}) // every runner runs
	}
}

// TestHR295_FindMatchesOnlyTheViewersScope (F304, F320): quick find
// matches names, titles and ids only among the records the viewer may
// read; counts leave hidden records out; a kind the viewer may not read is
// an omission, never a match or a count.
func TestHR295_FindMatchesOnlyTheViewersScope(t *testing.T) {
	f := newM11Fx(t)
	find := func(c tenancy.Caller, text string, kinds ...FindKind) FindResult {
		t.Helper()
		r, err := f.s.Find(as(c), FindRequest{Text: text, Kinds: kinds})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	// "ha" is in alpha (team A) and charlie (team C).
	org, _ := kindOf(find(f.auditor, "HA", FindAgents), FindAgents)
	team, _ := kindOf(find(f.responder, "HA", FindAgents), FindAgents)
	if org.Count != 2 || team.Count != 1 || len(team.Matches) != 1 || team.Matches[0].ID != f.agentA.String() ||
		team.Matches[0].MatchedBy != MatchedNameContains || team.Matches[0].Evidence[0] != "agent:"+f.agentA.String() {
		t.Fatalf("org %+v, team %+v", org, team)
	}
	if k, _ := kindOf(find(f.responder, "alpha", FindAgents), FindAgents); k.Matches[0].MatchedBy != MatchedNameExact {
		t.Fatalf("exact: %+v", k)
	}
	inc, _ := kindOf(find(f.responder, "exfil", FindIncidents), FindIncidents)
	if inc.Count != 1 || inc.Matches[0].ID != f.incidentA.String() {
		t.Fatalf("incidents: %+v", inc)
	}
	// An exact id of a hidden record matches nothing, as for a missing one.
	for _, id := range []string{f.agentB.String(), f.runB.String(), ids.NewV7().String()} {
		r := find(f.responder, id)
		for _, k := range r.Kinds {
			if k.Count != 0 || len(k.Matches) != 0 {
				t.Fatalf("%s: %s matched %+v", id, k.Kind, k)
			}
		}
	}
	if k, _ := kindOf(find(f.auditor, f.runB.String()), FindRuns); k.Count != 1 || k.Matches[0].MatchedBy != MatchedID {
		t.Fatalf("org viewer, run id: %+v", k)
	}
	if k, _ := kindOf(find(f.auditor, f.runB.String()[:13]), FindRuns); k.Count < 1 || k.Matches[0].MatchedBy != MatchedIDPrefix {
		t.Fatalf("org viewer, run id prefix: %+v", k)
	}
	// A responder holds no member, gateway or audit read: those kinds are
	// omissions, and wildcards are literal.
	r := find(f.responder, "a%")
	if _, ok := kindOf(r, FindPeople); ok || !hasOmission(r.Omissions, omissionRestricted, "people: outside your permissions") {
		t.Fatalf("people for a responder: %+v", r)
	}
	if k, _ := kindOf(r, FindAgents); k.Count != 0 {
		t.Fatalf("a%% matched %+v", k)
	}
}

// TestHR295_AskAnswersFromReadableRecordsWithEvidence (F305, F321): a
// question runs under the viewer's permissions and every row links its
// evidence; nothing runs while it needs clarification.
func TestHR295_AskAnswersFromReadableRecordsWithEvidence(t *testing.T) {
	f := newM11Fx(t)
	a, err := f.s.Ask(as(f.responder), "allowed actions by alpha today", "Europe/Paris", page.Request{Size: 10})
	if err != nil {
		t.Fatal(err)
	}
	if a.Result == nil || a.Result.Count != 6 || a.Interpretation.Meaning != MeaningAttempts || a.Interpretation.Timezone != "Europe/Paris" {
		t.Fatalf("ask: %+v %+v", a.Interpretation, a.Result)
	}
	for _, i := range a.Result.Items {
		if len(i.Evidence) == 0 || i.Fields["agent"] != f.agentA.String() {
			t.Fatalf("row %+v", i)
		}
	}
	a, err = f.s.Ask(as(f.auditor), "denied actions by bravo", "", page.Request{})
	if err != nil || a.Result == nil || a.Result.Count != 1 {
		t.Fatalf("org viewer, bravo: %+v %v", a, err)
	}
	a, err = f.s.Ask(as(f.auditor), "denied actions frobnicated", "", page.Request{})
	if err != nil || a.Result != nil || !a.Interpretation.NeedsClarification {
		t.Fatalf("unknown word ran: %+v %v", a, err)
	}
}

// TestT130_HiddenRecordsReadLikeMissingOnes: a question naming an agent
// the viewer may not read is answered exactly like one naming an agent
// that does not exist, and quick find suggests neither.
func TestT130_HiddenRecordsReadLikeMissingOnes(t *testing.T) {
	f := newM11Fx(t)
	hidden, err := f.s.Ask(as(f.responder), "denied actions by bravo", "", page.Request{})
	if err != nil {
		t.Fatal(err)
	}
	missing, err := f.s.Ask(as(f.responder), "denied actions by zulu", "", page.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if hidden.Result != nil || !slices.Equal(hidden.Interpretation.UnknownWords, []string{"bravo"}) ||
		!slices.Equal(missing.Interpretation.UnknownWords, []string{"zulu"}) ||
		len(hidden.Interpretation.Ambiguities) != 0 || len(hidden.Interpretation.Clarifications) != len(missing.Interpretation.Clarifications) {
		t.Fatalf("hidden %+v, missing %+v", hidden.Interpretation, missing.Interpretation)
	}
	r, err := f.s.Find(as(f.responder), FindRequest{Text: "bravo"})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range r.Kinds {
		if k.Count != 0 {
			t.Fatalf("bravo suggested as %s: %+v", k.Kind, k)
		}
	}
}

// v7s returns n new ids (page tokens carry UUIDv7 ids).
func v7s(n int) []ids.UUID {
	out := make([]ids.UUID, n)
	for i := range out {
		out[i] = ids.NewV7()
	}
	return out
}

func isCode(err error, code string) bool {
	var e *pcerr.Error
	return errors.As(err, &e) && e.Reason() == code
}

// TestHR296_ExportNeedsExportPermissionCapsAndIsAudited (F318): export
// needs evidence.export as well as the rows' own read permission, stops at
// 10 000 rows, and records the query in the audit ledger.
func TestHR296_ExportNeedsExportPermissionCapsAndIsAudited(t *testing.T) {
	f := newM11Fx(t)
	src := Source{Query: &Query{Entity: EntityTransactions}}
	if _, err := f.s.ExportResults(as(f.responder), src, FormatJSON); !isCode(err, "PERMISSION_DENIED") {
		t.Fatalf("responder without evidence.export: %v", err)
	}
	e, err := f.s.ExportResults(as(f.auditor), src, FormatCSV)
	if err != nil {
		t.Fatal(err)
	}
	if e.Rows != 11 || e.Truncated || e.AuditID.IsZero() || !strings.HasPrefix(string(e.Data), "entity,id,time,label,") {
		t.Fatalf("export: %d rows, truncated %v, audit %v\n%s", e.Rows, e.Truncated, e.AuditID, e.Data)
	}
	var n int
	var body string
	if err := f.p.InTenantTx(context.Background(), f.fx.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, `SELECT count(*), max(convert_from(body, 'UTF8')) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.search.exported'`,
			f.fx.org).Scan(&n, &body)
	}); err != nil {
		t.Fatal(err)
	}
	if n != 1 || !strings.Contains(body, `transactions`) || !strings.Contains(body, `query_sha256`) {
		t.Fatalf("audit: %d %s", n, body)
	}
	// Gateways need gateway.read, which an auditor holds only through
	// boundary reads; restricted entities are refused, never exported empty.
	if _, err := f.s.ExportResults(as(f.auditor), Source{Query: &Query{Entity: EntityGateways}}, FormatJSON); err != nil {
		t.Fatalf("auditor gateways: %v", err)
	}
	f.exec(`INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id, state)
		SELECT $1, t, $2, a, $3, 'payments.refund.create', 'ALLOW', 'R', 'gw', 'OPEN'
		FROM unnest($4::uuid[], $5::uuid[]) AS x(t, a)`, f.fx.org, f.runA, make([]byte, 32), v7s(10000), v7s(10000))
	e, err = f.s.ExportResults(as(f.auditor), src, FormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	if e.Rows != MaxExportRows || !e.Truncated || !hasOmission(e.Omissions, "TRUNCATED", "10000") {
		t.Fatalf("cap: %d rows, truncated %v", e.Rows, e.Truncated)
	}
}

// TestHR296_OpenCaseCarriesOnlyTheChosenItems (F318): a case opened from
// results carries the chosen rows' evidence and nothing else; a row the
// viewer cannot see in that search is refused, and case.manage is needed.
func TestHR296_OpenCaseCarriesOnlyTheChosenItems(t *testing.T) {
	f := newM11Fx(t)
	q := Query{Entity: EntityTransactions, Filters: Filters{Run: &f.runA}}
	page1 := f.search(f.responder, q)
	chosen := page1.Items[0]
	id, err := f.s.OpenCaseFromResults(as(f.responder), OpenCaseRequest{Source: Source{Query: &q}, Items: []string{chosen.ID}, Title: "Refunds"})
	if err != nil {
		t.Fatal(err)
	}
	var refs []string
	if err := f.p.InTenantTx(context.Background(), f.fx.org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := tx.Query(ctx, `SELECT ref_kind || ':' || lower(ref_id) FROM pc.case_entries
			WHERE org_id = $1 AND case_id = $2 AND kind = 'LINK' ORDER BY 1`, f.fx.org, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return err
			}
			refs = append(refs, s)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	want := slices.Sorted(slices.Values(chosen.Evidence))
	if !slices.Equal(refs, want) {
		t.Fatalf("case links %v, want %v", refs, want)
	}
	// A transaction of the hidden agent is not in the responder's results.
	var hiddenTxn string
	all := f.search(f.auditor, Query{Entity: EntityTransactions, Filters: Filters{Run: &f.runB}})
	hiddenTxn = all.Items[0].ID
	anyQ := Query{Entity: EntityTransactions}
	if _, err := f.s.OpenCaseFromResults(as(f.responder), OpenCaseRequest{Source: Source{Query: &anyQ}, Items: []string{hiddenTxn}, Title: "x"}); !isCode(err, "SEARCH_ITEMS_NOT_FOUND") {
		t.Fatalf("hidden item: %v", err)
	}
	if _, err := f.s.OpenCaseFromResults(as(f.auditor), OpenCaseRequest{Source: Source{Query: &anyQ}, Items: []string{hiddenTxn}, Title: "x"}); !isCode(err, "PERMISSION_DENIED") {
		t.Fatalf("auditor without case.manage: %v", err)
	}
	f.s.Cases = capp.NewOpener(edition(billing.Community))
	if _, err := f.s.OpenCaseFromResults(as(f.responder), OpenCaseRequest{Source: Source{Query: &q}, Items: []string{chosen.ID}, Title: "y"}); !isCode(err, "EDITION_REQUIRED") {
		t.Fatalf("community: %v", err)
	}
}

// TestT130_CorrelationStaysInTheViewersScope (F316): incident correlation
// shows the runs that share an operation sequence with the incident's run
// only where the viewer may read them, and needs the Team edition.
func TestT130_CorrelationStaysInTheViewersScope(t *testing.T) {
	f := newM11Fx(t)
	b := BuiltinQuery{Name: BuiltinIncidentCorrelation, Params: Params{Incident: &f.incidentA}}
	all, err := f.s.RunBuiltin(as(f.auditor), b, page.Request{})
	if err != nil {
		t.Fatal(err)
	}
	shares := func(r Result, run ids.UUID) bool {
		return slices.ContainsFunc(r.Items, func(i Item) bool { return i.Label == CorrSharedSequence && i.Fields["run"] == run.String() })
	}
	if !shares(all, f.runB) || !slices.ContainsFunc(all.Items, func(i Item) bool { return i.Label == CorrIncidentRun }) ||
		!hasOmission(all.Omissions, "CORRELATION_NOT_CAUSE", "never causes") {
		t.Fatalf("org viewer: %+v", all)
	}
	mine, err := f.s.RunBuiltin(as(f.responder), b, page.Request{})
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range mine.Items {
		if strings.Contains(strings.Join(i.Evidence, " "), f.runB.String()) || i.Fields["agent"] == f.agentB.String() {
			t.Fatalf("team viewer sees %+v", i)
		}
	}
	// The other team's incident is not found, like a missing one.
	other := BuiltinQuery{Name: BuiltinIncidentCorrelation, Params: Params{Incident: &f.incidentB}}
	if _, err := f.s.RunBuiltin(as(f.responder), other, page.Request{}); !isCode(err, "NOT_FOUND") {
		t.Fatalf("hidden incident: %v", err)
	}
	f.s.Editions = edition(billing.Community)
	if _, err := f.s.RunBuiltin(as(f.auditor), b, page.Request{}); !isCode(err, "EDITION_REQUIRED") {
		t.Fatalf("community: %v", err)
	}
}
