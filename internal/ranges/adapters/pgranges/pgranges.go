// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pgranges stores adversarial ranges in Postgres (G0 M12 W5,
// migration 00097) as the range service's store, reads the server's own
// transaction and probe records the service checks steps against, and
// abandons ranges nobody finished.
package pgranges

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"strings"
	"time"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/ranges/app"
	"github.com/katocxl/pantherclaw/internal/ranges/domain"
	"github.com/katocxl/pantherclaw/internal/sandbox/report"
)

// Store is the range store over a connection pool.
type Store struct{ Pool *db.Pool }

var _ app.Store = Store{}

// InTx runs fn in a tenant transaction for org.
func (s Store) InTx(ctx context.Context, org ids.OrgID, readOnly bool, fn func(context.Context, app.Tx) error) error {
	var opts []db.TxOption
	if readOnly {
		opts = append(opts, db.ReadOnly())
	}
	return s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		return fn(ctx, &txn{org: org, tx: tx, q: dbq.New(tx)})
	}, opts...)
}

type txn struct {
	org ids.OrgID
	tx  db.TenantTx
	q   *dbq.Queries
}

// Stored forms. The keys are part of the schema of jsonb columns.
type (
	scenarioJSON struct {
		ID       string `json:"id"`
		Digest   string `json:"digest"`
		Tier     string `json:"tier"`
		Category string `json:"category"`
		Suite    string `json:"suite"`
		Title    string `json:"title,omitzero"`
	}
	versionJSON struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		ID      string `json:"id"`
	}
	expectJSON struct {
		Outcome string `json:"outcome"`
		Reason  string `json:"reason,omitzero"`
		Code    string `json:"code,omitzero"`
	}
	stepJSON struct {
		ID          string     `json:"id"`
		Expect      expectJSON `json:"expect"`
		Observed    expectJSON `json:"observed"`
		ObservedBy  string     `json:"observed_by"`
		Mismatch    bool       `json:"mismatch,omitzero"`
		Claimed     expectJSON `json:"claimed,omitzero"`
		Matched     bool       `json:"matched"`
		Transaction string     `json:"transaction_id,omitzero"`
		Probe       string     `json:"probe_report_id,omitzero"`
		Decisive    string     `json:"decisive_control,omitzero"`
	}
)

func (t *txn) Agent(ctx context.Context, id ids.UUID) (app.AgentRef, error) {
	a, err := t.q.GetAgent(ctx, t.org, id)
	if db.IsNoRows(err) {
		return app.AgentRef{}, app.ErrAgentMissing
	} else if err != nil {
		return app.AgentRef{}, err
	}
	path, err := agents.PathOf(ctx, t.q, a)
	if err != nil {
		return app.AgentRef{}, err
	}
	return app.AgentRef{ID: a.ID, RangeAgent: a.RangeAgent, Path: path}, nil
}

func (t *txn) Versions(ctx context.Context, _ ids.UUID) (domain.Versions, error) {
	// Policy and package versions are org-wide: one published policy
	// version and the package pins.
	var v domain.Versions
	pol, err := t.q.RangePolicyVersions(ctx, t.org)
	if err != nil {
		return v, err
	}
	for _, p := range pol {
		v.Policies = append(v.Policies, domain.VersionRef{Name: p.Name, Version: p.Version, ID: p.ID})
	}
	pkg, err := t.q.RangePackageVersions(ctx, t.org)
	if err != nil {
		return v, err
	}
	for _, p := range pkg {
		v.Packages = append(v.Packages, domain.VersionRef{Name: p.Name, Version: p.Version, ID: p.ID})
	}
	return v, nil
}

func marshalVersions(refs []domain.VersionRef) ([]byte, error) {
	out := make([]versionJSON, 0, len(refs))
	for _, r := range refs {
		out = append(out, versionJSON(r))
	}
	return json.Marshal(out)
}

func (t *txn) InsertRange(ctx context.Context, r domain.Range) (domain.Range, error) {
	decls := make([]scenarioJSON, 0, len(r.Scenarios))
	for _, s := range r.Scenarios {
		decls = append(decls, scenarioJSON(s))
	}
	scenarios, err := json.Marshal(decls)
	if err != nil {
		return r, err
	}
	policies, err := marshalVersions(r.Versions.Policies)
	if err != nil {
		return r, err
	}
	packages, err := marshalVersions(r.Versions.Packages)
	if err != nil {
		return r, err
	}
	row, err := t.q.InsertRedteamRun(ctx, dbq.InsertRedteamRunParams{
		OrgID: t.org, ID: r.ID, RangeAgentID: r.Agent, StartedBy: r.StartedBy, RunnerVersion: r.RunnerVersion,
		ScenarioSetDigest: r.SetDigest, Scenarios: scenarios, PolicyVersions: policies, PackageVersions: packages,
		BaselineRangeID: r.Baseline,
	})
	if err != nil {
		return r, err
	}
	return rangeOf(row)
}

func rangeOf(r dbq.PcRedteamRun) (domain.Range, error) {
	var decls []scenarioJSON
	if err := json.Unmarshal(r.Scenarios, &decls); err != nil {
		return domain.Range{}, err
	}
	out := domain.Range{
		ID: r.ID, Agent: r.RangeAgentID, StartedBy: r.StartedBy, RunnerVersion: r.RunnerVersion, SetDigest: r.ScenarioSetDigest,
		Baseline: r.BaselineRangeID, State: domain.State(r.State), Started: r.StartedAt, Finished: r.FinishedAt,
	}
	for _, d := range decls {
		out.Scenarios = append(out.Scenarios, domain.Scenario(d))
	}
	var err error
	if out.Versions.Policies, err = versionsOf(r.PolicyVersions); err != nil {
		return out, err
	}
	out.Versions.Packages, err = versionsOf(r.PackageVersions)
	return out, err
}

func versionsOf(raw []byte) ([]domain.VersionRef, error) {
	var vs []versionJSON
	if err := json.Unmarshal(raw, &vs); err != nil {
		return nil, err
	}
	out := make([]domain.VersionRef, 0, len(vs))
	for _, v := range vs {
		out = append(out, domain.VersionRef(v))
	}
	return out, nil
}

func (t *txn) Range(ctx context.Context, id ids.UUID, lock bool) (domain.Range, error) {
	get := t.q.GetRedteamRun
	if lock {
		get = t.q.LockRedteamRun
	}
	row, err := get(ctx, t.org, id)
	if db.IsNoRows(err) {
		return domain.Range{}, app.ErrNotFound
	} else if err != nil {
		return domain.Range{}, err
	}
	return rangeOf(row)
}

func (t *txn) Transition(ctx context.Context, id ids.UUID, to domain.State) (time.Time, bool, error) {
	at, err := t.q.TransitionRedteamRun(ctx, string(to), t.org, id)
	if db.IsNoRows(err) {
		return time.Time{}, false, nil
	} else if err != nil {
		return time.Time{}, false, err
	}
	if at == nil {
		return time.Time{}, false, errors.New("pgranges: a finished range without its time")
	}
	return *at, true, nil
}

func (t *txn) ListRanges(ctx context.Context, agent *ids.UUID, after ids.UUID, limit int32) ([]domain.Range, error) {
	rows, err := t.q.ListRedteamRuns(ctx, dbq.ListRedteamRunsParams{OrgID: t.org, RangeAgentID: agent, Before: beforeOf(after), PageLimit: limit})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Range, 0, len(rows))
	for _, r := range rows {
		rg, err := rangeOf(r)
		if err != nil {
			return nil, err
		}
		out = append(out, rg)
	}
	return out, nil
}

// beforeOf turns the page cursor ("after" the last id, newest first) into
// the query's upper bound; the zero id is the first page.
func beforeOf(after ids.UUID) ids.UUID { return after }

func (t *txn) Results(ctx context.Context, rng ids.UUID) ([]domain.Result, error) {
	rows, err := t.q.RedteamResults(ctx, t.org, rng)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Result, 0, len(rows))
	for _, r := range rows {
		res, err := resultOf(r)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (e expectJSON) domain() domain.Expect { return domain.Expect(e) }

func resultOf(r dbq.PcRedteamResult) (domain.Result, error) {
	res := domain.Result{
		Scenario: domain.Scenario{ID: r.ScenarioID, Digest: r.ScenarioDigest, Tier: r.Tier, Category: r.Category, Suite: r.Suite, Title: r.Title},
		Verdict:  domain.Verdict(r.Verdict), Recorded: r.RecordedAt,
	}
	if r.ClaimedVerdict != nil {
		res.Claimed = domain.Verdict(*r.ClaimedVerdict)
	}
	var steps []stepJSON
	if err := json.Unmarshal(r.Steps, &steps); err != nil {
		return res, err
	}
	for _, s := range steps {
		st := domain.Step{
			ID: s.ID, Expect: s.Expect.domain(), Observed: s.Observed.domain(), ObservedBy: domain.ObservedBy(s.ObservedBy),
			Mismatch: s.Mismatch, Claimed: s.Claimed.domain(), Matched: s.Matched, Decisive: s.Decisive,
		}
		var err error
		if st.Transaction, err = optID(s.Transaction); err != nil {
			return res, err
		}
		if st.Probe, err = optID(s.Probe); err != nil {
			return res, err
		}
		res.Steps = append(res.Steps, st)
	}
	return res, nil
}

func optID(s string) (*ids.UUID, error) {
	if s == "" {
		return nil, nil
	}
	id, err := ids.ParseUUID(s)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

func idStr(id *ids.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

func (t *txn) InsertResult(ctx context.Context, rng ids.UUID, r domain.Result) (time.Time, bool, error) {
	steps := make([]stepJSON, 0, len(r.Steps))
	server, client, mismatches := 0, 0, 0
	for _, s := range r.Steps {
		steps = append(steps, stepJSON{
			ID: s.ID, Expect: expectJSON(s.Expect), Observed: expectJSON(s.Observed), ObservedBy: string(s.ObservedBy),
			Mismatch: s.Mismatch, Claimed: expectJSON(s.Claimed), Matched: s.Matched, Transaction: idStr(s.Transaction),
			Probe: idStr(s.Probe), Decisive: s.Decisive,
		})
		if s.ObservedBy == domain.Server {
			server++
		} else {
			client++
		}
		if s.Mismatch {
			mismatches++
		}
	}
	by := "NONE"
	switch {
	case server > 0 && client > 0:
		by = "MIXED"
	case server > 0:
		by = "SERVER"
	case client > 0:
		by = "CLIENT"
	}
	raw, err := json.Marshal(steps)
	if err != nil {
		return time.Time{}, false, err
	}
	var claimed *string
	if r.Claimed != "" {
		c := string(r.Claimed)
		claimed = &c
	}
	at, err := t.q.InsertRedteamResult(ctx, dbq.InsertRedteamResultParams{
		OrgID: t.org, RangeID: rng, ScenarioID: r.Scenario.ID, ScenarioDigest: r.Scenario.Digest, Title: r.Scenario.Title,
		Suite: r.Scenario.Suite, Category: r.Scenario.Category, Tier: r.Scenario.Tier, Verdict: string(r.Verdict),
		ClaimedVerdict: claimed, Steps: raw, ObservedBy: by, Mismatches: int32(mismatches),
	})
	if db.IsNoRows(err) {
		return time.Time{}, false, nil
	} else if err != nil {
		return time.Time{}, false, err
	}
	return at, true, nil
}

func (t *txn) Transaction(ctx context.Context, id ids.UUID) (domain.TransactionRecord, bool, error) {
	r, err := t.q.RangeTransaction(ctx, t.org, id)
	if db.IsNoRows(err) {
		return domain.TransactionRecord{}, false, nil
	} else if err != nil {
		return domain.TransactionRecord{}, false, err
	}
	return domain.TransactionRecord{
		ID: r.ID, Agent: r.AgentID, Simulated: r.Simulated, Created: r.CreatedAt, Decision: r.Decision, Reason: r.ReasonCode,
		EffectState: r.EffectState,
	}, true, nil
}

// Probe reads a stored probe report (the server verified its signature,
// nonce and session when it accepted it, HR-215). It supports BLOCKED when
// every result of the report was as expected, otherwise ALLOW: something
// the report expected blocked got through, or a control failed.
func (t *txn) Probe(ctx context.Context, id ids.UUID) (domain.ProbeRecord, bool, error) {
	r, err := t.q.RangeProbeReport(ctx, t.org, id)
	if db.IsNoRows(err) {
		return domain.ProbeRecord{}, false, nil
	} else if err != nil {
		return domain.ProbeRecord{}, false, err
	}
	outcome, err := ProbeOutcome(r.Report)
	if err != nil {
		return domain.ProbeRecord{}, false, err
	}
	return domain.ProbeRecord{ID: r.ID, Agent: r.AgentID, Recorded: r.ReceivedAt, Outcome: outcome}, true, nil
}

// ProbeOutcome reads the outcome a stored compact JWS report supports.
func ProbeOutcome(compact string) (string, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return "", errors.New("pgranges: a stored probe report is not a compact JWS")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	var rep report.Report
	if err := json.Unmarshal(payload, &rep); err != nil {
		return "", err
	}
	if len(rep.Results) == 0 {
		return domain.OutcomeAllow, nil
	}
	for _, res := range rep.Results {
		if !res.Passed() {
			return domain.OutcomeAllow, nil
		}
	}
	return domain.OutcomeBlocked, nil
}

func (t *txn) Audit(ctx context.Context, ev audit.Event) error {
	_, err := audit.Record(ctx, t.tx, ev)
	return err
}
