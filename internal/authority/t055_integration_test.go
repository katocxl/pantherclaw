// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package authority_test

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority"
	"github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	factsapp "github.com/katocxl/pantherclaw/internal/facts/app"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	polpg "github.com/katocxl/pantherclaw/internal/policy/adapters/pgstore"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// t055Refundable is the fact the reference package's refunds need (a
// prerequisite with a maximum age of 300 seconds), as a provider declares
// it.
var t055Refundable = []fdomain.Declaration{
	{Name: "payments.charge.refundable", Type: fdomain.TypeBoolean, SubjectType: "payments.charge", MaxLag: 5 * time.Minute},
}

// t055As is a caller of the fact use cases: a person or a service account
// of org.
func t055As(org ids.OrgID, kind td.PrincipalKind, id ids.UUID) context.Context {
	return tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{Org: org, Principal: td.PrincipalRef{Kind: kind, ID: id}}})
}

// t055Put reports that charge is (or is not) refundable, observed at at,
// through the PutFacts use case as the caller in ctx. It returns the
// call's error, or else the observation's.
func t055Put(f fixture, ctx context.Context, charge string, refundable bool, at time.Time) error {
	res, err := f.facts.PutFacts(ctx, []fdomain.Observation{{
		Name: "payments.charge.refundable", SubjectType: "payments.charge", SubjectID: charge,
		Value: jsontext.Value(fmt.Sprintf(`{"bool": %t}`, refundable)), ObservedAt: at,
	}})
	if err != nil {
		return err
	}
	return res[0].Err
}

// t055InOrg runs one statement in org's tenant transaction.
func t055InOrg(t *testing.T, f fixture, org ids.OrgID, sql string, args ...any) {
	t.Helper()
	if err := f.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// t055Authorize asks the Authority to decide a canonical action of the
// fixture's run, with the workload's verified credentials.
func t055Authorize(t *testing.T, f fixture, raw []byte) authority.Result {
	t.Helper()
	res, err := f.svc.Authorize(context.Background(), f.gw, raw, f.creds(t, f.wl, f.wl.token))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// t055Refund asks for a 30 USD refund of charge as action act of the run.
func t055Refund(t *testing.T, f fixture, charge string, act ids.UUID) authority.Result {
	t.Helper()
	return t055Authorize(t, f, f.actionOn(t, charge, "30.00", f.run, act, f.env.String(), f.wl.inst.Instance.String()))
}

// t055Edit returns the action raw with edit applied to its JSON members.
func t055Edit(t *testing.T, raw []byte, edit func(map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// t055Publish publishes rules as the org's policy.
func t055Publish(t *testing.T, f fixture, rules ...pdomain.Rule) {
	t.Helper()
	ctx := context.Background()
	store := &polpg.Store{Pool: f.pool}
	id, _, err := store.CreateVersion(ctx, f.gw.Org, &pdomain.Bundle{ID: "org-policy", Rules: rules}, "user:"+f.owner.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Publish(ctx, f.gw.Org, id, "user:"+f.owner.String(), nil); err != nil {
		t.Fatal(err)
	}
}

// TestT055_ValuesInTheActionAreNeverFacts (T-055, HR-160): no provider has
// reported the charge, so its refund is CANNOT_AUTHORIZE (FACT_MISSING).
// The agent, or a gateway relaying its action, then claims refundability
// itself: in the tool call, as a parameter of the action, or as an extra
// member of the ActionIR. None of these is a fact: the reviewed mapping
// builds no action from the tool call, and the Authority answers the others
// CANNOT_AUTHORIZE (AMBIGUOUS_INPUT) without a permit. The gateway's own
// authenticated context is no caller of the fact use cases either. Only the
// provider's report makes the plain refund allowed.
func TestT055_ValuesInTheActionAreNeverFacts(t *testing.T) {
	f := setup(t, "1000", 0, time.Minute)
	ctx := context.Background()
	const charge = "ch_unreported1"
	env, inst := f.env.String(), f.wl.inst.Instance.String()
	plain := func() []byte { return f.actionOn(t, charge, "30.00", f.run, ids.NewV7(), env, inst) }
	wantDecision(t, "the refund before any report", t055Authorize(t, f, plain()), domain.CannotAuthorize, fdomain.ReasonFactMissing, "")

	if _, err := f.mapper.MCP(ctx, mapping.Context{
		Org: f.gw.Org.String(), Env: env, RunID: f.run.String(), ActionID: ids.NewV7().String(), AgentInstance: inst, Connection: f.conn.String(),
	}, "create_refund", []byte(`{"charge":"`+charge+`","amount":"30.00","currency":"USD","reason":"duplicate","refundable":true}`)); err == nil {
		t.Error("the mapping built an action from a tool call claiming refundability")
	}
	for name, raw := range map[string][]byte{
		"a refundable parameter": t055Edit(t, plain(), func(m map[string]any) {
			m["params"].(map[string]any)["refundable"] = map[string]any{"bool": true}
		}),
		"a facts member": t055Edit(t, plain(), func(m map[string]any) {
			m["facts"] = map[string]any{"payments.charge.refundable": map[string]any{"bool": true}}
		}),
	} {
		res := t055Authorize(t, f, raw)
		wantDecision(t, name, res, domain.CannotAuthorize, domain.ReasonAmbiguousInput, "")
		if res.Permit != "" {
			t.Errorf("%s: a permit was issued", name)
		}
	}
	if err := t055Put(f, authority.WithGateway(ctx, f.gw), charge, true, time.Now()); !errors.Is(err, tenancy.ErrNoCaller) {
		t.Errorf("a gateway reported a fact: %v", err)
	}
	wantDecision(t, "the refund after the claims", t055Authorize(t, f, plain()), domain.CannotAuthorize, fdomain.ReasonFactMissing, "")

	f.refundable(t, charge)
	if res := t055Authorize(t, f, plain()); res.Decision != domain.Allow {
		t.Fatalf("the refund after the provider's report: %s %+v", res.Decision, res.Reasons)
	}
}

// TestT055_AnOldObservationIsNotCurrent (T-055, HR-160): a published rule
// forbids refunds of charges that are not refundable and reads the fact
// with a maximum age of 60 seconds. The provider reports a charge
// refundable two minutes late: inside its five-minute lag, so it is
// recorded, but at decision time it is older than the rule accepts, so the
// refund is CANNOT_AUTHORIZE (FACT_STALE, naming the fact), neither ALLOW
// nor a policy denial. The provider's current observation says the charge
// is not refundable; replaying the old "refundable" observation after it
// is refused, and the same refund, decided again, is denied by the rule.
func TestT055_AnOldObservationIsNotCurrent(t *testing.T) {
	f := setup(t, "1000", 0, time.Minute)
	t055Publish(t, f, pdomain.Rule{
		ID: "refundable-only", Kind: pdomain.Forbid, Summary: "only refundable charges", Operations: []string{"payments.refund.create"},
		When: `!facts.payments_charge_refundable`, Reason: "NOT_REFUNDABLE",
		Facts: []pdomain.FactRef{{Name: "payments.charge.refundable", MaxAgeSeconds: 60}},
	})
	billing := t055As(f.gw.Org, td.KindServiceAccount, f.billing)
	const charge = "ch_late1"
	late := time.Now().Add(-2 * time.Minute)
	if err := t055Put(f, billing, charge, true, late); err != nil {
		t.Fatalf("an observation inside the provider's lag: %v", err)
	}
	act := ids.NewV7()
	stale := t055Refund(t, f, charge, act)
	wantDecision(t, "the refund on a two-minute-old observation", stale, domain.CannotAuthorize, fdomain.ReasonFactStale, "")
	if len(stale.Reasons) > 0 && !strings.Contains(stale.Reasons[0].Detail, "payments.charge.refundable") {
		t.Errorf("the stale fact is not named: %q", stale.Reasons[0].Detail)
	}

	if err := t055Put(f, billing, charge, false, time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("the provider's current observation: %v", err)
	}
	if err := t055Put(f, billing, charge, true, late); !errors.Is(err, fdomain.ErrStale) {
		t.Fatalf("the old observation replayed over the current one: %v", err)
	}
	wantDecision(t, "the same refund on the current observation", t055Refund(t, f, charge, act), domain.Deny, "NOT_REFUNDABLE", "")
}

// TestT055_FactsAboutAnotherSubjectDoNotCount (T-055, HR-160): facts are
// about the action's own target in the action's own org. A report about a
// look-alike charge (the same id in another case) and a report about the
// very same charge id by another org's provider, registered there for the
// same fact name, do not make this org's refund of the charge allowed: it
// stays CANNOT_AUTHORIZE (FACT_MISSING) until this org's provider reports
// that charge.
func TestT055_FactsAboutAnotherSubjectDoNotCount(t *testing.T) {
	f := setup(t, "1000", 0, time.Minute)
	f.refundable(t, "ch_abcdef1")
	wantDecision(t, "a look-alike charge", t055Refund(t, f, "ch_ABCDEF1", ids.NewV7()), domain.CannotAuthorize, fdomain.ReasonFactMissing, "")

	other, sa := ids.New[ids.Org](), ids.NewV7()
	t055InOrg(t, f, other, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'other')", other)
	t055InOrg(t, f, other, "INSERT INTO pc.service_accounts (org_id, id, name, created_by) VALUES ($1, $2, 'billing', 'test')", other, sa)
	if _, err := f.facts.RegisterProvider(t055As(other, td.KindUser, ids.NewV7()), "billing.system", sa, t055Refundable); err != nil {
		t.Fatal(err)
	}
	const shared = "ch_shared1"
	if err := t055Put(f, t055As(other, td.KindServiceAccount, sa), shared, true, time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("the other org's provider: %v", err)
	}
	wantDecision(t, "a charge only another org's provider reported", t055Refund(t, f, shared, ids.NewV7()),
		domain.CannotAuthorize, fdomain.ReasonFactMissing, "")

	f.refundable(t, shared)
	if res := t055Refund(t, f, shared, ids.NewV7()); res.Decision != domain.Allow {
		t.Fatalf("the charge after this org's provider reported it: %s %+v", res.Decision, res.Reasons)
	}
}

// TestT055_ADisabledProviderVouchesForNothing (T-055, HR-160): a fact
// provider's account is compromised after it reported two charges
// refundable. Once the org disables the provider, its recorded facts stop
// counting at the next decision (FACT_MISSING), its account can no longer
// report (NOT_A_FACT_PROVIDER), and its facts do not come back when a new
// provider is registered for the same fact name; only the new provider's
// own report makes the refund allowed.
func TestT055_ADisabledProviderVouchesForNothing(t *testing.T) {
	f := setup(t, "1000", 0, time.Minute)
	ctx := context.Background()
	f.refundable(t, "ch_before1", "ch_before2")
	if res := t055Refund(t, f, "ch_before1", ids.NewV7()); res.Decision != domain.Allow {
		t.Fatalf("a refund on the provider's report: %s %+v", res.Decision, res.Reasons)
	}
	provs, err := (&factspg.Store{Pool: f.pool}).ListProviders(ctx, f.gw.Org, false)
	if err != nil || len(provs) != 1 {
		t.Fatalf("providers %+v, %v", provs, err)
	}
	person := t055As(f.gw.Org, td.KindUser, f.owner)
	if err := f.facts.DisableProvider(person, provs[0].ID); err != nil {
		t.Fatal(err)
	}
	wantDecision(t, "a charge the disabled provider reported", t055Refund(t, f, "ch_before2", ids.NewV7()),
		domain.CannotAuthorize, fdomain.ReasonFactMissing, "")
	if err := t055Put(f, t055As(f.gw.Org, td.KindServiceAccount, f.billing), "ch_before2", true, time.Now()); !errors.Is(err, factsapp.ErrNotProvider) {
		t.Fatalf("the disabled provider's account reported a fact: %v", err)
	}

	successor := ids.NewV7()
	f.exec(t, "INSERT INTO pc.service_accounts (org_id, id, name, created_by) VALUES ($1, $2, 'billing-v2', 'test')", f.gw.Org, successor)
	if _, err := f.facts.RegisterProvider(person, "billing.v2", successor, t055Refundable); err != nil {
		t.Fatal(err)
	}
	wantDecision(t, "the charge once a successor is registered", t055Refund(t, f, "ch_before2", ids.NewV7()),
		domain.CannotAuthorize, fdomain.ReasonFactMissing, "")
	if err := t055Put(f, t055As(f.gw.Org, td.KindServiceAccount, successor), "ch_before2", true, time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("the successor's report: %v", err)
	}
	if res := t055Refund(t, f, "ch_before2", ids.NewV7()); res.Decision != domain.Allow {
		t.Fatalf("the charge after the successor reported it: %s %+v", res.Decision, res.Reasons)
	}
}
