// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/adapters/pgauthority"
	"github.com/katocxl/pantherclaw/internal/authority/consequences"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	gapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// notices records the notifications the store enqueues.
type notices struct {
	mu  sync.Mutex
	got []napp.Message
}

func (n *notices) Enqueue(_ context.Context, _ db.TenantTx, m napp.Message) (napp.Enqueued, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.got = append(n.got, m)
	return napp.Enqueued{}, nil
}

func (n *notices) all() []napp.Message {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]napp.Message(nil), n.got...)
}

// TestHR206_AMonitorRouteRunsAnUnknownConsequenceAndSaysItWouldHold
// (founder decision 2026-10-13, HR-206 with HR-184): monitor mode stays
// observe-only. A refund whose payout cannot be ruled out still gets its
// permit on a monitor-mode route, with the same reasons as enforce mode;
// its answer, receipt and receipt entry say "HOLD: consequence unknown",
// and one security notice goes out for the transaction, not again for the
// same action resubmitted. On an enforce-mode route the same refund is held.
func TestHR206_AMonitorRouteRunsAnUnknownConsequenceAndSaysItWouldHold(t *testing.T) {
	w := newWorldWith(t, pipelinetest.PayoutConsequence)
	n := &notices{}
	w.auth.Store.(*pgauthority.Store).Notify = n
	w.refundable("ch_1")
	b, _ := gdomain.DecodeBounds([]byte(`{"operations": ["payments.refund.create", "payments.payout.trigger"],
	  "params": {"payments.refund.create": {"amount": {"max": {"USD": "100.00"}}}}}`))
	g, err := w.grants.Issue(w.human, gapp.IssueRequest{
		AgentID: w.agent, Principal: gdomain.Principal{Kind: gdomain.PrincipalUser, ID: w.alice}, TaskRef: "refunds",
		ExpiresAt: time.Now().Add(48 * time.Hour), Bounds: b, Delegation: gdomain.Delegation{Depth: 1, MaxChildren: 5},
		Requirements: []gdomain.Requirement{{
			Operations: gdomain.Ops{"payments.payout.trigger"}, Reason: "PAYOUTS_NEED_AN_APPROVER",
			Approval: &pdomain.ApprovalRequirement{Role: "approver", Count: 1},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	run := w.run(g.ID, ids.UUID{})

	req := w.through(w.withConnection(pipeline.ModeMonitor), run, "ch_1", "30.00")
	r := w.authorize(req)
	const would = "HOLD: consequence unknown"
	if r.Permit == "" || r.Mode != pipeline.ModeMonitor || r.Decision != adomain.RequireApproval || decisive(r) != consequences.ReasonUnknown ||
		r.Would != would {
		t.Fatalf("monitor: %s %s permit %t would %q", r.Decision, decisive(r), r.Permit != "", r.Would)
	}
	if c := claims(t, r.Receipt); c["would"] != would || c["monitor"] != true {
		t.Fatalf("the receipt says would %v, monitor %v", c["would"], c["monitor"])
	}
	if got := w.scalar(`SELECT count(*)::text FROM pc.ledger_entries WHERE kind = 'receipt.decision'
		AND convert_from(body, 'UTF8')::jsonb ->> 'would' = $1 AND convert_from(body, 'UTF8')::jsonb ->> 'txn' = $2`,
		would, r.TransactionID.String()); got != "1" {
		t.Fatalf("%s receipt entries say it would hold, want 1", got)
	}
	got := n.all()
	if len(got) != 1 || got[0].Type != "security.consequence_unknown_dispatched" || got[0].Org != w.org ||
		got[0].Params["operation"] != "payments.refund.create" || got[0].Params["consequence"] != "payments.payout.trigger on ch_1" ||
		got[0].Params["would"] != would || got[0].Params["transaction"] != r.TransactionID.String() ||
		got[0].DedupeKey != "consequence_unknown_dispatched:"+r.TransactionID.String() {
		t.Fatalf("notices %+v", got)
	}
	if again := w.authorize(req); !again.Repeat || again.TransactionID != r.TransactionID || len(n.all()) != 1 {
		t.Fatalf("the same action again: repeat %t, %d notices", again.Repeat, len(n.all()))
	}

	e := w.authorize(w.through(w.withConnection(pipeline.ModeEnforce), run, "ch_1", "30.00"))
	if e.Decision != adomain.RequireApproval || decisive(e) != consequences.ReasonUnknown || e.Permit != "" || e.Wait == nil || e.Would != "" {
		t.Fatalf("enforce: %s %s permit %t would %q", e.Decision, decisive(e), e.Permit != "", e.Would)
	}
	if c := claims(t, e.Receipt); c["would"] != nil {
		t.Fatalf("an enforce-mode receipt says would %v", c["would"])
	}
	if len(n.all()) != 1 {
		t.Fatalf("an enforce-mode hold notified: %+v", n.all())
	}
}
