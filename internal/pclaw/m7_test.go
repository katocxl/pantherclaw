// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

type recordTransactions struct {
	pantherclawv1connect.UnimplementedTransactionServiceHandler
	list *pantherclawv1.ListTransactionsRequest
	show *pantherclawv1.GetTransactionEvidenceRequest
}

func (r *recordTransactions) ListTransactions(_ context.Context, req *pantherclawv1.ListTransactionsRequest) (*pantherclawv1.ListTransactionsResponse, error) {
	r.list = req
	return &pantherclawv1.ListTransactionsResponse{}, nil
}

func (r *recordTransactions) GetTransactionEvidence(_ context.Context, req *pantherclawv1.GetTransactionEvidenceRequest) (*pantherclawv1.GetTransactionEvidenceResponse, error) {
	r.show = req
	return &pantherclawv1.GetTransactionEvidenceResponse{Transaction: &pantherclawv1.Transaction{
		Id: req.GetId(), ExecutionState: pantherclawv1.ExecutionState_EXECUTION_STATE_ACCEPTED,
		EffectState: pantherclawv1.EffectState_EFFECT_STATE_CONFIRMED,
	}}, nil
}

type recordReconciliations struct {
	pantherclawv1connect.UnimplementedReconciliationServiceHandler
	list     *pantherclawv1.ListReconciliationsRequest
	occurred *pantherclawv1.ResolveOccurredRequest
	verify   *pantherclawv1.RequestVerificationRequest
	link     *pantherclawv1.LinkTransactionRequest
}

func (r *recordReconciliations) ListReconciliations(_ context.Context, req *pantherclawv1.ListReconciliationsRequest) (*pantherclawv1.ListReconciliationsResponse, error) {
	r.list = req
	return &pantherclawv1.ListReconciliationsResponse{}, nil
}

func (r *recordReconciliations) ResolveOccurred(_ context.Context, req *pantherclawv1.ResolveOccurredRequest) (*pantherclawv1.ResolveOccurredResponse, error) {
	r.occurred = req
	return &pantherclawv1.ResolveOccurredResponse{}, nil
}

func (r *recordReconciliations) RequestVerification(_ context.Context, req *pantherclawv1.RequestVerificationRequest) (*pantherclawv1.RequestVerificationResponse, error) {
	r.verify = req
	return &pantherclawv1.RequestVerificationResponse{VerificationId: "0192aaaa-bbbb-7ccc-8ddd-0000000000aa"}, nil
}

func (r *recordReconciliations) LinkTransaction(_ context.Context, req *pantherclawv1.LinkTransactionRequest) (*pantherclawv1.LinkTransactionResponse, error) {
	r.link = req
	return &pantherclawv1.LinkTransactionResponse{}, nil
}

func TestM7TransactionAndReconcileCommands(t *testing.T) {
	rt, rr := &recordTransactions{}, &recordReconciliations{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterTransactionServiceHandler(cs, rt)
	pantherclawv1connect.RegisterReconciliationServiceHandler(cs, rr)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})
	const (
		txn   = "0192aaaa-bbbb-7ccc-8ddd-000000000001"
		other = "0192aaaa-bbbb-7ccc-8ddd-000000000002"
		obs   = "0192aaaa-bbbb-7ccc-8ddd-000000000003"
	)

	code, _, errs := run(t, env, "txn", "list", "--run", txn, "--execution", "dispatched", "--execution", "cancelled", //nolint:misspell // the state's name
		"--effect", "unknown", "--decision", "allow", "--since", "24h", "--page-size", "10")
	l := rt.list
	if code != 0 || l.GetRunId() != txn || l.AgentId != nil || len(l.GetExecutionStates()) != 2 ||
		l.GetExecutionStates()[1] != pantherclawv1.ExecutionState_EXECUTION_STATE_CANCELLED || //nolint:misspell // the state's name
		l.GetEffectStates()[0] != pantherclawv1.EffectState_EFFECT_STATE_UNKNOWN || l.GetDecisions()[0] != pantherclawv1.Decision_DECISION_ALLOW ||
		l.GetPageSize() != 10 || l.GetStartTime() == nil || time.Since(l.GetStartTime().AsTime()) < 23*time.Hour {
		t.Fatalf("txn list = %d %q, request %v", code, errs, l)
	}
	if code, _, errs := run(t, env, "txn", "list", "--execution", "sent"); code == 0 || !strings.Contains(errs, "--execution") {
		t.Fatalf("an unknown execution state = %d %q", code, errs)
	}
	if code, _, errs := run(t, env, "txn", "list", "--effect", "unspecified"); code == 0 || !strings.Contains(errs, "--effect") {
		t.Fatalf("unspecified = %d %q", code, errs)
	}
	code, out, errs := run(t, env, "txn", "show", txn)
	if code != 0 || rt.show.GetId() != txn || !strings.Contains(out, "EXECUTION_STATE_ACCEPTED") || !strings.Contains(out, "EFFECT_STATE_CONFIRMED") {
		t.Fatalf("txn show = %d %q %q", code, out, errs)
	}

	if code, _, errs := run(t, env, "reconcile", "list", "--state", "open", "--kind", "unknown_outcome", "--transaction", txn); code != 0 ||
		rr.list.GetStates()[0] != pantherclawv1.ReconciliationState_RECONCILIATION_STATE_OPEN ||
		rr.list.GetKinds()[0] != pantherclawv1.ReconciliationKind_RECONCILIATION_KIND_UNKNOWN_OUTCOME || rr.list.GetTransactionId() != txn {
		t.Fatalf("reconcile list = %d %q, request %v", code, errs, rr.list)
	}
	if code, _, errs := run(t, env, "reconcile", "occurred", txn); code == 0 || !strings.Contains(errs, "--basis") || rr.occurred != nil {
		t.Fatalf("occurred without a basis = %d %q", code, errs)
	}
	code, _, errs = run(t, env, "reconcile", "occurred", txn, "--basis", "in the processor's dashboard", "--evidence", obs, "--authoritative", obs)
	if o := rr.occurred; code != 0 || o.GetId() != txn || o.GetBasis() != "in the processor's dashboard" || len(o.GetEvidence()) != 1 || o.GetObservationId() != obs {
		t.Fatalf("reconcile occurred = %d %q, request %v", code, errs, rr.occurred)
	}
	if code, out, _ := run(t, env, "reconcile", "verify", txn); code != 0 || rr.verify.GetTransactionId() != txn || !strings.Contains(out, "0000000000aa") {
		t.Fatalf("reconcile verify = %d %q", code, out)
	}
	if code, _, errs := run(t, env, "reconcile", "link", other, txn, "--kind", "compensates"); code != 0 || rr.link.GetFromTransactionId() != other ||
		rr.link.GetToTransactionId() != txn || rr.link.GetKind() != pantherclawv1.LinkKind_LINK_KIND_COMPENSATES {
		t.Fatalf("reconcile link = %d %q, request %v", code, errs, rr.link)
	}
	if code, _, errs := run(t, env, "reconcile", "link", other, txn); code == 0 || !strings.Contains(errs, "--kind") {
		t.Fatalf("a link without a kind = %d %q", code, errs)
	}
	// Releasing ("did not occur") needs a security key on the page.
	if _, ok := commands["reconcile release"]; ok {
		t.Fatal("pclaw must not release a reconciliation")
	}
}
