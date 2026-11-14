// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"encoding/json/v2"
	"flag"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// pclaw editor (G0 M36 D1067, FQ36-4): what an editor extension shows for
// one agent, read through the signed-in pclaw on the machine so that no
// token lives in the editor. Both verbs only read (HR-794): editor status
// lists coverage, waiting approvals and recent decisions with their console
// links; editor open prints a console link. Neither approves, declines nor
// changes anything; approving stays on the approval page.

// editorRecentWindow and editorRecentLimit bound the recent decisions.
const (
	editorRecentWindow = 24 * time.Hour
	editorRecentLimit  = 50
	editorPageSize     = 200
)

// editorStatus is the JSON document editor status prints.
type editorStatus struct {
	AgentID      string           `json:"agent_id"`
	Server       string           `json:"server"`
	GeneratedAt  time.Time        `json:"generated_at"`
	Coverage     []editorCoverage `json:"coverage"`
	Waiting      int              `json:"waiting"`
	Approvals    []editorApproval `json:"approvals"`
	Decisions    []editorDecision `json:"decisions"`
	ApprovalsURL string           `json:"approvals_url"`
}

type editorCoverage struct {
	ConnectionID string `json:"connection_id"`
	Operation    string `json:"operation"`
	State        string `json:"state"`
}

type editorApproval struct {
	ID            string     `json:"id"`
	Operation     string     `json:"operation"`
	State         string     `json:"state"`
	RunID         string     `json:"run_id,omitempty"`
	TransactionID string     `json:"transaction_id,omitempty"`
	CreatedAt     *time.Time `json:"created_at,omitempty"`
	DeadlineAt    *time.Time `json:"deadline_at,omitempty"`
	URL           string     `json:"url"`
}

type editorDecision struct {
	ID         string     `json:"id"`
	Operation  string     `json:"operation"`
	Decision   string     `json:"decision"`
	ReasonCode string     `json:"reason_code,omitempty"`
	RunID      string     `json:"run_id,omitempty"`
	CreatedAt  *time.Time `json:"created_at,omitempty"`
	URL        string     `json:"url"`
}

func editorTime(t *timestamppb.Timestamp) *time.Time {
	if t == nil {
		return nil
	}
	v := t.AsTime().UTC()
	return &v
}

// approvalURL and transactionURL are the console pages (the approval page,
// authn ApprovalsPath, and the evidence page, authority NextActions).
func approvalURL(server, id string) string {
	u := strings.TrimSuffix(server, "/") + "/approvals"
	if id != "" {
		u += "/" + id
	}
	return u
}

func transactionURL(server, id string) string {
	return strings.TrimSuffix(server, "/") + "/app/evidence/transactions/" + id
}

func editorStatusCmd(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("editor status", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	agent := fs.String("agent", "", "the agent's id (required)")
	_ = fs.Bool("json", true, "print JSON (the only format)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || !uuidRe.MatchString(*agent) {
		return errUsage
	}
	s, err := a.session()
	if err != nil {
		return err
	}
	cc := s.connect()
	out := editorStatus{
		AgentID: *agent, Server: s.server, GeneratedAt: time.Now().UTC(),
		Coverage: []editorCoverage{}, Approvals: []editorApproval{}, Decisions: []editorDecision{},
		ApprovalsURL: approvalURL(s.server, ""),
	}

	cov, err := pantherclawv1connect.NewCoverageServiceClient(cc).ListCoverage(ctx, &pantherclawv1.ListCoverageRequest{
		AgentId: agent, PageSize: editorPageSize,
	})
	if err != nil {
		return fmt.Errorf("coverage: %w", err)
	}
	for _, r := range cov.GetRecords() {
		out.Coverage = append(out.Coverage, editorCoverage{
			ConnectionID: r.GetScope().GetConnectionId(), Operation: r.GetScope().GetOperation(),
			State: strings.TrimPrefix(r.GetState().String(), "COVERAGE_STATE_"),
		})
	}

	aps, err := pantherclawv1connect.NewApprovalServiceClient(cc).ListApprovalRequests(ctx, &pantherclawv1.ListApprovalRequestsRequest{
		AgentId: agent, PageSize: editorPageSize,
		States: []pantherclawv1.ApprovalState{pantherclawv1.ApprovalState_APPROVAL_STATE_PENDING},
	})
	if err != nil {
		return fmt.Errorf("approvals: %w", err)
	}
	for _, r := range aps.GetRequests() {
		out.Approvals = append(out.Approvals, editorApproval{
			ID: r.GetId(), Operation: r.GetOperation(), State: strings.TrimPrefix(r.GetState().String(), "APPROVAL_STATE_"),
			RunID: r.GetRunId(), TransactionID: r.GetTransactionId(),
			CreatedAt: editorTime(r.GetCreateTime()), DeadlineAt: editorTime(r.GetDeadlineTime()),
			URL: approvalURL(s.server, r.GetId()),
		})
	}
	out.Waiting = len(out.Approvals)

	txs, err := pantherclawv1connect.NewTransactionServiceClient(cc).ListTransactions(ctx, &pantherclawv1.ListTransactionsRequest{
		AgentId: agent, PageSize: editorRecentLimit, StartTime: timestamppb.New(time.Now().Add(-editorRecentWindow)),
	})
	if err != nil {
		return fmt.Errorf("decisions: %w", err)
	}
	for _, t := range txs.GetTransactions() {
		out.Decisions = append(out.Decisions, editorDecision{
			ID: t.GetId(), Operation: t.GetOperation(), Decision: strings.TrimPrefix(t.GetDecision().String(), "DECISION_"),
			ReasonCode: t.GetReasonCode(), RunID: t.GetRunId(), CreatedAt: editorTime(t.GetCreateTime()),
			URL: transactionURL(s.server, t.GetId()),
		})
	}

	b, err := json.Marshal(out, json.Deterministic(true))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(a.stdout, string(b))
	return err
}

// editorOpenCmd prints the console link for an approval or a transaction.
// It contacts nothing; the editor opens the link in the browser.
func editorOpenCmd(_ context.Context, a *app, args []string) error {
	if len(args) != 2 || !uuidRe.MatchString(args[1]) {
		return errUsage
	}
	s, err := a.session()
	if err != nil {
		return err
	}
	var u string
	switch args[0] {
	case "approval":
		u = approvalURL(s.server, args[1])
	case "transaction":
		u = transactionURL(s.server, args[1])
	default:
		return errUsage
	}
	b, err := json.Marshal(struct {
		URL string `json:"url"`
	}{u})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(a.stdout, string(b))
	return err
}

func init() {
	commands["editor status"] = command{"editor status --agent ID [--json]", editorStatusCmd}
	commands["editor open"] = command{"editor open approval|transaction ID", editorOpenCmd}
}
