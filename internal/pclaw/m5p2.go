// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// M5 part 2 commands: approval requests, the waitlist's writes, access
// requests, escalation chains and waiting on a held action. Approving
// happens on the approval page with a security key (decision 1): `pclaw
// approval approve` only opens it.

type m5p2Clients struct {
	approvals pantherclawv1connect.ApprovalServiceClient
}

func init() {
	for k, v := range approvalCommands() {
		commands[k] = v
	}
	for k, v := range waitlistCommands() {
		commands[k] = v
	}
	commands["workload wait"] = command{
		"workload wait HANDLE --key-file FILE [--token-file FILE] [--run ID] [--timeout SECONDS] [--follow]", workloadWait,
	}
}

// code maps a lower-case code such as too_risky to its enum value.
func code[E ~int32](flagName, s, prefix string, names map[string]int32) (E, error) {
	if s == "" {
		return 0, nil
	}
	n, ok := names[prefix+strings.ToUpper(s)]
	if !ok {
		return 0, fmt.Errorf("--%s: unknown value %q", flagName, s)
	}
	return E(n), nil
}

func approvalCommands() map[string]command {
	return map[string]command{
		"approval list": rpc("approval list [--state S,...] [--agent ID] [--run ID] [--waiting-for-me]", 0, func(fs *flag.FlagSet) call {
			var states list
			fs.Var(&states, "state", "only these states (pending, evidence_requested, approved, consumed, declined, expired, invalidated, superseded)")
			agent, run := fs.String("agent", "", "only this agent"), fs.String("run", "", "only this run")
			mine := fs.Bool("waiting-for-me", false, "only the requests you may decide now and have not approved")
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				st, err := enumList[pantherclawv1.ApprovalState](states, "APPROVAL_STATE_", pantherclawv1.ApprovalState_value)
				if err != nil {
					return nil, err
				}
				return c.approvals.ListApprovalRequests(ctx, &pantherclawv1.ListApprovalRequestsRequest{
					PageSize: size(n), PageToken: *tok, States: st, AgentId: optStr(*agent), RunId: optStr(*run), WaitingForMe: *mine,
				})
			}
		}),
		"approval get": rpc("approval get ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.approvals.GetApprovalRequest(ctx, &pantherclawv1.GetApprovalRequestRequest{Id: a[0]})
			}
		}),
		"approval approve": {"approval approve ID [--no-browser]", approvalApprove},
		"approval decline": rpc("approval decline ID --reason not_needed|too_risky|wrong_target|needs_different_approach|other "+
			"[--alternative narrower_action|person_performs|retry_later|ask_owner] [--note TEXT]", 1, func(fs *flag.FlagSet) call {
			reason, alt, note := fs.String("reason", "", "why (required)"), fs.String("alternative", "", "a safer alternative"), fs.String("note", "", "a note for the requester")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				r, err := code[pantherclawv1.DeclineReason]("reason", *reason, "DECLINE_REASON_", pantherclawv1.DeclineReason_value)
				if err != nil {
					return nil, err
				}
				alternative, err := code[pantherclawv1.SaferAlternative]("alternative", *alt, "SAFER_ALTERNATIVE_", pantherclawv1.SaferAlternative_value)
				if err != nil {
					return nil, err
				}
				return c.approvals.DeclineApprovalRequest(ctx, &pantherclawv1.DeclineApprovalRequestRequest{
					Id: a[0], Reason: r, Alternative: alternative, Note: *note,
				})
			}
		}),
		"approval request-evidence": rpc("approval request-evidence ID --question why_needed|context|parameter_basis|other "+
			"[--note TEXT] [--within DURATION]", 1, func(fs *flag.FlagSet) call {
			question, note := fs.String("question", "", "what to ask (required)"), fs.String("note", "", "a note for the requester")
			within := fs.Duration("within", time.Hour, "how long the requester has to answer (before the request's deadline)")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				q, err := code[pantherclawv1.EvidenceQuestion]("question", *question, "EVIDENCE_QUESTION_", pantherclawv1.EvidenceQuestion_value)
				if err != nil {
					return nil, err
				}
				return c.approvals.RequestApprovalEvidence(ctx, &pantherclawv1.RequestApprovalEvidenceRequest{
					Id: a[0], Question: q, Note: *note, EvidenceDeadlineTime: timestamppb.New(time.Now().Add(*within)),
				})
			}
		}),
		"approval evidence": rpc("approval evidence ID --note TEXT", 1, func(fs *flag.FlagSet) call {
			note := fs.String("note", "", "the evidence (required; shown to the deciders as untrusted)")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.approvals.SubmitApprovalEvidence(ctx, &pantherclawv1.SubmitApprovalEvidenceRequest{Id: a[0], Note: *note})
			}
		}),
		"approval propose": rpc("approval propose ID --params-file FILE [--note TEXT] [--validate-only]", 1, func(fs *flag.FlagSet) call {
			file, note := fs.String("params-file", "", "the narrower parameters (JSON)"), fs.String("note", "", "a note for the requester")
			validate := fs.Bool("validate-only", false, "only simulate the proposal; record nothing")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				b, err := readDocument("params-file", *file)
				if err != nil {
					return nil, err
				}
				if len(b) == 0 {
					return nil, errors.New("--params-file is required")
				}
				return c.approvals.ProposeNarrowerAction(ctx, &pantherclawv1.ProposeNarrowerActionRequest{
					Id: a[0], Params: b, Note: *note, ValidateOnly: *validate,
				})
			}
		}),
		"approval decline-batch": rpc("approval decline-batch --ids ID,... --reason REASON [--note TEXT]", 0, func(fs *flag.FlagSet) call {
			var batch list
			fs.Var(&batch, "ids", "the requests (1 to 25, one operation)")
			reason, note := fs.String("reason", "", "why (required)"), fs.String("note", "", "a note for the requesters")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				r, err := code[pantherclawv1.DeclineReason]("reason", *reason, "DECLINE_REASON_", pantherclawv1.DeclineReason_value)
				if err != nil {
					return nil, err
				}
				var requests []string
				for _, v := range batch {
					requests = append(requests, strings.Split(v, ",")...)
				}
				return c.approvals.DeclineApprovalBatch(ctx, &pantherclawv1.DeclineApprovalBatchRequest{Ids: requests, Reason: r, Note: *note})
			}
		}),
		"agent restore": rpc("agent restore AGENT --reason TEXT", 1, func(fs *flag.FlagSet) call {
			reason := fs.String("reason", "", "why it should be restored (required)")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.agents.RequestAgentRestoration(ctx, &pantherclawv1.RequestAgentRestorationRequest{Id: a[0], Reason: *reason})
			}
		}),
	}
}

// approvalApprove opens the approval page: approving needs a person and
// their security key in the browser (decision 1).
func approvalApprove(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("approval approve", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	noBrowser := fs.Bool("no-browser", false, "print the link only")
	if len(args) < 1 {
		return errUsage
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	id, err := ids.ParseUUID(args[0])
	if fs.NArg() != 0 || err != nil {
		return errUsage
	}
	s, err := a.session()
	if err != nil {
		return err
	}
	if s.apiKey != "" {
		return errors.New("an API key never approves: a person approves on the approval page with a security key")
	}
	link := s.server + "/approvals/" + id.String() + "?org=" + url.QueryEscape(s.creds.Org)
	_, _ = fmt.Fprintf(a.stdout, "Approve with your security key on the approval page:\n\n  %s\n", link)
	if !*noBrowser && a.openBrowser != nil {
		if err := a.openBrowser(ctx, link); err != nil {
			_, _ = fmt.Fprintln(a.stderr, "(could not open a browser; open the link yourself)")
		}
	}
	return nil
}

var waitlistKindNames = pantherclawv1.WaitlistKind_value

func waitlistCommands() map[string]command {
	return map[string]command{
		"waitlist assign": rpc("waitlist assign ID [--unassign]", 1, func(fs *flag.FlagSet) call {
			unassign := fs.Bool("unassign", false, "stop working on it")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.waitlist.AssignWaitlistEntry(ctx, &pantherclawv1.AssignWaitlistEntryRequest{Id: a[0], Unassign: *unassign})
			}
		}),
		"waitlist metrics": rpc("waitlist metrics [--days N] [--kind K,...]", 0, func(fs *flag.FlagSet) call {
			days := fs.Int("days", 0, "the window in days (1-90, default 30)")
			var kinds list
			fs.Var(&kinds, "kind", "only these kinds (admission, access_request, action_hold, tool_review, restoration, reconciliation)")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				k, err := enumList[pantherclawv1.WaitlistKind](kinds, "WAITLIST_KIND_", waitlistKindNames)
				if err != nil {
					return nil, err
				}
				return c.waitlist.GetWaitlistMetrics(ctx, &pantherclawv1.GetWaitlistMetricsRequest{WindowDays: int32(min(max(*days, 0), 90)), Kinds: k})
			}
		}),
		"waitlist settings": rpc("waitlist settings", 0, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.waitlist.GetWaitlistSettings(ctx, &pantherclawv1.GetWaitlistSettingsRequest{})
			}
		}),
		"waitlist update-settings": rpc("waitlist update-settings --file SETTINGS.json", 0, func(fs *flag.FlagSet) call {
			file := fs.String("file", "", "the settings (JSON as printed by pclaw waitlist settings; zero means the default)")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				var st pantherclawv1.WaitlistSettings
				if err := readMessage("file", *file, &st); err != nil {
					return nil, err
				}
				return c.waitlist.UpdateWaitlistSettings(ctx, &pantherclawv1.UpdateWaitlistSettingsRequest{Settings: &st})
			}
		}),
		"access request": rpc("access request RUN --note TEXT [--transaction ID]", 1, func(fs *flag.FlagSet) call {
			note, txn := fs.String("note", "", "what the run needs and why (required)"), fs.String("transaction", "", "the transaction refused for scope")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.waitlist.RequestAccess(ctx, &pantherclawv1.RequestAccessRequest{RunId: a[0], Note: *note, TransactionId: optStr(*txn)})
			}
		}),
		"access dismiss": rpc("access dismiss ENTRY --reason TEXT", 1, func(fs *flag.FlagSet) call {
			reason := fs.String("reason", "", "why (required)")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.waitlist.DismissAccessRequest(ctx, &pantherclawv1.DismissAccessRequestRequest{Id: a[0], Reason: *reason})
			}
		}),
		"escalation get": rpc("escalation get [--team ID]", 0, func(fs *flag.FlagSet) call {
			team := fs.String("team", "", "a team's chain (default: the org's)")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.waitlist.GetEscalationChain(ctx, &pantherclawv1.GetEscalationChainRequest{TeamId: optStr(*team)})
			}
		}),
		"escalation set": rpc("escalation set --file STEPS.json [--team ID] [--revision N]", 0, func(fs *flag.FlagSet) call {
			file, team := fs.String("file", "", `the steps: {"steps": [{"atPercent": 0, "scope": "ESCALATION_SCOPE_NEAREST"}, ...]}`), fs.String("team", "", "a team's chain (default: the org's)")
			revision := fs.Int("revision", 0, "the revision this replaces (0: whatever is current)")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				var req pantherclawv1.SetEscalationChainRequest
				if err := readMessage("file", *file, &req); err != nil {
					return nil, err
				}
				req.TeamId, req.Revision = optStr(*team), int32(min(max(*revision, 0), 1<<30))
				return c.waitlist.SetEscalationChain(ctx, &req)
			}
		}),
	}
}

// readMessage reads a required JSON document into m (field names as the
// API prints them; unknown fields are refused).
func readMessage(flagName, path string, m proto.Message) error {
	b, err := readDocument(flagName, path)
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return fmt.Errorf("--%s is required", flagName)
	}
	if err := protojson.Unmarshal(b, m); err != nil {
		return fmt.Errorf("--%s: %w", flagName, err)
	}
	return nil
}

// workloadWait waits on a held action's handle (HR-174) with the
// workload's own credentials: once, or with --follow until it is READY or
// ends. An ended hold exits with an error naming its state and code.
func workloadWait(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("workload wait", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	keyFile := fs.String("key-file", "", "enrolled workload key file")
	tokenFile := fs.String("token-file", "", "a workload token to use instead of issuing one")
	run := fs.String("run", "", "the run (default: the key file's)")
	timeout := fs.Int("timeout", 30, "seconds to wait at most per call (1-30)")
	follow := fs.Bool("follow", false, "wait again until the action is READY or the hold ends")
	if len(args) < 1 {
		return errUsage
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	handle, err := ids.ParseUUID(args[0])
	if fs.NArg() != 0 || err != nil || *keyFile == "" {
		return errUsage
	}
	kf, err := workloadclient.ReadKeyFile(*keyFile)
	if err != nil {
		return err
	}
	if *run == "" {
		*run = kf.RunID
	}
	token, err := a.hookToken(ctx, kf, *keyFile, *tokenFile)
	if err != nil {
		return err
	}
	wc, err := a.workloadTokenClient(kf, token)
	if err != nil {
		return err
	}
	known := pantherclawv1.WaitState_WAIT_STATE_UNSPECIFIED
	for {
		res, err := wc.Wait(ctx, &pantherclawv1.WaitRequest{
			RunId: *run, Handle: handle.String(), KnownState: known, TimeoutSeconds: int32(min(max(*timeout, 1), 30)),
		})
		if err != nil {
			return err
		}
		w := res.GetWait()
		if !res.GetTimedOut() || !*follow {
			if err := a.print(w); err != nil {
				return err
			}
		}
		if w.GetState() == pantherclawv1.WaitState_WAIT_STATE_READY {
			return nil
		}
		if w.GetState() != pantherclawv1.WaitState_WAIT_STATE_PENDING && w.GetState() != pantherclawv1.WaitState_WAIT_STATE_EVIDENCE_REQUESTED {
			return fmt.Errorf("the hold ended: %s %s", strings.TrimPrefix(w.GetState().String(), "WAIT_STATE_"), w.GetCode())
		}
		if !*follow {
			return nil
		}
		known = w.GetState()
	}
}

// workloadTokenClient is WorkloadService with the workload's key and token.
func (a *app) workloadTokenClient(kf workloadclient.KeyFile, token string) (pantherclawv1connect.WorkloadServiceClient, error) {
	if kf.Server == "" {
		return nil, errors.New("the key file is not enrolled yet: run pclaw workload enroll")
	}
	return a.workloadClientAt(kf.Server, kf, func() string { return token })
}
