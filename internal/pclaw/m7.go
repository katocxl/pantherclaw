// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// M7 track A commands: transactions and their evidence, and reconciliation.
// "Did not occur" is released only on the reconciliation's page with a
// security key (G0 M7 decision 2), never from the command line.

func init() {
	for k, v := range m7Commands() {
		commands[k] = v
	}
}

// m7Clients are the M7 track A service clients.
type m7Clients struct {
	transactions    pantherclawv1connect.TransactionServiceClient
	reconciliations pantherclawv1connect.ReconciliationServiceClient
	// evidence serves the M7 track B commands (pclaw pack).
	evidence pantherclawv1connect.EvidenceServiceClient
}

// enumOf maps a lower-case flag value to the proto enum value
// PREFIX_VALUE, refusing unknown and unspecified values.
func enumOf[T ~int32](values map[string]int32, prefix, flagName, v string) (T, error) {
	n, ok := values[prefix+strings.ToUpper(v)]
	if !ok || n == 0 {
		return 0, fmt.Errorf("--%s: unknown value %q", flagName, v)
	}
	return T(n), nil
}

// enumsOf maps repeated flag values with enumOf.
func enumsOf[T ~int32](values map[string]int32, prefix, flagName string, vs []string) ([]T, error) {
	var out []T
	for _, v := range vs {
		e, err := enumOf[T](values, prefix, flagName, v)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// sinceOf parses an RFC 3339 time or a duration before now ("24h"); empty
// is unset.
func sinceOf(flagName, s string) (*timestamppb.Timestamp, error) {
	if s == "" {
		return nil, nil //nolint:nilnil // unset
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return timestamppb.New(time.Now().Add(-d)), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil, fmt.Errorf("--%s must be a duration such as 24h or an RFC 3339 time", flagName)
	}
	return timestamppb.New(t), nil
}

func m7Commands() map[string]command {
	return map[string]command{
		"txn list": rpc("txn list [--run ID] [--agent ID] [--connection ID] [--decision D]... [--execution S]... "+
			"[--effect S]... [--since 24h|TIME] [--until TIME]", 0, func(fs *flag.FlagSet) call {
			var run, agent, conn optional
			fs.Var(&run, "run", "only this run's")
			fs.Var(&agent, "agent", "only this agent's")
			fs.Var(&conn, "connection", "only through this connection")
			var decisions, executions, effects list
			fs.Var(&decisions, "decision", "allow, deny, require_approval, ... (repeatable)")
			fs.Var(&executions, "execution", "requested, blocked, waiting, authorized, dispatched, accepted, failed, cancelled (repeatable)") //nolint:misspell // the state's name
			fs.Var(&effects, "effect", "confirmed, none_confirmed, partial, propagation_pending, conflicting, unverifiable, unknown, compensated (repeatable)")
			since, until := fs.String("since", "", "created at or after (a duration before now, or RFC 3339)"),
				fs.String("until", "", "created before (RFC 3339)")
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				req := &pantherclawv1.ListTransactionsRequest{
					PageSize: size(n), PageToken: *tok, RunId: run.ptr(), AgentId: agent.ptr(), ConnectionId: conn.ptr(),
				}
				var err error
				if req.Decisions, err = enumsOf[pantherclawv1.Decision](pantherclawv1.Decision_value, "DECISION_", "decision", decisions); err != nil {
					return nil, err
				}
				if req.ExecutionStates, err = enumsOf[pantherclawv1.ExecutionState](pantherclawv1.ExecutionState_value, "EXECUTION_STATE_", "execution", executions); err != nil {
					return nil, err
				}
				if req.EffectStates, err = enumsOf[pantherclawv1.EffectState](pantherclawv1.EffectState_value, "EFFECT_STATE_", "effect", effects); err != nil {
					return nil, err
				}
				if req.StartTime, err = sinceOf("since", *since); err != nil {
					return nil, err
				}
				if req.EndTime, err = sinceOf("until", *until); err != nil {
					return nil, err
				}
				return c.transactions.ListTransactions(ctx, req)
			}
		}),
		"txn show": rpc("txn show ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.transactions.GetTransactionEvidence(ctx, &pantherclawv1.GetTransactionEvidenceRequest{Id: a[0]})
			}
		}),
		"reconcile list": rpc("reconcile list [--state open|occurred|not_occurred]... [--kind unknown_outcome|conflicting_effect]... "+
			"[--transaction ID]", 0, func(fs *flag.FlagSet) call {
			var states, kinds list
			fs.Var(&states, "state", "open, occurred or not_occurred (repeatable)")
			fs.Var(&kinds, "kind", "unknown_outcome or conflicting_effect (repeatable)")
			var txn optional
			fs.Var(&txn, "transaction", "only this transaction's")
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				req := &pantherclawv1.ListReconciliationsRequest{PageSize: size(n), PageToken: *tok, TransactionId: txn.ptr()}
				var err error
				if req.States, err = enumsOf[pantherclawv1.ReconciliationState](pantherclawv1.ReconciliationState_value, "RECONCILIATION_STATE_", "state", states); err != nil {
					return nil, err
				}
				if req.Kinds, err = enumsOf[pantherclawv1.ReconciliationKind](pantherclawv1.ReconciliationKind_value, "RECONCILIATION_KIND_", "kind", kinds); err != nil {
					return nil, err
				}
				return c.reconciliations.ListReconciliations(ctx, req)
			}
		}),
		"reconcile show": rpc("reconcile show ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.reconciliations.GetReconciliation(ctx, &pantherclawv1.GetReconciliationRequest{Id: a[0]})
			}
		}),
		// "occurred" only commits held budget, the safe direction; releasing
		// ("did not occur") is on the reconciliation's page.
		"reconcile occurred": rpc("reconcile occurred ID --basis TEXT [--evidence OBSERVATION]... [--authoritative OBSERVATION]", 1,
			func(fs *flag.FlagSet) call {
				basis := fs.String("basis", "", "what you checked (recorded; required)")
				var evidence list
				fs.Var(&evidence, "evidence", "an observation you relied on (repeatable)")
				var authoritative optional
				fs.Var(&authoritative, "authoritative", "the observation you found authoritative, one of --evidence")
				return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
					if *basis == "" {
						return nil, fmt.Errorf("--basis is required: say what you checked")
					}
					return c.reconciliations.ResolveOccurred(ctx, &pantherclawv1.ResolveOccurredRequest{
						Id: a[0], Basis: *basis, Evidence: evidence, ObservationId: authoritative.ptr(),
					})
				}
			}),
		"reconcile verify": rpc("reconcile verify TRANSACTION", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.reconciliations.RequestVerification(ctx, &pantherclawv1.RequestVerificationRequest{TransactionId: a[0]})
			}
		}),
		"reconcile link": rpc("reconcile link LATER EARLIER --kind compensates|recovers", 2, func(fs *flag.FlagSet) call {
			kind := fs.String("kind", "", "compensates or recovers (required)")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				k, err := enumOf[pantherclawv1.LinkKind](pantherclawv1.LinkKind_value, "LINK_KIND_", "kind", *kind)
				if err != nil {
					return nil, err
				}
				return c.reconciliations.LinkTransaction(ctx, &pantherclawv1.LinkTransactionRequest{
					FromTransactionId: a[0], ToTransactionId: a[1], Kind: k,
				})
			}
		}),
	}
}
