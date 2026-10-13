// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
	"flag"

	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// pclaw retention get|set and pclaw hold create|list|release (G0 M7
// design decision 9, HR-198): what evidence the org keeps. A person holding
// evidence.retention.manage (the Records Manager) runs them; a shorter
// period takes effect 7 days after it is set.

func init() {
	for k, v := range retentionCommands() {
		commands[k] = v
	}
}

// adminCall is one EvidenceAdminService call.
type adminCall func(ctx context.Context, c pantherclawv1connect.EvidenceAdminServiceClient, args []string) (proto.Message, error)

// adminRPC is rpc for EvidenceAdminService.
func adminRPC(usage string, nargs int, setup func(fs *flag.FlagSet) adminCall) command {
	return command{usage: usage, run: func(ctx context.Context, a *app, args []string) error {
		if len(args) < nargs {
			return errUsage
		}
		fs := flag.NewFlagSet(usage, flag.ContinueOnError)
		fs.SetOutput(a.stderr)
		fn := setup(fs)
		if err := fs.Parse(args[nargs:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errUsage
		}
		s, err := a.session()
		if err != nil {
			return err
		}
		res, err := fn(ctx, pantherclawv1connect.NewEvidenceAdminServiceClient(s.connect()), args[:nargs])
		if err != nil {
			return err
		}
		return a.print(res)
	}}
}

func retentionCommands() map[string]command {
	return map[string]command{
		"retention get": adminRPC("retention get", 0, func(*flag.FlagSet) adminCall {
			return func(ctx context.Context, c pantherclawv1connect.EvidenceAdminServiceClient, _ []string) (proto.Message, error) {
				return c.GetRetentionPolicies(ctx, &pantherclawv1.GetRetentionPoliciesRequest{})
			}
		}),
		"retention set": adminRPC("retention set CATEGORY --days N   (payloads|normalized_facts|receipts|approvals|security_audit; "+
			"a shorter period takes effect 7 days later)", 1, func(fs *flag.FlagSet) adminCall {
			days := fs.Int("days", 0, "days a body is kept, within the category's bounds (required)")
			return func(ctx context.Context, c pantherclawv1connect.EvidenceAdminServiceClient, a []string) (proto.Message, error) {
				cat, err := enumOf[pantherclawv1.RetentionCategory](pantherclawv1.RetentionCategory_value, "RETENTION_CATEGORY_", "category", a[0])
				if err != nil {
					return nil, err
				}
				if *days < 1 || *days > 3650 {
					return nil, errors.New("--days must be 1..3650 and within the category's bounds")
				}
				return c.SetRetentionPolicy(ctx, &pantherclawv1.SetRetentionPolicyRequest{Category: cat, Days: int32(*days)})
			}
		}),
		"hold create": adminRPC("hold create --scope org|agent|run|transaction|time_range [--id ID] [--start TIME --end TIME] "+
			"--reason TEXT", 0, func(fs *flag.FlagSet) adminCall {
			scope := fs.String("scope", "", "org, agent, run, transaction or time_range (required)")
			var id optional
			fs.Var(&id, "id", "the agent, run or transaction to hold")
			start, end := fs.String("start", "", "a time range's start (inclusive): RFC 3339, or a duration before now such as 720h"),
				fs.String("end", "", "a time range's end (exclusive): RFC 3339, or a duration from now such as 48h")
			reason := fs.String("reason", "", "why (recorded; required)")
			return func(ctx context.Context, c pantherclawv1connect.EvidenceAdminServiceClient, _ []string) (proto.Message, error) {
				s, err := enumOf[pantherclawv1.LegalHoldScope](pantherclawv1.LegalHoldScope_value, "LEGAL_HOLD_SCOPE_", "scope", *scope)
				if err != nil {
					return nil, err
				}
				if *reason == "" {
					return nil, errors.New("--reason is required: say why the evidence must be kept")
				}
				req := &pantherclawv1.CreateLegalHoldRequest{Scope: s, ScopeId: id.ptr(), Reason: *reason}
				if req.StartTime, err = sinceOf("start", *start); err != nil {
					return nil, err
				}
				if req.EndTime, err = timeOf("end", *end); err != nil {
					return nil, err
				}
				return c.CreateLegalHold(ctx, req)
			}
		}),
		"hold list": adminRPC("hold list [--state active|released]", 0, func(fs *flag.FlagSet) adminCall {
			state := fs.String("state", "", "active or released (default: both)")
			n, tok := paging(fs)
			return func(ctx context.Context, c pantherclawv1connect.EvidenceAdminServiceClient, _ []string) (proto.Message, error) {
				req := &pantherclawv1.ListLegalHoldsRequest{PageSize: size(n), PageToken: *tok}
				if *state != "" {
					st, err := enumOf[pantherclawv1.LegalHoldState](pantherclawv1.LegalHoldState_value, "LEGAL_HOLD_STATE_", "state", *state)
					if err != nil {
						return nil, err
					}
					req.State = st
				}
				return c.ListLegalHolds(ctx, req)
			}
		}),
		"hold release": adminRPC("hold release ID --reason TEXT", 1, func(fs *flag.FlagSet) adminCall {
			reason := fs.String("reason", "", "why (recorded; required)")
			return func(ctx context.Context, c pantherclawv1connect.EvidenceAdminServiceClient, a []string) (proto.Message, error) {
				if *reason == "" {
					return nil, errors.New("--reason is required: say why the hold ends")
				}
				return c.ReleaseLegalHold(ctx, &pantherclawv1.ReleaseLegalHoldRequest{Id: a[0], Reason: *reason})
			}
		}),
	}
}
