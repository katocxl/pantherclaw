// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
	"flag"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// Change window commands (G0 M8, HR-207), for a person holding
// release.window.manage: when a release approval for an environment
// counts.

// m8pClients are the clients of G0 M8 track P.
type m8pClients struct {
	windows pantherclawv1connect.ChangeWindowServiceClient
}

func init() {
	for k, v := range windowCommands() {
		commands[k] = v
	}
}

func windowCommands() map[string]command {
	return map[string]command{
		"window create": rpc("window create --environment ENV [--repository OWNER/NAME] --time-zone ZONE "+
			"[--weekly 'DAY HH:MM MINUTES']... [--one-off START/END]... [--freeze START/END]...", 0, func(fs *flag.FlagSet) call {
			env, repo := fs.String("environment", "", "the deployment environment, for example production"),
				fs.String("repository", "", "owner/name, for one repository only")
			zone := fs.String("time-zone", "", "IANA time zone of the weekly entries, for example Europe/London")
			var weekly, oneOff, freezes list
			fs.Var(&weekly, "weekly", "a weekly entry: DAY HH:MM MINUTES, for example 'mon 09:00 480' (repeatable)")
			fs.Var(&oneOff, "one-off", "a one-off window: START/END in RFC 3339 (repeatable)")
			fs.Var(&freezes, "freeze", "a freeze, which overrides every window: START/END in RFC 3339 (repeatable)")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				req := &pb.CreateChangeWindowRequest{Environment: *env, Repository: *repo, TimeZone: *zone}
				for _, w := range weekly {
					e, err := weeklyEntry(w)
					if err != nil {
						return nil, err
					}
					req.Weekly = append(req.Weekly, e)
				}
				var err error
				if req.OneOff, err = timeSpans(oneOff); err != nil {
					return nil, err
				}
				if req.Freezes, err = timeSpans(freezes); err != nil {
					return nil, err
				}
				return c.windows.CreateChangeWindow(ctx, req)
			}
		}),
		"window list": rpc("window list [--environment ENV] [--retired]", 0, func(fs *flag.FlagSet) call {
			env, retired := fs.String("environment", "", "only this environment's windows"), fs.Bool("retired", false, "the retired windows too")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.windows.ListChangeWindows(ctx, &pb.ListChangeWindowsRequest{Environment: *env, IncludeRetired: *retired})
			}
		}),
		"window retire": rpc("window retire ID --reason TEXT", 1, func(fs *flag.FlagSet) call {
			reason := fs.String("reason", "", "why the window is retired")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.windows.RetireChangeWindow(ctx, &pb.RetireChangeWindowRequest{Id: a[0], Reason: *reason})
			}
		}),
		"window active": rpc("window active --environment ENV [--repository OWNER/NAME]", 0, func(fs *flag.FlagSet) call {
			env, repo := fs.String("environment", "", "the deployment environment"), fs.String("repository", "", "owner/name")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.windows.GetActiveWindows(ctx, &pb.GetActiveWindowsRequest{Environment: *env, Repository: *repo})
			}
		}),
	}
}

// weeklyEntry parses DAY HH:MM MINUTES.
func weeklyEntry(s string) (*pb.WeeklyEntry, error) {
	f := strings.Fields(s)
	if len(f) != 3 {
		return nil, errors.New("--weekly: want DAY HH:MM MINUTES, for example 'mon 09:00 480'")
	}
	m, err := strconv.Atoi(f[2])
	if err != nil {
		return nil, errors.New("--weekly: MINUTES must be a number")
	}
	return &pb.WeeklyEntry{Day: strings.ToLower(f[0]), Start: f[1], Minutes: int32(min(max(m, 0), 1<<20))}, nil
}

// timeSpans parses START/END pairs in RFC 3339.
func timeSpans(in []string) ([]*pb.TimeSpan, error) {
	var out []*pb.TimeSpan
	for _, s := range in {
		a, b, ok := strings.Cut(s, "/")
		start, err1 := time.Parse(time.RFC3339, a)
		end, err2 := time.Parse(time.RFC3339, b)
		if !ok || err1 != nil || err2 != nil {
			return nil, errors.New("a span is START/END in RFC 3339, for example 2026-12-21T00:00:00Z/2027-01-04T00:00:00Z")
		}
		out = append(out, &pb.TimeSpan{StartTime: timestamppb.New(start), EndTime: timestamppb.New(end)})
	}
	return out, nil
}
