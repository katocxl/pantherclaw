// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// Automation trigger commands (G0 M11 part 2 D16–D23, D53, D59): preview a
// schedule, start or retry an automation by hand, read its trigger
// records, and manage inbound event sources and automation destinations.
// Activating a source or destination, rotating its secret, and starting a
// version that requires it need a security key: the commands print the
// page where a person does that.

func init() {
	commands["automation trigger"] = group("automation trigger", automationTriggerCommands())
	commands["automation source"] = group("automation source", automationSourceCommands())
	commands["automation destination"] = group("automation destination", automationDestinationCommands())
}

// triggerCall is one TriggerService call.
type triggerCall func(ctx context.Context, c pantherclawv1connect.TriggerServiceClient, args []string) (proto.Message, error)

// triggerRPC builds a command on TriggerService with nargs positional
// arguments before any flags.
func triggerRPC(usage string, nargs int, setup func(fs *flag.FlagSet) triggerCall) command {
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
		res, err := fn(ctx, pantherclawv1connect.NewTriggerServiceClient(s.connect()), args[:nargs])
		if err != nil {
			return stepUpHint(a, err)
		}
		return a.print(res)
	}}
}

// stepUpHint explains a STEP_UP_REQUIRED refusal: the page does it.
func stepUpHint(a *app, err error) error {
	if strings.Contains(err.Error(), "STEP_UP_REQUIRED") || strings.Contains(err.Error(), "security key") {
		_, _ = fmt.Fprintln(a.stderr, "this needs your security key: open the confirm_url shown by `get` (or the automation's start page) in a browser")
	}
	return err
}

// keyValues is a repeatable name=value flag.
type keyValues map[string]string

func (k keyValues) String() string { return "" }

func (k keyValues) Set(v string) error {
	name, value, ok := strings.Cut(v, "=")
	if !ok || name == "" {
		return fmt.Errorf("want name=value, got %q", v)
	}
	k[name] = value
	return nil
}

func newIdempotencyKey() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func automationTriggerCommands() map[string]command {
	return map[string]command{
		"preview": triggerRPC("automation trigger preview CRON TIMEZONE [--shift] [--count N] [--from RFC3339]", 2, func(fs *flag.FlagSet) triggerCall {
			shift := fs.Bool("shift", false, "times inside a spring-forward gap fire at its end (default: skipped)")
			count := fs.Int("count", 10, "occurrences to show (1 to 50)")
			from := fs.String("from", "", "start after this time (default now)")
			return func(ctx context.Context, c pantherclawv1connect.TriggerServiceClient, a []string) (proto.Message, error) {
				req := &pantherclawv1.PreviewScheduleRequest{Cron: a[0], Timezone: a[1], Count: int32(*count)} //nolint:gosec // validated ≤ 50
				if *shift {
					req.DstGap = "SHIFT"
				}
				if *from != "" {
					t, err := time.Parse(time.RFC3339, *from)
					if err != nil {
						return nil, fmt.Errorf("--from: %w", err)
					}
					req.From = timestamppb.New(t)
				}
				return c.PreviewSchedule(ctx, req)
			}
		}),
		"start": triggerRPC("automation trigger start AUTOMATION_ID [--param NAME=VALUE]... [--idempotency-key KEY]", 1, func(fs *flag.FlagSet) triggerCall {
			params := keyValues{}
			fs.Var(params, "param", "a declared parameter (repeatable)")
			key := fs.String("idempotency-key", "", "one start per key (default: a new key)")
			return func(ctx context.Context, c pantherclawv1connect.TriggerServiceClient, a []string) (proto.Message, error) {
				k := *key
				if k == "" {
					k = newIdempotencyKey()
				}
				return c.StartExecution(ctx, &pantherclawv1.StartExecutionRequest{AutomationId: a[0], Params: params, IdempotencyKey: k})
			}
		}),
		"retry": triggerRPC("automation trigger retry EXECUTION_ID [--idempotency-key KEY]", 1, func(fs *flag.FlagSet) triggerCall {
			key := fs.String("idempotency-key", "", "one retry per key (default: a new key)")
			return func(ctx context.Context, c pantherclawv1connect.TriggerServiceClient, a []string) (proto.Message, error) {
				k := *key
				if k == "" {
					k = newIdempotencyKey()
				}
				return c.RetryExecution(ctx, &pantherclawv1.RetryExecutionRequest{ExecutionId: a[0], IdempotencyKey: k})
			}
		}),
		"list": triggerRPC("automation trigger list AUTOMATION_ID [--state STATE] [--page-size N] [--page-token T]", 1, func(fs *flag.FlagSet) triggerCall {
			state := fs.String("state", "", "only this state (ACCEPTED, REFUSED_DUPLICATE, …)")
			size := fs.Int("page-size", 50, "at most this many (1 to 200)")
			token := fs.String("page-token", "", "from a previous answer")
			return func(ctx context.Context, c pantherclawv1connect.TriggerServiceClient, a []string) (proto.Message, error) {
				return c.ListTriggers(ctx, &pantherclawv1.ListTriggersRequest{
					AutomationId: a[0], State: *state, PageSize: int32(*size), PageToken: *token, //nolint:gosec // validated ≤ 200
				})
			}
		}),
		"get": triggerRPC("automation trigger get TRIGGER_ID", 1, func(*flag.FlagSet) triggerCall {
			return func(ctx context.Context, c pantherclawv1connect.TriggerServiceClient, a []string) (proto.Message, error) {
				return c.GetTrigger(ctx, &pantherclawv1.GetTriggerRequest{Id: a[0]})
			}
		}),
	}
}

func automationSourceCommands() map[string]command {
	byID := func(usage string, fn func(ctx context.Context, c pantherclawv1connect.TriggerServiceClient, id string) (proto.Message, error)) command {
		return triggerRPC(usage, 1, func(*flag.FlagSet) triggerCall {
			return func(ctx context.Context, c pantherclawv1connect.TriggerServiceClient, a []string) (proto.Message, error) {
				return fn(ctx, c, a[0])
			}
		})
	}
	return map[string]command{
		"create": triggerRPC("automation source create NAME --type TYPE [--type TYPE]... [--description TEXT] [--rate N]", 1, func(fs *flag.FlagSet) triggerCall {
			var types list
			fs.Var(&types, "type", "an event type it may send (repeatable)")
			desc := fs.String("description", "", "what it is for")
			rate := fs.Int("rate", 0, "requests a minute (1 to 600, default 60)")
			return func(ctx context.Context, c pantherclawv1connect.TriggerServiceClient, a []string) (proto.Message, error) {
				return c.CreateEventSource(ctx, &pantherclawv1.CreateEventSourceRequest{
					Name: a[0], Description: *desc, Types: types, RatePerMinute: int32(*rate), //nolint:gosec // validated ≤ 600
				})
			}
		}),
		"activate": byID("automation source activate SOURCE_ID (needs your security key: use the confirm page)", func(ctx context.Context, c pantherclawv1connect.TriggerServiceClient, id string) (proto.Message, error) {
			return c.ActivateEventSource(ctx, &pantherclawv1.ActivateEventSourceRequest{Id: id})
		}),
		"rotate": byID("automation source rotate SOURCE_ID (needs your security key: use the confirm page)", func(ctx context.Context, c pantherclawv1connect.TriggerServiceClient, id string) (proto.Message, error) {
			return c.RotateEventSourceSecret(ctx, &pantherclawv1.RotateEventSourceSecretRequest{Id: id})
		}),
		"disable": byID("automation source disable SOURCE_ID", func(ctx context.Context, c pantherclawv1connect.TriggerServiceClient, id string) (proto.Message, error) {
			return c.DisableEventSource(ctx, &pantherclawv1.DisableEventSourceRequest{Id: id})
		}),
		"get": byID("automation source get SOURCE_ID", func(ctx context.Context, c pantherclawv1connect.TriggerServiceClient, id string) (proto.Message, error) {
			return c.GetEventSource(ctx, &pantherclawv1.GetEventSourceRequest{Id: id})
		}),
		"list": triggerRPC("automation source list", 0, func(*flag.FlagSet) triggerCall {
			return func(ctx context.Context, c pantherclawv1connect.TriggerServiceClient, _ []string) (proto.Message, error) {
				return c.ListEventSources(ctx, &pantherclawv1.ListEventSourcesRequest{})
			}
		}),
	}
}

func automationDestinationCommands() map[string]command {
	byID := func(usage string, fn func(ctx context.Context, c pantherclawv1connect.TriggerServiceClient, id string) (proto.Message, error)) command {
		return triggerRPC(usage, 1, func(*flag.FlagSet) triggerCall {
			return func(ctx context.Context, c pantherclawv1connect.TriggerServiceClient, a []string) (proto.Message, error) {
				return fn(ctx, c, a[0])
			}
		})
	}
	state := func(verb, to string) command {
		return byID("automation destination "+verb+" DESTINATION_ID", func(ctx context.Context, c pantherclawv1connect.TriggerServiceClient, id string) (proto.Message, error) {
			return c.SetAutomationDestinationState(ctx, &pantherclawv1.SetAutomationDestinationStateRequest{Id: id, State: to})
		})
	}
	return map[string]command{
		"create": triggerRPC("automation destination create NAME URL --purpose LAUNCH|DIGEST|NOTICE [--purpose ...] [--internal]", 2, func(fs *flag.FlagSet) triggerCall {
			var purposes list
			fs.Var(&purposes, "purpose", "what it receives (repeatable)")
			internal := fs.Bool("internal", false, "allow a private or loopback address")
			return func(ctx context.Context, c pantherclawv1connect.TriggerServiceClient, a []string) (proto.Message, error) {
				return c.CreateAutomationDestination(ctx, &pantherclawv1.CreateAutomationDestinationRequest{
					Name: a[0], Url: a[1], Internal: *internal, Purposes: purposes,
				})
			}
		}),
		"activate": byID("automation destination activate DESTINATION_ID (needs your security key: use the confirm page)", func(ctx context.Context, c pantherclawv1connect.TriggerServiceClient, id string) (proto.Message, error) {
			return c.ActivateAutomationDestination(ctx, &pantherclawv1.ActivateAutomationDestinationRequest{Id: id})
		}),
		"rotate": byID("automation destination rotate DESTINATION_ID (needs your security key: use the confirm page)", func(ctx context.Context, c pantherclawv1connect.TriggerServiceClient, id string) (proto.Message, error) {
			return c.RotateAutomationDestinationSecret(ctx, &pantherclawv1.RotateAutomationDestinationSecretRequest{Id: id})
		}),
		"pause":   state("pause", "PAUSED"),
		"resume":  state("resume", "ACTIVE"),
		"disable": state("disable", "DISABLED"),
		"get": byID("automation destination get DESTINATION_ID", func(ctx context.Context, c pantherclawv1connect.TriggerServiceClient, id string) (proto.Message, error) {
			return c.GetAutomationDestination(ctx, &pantherclawv1.GetAutomationDestinationRequest{Id: id})
		}),
		"list": triggerRPC("automation destination list", 0, func(*flag.FlagSet) triggerCall {
			return func(ctx context.Context, c pantherclawv1connect.TriggerServiceClient, _ []string) (proto.Message, error) {
				return c.ListAutomationDestinations(ctx, &pantherclawv1.ListAutomationDestinationsRequest{})
			}
		}),
	}
}
