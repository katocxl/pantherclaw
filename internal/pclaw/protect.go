// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
	"flag"
	"strings"

	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// pclaw protect and pclaw publisher (G0 M11 part 2 D42, D43; HR-292,
// HR-293): protected-change settings and the changes waiting for a
// distinct publisher; compromised publishers, their exposure, its review
// and clearing. Applying a change in an emergency and marking a publisher
// compromised need a security key, so they are done on their pages
// (/protected-changes/{request}/emergency, /publishers/compromise).

type protectCall func(ctx context.Context, c pantherclawv1connect.ProtectedChangeServiceClient, args []string) (proto.Message, error)

type protectVerb struct {
	usage string
	nargs int
	setup func(fs *flag.FlagSet) protectCall
}

var protectVerbs = map[string]protectVerb{
	"settings": {"settings", 0, func(*flag.FlagSet) protectCall {
		return func(ctx context.Context, c pantherclawv1connect.ProtectedChangeServiceClient, _ []string) (proto.Message, error) {
			return c.GetProtectedChangeSettings(ctx, &pantherclawv1.GetProtectedChangeSettingsRequest{})
		}
	}},
	"set": {"set tool_meaning|consequence_rules|custody|coverage_exclusion off|distinct_publisher", 2, func(*flag.FlagSet) protectCall {
		return func(ctx context.Context, c pantherclawv1connect.ProtectedChangeServiceClient, args []string) (proto.Message, error) {
			return c.SetProtectedCategoryMode(ctx, &pantherclawv1.SetProtectedCategoryModeRequest{
				Category: strings.ToUpper(args[0]), Mode: strings.ToUpper(args[1]),
			})
		}
	}},
	"list": {"list [--state pending|applied|emergency|declined|expired|voided] [--category CATEGORY]", 0, func(fs *flag.FlagSet) protectCall {
		state, category := fs.String("state", "", "only this state"), fs.String("category", "", "only this category")
		n, tok := paging(fs)
		return func(ctx context.Context, c pantherclawv1connect.ProtectedChangeServiceClient, _ []string) (proto.Message, error) {
			return c.ListProtectedChanges(ctx, &pantherclawv1.ListProtectedChangesRequest{
				State: strings.ToUpper(*state), Category: strings.ToUpper(*category), PageSize: size(n), PageToken: *tok,
			})
		}
	}},
}

type publisherCall func(ctx context.Context, c pantherclawv1connect.PublisherServiceClient, args []string) (proto.Message, error)

type publisherVerb struct {
	usage string
	nargs int
	setup func(fs *flag.FlagSet) publisherCall
}

var publisherVerbs = map[string]publisherVerb{
	"list": {"list [--active]", 0, func(fs *flag.FlagSet) publisherCall {
		active := fs.Bool("active", false, "only marks not yet cleared")
		return func(ctx context.Context, c pantherclawv1connect.PublisherServiceClient, _ []string) (proto.Message, error) {
			return c.ListCompromises(ctx, &pantherclawv1.ListCompromisesRequest{ActiveOnly: *active})
		}
	}},
	"exposed": {"exposed COMPROMISE_ID", 1, func(*flag.FlagSet) publisherCall {
		return func(ctx context.Context, c pantherclawv1connect.PublisherServiceClient, args []string) (proto.Message, error) {
			return c.ListExposed(ctx, &pantherclawv1.ListExposedRequest{CompromiseId: args[0]})
		}
	}},
	"review": {"review COMPROMISE_ID KIND ITEM_ID keep|rollback [--note TEXT]", 4, func(fs *flag.FlagSet) publisherCall {
		note := fs.String("note", "", "why (at most 500 characters)")
		return func(ctx context.Context, c pantherclawv1connect.PublisherServiceClient, args []string) (proto.Message, error) {
			decision := strings.ToUpper(args[3])
			if decision != "KEEP" && decision != "ROLLBACK" {
				return nil, errors.New("the decision is keep or rollback")
			}
			return c.ReviewExposed(ctx, &pantherclawv1.ReviewExposedRequest{
				CompromiseId: args[0], Kind: strings.ToUpper(args[1]), ItemId: args[2], Decision: decision, Note: *note,
			})
		}
	}},
	"clear": {"clear COMPROMISE_ID", 1, func(*flag.FlagSet) publisherCall {
		return func(ctx context.Context, c pantherclawv1connect.PublisherServiceClient, args []string) (proto.Message, error) {
			return c.ClearCompromise(ctx, &pantherclawv1.ClearCompromiseRequest{CompromiseId: args[0]})
		}
	}},
}

func protectUsage() string {
	lines := []string{}
	for _, v := range []string{"settings", "set", "list"} {
		lines = append(lines, "protect "+protectVerbs[v].usage)
	}
	return strings.Join(lines, "\n  pclaw ")
}

func publisherUsage() string {
	lines := []string{}
	for _, v := range []string{"list", "exposed", "review", "clear"} {
		lines = append(lines, "publisher "+publisherVerbs[v].usage)
	}
	return strings.Join(lines, "\n  pclaw ")
}

func init() {
	commands["protect"] = command{usage: protectUsage(), run: runProtect}
	commands["publisher"] = command{usage: publisherUsage(), run: runPublisher}
}

// verbArgs parses a verb's flags after its positional arguments.
func verbArgs(a *app, nargs int, args []string, fs *flag.FlagSet) ([]string, error) {
	if len(args) < nargs {
		return nil, errUsage
	}
	fs.SetOutput(a.stderr)
	if err := fs.Parse(args[nargs:]); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, errUsage
	}
	return args[:nargs], nil
}

func runProtect(ctx context.Context, a *app, args []string) error {
	if len(args) == 0 {
		return errUsage
	}
	v, ok := protectVerbs[args[0]]
	if !ok {
		return errUsage
	}
	fs := flag.NewFlagSet("protect "+v.usage, flag.ContinueOnError)
	fn := v.setup(fs)
	pos, err := verbArgs(a, v.nargs, args[1:], fs)
	if err != nil {
		return err
	}
	s, err := a.session()
	if err != nil {
		return err
	}
	res, err := fn(ctx, pantherclawv1connect.NewProtectedChangeServiceClient(s.connect()), pos)
	if err != nil {
		return err
	}
	return a.print(res)
}

func runPublisher(ctx context.Context, a *app, args []string) error {
	if len(args) == 0 {
		return errUsage
	}
	v, ok := publisherVerbs[args[0]]
	if !ok {
		return errUsage
	}
	fs := flag.NewFlagSet("publisher "+v.usage, flag.ContinueOnError)
	fn := v.setup(fs)
	pos, err := verbArgs(a, v.nargs, args[1:], fs)
	if err != nil {
		return err
	}
	s, err := a.session()
	if err != nil {
		return err
	}
	res, err := fn(ctx, pantherclawv1connect.NewPublisherServiceClient(s.connect()), pos)
	if err != nil {
		return err
	}
	return a.print(res)
}
