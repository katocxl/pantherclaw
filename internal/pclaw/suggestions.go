// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// pclaw suggestions (G0 M16 D92; F185): list, show, dismiss and draft the
// evidence-backed suggestions made from unused-authority findings. A
// suggestion never changes policy: draft creates a policy DRAFT that only
// the publication gate can publish (HR-442).

type suggestionCall func(ctx context.Context, c pantherclawv1connect.SuggestionServiceClient, args []string) (proto.Message, error)

type suggestionVerb struct {
	usage string
	nargs int
	setup func(fs *flag.FlagSet) suggestionCall
}

var suggestionStates = map[string]pantherclawv1.SuggestionState{
	"open": pantherclawv1.SuggestionState_SUGGESTION_STATE_OPEN, "drafted": pantherclawv1.SuggestionState_SUGGESTION_STATE_DRAFTED,
	"dismissed": pantherclawv1.SuggestionState_SUGGESTION_STATE_DISMISSED, "stale": pantherclawv1.SuggestionState_SUGGESTION_STATE_STALE,
}

var suggestionVerbs = map[string]suggestionVerb{
	"list": {
		"list [--state open|drafted|dismissed|stale]... [--kind unused_authority]", 0,
		func(fs *flag.FlagSet) suggestionCall {
			var states list
			fs.Var(&states, "state", "only this state (repeat)")
			kind := fs.String("kind", "", "only this kind (unused_authority)")
			n, tok := paging(fs)
			return func(ctx context.Context, c pantherclawv1connect.SuggestionServiceClient, _ []string) (proto.Message, error) {
				req := &pantherclawv1.ListSuggestionsRequest{PageSize: size(n), PageToken: *tok}
				for _, s := range states {
					st, ok := suggestionStates[strings.ToLower(s)]
					if !ok {
						return nil, fmt.Errorf("--state %q: want open, drafted, dismissed or stale", s)
					}
					req.States = append(req.States, st)
				}
				switch strings.ToLower(*kind) {
				case "":
				case "unused_authority":
					req.Kind = pantherclawv1.SuggestionKind_SUGGESTION_KIND_UNUSED_AUTHORITY
				default:
					return nil, fmt.Errorf("--kind %q: want unused_authority", *kind)
				}
				return c.ListSuggestions(ctx, req)
			}
		},
	},
	"show": {"show ID", 1, func(*flag.FlagSet) suggestionCall {
		return func(ctx context.Context, c pantherclawv1connect.SuggestionServiceClient, args []string) (proto.Message, error) {
			return c.GetSuggestion(ctx, &pantherclawv1.GetSuggestionRequest{Id: args[0]})
		}
	}},
	"dismiss": {"dismiss ID --reason TEXT", 1, func(fs *flag.FlagSet) suggestionCall {
		reason := fs.String("reason", "", "why (10 to 1000 characters; required)")
		return func(ctx context.Context, c pantherclawv1connect.SuggestionServiceClient, args []string) (proto.Message, error) {
			if n := utf8.RuneCountInString(strings.TrimSpace(*reason)); n < 10 || n > 1000 {
				return nil, errors.New("--reason is required, 10 to 1000 characters")
			}
			return c.DismissSuggestion(ctx, &pantherclawv1.DismissSuggestionRequest{Id: args[0], Reason: *reason})
		}
	}},
	"draft": {"draft ID", 1, func(*flag.FlagSet) suggestionCall {
		return func(ctx context.Context, c pantherclawv1connect.SuggestionServiceClient, args []string) (proto.Message, error) {
			return c.DraftFromSuggestion(ctx, &pantherclawv1.DraftFromSuggestionRequest{Id: args[0]})
		}
	}},
}

func suggestionsUsage() string {
	verbs := []string{"list", "show", "dismiss", "draft"}
	lines := make([]string, 0, len(verbs))
	for _, v := range verbs {
		lines = append(lines, "suggestions "+suggestionVerbs[v].usage)
	}
	return strings.Join(lines, "\n  pclaw ")
}

func init() {
	commands["suggestions"] = command{usage: suggestionsUsage(), run: runSuggestions}
}

func runSuggestions(ctx context.Context, a *app, args []string) error {
	if len(args) == 0 {
		return errUsage
	}
	v, ok := suggestionVerbs[args[0]]
	if !ok || len(args)-1 < v.nargs {
		return errUsage
	}
	args = args[1:]
	fs := flag.NewFlagSet("suggestions "+v.usage, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	fn := v.setup(fs)
	if err := fs.Parse(args[v.nargs:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errUsage
	}
	s, err := a.session()
	if err != nil {
		return err
	}
	res, err := fn(ctx, pantherclawv1connect.NewSuggestionServiceClient(s.connect()), args[:v.nargs])
	if err != nil {
		return err
	}
	if r, ok := res.(*pantherclawv1.DraftFromSuggestionResponse); ok {
		_, _ = fmt.Fprintf(a.stderr, "Drafted policy version %d (%s); it is not published: review and publish it through the policy gate.\n",
			r.GetPolicyVersion(), r.GetPolicyVersionId())
	}
	return a.print(res)
}
