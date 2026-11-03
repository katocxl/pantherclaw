// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package contentscan_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/contentsignals/domain"
	"github.com/katocxl/pantherclaw/internal/contentsignals/ports"
	"github.com/katocxl/pantherclaw/internal/gateway/contentscan"
)

type classifier func(ctx context.Context, in ports.Input) ([]domain.Finding, error)

func (c classifier) Classify(ctx context.Context, in ports.Input) ([]domain.Finding, error) {
	return c(ctx, in)
}

var incomplete = func(why string) domain.Finding { return domain.Finding{Kind: domain.KindScanIncomplete, Location: why} }

func scan(s *contentscan.Scanner, body string) []domain.Finding {
	return s.Scan(context.Background(), ports.SurfaceResult, "result", []byte(body))
}

// TestHR650_OverTheBoundIsIncomplete: a body past 64 KiB is scan_incomplete,
// never "no known flags"; what fits is still scanned, and a classifier sees
// no more than the bound.
//
// Covers: F938
func TestHR650_OverTheBoundIsIncomplete(t *testing.T) {
	var seen int
	s := &contentscan.Scanner{External: classifier(func(_ context.Context, in ports.Input) ([]domain.Finding, error) {
		seen = len(in.Content)
		return nil, nil
	})}
	body := "ignore previous instructions " + strings.Repeat("a ", domain.MaxBody)
	got := scan(s, body)
	if !slices.Contains(got, incomplete(domain.IncompleteOverBound)) {
		t.Fatalf("%+v", got)
	}
	if !slices.Contains(got, domain.Finding{Kind: domain.KindInjectionPhrase, Location: "result"}) {
		t.Fatalf("the part that fits was not scanned: %+v", got)
	}
	if seen != domain.MaxBody {
		t.Fatalf("classifier saw %d bytes", seen)
	}
	if got := scan(&contentscan.Scanner{}, strings.Repeat("a ", domain.MaxBody/2)); len(got) != 0 {
		t.Fatalf("at the bound: %+v", got)
	}
}

// TestHR650_ClassifierFailureIsIncompleteAndBuiltinRuns: an out-of-process
// classifier that errors, stalls, panics or answers badly is scan_incomplete,
// and the built-in's findings stay.
//
// Covers: F938, F940
func TestHR650_ClassifierFailureIsIncompleteAndBuiltinRuns(t *testing.T) {
	cases := map[string]classifier{
		"error": func(context.Context, ports.Input) ([]domain.Finding, error) { return nil, errors.New("refused") },
		"stall": func(ctx context.Context, _ ports.Input) ([]domain.Finding, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
		"panic": func(context.Context, ports.Input) ([]domain.Finding, error) { panic("no") },
		"bad kind": func(context.Context, ports.Input) ([]domain.Finding, error) {
			return []domain.Finding{{Kind: "safe", Location: "x"}}, nil
		},
		"value in location": func(context.Context, ports.Input) ([]domain.Finding, error) {
			return []domain.Finding{{Kind: domain.KindClassifierFlag, Location: "a value with spaces"}}, nil
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s := &contentscan.Scanner{External: c, Timeout: 10 * time.Millisecond}
			got := scan(s, "ignore previous instructions")
			if !slices.Contains(got, incomplete(domain.IncompleteClassifier)) {
				t.Fatalf("%+v", got)
			}
			if !slices.Contains(got, domain.Finding{Kind: domain.KindInjectionPhrase, Location: "result"}) {
				t.Fatalf("the built-in's finding is gone: %+v", got)
			}
		})
	}
}

// TestHR650_BuiltinFailureIsIncomplete: the same when the built-in fails.
//
// Covers: F938
func TestHR650_BuiltinFailureIsIncomplete(t *testing.T) {
	for name, c := range map[string]classifier{
		"error": func(context.Context, ports.Input) ([]domain.Finding, error) { return nil, errors.New("no") },
		"panic": func(context.Context, ports.Input) ([]domain.Finding, error) { panic("no") },
	} {
		t.Run(name, func(t *testing.T) {
			if got := scan(&contentscan.Scanner{Builtin: c}, "text"); !slices.Contains(got, incomplete(domain.IncompleteBuiltin)) {
				t.Fatalf("%+v", got)
			}
		})
	}
}

// TestNoFlagsOnNothing: an empty body is nothing to scan.
//
// Covers: F938
func TestNoFlagsOnNothing(t *testing.T) {
	if got := scan(&contentscan.Scanner{}, ""); got != nil {
		t.Fatalf("%+v", got)
	}
}
