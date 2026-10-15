// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package search

import (
	"context"
	"errors"
	"testing"
	"time"

	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type fakeExposure struct {
	view     ExposureView
	err      error
	resource string
}

func (f *fakeExposure) WhoCanWrite(_ context.Context, rg string, _ *ids.UUID) (ExposureView, error) {
	f.resource = rg
	return f.view, f.err
}

func (f *fakeExposure) Widest(context.Context, int) (ExposureView, error) { return f.view, f.err }

func searchCaller() context.Context {
	org := ids.New[ids.Org]()
	return tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RoleResponder, Scope: td.Scope{Type: td.ScopeTeam, ID: ids.NewV7()}}},
	}})
}

// TestExposureBuiltins: who_can_write and widest_exposure answer from the
// exposure port with its scope, staleness and gaps stated; without the
// port they are not available (never empty), and the exposure port's own
// refusals pass through.
func TestExposureBuiltins(t *testing.T) {
	ctx := searchCaller()
	s := &Service{}
	if _, err := s.RunBuiltin(ctx, BuiltinQuery{Name: BuiltinWidestExposure}, page.Request{Size: 10}); !errors.Is(err, ErrExposureUnavailable) {
		t.Fatalf("nil port: %v", err)
	}
	changed := time.Now().Add(-time.Minute)
	f := &fakeExposure{view: ExposureView{
		Items: []Item{{Entity: "exposure", ID: "r1", Label: "EFFECTIVE/USABLE"}}, Restricted: true,
		ComputedAt: time.Now().Add(-time.Hour), Stale: true, ChangedAt: &changed, Gaps: []string{"credential scope of conn x unknown"},
	}}
	s.Exposure = f
	r, err := s.RunBuiltin(ctx, BuiltinQuery{Name: BuiltinWhoCanWrite, Params: Params{Resource: "repo:acme/*"}}, page.Request{Size: 10})
	if err != nil {
		t.Fatal(err)
	}
	if f.resource != "repo:acme/*" || r.Count != 1 || r.Scope.All || !r.Range.Changing || len(r.Omissions) != 3 {
		t.Fatalf("who_can_write: %+v", r)
	}
	for _, bad := range []BuiltinQuery{
		{Name: BuiltinWhoCanWrite},
		{Name: BuiltinWhoCanWrite, Params: Params{Resource: "a\x00b"}},
		{Name: BuiltinWidestExposure, Params: Params{Days: 3}},
	} {
		if _, err := s.RunBuiltin(ctx, bad, page.Request{Size: 10}); !invalid(err) {
			t.Errorf("%+v accepted: %v", bad, err)
		}
	}
	f.err = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "breach radius needs Team")
	if _, err := s.RunBuiltin(ctx, BuiltinQuery{Name: BuiltinWidestExposure}, page.Request{Size: 10}); !errors.Is(err, f.err) {
		t.Fatalf("edition refusal: %v", err)
	}
	if err := (Spec{Builtin: &BuiltinQuery{Name: BuiltinWhoCanWrite, Params: Params{Resource: "x"}}}).Validate(); err != nil {
		t.Fatalf("saved who_can_write: %v", err)
	}
}
