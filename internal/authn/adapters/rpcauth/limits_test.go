// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package rpcauth_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/rpcauth"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/ratelimit"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// keyAuthn authenticates each bearer as its own API key of one service
// account of org, or of other for bearers starting "other".
type keyAuthn struct {
	org, other ids.OrgID
	sa         ids.UUID
	keys       map[string]ids.UUID
}

func (k keyAuthn) Authenticate(_ context.Context, bearer string) (tapp.Caller, error) {
	cred := tapp.CredAPIKey
	if base, ok := strings.CutSuffix(bearer, "-token"); ok {
		// An access token of the same service-account key.
		bearer, cred = base, tapp.CredAccessToken
	}
	id, ok := k.keys[bearer]
	if !ok {
		return tapp.Caller{}, pcerr.New(pcerr.Unauthenticated, "UNAUTHENTICATED", "invalid or expired credentials")
	}
	org := k.org
	if strings.HasPrefix(bearer, "other") {
		org = k.other
	}
	return tapp.Caller{Subject: td.Subject{
		Org: org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: k.sa},
		Bindings: []td.Binding{{Role: td.RoleViewer, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}},
	}, Credential: cred, CredentialID: id}, nil
}

// limitServer serves AccessService with perms under limits, and returns a
// function making one raw Connect call with a bearer: its HTTP status and
// Retry-After.
func limitServer(t *testing.T, perms map[string]td.Permission, gw rpc.Authenticator, limits rpcauth.APILimits,
	gate rpcauth.PlanGate,
) func(proc, bearer string) (int, string) {
	t.Helper()
	a := keyAuthn{org: ids.New[ids.Org](), other: ids.New[ids.Org](), sa: ids.NewV7(), keys: map[string]ids.UUID{}}
	for _, k := range []string{"key-a", "key-b", "key-c", "other-a"} {
		a.keys[k] = ids.NewV7()
	}
	opts := []rpcauth.Option{rpcauth.WithAPILimits(limits)}
	if gate != nil {
		opts = append(opts, rpcauth.WithPlanGate(gate))
	}
	s, err := rpc.NewServer(rpc.Options{Authenticate: rpcauth.New(a, perms, gw, opts...)})
	if err != nil {
		t.Fatal(err)
	}
	pantherclawv1connect.RegisterAccessServiceHandler(s, fakeAccess{})
	mux := http.NewServeMux()
	rpc.Mount(mux, s)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return func(proc, bearer string) (int, string) {
		req, err := http.NewRequest(http.MethodPost, ts.URL+proc, strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+bearer)
		res, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if res.StatusCode == http.StatusTooManyRequests && !strings.Contains(string(body), "RATE_LIMITED") {
			t.Fatalf("429 without RATE_LIMITED: %s", body)
		}
		return res.StatusCode, res.Header.Get("Retry-After")
	}
}

// TestHR375_APICallsAreLimitedPerCredentialAndOrg: a credential past its
// limit a minute gets RESOURCE_EXHAUSTED RATE_LIMITED with Retry-After;
// another credential of the org still works until the org's limit; another
// org is never affected; a new window starts afresh.
func TestHR375_APICallsAreLimitedPerCredentialAndOrg(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 21, 12, 0, 15, 0, time.UTC))
	perms := map[string]td.Permission{pantherclawv1connect.AccessServiceWhoAmIProcedure: td.PermAuthenticated}
	call := limitServer(t, perms, nil, rpcauth.APILimits{PerOrg: 5, PerCredential: 3, Limiter: ratelimit.NewMemory(clk)}, nil)
	who := pantherclawv1connect.AccessServiceWhoAmIProcedure
	for i := range 3 {
		if st, _ := call(who, "key-a"); st != http.StatusOK {
			t.Fatalf("call %d of key-a: %d", i+1, st)
		}
	}
	st, retry := call(who, "key-a")
	if st != http.StatusTooManyRequests {
		t.Fatalf("key-a past its limit: %d", st)
	}
	if n, err := strconv.Atoi(retry); err != nil || n != 45 {
		t.Fatalf("Retry-After = %q, want 45 (the rest of the minute)", retry)
	}
	// key-a's refusal used nothing of the org: key-b gets the org's two
	// remaining calls, then the org's limit refuses every credential.
	for i := range 2 {
		if st, _ := call(who, "key-b"); st != http.StatusOK {
			t.Fatalf("call %d of key-b: %d", i+1, st)
		}
	}
	if st, retry := call(who, "key-c"); st != http.StatusTooManyRequests || retry == "" {
		t.Fatalf("the org past its limit: %d %q", st, retry)
	}
	if st, _ := call(who, "other-a"); st != http.StatusOK {
		t.Fatalf("another org: %d", st)
	}
	clk.Advance(time.Minute)
	if st, _ := call(who, "key-a"); st != http.StatusOK {
		t.Fatalf("a new minute: %d", st)
	}
}

// TestHR375_EnforcementIsNeverRateLimited: gateway, workload and gateway
// enrollment procedures return before the API limits, however many calls
// are made (HR-357); a refused permission is not counted; the limit runs
// before the plan gate.
func TestHR375_EnforcementIsNeverRateLimited(t *testing.T) {
	limits := rpcauth.APILimits{PerOrg: 1, PerCredential: 1, Limiter: ratelimit.NewMemory(nil)}
	who := pantherclawv1connect.AccessServiceWhoAmIProcedure
	for _, perm := range []td.Permission{td.PermGatewayAuthorize, td.PermGatewayEnroll, td.PermWorkloadToken} {
		if !perm.Gateway() && !perm.Workload() && perm != td.PermGatewayEnroll {
			t.Fatalf("%s is not an enforcement permission", perm)
		}
		gw := func(ctx context.Context, _ *connect.CallInfo, _ connect.Spec) (context.Context, error) {
			return ctx, nil
		}
		call := limitServer(t, map[string]td.Permission{who: perm}, gw, limits, nil)
		for i := range 20 {
			// The fake handler refuses without a caller (401): never 429.
			if st, _ := call(who, "key-a"); st == http.StatusTooManyRequests {
				t.Fatalf("%s: call %d rate-limited", perm, i+1)
			}
		}
	}
	// A refused permission is not counted.
	list := pantherclawv1connect.AccessServiceListUsersProcedure
	gated := 0
	gate := func(context.Context, tapp.Caller, string) error { gated++; return nil }
	call := limitServer(t, map[string]td.Permission{list: td.PermUserRead, who: td.PermAuthenticated}, nil, limits, gate)
	for range 3 {
		if st, _ := call(list, "key-a"); st != http.StatusForbidden {
			t.Fatalf("user.read refused: %d", st)
		}
	}
	if st, _ := call(who, "key-a"); st != http.StatusOK || gated != 1 {
		t.Fatalf("first permitted call: %d, gated %d", st, gated)
	}
	// Over the limit, the plan gate is never asked.
	if st, _ := call(who, "key-a"); st != http.StatusTooManyRequests || gated != 1 {
		t.Fatalf("past the limit: %d, gated %d", st, gated)
	}
}

// TestT170_AFloodingCredentialIsContained: a compromised API key flooding
// the management API is refused past its own limit and cannot use up its
// org's, so the org's other credentials keep working (HR-375).
func TestT170_AFloodingCredentialIsContained(t *testing.T) {
	// A stopped clock: 500 calls on a loaded runner can span two windows, and
	// the count below is of one.
	stopped := clock.NewFake(time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC))
	limits := rpcauth.APILimits{PerOrg: 60, PerCredential: 12, Limiter: ratelimit.NewMemory(stopped)}
	who := pantherclawv1connect.AccessServiceWhoAmIProcedure
	call := limitServer(t, map[string]td.Permission{who: td.PermAuthenticated}, nil, limits, nil)
	allowed := 0
	for range 500 {
		if st, _ := call(who, "key-a"); st == http.StatusOK {
			allowed++
		}
	}
	if allowed != 12 {
		t.Fatalf("the flooding key made %d calls, want 12", allowed)
	}
	// The same key through its access token shares the key's bucket (D28).
	if st, _ := call(who, "key-a-token"); st != http.StatusTooManyRequests {
		t.Fatalf("the flooding key's access token: %d", st)
	}
	if st, _ := call(who, "key-b"); st != http.StatusOK {
		t.Fatalf("another key of the org: %d", st)
	}
}

// TestHR375_SafetyCallsSkipTheOrgLimit (D27): credentials flooding an org
// exhaust its per-org limit, yet another credential still reaches a
// procedure exempt from the org limit (containment), while the flooding
// credential stays limited by its own limit.
func TestHR375_SafetyCallsSkipTheOrgLimit(t *testing.T) {
	who := pantherclawv1connect.AccessServiceWhoAmIProcedure
	contain := pantherclawv1connect.AccessServiceListRolesProcedure // stands in for a safety procedure
	limits := rpcauth.APILimits{
		PerOrg: 4, PerCredential: 2, Limiter: ratelimit.NewMemory(nil),
		OrgExempt: func(p string) bool { return p == contain },
	}
	perms := map[string]td.Permission{who: td.PermAuthenticated, contain: td.PermAuthenticated}
	call := limitServer(t, perms, nil, limits, nil)
	for _, k := range []string{"key-a", "key-a", "key-b", "key-b"} {
		if st, _ := call(who, k); st != http.StatusOK {
			t.Fatalf("filling the org: %d", st)
		}
	}
	if st, _ := call(who, "key-c"); st != http.StatusTooManyRequests {
		t.Fatalf("the org's limit: %d", st)
	}
	// key-c's refused call above used one of its own two calls.
	if st, _ := call(contain, "key-c"); st != http.StatusOK {
		t.Fatalf("containment with the org exhausted: %d", st)
	}
	if st, _ := call(contain, "key-c"); st != http.StatusTooManyRequests {
		t.Fatalf("containment past the credential's own limit: %d", st)
	}
	if st, _ := call(contain, "key-a"); st != http.StatusTooManyRequests {
		t.Fatalf("the flooding credential on containment: %d", st)
	}
}

// failingShared is a shared counter that cannot be reached.
type failingShared struct{}

func (failingShared) Take(context.Context, string, string, time.Duration, int, int) (ratelimit.Decision, error) {
	return ratelimit.Decision{}, errors.New("counter unavailable")
}

// TestHR375_ExportsAreCappedPerOrg (D45): export procedures are capped per
// org an hour across all its credentials, even though they skip the
// per-org minute limit; containment is never counted against the cap; a
// counter that cannot be reached refuses exports (HR-376) but nothing
// else.
func TestHR375_ExportsAreCappedPerOrg(t *testing.T) {
	export := pantherclawv1connect.AccessServiceListRolesProcedure  // stands in for ExportBundle
	contain := pantherclawv1connect.AccessServiceListUsersProcedure // stands in for Contain
	perms := map[string]td.Permission{export: td.PermAuthenticated, contain: td.PermAuthenticated}
	limits := func(shared ratelimit.Limiter) rpcauth.APILimits {
		return rpcauth.APILimits{
			PerOrg: 100, PerCredential: 100, Limiter: ratelimit.NewMemory(nil),
			OrgExempt:            func(p string) bool { return p == export || p == contain },
			Exports:              func(p string) bool { return p == export },
			PerOrgExportsPerHour: 3, Shared: shared,
		}
	}
	call := limitServer(t, perms, nil, limits(ratelimit.NewMemory(nil)), nil)
	for _, k := range []string{"key-a", "key-b", "key-c"} {
		if st, _ := call(export, k); st != http.StatusOK {
			t.Fatalf("export by %s: %d", k, st)
		}
	}
	st, retry := call(export, "key-a")
	if st != http.StatusTooManyRequests || retry == "" {
		t.Fatalf("the org's fourth export this hour: %d %q", st, retry)
	}
	if st, _ := call(export, "other-a"); st != http.StatusOK {
		t.Fatalf("another org's export: %d", st)
	}
	for range 10 {
		if st, _ := call(contain, "key-a"); st != http.StatusOK {
			t.Fatalf("containment with the export cap reached: %d", st)
		}
	}
	broken := limitServer(t, perms, nil, limits(failingShared{}), nil)
	if st, _ := broken(export, "key-a"); st != http.StatusTooManyRequests {
		t.Fatalf("export with the counter unavailable: %d", st)
	}
	if st, _ := broken(contain, "key-a"); st != http.StatusOK {
		t.Fatalf("containment with the counter unavailable: %d", st)
	}
}

// TestHR490_AStoreErrorRefusesButSafetyCalls (G0 M19 D201): when the
// shared counter behind the API limits cannot be reached, an ordinary
// call is refused with RATE_LIMITED and Retry-After (HR-376), and a
// procedure of the safety or allow classes is still admitted.
// Covers: HR-490, HR-376
func TestHR490_AStoreErrorRefusesButSafetyCalls(t *testing.T) {
	who := pantherclawv1connect.AccessServiceWhoAmIProcedure
	contain := pantherclawv1connect.AccessServiceListRolesProcedure // stands in for a safety procedure
	limits := rpcauth.APILimits{
		PerOrg: 100, PerCredential: 100, Limiter: ratelimit.NewLeased(failingShared{}, nil),
		OrgExempt: func(p string) bool { return p == contain },
	}
	perms := map[string]td.Permission{who: td.PermAuthenticated, contain: td.PermAuthenticated}
	call := limitServer(t, perms, nil, limits, nil)
	if st, ra := call(who, "key-a"); st != http.StatusTooManyRequests || ra == "" {
		t.Fatalf("an ordinary call with the counter down: %d Retry-After %q", st, ra)
	}
	if st, _ := call(contain, "key-a"); st != http.StatusOK {
		t.Fatalf("a safety call with the counter down: %d", st)
	}
}

// stalledShared is a shared counter that hangs for stall, then fails.
type stalledShared struct{ stall time.Duration }

func (s stalledShared) Take(ctx context.Context, _, _ string, _ time.Duration, _, _ int) (ratelimit.Decision, error) {
	select {
	case <-time.After(s.stall):
		return ratelimit.Decision{}, errors.New("statement timeout")
	case <-ctx.Done():
		return ratelimit.Decision{}, ctx.Err()
	}
}

// TestHR490_ASafetyCallIsNotQueuedBehindAStalledStore (D215): while the
// shared counter hangs and ordinary calls of a credential wait on it, a
// safety call of the same credential is admitted within one store timeout,
// not after every queued call's timeout in turn.
// Covers: HR-490, HR-376
func TestHR490_ASafetyCallIsNotQueuedBehindAStalledStore(t *testing.T) {
	const stall = 400 * time.Millisecond
	who := pantherclawv1connect.AccessServiceWhoAmIProcedure
	contain := pantherclawv1connect.AccessServiceListRolesProcedure // stands in for a safety procedure
	limits := rpcauth.APILimits{
		PerOrg: 100, PerCredential: 100, Limiter: ratelimit.NewLeased(stalledShared{stall: stall}, nil),
		OrgExempt: func(p string) bool { return p == contain },
	}
	perms := map[string]td.Permission{who: td.PermAuthenticated, contain: td.PermAuthenticated}
	call := limitServer(t, perms, nil, limits, nil)
	for range 6 {
		go call(who, "key-a")
	}
	time.Sleep(20 * time.Millisecond)
	begin := time.Now()
	if st, _ := call(contain, "key-a"); st != http.StatusOK {
		t.Fatalf("a safety call with the counter stalled: %d", st)
	}
	if d := time.Since(begin); d > 2*stall {
		t.Fatalf("the safety call took %v, one store timeout is %v", d, stall)
	}
}
