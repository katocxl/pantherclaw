// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package extension

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

// HR-341: extension routes live only under /v1/ext/ and /app/ext/.
func TestHR341_RoutePrefixes(t *testing.T) {
	ok := []string{
		"/v1/ext/billing/webhook",
		"POST /v1/ext/billing/paddle/webhook",
		"GET /app/ext/billing/plans",
		"POST /app/ext/billing/checkout",
		"GET /v1/ext/billing/fake/{id}",
		"/app/ext/x/",
	}
	for _, p := range ok {
		if _, _, err := SplitPattern(p); err != nil {
			t.Errorf("SplitPattern(%q) = %v, want ok", p, err)
		}
	}
	bad := []string{
		"", "/", "/v1/ext/", "/app/ext/", "/v1/ext/{x}", "/v1/extra", "/v1/ext", "/app/", "/app/x",
		"/pantherclaw.v1.AccessService/WhoAmI", "/login", "/static/pc.css",
		"example.com/v1/ext/x", "POST example.com/v1/ext/x", "FETCH /v1/ext/x", "post /v1/ext/x",
		"/v1/ext/a//b", "/v1/ext/a/../b", "/v1/ext/a/./b", "/v1/ext/a\\b", "/v1/ext/a%2fb", "/v1/ext/a?b",
		"/v1/ext/a b", "GET  /v1/ext/a", " /v1/ext/a", "/v1/ext/ä",
	}
	for _, p := range bad {
		if _, _, err := SplitPattern(p); !errors.Is(err, ErrRoute) {
			t.Errorf("SplitPattern(%q) = %v, want ErrRoute", p, err)
		}
	}
}

func TestValidateRoute(t *testing.T) {
	h := http.NotFoundHandler()
	if err := ValidateRoute(Route{Pattern: "POST /v1/ext/a", Auth: AuthSessionCSRF, Handler: h}); err != nil {
		t.Fatal(err)
	}
	for _, r := range []Route{
		{Pattern: "/v1/ext/a", Auth: AuthNone},
		{Pattern: "/v1/ext/a", Auth: RouteAuth(9), Handler: h},
		{Pattern: "/v2/ext/a", Auth: AuthNone, Handler: h},
	} {
		if err := ValidateRoute(r); !errors.Is(err, ErrRoute) {
			t.Errorf("ValidateRoute(%+v) = %v, want ErrRoute", r, err)
		}
	}
}

func TestPrincipalFrom(t *testing.T) {
	if _, ok := PrincipalFrom(context.Background()); ok {
		t.Fatal("principal without one set")
	}
	want := Principal{OrgID: "o", UserID: "u"}
	got, ok := PrincipalFrom(WithPrincipal(context.Background(), want))
	if !ok || got != want {
		t.Fatalf("PrincipalFrom = %+v, %v", got, ok)
	}
}

func TestEnums(t *testing.T) {
	for _, d := range []Deployment{DeploymentDevelopment, DeploymentStaging, DeploymentProduction} {
		if !d.Valid() {
			t.Errorf("%q invalid", d)
		}
	}
	for _, d := range []Deployment{"", "prod", "Production"} {
		if d.Valid() {
			t.Errorf("%q valid", d)
		}
	}
	for _, s := range []PlanStatus{"COMP", "DEV", "", "active"} {
		if s.Valid() {
			t.Errorf("plan status %q accepted", s)
		}
	}
	if !PlanActive.Valid() || !PlanLapsed.Valid() {
		t.Error("plan states refused")
	}
}
