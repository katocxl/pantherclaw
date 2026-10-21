// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// unpublishedPolicies answers GetPublishedPolicy as the server does for an
// org that has published nothing: an empty response.
type unpublishedPolicies struct {
	pantherclawv1connect.UnimplementedPolicyServiceHandler
}

func (unpublishedPolicies) GetPublishedPolicy(context.Context, *pantherclawv1.GetPublishedPolicyRequest) (*pantherclawv1.GetPublishedPolicyResponse, error) {
	return &pantherclawv1.GetPublishedPolicyResponse{}, nil
}

// TestPublishedBundleOfAFreshOrg: an empty GetPublishedPolicy response
// means no policy yet, like NotFound: an empty bundle and no version, so a
// fresh org can apply a template.
func TestPublishedBundleOfAFreshOrg(t *testing.T) {
	cs := connect.NewServer()
	pantherclawv1connect.RegisterPolicyServiceHandler(cs, unpublishedPolicies{})
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	a := &app{stdout: io.Discard, stderr: io.Discard, http: ts.Client(), env: envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})}
	c, err := a.clients()
	if err != nil {
		t.Fatal(err)
	}
	bundle, version, err := publishedBundle(context.Background(), c)
	if err != nil || version != "" || bundle["id"] != "org-policy" {
		t.Fatalf("publishedBundle = %v, %q, %v", bundle, version, err)
	}
	if rules, ok := bundle["rules"].([]any); !ok || len(rules) != 0 {
		t.Fatalf("rules = %v", bundle["rules"])
	}
}
