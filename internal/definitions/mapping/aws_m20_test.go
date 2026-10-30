// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapping

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

func m20Mapper(t testing.TB) *Mapper {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "m20-format.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return mapperFor(t, raw)
}

func awsHeader(target, ct string) http.Header {
	h := http.Header{}
	if target != "" {
		h.Set("X-Amz-Target", target)
	}
	h.Set("Content-Type", ct)
	return h
}

// TestHR526_FixedHeadersSelectTheRouteAndNothingElse: two aws-json routes
// share POST / and only the exact fixed X-Amz-Target selects one; a
// request without it, with another value or with it twice maps nothing,
// and an aws-json body needs an aws-json media type.
// Covers: HR-526
func TestHR526_FixedHeadersSelectTheRouteAndNothingElse(t *testing.T) {
	m := m20Mapper(t)
	ctx := context.Background()
	body := []byte(`{"name":"web","size":3}`)
	p, err := m.HTTPRequestHeader(ctx, tc, http.MethodPost, "/", "", awsHeader("Svc_20261030.UpdateThing", "application/x-amz-json-1.1"), body)
	if err != nil {
		t.Fatal(err)
	}
	if p.Action.Operation != "svc.thing.update" || p.Action.Route != "thing-update" || p.Action.Target.ID != "web" {
		t.Fatalf("mapped %+v", p.Action)
	}
	p, err = m.HTTPRequestHeader(ctx, tc, http.MethodPost, "/", "", awsHeader("Svc_20261030.DescribeThing", "application/x-amz-json-1.0"),
		[]byte(`{"name":"web"}`))
	if err != nil || p.Action.Operation != "svc.thing.describe" {
		t.Fatalf("describe: %+v %v", p.Action, err)
	}
	twice := awsHeader("Svc_20261030.UpdateThing", "application/x-amz-json-1.1")
	twice.Add("X-Amz-Target", "Svc_20261030.UpdateThing")
	for name, h := range map[string]http.Header{
		"no target":     awsHeader("", "application/x-amz-json-1.1"),
		"other target":  awsHeader("Svc_20261030.DeleteThing", "application/x-amz-json-1.1"),
		"case of value": awsHeader("svc_20261030.updatething", "application/x-amz-json-1.1"),
		"twice":         twice,
	} {
		if _, err := m.HTTPRequestHeader(ctx, tc, http.MethodPost, "/", "", h, body); !errors.Is(err, ErrUnmapped) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, ct := range []string{"application/json", "application/x-amz-json-1.1; charset=utf-8", ""} {
		if _, err := m.HTTPRequestHeader(ctx, tc, http.MethodPost, "/", "", awsHeader("Svc_20261030.UpdateThing", ct), body); !errors.Is(err, actionir.ErrAmbiguous) {
			t.Errorf("content type %q: %v", ct, err)
		}
	}
	if _, err := m.HTTPRequestHeader(ctx, tc, http.MethodPost, "/x", "", awsHeader("Svc_20261030.UpdateThing", "application/x-amz-json-1.1"), body); !errors.Is(err, ErrUnmapped) {
		t.Errorf("a path below the root: %v", err)
	}
	if route, ok := m.HTTPRouteHeader(http.MethodPost, "/", awsHeader("Svc_20261030.DescribeThing", "")); !ok || route != "thing-describe" {
		t.Errorf("route %q %v", route, ok)
	}
	if _, ok := m.HTTPRoute(http.MethodPost, "/"); ok {
		t.Error("a route named without its headers")
	}
}

// TestHR526_AgentHeadersNeverWidenTheMapping: a header the mapping does not
// fix, such as a session token or another operation's target, changes
// nothing about the action: the canonical action is identical.
// Covers: HR-526
func TestHR526_AgentHeadersNeverWidenTheMapping(t *testing.T) {
	m := m20Mapper(t)
	ctx := context.Background()
	body := []byte(`{"name":"web","size":3}`)
	plain, err := m.HTTPRequestHeader(ctx, tc, http.MethodPost, "/", "", awsHeader("Svc_20261030.UpdateThing", "application/x-amz-json-1.1"), body)
	if err != nil {
		t.Fatal(err)
	}
	h := awsHeader("Svc_20261030.UpdateThing", "application/x-amz-json-1.1")
	h.Set("X-Amz-Security-Token", "agent-chosen")
	h.Set("X-Amz-Date", "20990101T000000Z")
	h.Set("Content-Encoding", "gzip")
	extra, err := m.HTTPRequestHeader(ctx, tc, http.MethodPost, "/", "", h, body)
	if err != nil {
		t.Fatal(err)
	}
	if string(extra.Canonical) != string(plain.Canonical) {
		t.Fatal("an unmapped header changed the action")
	}
}
