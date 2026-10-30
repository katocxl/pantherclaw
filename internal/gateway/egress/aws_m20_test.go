// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package egress

import (
	"context"
	"net/http"
	"os"
	"reflect"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
)

func m20Package(t testing.TB) *defs.Package {
	t.Helper()
	raw, err := os.ReadFile("../../definitions/mapping/testdata/m20-format.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := manifest.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestHR526_TheOutboundRequestCarriesOnlyThePackagesHeadersAndEncoding: an
// agent request with its own headers (a session token, a date, another
// operation's target) is rebuilt from the action alone: the outbound
// aws-json request carries exactly the template's X-Amz-Target and media
// type, and an aws-query request exactly its literal Action and Version
// in a flat form.
// Covers: HR-526
func TestHR526_TheOutboundRequestCarriesOnlyThePackagesHeadersAndEncoding(t *testing.T) {
	p := m20Package(t)
	m, err := mapping.New(p, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	h.Set("X-Amz-Target", "Svc_20261030.UpdateThing")
	h.Set("Content-Type", "application/x-amz-json-1.1")
	h.Set("X-Amz-Security-Token", "agent-token")
	h.Set("X-Amz-Date", "20990101T000000Z")
	parsed, err := m.HTTPRequestHeader(context.Background(), mapping.Context{
		Org: "01920000-0000-7000-8000-000000000001", Env: "01920000-0000-7000-8000-000000000002",
		RunID: "01920000-0000-7000-8000-000000000003", ActionID: "01920000-0000-7000-8000-000000000004",
		AgentInstance: "01920000-0000-7000-8000-000000000005",
	},
		http.MethodPost, "/", "", h, []byte(`{"name":"web","size":3}`))
	if err != nil {
		t.Fatal(err)
	}
	d, _ := p.Definition("svc.thing.update")
	req, err := Build("https://ecs.us-east-1.amazonaws.com", d, parsed.Action, "txn")
	if err != nil {
		t.Fatal(err)
	}
	if req.URL.String() != "https://ecs.us-east-1.amazonaws.com/" || req.ContentType != defs.AWSJSONContentType ||
		!reflect.DeepEqual(req.Headers, map[string]string{"X-Amz-Target": "Svc_20261030.UpdateThing"}) ||
		string(req.Body) != `{"name":"web","size":3}` {
		t.Fatalf("built %s %s %v %s", req.URL, req.ContentType, req.Headers, req.Body)
	}
	c, err := NewClient("https://ecs.us-east-1.amazonaws.com", 0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	hr, err := c.HTTPRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"X-Amz-Security-Token", "X-Amz-Date"} {
		if hr.Header.Get(name) != "" {
			t.Fatalf("%s reached the target", name)
		}
	}
	if hr.Header.Get("Content-Type") != defs.AWSJSONContentType {
		t.Fatalf("content type %q", hr.Header.Get("Content-Type"))
	}

	role, _ := p.Definition("svc.role.read")
	a := actionir.ActionIR{Target: actionir.Target{Type: "svc.role", ID: "deploy"}, Params: []byte(`{}`)}
	req, err = Build("https://iam.amazonaws.com", role, a, "txn")
	if err != nil {
		t.Fatal(err)
	}
	if req.ContentType != defs.AWSQueryType || string(req.Body) != "Action=GetRole&RoleName=deploy&Version=2010-05-08" || len(req.Headers) != 0 {
		t.Fatalf("aws-query %s %q %v", req.ContentType, req.Body, req.Headers)
	}

	describe, _ := p.Definition("svc.thing.describe")
	describe.Dispatch.HTTP.Body = nil
	req, err = Build("https://ecs.us-east-1.amazonaws.com", describe, actionir.ActionIR{Target: actionir.Target{Type: "svc.thing", ID: "web"}, Params: []byte(`{}`)}, "txn")
	if err != nil || string(req.Body) != "{}" || req.ContentType != defs.AWSJSONContentType {
		t.Fatalf("empty aws-json body: %q %v", req.Body, err)
	}
}
