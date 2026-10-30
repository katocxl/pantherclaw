// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"strings"
	"testing"
)

// awsDef is a valid aws-json read with an http mapping.
func awsDef() Definition {
	return Definition{
		Operation: "svc.thing.describe", Summary: "Describe a thing", Access: AccessRead,
		Target: TargetSpec{Type: "svc.thing", IDPattern: `^[a-z]{1,8}$`, Account: PresenceNone},
		Params: map[string]ParamSpec{}, Effects: []Effect{{Kind: "none", Description: "Reads only"}}, Reversibility: Reversible,
		Retry:     RetrySpec{Safe: true, OnUnknown: OnUnknownFail},
		Assurance: Assurance{Basis: BasisDeclared, ReviewedBy: []string{"tests"}, ValidUntil: "2027-10-30"},
		Dispatch: &Dispatch{HTTP: &HTTPDispatch{
			Method: "POST", Path: "/", Encoding: EncodingAWSJSON,
			Headers: map[string]string{"X-Amz-Target": "Svc.DescribeThing"}, Body: map[string]string{"name": "target.id"},
		}},
		Mappings: []Mapping{{
			Channel: ChannelHTTP, Method: "POST", Path: "/", Encoding: EncodingAWSJSON, Route: "thing-describe",
			Headers: map[string]string{"X-Amz-Target": "Svc.DescribeThing"},
			Extract: Extract{TargetID: "input.name", Params: map[string]string{}},
		}},
	}
}

// TestHR526_HeadersAndEncodingsAreFixedByThePackage: an aws template's
// operation is fixed in the package (a literal X-Amz-Target, or literal
// Action and Version), it posts to the root only, a header the SigV4
// signer sets can never be fixed, and match headers are http-only literals.
// Covers: HR-526
func TestHR526_HeadersAndEncodingsAreFixedByThePackage(t *testing.T) {
	d := awsDef()
	if err := d.Validate(); err != nil {
		t.Fatalf("valid aws-json definition: %v", err)
	}
	q := awsDef()
	q.Mappings = nil
	q.Dispatch.HTTP = &HTTPDispatch{Method: "POST", Path: "/", Encoding: EncodingAWSQuery,
		Body: map[string]string{"Action": "literal.GetRole", "Version": "literal.2010-05-08", "RoleName": "target.id"}}
	if err := q.Validate(); err != nil {
		t.Fatalf("valid aws-query definition: %v", err)
	}
	for name, mut := range map[string]func(*Definition){
		"aws-json without a target": func(d *Definition) { d.Dispatch.HTTP.Headers = nil },
		"aws-json GET": func(d *Definition) {
			d.Dispatch.HTTP.Method, d.Dispatch.HTTP.Body = "GET", nil
		},
		"aws-json below the root":   func(d *Definition) { d.Dispatch.HTTP.Path = "/things" },
		"json at the root":          func(d *Definition) { d.Dispatch.HTTP.Encoding = EncodingJSON },
		"signer header x-amz-date":  func(d *Definition) { d.Dispatch.HTTP.Headers["X-Amz-Date"] = "20261030T000000Z" },
		"signer header token":       func(d *Definition) { d.Dispatch.HTTP.Headers["X-Amz-Security-Token"] = "x" },
		"signer header sha256":      func(d *Definition) { d.Dispatch.HTTP.Headers["x-amz-content-sha256"] = "x" },
		"target from a reference":   func(d *Definition) { d.Dispatch.HTTP.Headers["X-Amz-Target"] = "{target.id}" },
		"idempotency header":        func(d *Definition) { d.Dispatch.HTTP.IdempotencyHeader = "X-Token" },
		"unknown encoding":          func(d *Definition) { d.Dispatch.HTTP.Encoding = "aws-rest-xml" },
		"mapping without target":    func(d *Definition) { d.Mappings[0].Headers = nil },
		"mapping json at the root":  func(d *Definition) { d.Mappings[0].Encoding = EncodingJSON },
		"mapping reserved header":   func(d *Definition) { d.Mappings[0].Headers["Authorization"] = "x" },
		"mapping header twice":      func(d *Definition) { d.Mappings[0].Headers["x-amz-target"] = "Svc.DescribeThing" },
		"mapping header reference":  func(d *Definition) { d.Mappings[0].Headers["X-Amz-Target"] = "{x}" },
		"mapping pc- header":        func(d *Definition) { d.Mappings[0].Headers["PC-Run"] = "x" },
		"mapping aws-json GET":      func(d *Definition) { d.Mappings[0].Method = "GET" },
		"headers on an mcp mapping": func(d *Definition) { d.Mappings[0].Channel, d.Mappings[0].Tool = ChannelMCP, "describe" },
	} {
		d := awsDef()
		mut(&d)
		if err := d.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, body := range map[string]map[string]string{
		"no Action":         {"Version": "literal.2010-05-08", "RoleName": "target.id"},
		"Action from input": {"Action": "target.id", "Version": "literal.2010-05-08"},
		"no Version":        {"Action": "literal.GetRole", "RoleName": "target.id"},
	} {
		q := awsDef()
		q.Mappings = nil
		q.Dispatch.HTTP = &HTTPDispatch{Method: "POST", Path: "/", Encoding: EncodingAWSQuery, Body: body}
		if err := q.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("aws-query %s: %v", name, err)
		}
	}
	l := awsDef()
	l.Mappings = nil
	l.Params = map[string]ParamSpec{"names": {Type: TypeIdentifierList, Material: true, Pattern: `^[a-z]{1,8}$`, MaxItems: 4}}
	l.Dispatch.HTTP = &HTTPDispatch{Method: "POST", Path: "/", Encoding: EncodingAWSQuery,
		Body: map[string]string{"Action": "literal.GetRole", "Version": "literal.2010-05-08", "Names": "params.names"}}
	if err := l.Validate(); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "sends no lists") {
		t.Errorf("aws-query list: %v", err)
	}
}

// TestHR525_AWSActionIsTheOneThePackageFixes: the action a session is
// narrowed to comes from the template's literal X-Amz-Target or Action,
// GET or POST, and a non-AWS template names none.
// Covers: HR-525
func TestHR525_AWSActionIsTheOneThePackageFixes(t *testing.T) {
	d := awsDef()
	if a, ok := d.AWSAction(); !ok || a != "DescribeThing" {
		t.Fatalf("aws-json: %q %v", a, ok)
	}
	d.Dispatch.HTTP = &HTTPDispatch{Method: "POST", Path: "/", Encoding: EncodingAWSQuery,
		Body: map[string]string{"Action": "literal.GetRole", "Version": "literal.2010-05-08"}}
	if a, ok := d.AWSAction(); !ok || a != "GetRole" {
		t.Fatalf("aws-query: %q %v", a, ok)
	}
	d.Dispatch.HTTP = &HTTPDispatch{Method: "GET", Path: "/", Encoding: EncodingAWSQuery,
		Query: map[string]string{"Action": "literal.GetAccountSummary", "Version": "literal.2010-05-08"}}
	if err := d.validateHTTPDispatch("t", d.Dispatch.HTTP); err != nil {
		t.Fatalf("aws-query GET: %v", err)
	}
	if a, ok := d.AWSAction(); !ok || a != "GetAccountSummary" {
		t.Fatalf("aws-query GET: %q %v", a, ok)
	}
	d.Dispatch.HTTP.Body = map[string]string{"Action": "literal.DeleteRole"}
	if a, _ := d.AWSAction(); a != "GetAccountSummary" {
		t.Fatalf("a GET read its action from a body: %q", a)
	}
	d.Dispatch.HTTP = &HTTPDispatch{Method: "GET", Path: "/x", Encoding: EncodingJSON}
	if _, ok := d.AWSAction(); ok {
		t.Fatal("a JSON template named an AWS action")
	}
	post := &HTTPDispatch{Method: "POST", Path: "/", Encoding: EncodingAWSQuery,
		Body:  map[string]string{"Action": "literal.GetRole", "Version": "literal.2010-05-08"},
		Query: map[string]string{"Action": "literal.DeleteRole"}}
	if err := d.validateHTTPDispatch("t", post); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a POST with a query Action: %v", err)
	}
}
