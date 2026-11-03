// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/extension"
)

// Covers: F918. An extension audit kind names one of the three extensions
// and nothing else (D405, D88).
func TestExtensionAuditKinds(t *testing.T) {
	for _, k := range []string{"billing.subscription.ended", "scim.user.created", "saml.assertion_refused"} {
		if !validExtensionKind(k) {
			t.Errorf("%q refused", k)
		}
	}
	for _, k := range []string{
		"", "billing", "billing.", "scim.", "saml..x", "scim.User", "access.role_bound", "authn.login", "xscim.user",
		"scim.1x", "saml.a b", "scim.\n", "billing." + strings.Repeat("a", 64),
	} {
		if validExtensionKind(k) {
			t.Errorf("%q allowed", k)
		}
	}
	for _, p := range extension.AuditKindPrefixes {
		if !validExtensionKind(p + "x") {
			t.Errorf("prefix %q is not accepted", p)
		}
	}
	// A kind the core writes is never an extension's (D528).
	for k := range extension.CoreAuditKinds {
		if validExtensionKind(k) {
			t.Errorf("core kind %q allowed", k)
		}
	}
}

type kinds []string

func (k *kinds) Record(_ context.Context, _, kind string, _ map[string]string) error {
	*k = append(*k, kind)
	return nil
}

// TestD528_ExtensionAuditLimitedToItsPrefixes: each set's Mount gets a
// recorder limited to its own prefixes, composed or not, and none writes a
// core kind.
func TestD528_ExtensionAuditLimitedToItsPrefixes(t *testing.T) {
	var got kinds
	try := func(set extension.Set, kind string) error {
		var rec extension.AuditRecorder
		mux := coreMux()
		probe := extension.Set{AuditPrefixes: set.AuditPrefixes, Mount: func(d extension.Deps) ([]extension.Route, error) {
			rec = d.Audit
			return nil, nil
		}}
		if err := mountExtension(mux, probe, extension.Deps{Audit: &got}, nil, nil); err != nil {
			t.Fatal(err)
		}
		return rec.Record(context.Background(), "org", kind, nil)
	}
	scimSet := extension.Set{AuditPrefixes: []string{"scim.", "saml."}}
	if err := try(scimSet, "saml.sign_in_refused"); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"billing.webhook_received", "scim.user_created", "saml.connection_put", "access.role_bound"} {
		if err := try(scimSet, k); !errors.Is(err, extension.ErrAuditKind) {
			t.Errorf("%s: %v", k, err)
		}
	}
	if err := try(extension.Set{}, "scim.x"); !errors.Is(err, extension.ErrAuditKind) {
		t.Errorf("a set with no prefixes wrote: %v", err)
	}
	// Composed: each set keeps its own limit.
	var billingRec, scimRec extension.AuditRecorder
	c := extension.Compose(
		extension.Set{AuditPrefixes: []string{"billing."}, Mount: func(d extension.Deps) ([]extension.Route, error) { billingRec = d.Audit; return nil, nil }},
		extension.Set{AuditPrefixes: []string{"scim.", "saml."}, Mount: func(d extension.Deps) ([]extension.Route, error) { scimRec = d.Audit; return nil, nil }},
	)
	if err := mountExtension(coreMux(), c, extension.Deps{Audit: &got}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := billingRec.Record(context.Background(), "org", "saml.sign_in_refused", nil); !errors.Is(err, extension.ErrAuditKind) {
		t.Errorf("billing wrote saml: %v", err)
	}
	if err := scimRec.Record(context.Background(), "org", "billing.webhook_received", nil); !errors.Is(err, extension.ErrAuditKind) {
		t.Errorf("scim wrote billing: %v", err)
	}
	if err := billingRec.Record(context.Background(), "org", "billing.webhook_received", nil); err != nil {
		t.Error(err)
	}
	if len(got) != 2 || got[0] != "saml.sign_in_refused" || got[1] != "billing.webhook_received" {
		t.Fatalf("recorded %v", got)
	}
}
