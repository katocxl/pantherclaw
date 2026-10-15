// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package signals

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

func (f *rxFixture) as(kind td.PrincipalKind, roles ...td.RoleName) context.Context {
	bs := make([]td.Binding, 0, len(roles))
	for _, r := range roles {
		bs = append(bs, td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}})
	}
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{Org: f.org, Principal: td.PrincipalRef{Kind: kind, ID: f.alice}, Bindings: bs},
	})
}

// TestHR261_TransmittersNeedAPersonAKeyAndBusiness: a transmitter is
// created PENDING by a person holding signals.manage on a Business
// licence, with a JWKS URI on the issuer's host, and accepts events only
// after a person activates it with a fresh step-up.
func TestHR261_TransmittersNeedAPersonAKeyAndBusiness(t *testing.T) {
	f := newRxFixture(t)
	admin := f.as(td.KindUser, td.RoleSecurityAdmin)
	in := NewTransmitter{Name: "okta", Issuer: f.issuer, JWKSURI: f.issuer + "/jwks"}

	f.ed.e = billing.Team
	if _, err := f.svc.Create(admin, in); !errors.Is(err, ErrEdition) {
		t.Fatalf("Team edition: %v", err)
	}
	f.ed.e = billing.Business
	if _, err := f.svc.Create(f.as(td.KindUser, td.RoleAuditor), in); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("auditor: %v", err)
	}
	if _, err := f.svc.Create(f.as(td.KindServiceAccount, td.RoleSecurityAdmin), in); err == nil {
		t.Fatal("a service account created a transmitter")
	}
	if _, err := f.svc.Create(admin, NewTransmitter{Name: "evil", Issuer: f.issuer, JWKSURI: "https://evil.example/jwks"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("JWKS on another host: %v", err)
	}
	tr, err := f.svc.Create(admin, in)
	if err != nil {
		t.Fatal(err)
	}
	if tr.State != StatePending || tr.Audience != tr.EndpointURL {
		t.Fatalf("created = %+v", tr)
	}
	// Pending: the receiver answers as for an unknown transmitter.
	if a := f.post(t, f.org, tr.ID, ContentType, f.token(t, f.key, tr.ID, nil)); a.status != http.StatusNotFound {
		t.Fatalf("pending push: %+v", a)
	}
	if _, err := f.svc.Activate(admin, tr.ID, stepup.StepUp{Credential: f.cred, At: time.Now().Add(-time.Hour)}); !errors.Is(err, stepup.ErrStepUp) {
		t.Fatalf("stale step-up: %v", err)
	}
	if _, err := f.svc.Activate(admin, tr.ID, stepup.StepUp{Credential: f.cred, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if a := f.post(t, f.org, tr.ID, ContentType, f.token(t, f.key, tr.ID, nil)); a.status != http.StatusAccepted {
		t.Fatalf("active push: %+v", a)
	}
	events, err := f.svc.Events(f.as(td.KindUser, td.RoleAuditor), tr.ID)
	if err != nil || len(events) != 1 || events[0].MatchBasis != "iss_sub" {
		t.Fatalf("events = %+v, %v", events, err)
	}
	list, _, err := f.svc.List(admin, 0, "")
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %d, %v", len(list), err)
	}
	f.ed.e = billing.Team
	if _, err := f.svc.SetState(admin, tr.ID, StateDisabled); err != nil {
		t.Fatalf("disable after lapse: %v", err)
	}
}
