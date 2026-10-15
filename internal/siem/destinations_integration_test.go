// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package siem

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/ocsf"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type edition struct{ e billing.Edition }

func (e *edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: e.e}, nil
}

func (f *exportFixture) as(kind td.PrincipalKind, roles ...td.RoleName) context.Context {
	bs := make([]td.Binding, 0, len(roles))
	for _, r := range roles {
		bs = append(bs, td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}})
	}
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{Org: f.org, Principal: td.PrincipalRef{Kind: kind, ID: f.user}, Bindings: bs},
	})
}

// TestHR259_DestinationsNeedAPersonAKeyAndBusiness: a destination is
// created PENDING by a person holding siem.manage on a Business licence,
// is activated only with a fresh step-up made with their own key, starts
// exporting at the feed's head, and its URL rules hold at creation.
func TestHR259_DestinationsNeedAPersonAKeyAndBusiness(t *testing.T) {
	f := newExportFixture(t)
	ed := &edition{e: billing.Team}
	f.svc.WithEditions(ed)
	f.feed.events = []ocsf.Event{ev(1, "reflex.alert"), ev(2, "reflex.alert")}
	admin := f.as(td.KindUser, td.RoleSecurityAdmin)
	in := NewDestination{Name: "splunk", URL: "https://siem.example.net/ingest", DataClasses: []string{"alerts"}}

	if _, err := f.svc.Create(admin, in); !errors.Is(err, ErrEdition) {
		t.Fatalf("Team edition: %v", err)
	}
	ed.e = billing.Business
	if _, err := f.svc.Create(f.as(td.KindUser, td.RoleAuditor), in); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("auditor: %v", err)
	}
	if _, err := f.svc.Create(f.as(td.KindServiceAccount, td.RoleSecurityAdmin), in); err == nil {
		t.Fatal("a service account created a destination")
	}
	for _, bad := range []NewDestination{
		{Name: "a", URL: "https://10.0.0.5/x", DataClasses: []string{"alerts"}},
		{Name: "b", URL: "https://169.254.169.254/", Internal: true, DataClasses: []string{"alerts"}},
		{Name: "c", URL: "https://pc.example.com/x", DataClasses: []string{"alerts"}},
		{Name: "d", URL: "https://siem.example.net/", DataClasses: []string{"payloads"}},
	} {
		if _, err := f.svc.Create(admin, bad); err == nil {
			t.Errorf("created %+v", bad)
		}
	}
	created, err := f.svc.Create(admin, in)
	if err != nil {
		t.Fatal(err)
	}
	if created.Destination.State != StatePending || !strings.HasPrefix(created.Secret, "whsec_") {
		t.Fatalf("created = %+v", created.Destination)
	}
	id := created.Destination.ID
	if _, err := f.svc.Create(admin, in); !errors.Is(err, ErrExists) {
		t.Fatalf("same name: %v", err)
	}
	// Not active: nothing is exported.
	if st, err := f.svc.ExportOnce(context.Background(), f.org, id); err != nil || st.Sent {
		t.Fatalf("pending exported: %+v %v", st, err)
	}

	now := time.Now()
	for name, su := range map[string]stepup.StepUp{
		"no step-up": {}, "stale": {Credential: f.cred, At: now.Add(-10 * time.Minute)}, "unknown key": {Credential: ids.NewV7(), At: now},
	} {
		if _, err := f.svc.Activate(admin, id, su); !errors.Is(err, stepup.ErrStepUp) {
			t.Errorf("%s: %v", name, err)
		}
	}
	d, err := f.svc.Activate(admin, id, stepup.StepUp{Credential: f.cred, At: now})
	if err != nil {
		t.Fatal(err)
	}
	if d.State != StateActive || d.CursorSeq != 2 || d.ActivatedBy == nil || *d.ActivatedBy != f.user {
		t.Fatalf("activated = %+v", d)
	}
	if _, err := f.svc.Activate(admin, id, stepup.StepUp{Credential: f.cred, At: now}); !errors.Is(err, ErrState) {
		t.Fatalf("second activation: %v", err)
	}
	if _, err := f.svc.RetryDestination(admin, id); !errors.Is(err, ErrNothingWaiting) {
		t.Fatalf("retry with nothing waiting: %v", err)
	}
	secret, err := f.svc.RotateSecret(admin, id)
	if err != nil || !strings.HasPrefix(secret, "whsec_") || secret == created.Secret {
		t.Fatalf("rotate: %q %v", secret, err)
	}
	if d, err := f.svc.Get(f.as(td.KindUser, td.RoleAuditor), id); err != nil || d.RotationEndsAt == nil {
		t.Fatalf("auditor read: %+v %v", d, err)
	}
	list, next, err := f.svc.List(admin, 0, "")
	if err != nil || len(list) != 1 || next != "" {
		t.Fatalf("list: %d %q %v", len(list), next, err)
	}
	// After the licence lapses, pausing and disabling still work; resuming
	// does not.
	ed.e = billing.Team
	if _, err := f.svc.SetState(admin, id, StatePaused); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SetState(admin, id, StateActive); !errors.Is(err, ErrEdition) {
		t.Fatalf("resume after lapse: %v", err)
	}
	if _, err := f.svc.SetState(admin, id, StateDisabled); err != nil {
		t.Fatal(err)
	}
}
