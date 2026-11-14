// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"errors"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/otlpexport"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m36Edition is the licence the OTLP exporter sees in this test.
type m36Edition struct{ e billing.Edition }

func (e m36Edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: e.e}, nil
}

// TestE2E_M36_OTLPExportNeedsBusiness is M36's exit: on the real stack a
// Security Admin on Team cannot create an OTLP destination, and on Business
// the same call stores one PENDING destination that exports nothing until
// a person activates it with a security key.
// Covers: F1061, HR-786
func TestE2E_M36_OTLPExportNeedsBusiness(t *testing.T) {
	s := start(t, options{budget: "1000.00"})
	kp, err := keys.NewFileProvider([]string{s.kek})
	if err != nil {
		t.Fatal(err)
	}
	env := pccrypto.NewEnvelope(keystore.NewDEKStore(s.pool, kp))
	svc, err := otlpexport.New(s.pool, env, feed.Reader{}, otlpexport.Config{PublicURL: s.apiURL}, clock.System{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	admin := s.person(t, "otlp-admin", td.RoleSecurityAdmin)
	in := otlpexport.NewDestination{Name: "traces", URL: "https://collector.example/v1/traces"}

	svc.WithEditions(m36Edition{billing.Team})
	if _, err := svc.Create(admin.ctx, in); !errors.Is(err, otlpexport.ErrEdition) {
		t.Fatalf("Team create: %v", err)
	}
	if n := s.row(t, "SELECT count(*)::text FROM pc.otlp_destinations"); n != "0" {
		t.Fatalf("%s destinations stored on Team", n)
	}

	svc.WithEditions(m36Edition{billing.Business})
	created, err := svc.Create(admin.ctx, in)
	if err != nil {
		t.Fatalf("Business create: %v", err)
	}
	if created.State != otlpexport.StatePending || len(created.HeaderNames) != 0 {
		t.Fatalf("created %+v", created)
	}
	if n := s.row(t, "SELECT state FROM pc.otlp_destinations"); n != "PENDING" {
		t.Fatalf("state %s", n)
	}
	st, err := svc.ExportOnce(context.Background(), s.org, created.ID)
	if err != nil || st.Sent {
		t.Fatalf("pending export: %+v %v", st, err)
	}
}
