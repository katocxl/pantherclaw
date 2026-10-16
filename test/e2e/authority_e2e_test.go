// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"google.golang.org/protobuf/types/known/timestamppb"

	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	defsapp "github.com/katocxl/pantherclaw/internal/definitions/app"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	factsapp "github.com/katocxl/pantherclaw/internal/facts/app"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	grantspg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/grants/grantstest"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
)

type keyBearer struct{ key string }

func (b keyBearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.key)
	return http.DefaultTransport.RoundTrip(r)
}

// refundable reports charges as refundable through FactService, with the
// API key `dev seed --facts-key-out` wrote (HR-160: only the provider's own
// service account reports facts).
func refundable(t *testing.T, base, keyFile string, charges ...string) {
	t.Helper()
	key, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	facts := pantherclawv1connect.NewFactServiceClient(connect.NewClient(connecthttp.NewTransport(&http.Client{
		Timeout: 10 * time.Second, Transport: keyBearer{strings.TrimSpace(string(key))},
	}, base)))
	var obs []*pantherclawv1.FactObservation
	for _, c := range charges {
		obs = append(obs, &pantherclawv1.FactObservation{
			Name: "payments.charge.refundable", SubjectType: "payments.charge", SubjectId: c, Value: []byte(`{"bool": true}`),
			ObserveTime: timestamppb.Now(),
		})
	}
	res, err := facts.PutFacts(context.Background(), &pantherclawv1.PutFactsRequest{Observations: obs})
	if err != nil {
		t.Fatalf("PutFacts: %v", err)
	}
	for _, r := range res.GetResults() {
		if !r.GetAccepted() {
			t.Fatalf("fact %d refused: %s %s", r.GetIndex(), r.GetCode(), r.GetDetail())
		}
	}
}

// allowAll stands in for the caller's role bindings when a test seeds
// authority directly through the use cases.
type allowAll struct{}

func (allowAll) Require(tenancy.Caller, td.Permission, td.Path) error { return nil }

// seedAuthority gives an org what a refund through the pipeline needs:
// the reference package (signed with a test root, imported and active), a
// fresh refundable fact about each charge from a billing provider, and a
// root grant for agent on behalf of user (refunds of at most $100, a $500
// task budget). It returns the grant id.
func seedAuthority(t *testing.T, pool *db.Pool, org ids.OrgID, agent, user ids.UUID, charges ...string) string {
	t.Helper()
	ctx := context.Background()
	seedPackage(t, pool, org)
	defStore := &defspg.Store{Pool: pool}

	billing := ids.NewV7()
	if err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "INSERT INTO pc.service_accounts (org_id, id, name, created_by) VALUES ($1, $2, 'billing', 'e2e')", org, billing)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return seedFactsAndGrant(t, pool, org, defStore, billing, agent, user, charges...)
}

// seedPackage imports the reference package into org, signed with a test
// root, and activates it. Tests seed it directly: importing through
// PackageService needs a targets document signed by a root the server
// trusts, and a test server trusts none (G0 M4 decision 3).
func seedPackage(t *testing.T, pool *db.Pool, org ids.OrgID) {
	t.Helper()
	ctx := context.Background()
	priv, kid, err := rootkey.Generate(rootkey.PurposePackages)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := jws.NewSigner(kid, priv)
	sum := sha256.Sum256(mockpayments.Package)
	doc, err := trust.Sign(trust.Targets{
		Version: 1, Expires: time.Now().Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339),
		Targets: map[string]trust.Target{trust.Key(mockpayments.Name, mockpayments.Version): {
			Length: int64(len(mockpayments.Package)), Hashes: map[string]string{"sha256": hex.EncodeToString(sum[:])},
		}},
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	im := &defsapp.Importer{Roots: trust.Roots{kid: signer.Public()}, Repo: &defspg.Store{Pool: pool}, Clock: clock.System{}}
	if _, err := im.Import(ctx, org, mockpayments.Name, mockpayments.Version, doc, mockpayments.Package, nil); err != nil {
		t.Fatal(err)
	}
	if err := im.Transition(ctx, org, mockpayments.Name, mockpayments.Version, defs.StateActive, nil); err != nil {
		t.Fatal(err)
	}
}

// seedFactsAndGrant registers billing as the provider of refundable facts,
// reports each charge, and issues the grant seedAuthority describes.
func seedFactsAndGrant(t *testing.T, pool *db.Pool, org ids.OrgID, defStore *defspg.Store, billing, agent, user ids.UUID, charges ...string) string {
	t.Helper()
	ctx := context.Background()
	human := tenancy.WithCaller(ctx, tenancy.Caller{Subject: td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user}}})
	facts := &factsapp.Service{Store: &factspg.Store{Pool: pool}, Authz: allowAll{}}
	if _, err := facts.RegisterProvider(human, "billing.system", billing, []fdomain.Declaration{
		{Name: "payments.charge.refundable", Type: fdomain.TypeBoolean, SubjectType: "payments.charge", MaxLag: 5 * time.Minute},
	}); err != nil {
		t.Fatal(err)
	}
	var obs []fdomain.Observation
	for _, c := range charges {
		obs = append(obs, fdomain.Observation{
			Name: "payments.charge.refundable", SubjectType: "payments.charge", SubjectID: c,
			Value: jsontext.Value(`{"bool": true}`), ObservedAt: time.Now().Add(-time.Second),
		})
	}
	asBilling := tenancy.WithCaller(ctx, tenancy.Caller{Subject: td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: billing}}})
	res, err := facts.PutFacts(asBilling, obs)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if r.Err != nil {
			t.Fatalf("fact %s: %v", r.SubjectID, r.Err)
		}
	}

	b, err := gdomain.DecodeBounds([]byte(`{"operations": ["payments.refund.create"],
	  "params": {"payments.refund.create": {"amount": {"max": {"USD": "100.00"}}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	lim, err := gdomain.DecodeLimits([]byte(`{"budgets": [{"id": "task", "grouping": "task", "operations": ["payments.refund.create"],
	  "currency": "USD", "limit": "500.00", "period": "none"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	gs := &grantspg.Store{Pool: pool, Promotions: grantstest.OpenGate{}}
	grants := &grantsapp.Service{Repo: gs, Subjects: gs, Defs: defStore, Authz: allowAll{}, Clock: clock.System{}}
	g, err := grants.Issue(human, grantsapp.IssueRequest{
		AgentID: agent, Principal: gdomain.Principal{Kind: gdomain.PrincipalUser, ID: user}, TaskRef: "refunds",
		ExpiresAt: time.Now().Add(24 * time.Hour), Bounds: b, Limits: lim,
	})
	if err != nil {
		t.Fatal(err)
	}
	return g.ID.String()
}
