// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package packagesrpc_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/rpcauth"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/authn/token"
	"github.com/katocxl/pantherclaw/internal/definitions/adapters/packagesrpc"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	defsapp "github.com/katocxl/pantherclaw/internal/definitions/app"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/facts/adapters/factsrpc"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	factsapp "github.com/katocxl/pantherclaw/internal/facts/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
	"github.com/katocxl/pantherclaw/internal/platform/rpc/protoperms"
	"github.com/katocxl/pantherclaw/internal/policy/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/policy/adapters/policiesrpc"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type stack struct {
	pool   *db.Pool
	tokens *token.Service
	url    string
	// ents is the edition the package service sees (Team unless a test
	// changes it).
	ents *ents
}

func newStack(t *testing.T, roots trust.Roots) *stack {
	t.Helper()
	pool := dbtest.New(t).AppPool(t)
	reg := keys.NewRegistry()
	for _, p := range keys.Purposes() {
		k, err := keys.GenerateSigningKey(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := reg.Put(k); err != nil {
			t.Fatal(err)
		}
	}
	tokens, err := token.New(reg, "https://pc.example.test", token.Audience)
	if err != nil {
		t.Fatal(err)
	}
	authn, err := authnapp.NewAuthenticator(pool, tokens, credential.EnvTest, clock.System{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	declared, err := protoperms.Declared(filepath.Join("..", "..", "..", "..", "proto"))
	if err != nil {
		t.Fatal(err)
	}
	perms := map[string]td.Permission{}
	for proc, p := range declared {
		perms[proc] = td.Permission(p)
	}
	s, err := rpc.NewServer(rpc.Options{Authenticate: rpcauth.New(authn, perms, nil)})
	if err != nil {
		t.Fatal(err)
	}
	authz := grantsapp.SubjectAuthorizer{}
	defs := &defspg.Store{Pool: pool}
	facts := &factspg.Store{Pool: pool}
	edition := &ents{e: team}
	pantherclawv1connect.RegisterPackageServiceHandler(s, packagesrpc.New(&defsapp.Admin{
		Importer: &defsapp.Importer{Roots: roots, Repo: defs, Keys: defs, Clock: clock.System{}}, Reads: defs, Authz: authz,
		Ents: edition,
	}))
	pantherclawv1connect.RegisterPolicyServiceHandler(s, policiesrpc.New(&policyapp.Versions{
		Store: &pgstore.Store{Pool: pool}, Facts: facts, Definitions: defs, Authz: authz, Limits: celenv.DefaultLimits,
		Validator: passingGate{}, Tests: passingGate{},
	}))
	pantherclawv1connect.RegisterFactServiceHandler(s, factsrpc.New(&factsapp.Service{Store: facts, Authz: authz, Reads: facts}))
	mux := http.NewServeMux()
	rpc.Mount(mux, s)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return &stack{pool: pool, tokens: tokens, url: ts.URL, ents: edition}
}

func (s *stack) exec(t *testing.T, org ids.OrgID, sql string, args ...any) {
	t.Helper()
	if err := s.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (s *stack) org(t *testing.T) ids.OrgID {
	t.Helper()
	org := ids.New[ids.Org]()
	s.exec(t, org, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", org)
	if err := s.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		return dbq.New(tx).InsertContainment(ctx, org)
	}); err != nil {
		t.Fatal(err)
	}
	return org
}

// login creates a user with roles at org scope and returns a bearer token.
func (s *stack) login(t *testing.T, org ids.OrgID, subject string, roles ...td.RoleName) string {
	t.Helper()
	user, session := ids.NewV7(), ids.NewV7()
	s.exec(t, org, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", org, user, subject)
	for _, role := range roles {
		s.exec(t, org, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by)
			VALUES ($1, $2, $3, $4, 'ORG', 'test')`, org, ids.NewV7(), string(role), user)
	}
	s.exec(t, org, `INSERT INTO pc.cli_sessions (org_id, id, user_id, device_jkt, device_jwk, refresh_hash, expires_at)
		VALUES ($1, $2, $3, repeat('d', 43), '{}', $4, now() + interval '8 hours')`, org, session, user, user.String()[:32])
	tok, _, err := s.tokens.Issue(token.Grant{
		Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user}, Session: session, ClientID: "pclaw",
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// serviceAccount creates a service account with roles and an API key with
// scopes, and returns its id and the key.
func (s *stack) serviceAccount(t *testing.T, org ids.OrgID, scopes []string, roles ...td.RoleName) (ids.UUID, string) {
	t.Helper()
	sa := ids.NewV7()
	s.exec(t, org, "INSERT INTO pc.service_accounts (org_id, id, name, created_by) VALUES ($1, $2, $3, 'test')", org, sa, "sa-"+sa.String()[24:])
	for _, role := range roles {
		s.exec(t, org, `INSERT INTO pc.role_bindings (org_id, id, role, service_account_id, scope_type, created_by)
			VALUES ($1, $2, $3, $4, 'ORG', 'test')`, org, ids.NewV7(), string(role), sa)
	}
	key, err := credential.New(credential.APIKey, credential.EnvTest, org)
	if err != nil {
		t.Fatal(err)
	}
	s.exec(t, org, `INSERT INTO pc.api_keys (org_id, id, service_account_id, name, secret_hash, hint, scopes, created_by, expires_at)
		VALUES ($1, $2, $3, 'key', $4, $5, $6, 'test', now() + interval '90 days')`,
		org, ids.NewV7(), sa, key.Hash(), key.Hint(), scopes)
	return sa, key.Reveal()
}

type bearer struct{ tok string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.tok)
	return http.DefaultTransport.RoundTrip(r)
}

type clients struct {
	packages pantherclawv1connect.PackageServiceClient
	policies pantherclawv1connect.PolicyServiceClient
	facts    pantherclawv1connect.FactServiceClient
}

func (s *stack) clients(tok string) clients {
	tr := connecthttp.NewTransport(&http.Client{Transport: bearer{tok}}, s.url)
	return clients{
		packages: pantherclawv1connect.NewPackageServiceClient(connect.NewClient(tr)),
		policies: pantherclawv1connect.NewPolicyServiceClient(connect.NewClient(tr)),
		facts:    pantherclawv1connect.NewFactServiceClient(connect.NewClient(tr)),
	}
}

func wantCode(t *testing.T, what string, err error, want connect.Code) {
	t.Helper()
	if connect.CodeOf(err) != want {
		t.Errorf("%s: %v, want %s", what, err, want)
	}
}

// signedPackage returns the reference package and a targets document for
// it signed by a fresh test root.
func signedPackage(t *testing.T) ([]byte, string, trust.Roots) {
	t.Helper()
	raw, err := os.ReadFile("../../../../packages/mock-payments/package.yaml")
	if err != nil {
		t.Fatal(err)
	}
	priv, kid, err := rootkey.Generate(rootkey.PurposePackages)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jws.NewSigner(kid, priv)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	doc, err := trust.Sign(trust.Targets{
		Version: 1, Expires: time.Now().Add(180 * 24 * time.Hour).UTC().Format(time.RFC3339),
		Targets: map[string]trust.Target{
			trust.Key("pc.mock-payments", "1.0.0"): {Length: int64(len(raw)), Hashes: map[string]string{"sha256": hex.EncodeToString(sum[:])}},
		},
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	return raw, doc, trust.Roots{kid: signer.Public()}
}

const bundle = `{"id": "refunds", "rules": [{"id": "big-refunds", "kind": "REQUIRE_APPROVAL", "summary": "large refunds",
	"operations": ["payments.refund.create"], "when": "action.params.amount > money(\"500.00\", \"USD\")",
	"reason": "REFUND_REVIEW", "approval": {"role": "approver", "count": 1}}]}`

// TestIntRPCPackagesPoliciesAndFacts drives PackageService, PolicyService
// and FactService: a signed package is imported and activated by a person,
// a policy compiled against it is created and published, and a fact
// provider's own service account reports facts (HR-123, HR-040, HR-160,
// HR-161). Human-only steps refuse service accounts, and another org sees
// nothing.
func TestIntRPCPackagesPoliciesAndFacts(t *testing.T) {
	raw, doc, roots := signedPackage(t)
	s := newStack(t, roots)
	ctx := context.Background()
	org := s.org(t)
	admin := s.clients(s.login(t, org, "admin", td.RoleOrgAdmin, td.RolePolicyPublisher, td.RolePolicyAuthor))

	// Packages: import (REVIEWED, decides nothing), a repeat is a no-op, a
	// tampered file is untrusted, then a person activates it.
	imp, err := admin.packages.ImportPackage(ctx, &pantherclawv1.ImportPackageRequest{
		Name: "pc.mock-payments", Version: "1.0.0", Targets: doc, Package: raw,
	})
	if err != nil || imp.GetPackage().GetState() != pantherclawv1.PackageState_PACKAGE_STATE_REVIEWED ||
		!imp.GetPackage().GetPinned() || len(imp.GetPackage().GetDefinitions()) == 0 || imp.GetAlreadyImported() {
		t.Fatalf("ImportPackage = %v, %v", imp, err)
	}
	again, err := admin.packages.ImportPackage(ctx, &pantherclawv1.ImportPackageRequest{
		Name: "pc.mock-payments", Version: "1.0.0", Targets: doc, Package: raw,
	})
	if err != nil || !again.GetAlreadyImported() {
		t.Fatalf("ImportPackage again = %v, %v", again, err)
	}
	tampered := append([]byte{}, raw...)
	tampered[len(tampered)-2] ^= 1
	_, err = admin.packages.ImportPackage(ctx, &pantherclawv1.ImportPackageRequest{
		Name: "pc.mock-payments", Version: "1.0.0", Targets: doc, Package: tampered,
	})
	wantCode(t, "a tampered package", err, connect.CodeFailedPrecondition)

	_, saKey := s.serviceAccount(t, org, []string{"package.activate", "package.read", "policy.publish", "policy.read"}, td.RolePolicyPublisher)
	sa := s.clients(saKey)
	_, err = sa.packages.TransitionPackage(ctx, &pantherclawv1.TransitionPackageRequest{
		Name: "pc.mock-payments", Version: "1.0.0", State: pantherclawv1.PackageState_PACKAGE_STATE_ACTIVE,
	})
	wantCode(t, "a service account activates a package", err, connect.CodePermissionDenied)
	act, err := admin.packages.TransitionPackage(ctx, &pantherclawv1.TransitionPackageRequest{
		Name: "pc.mock-payments", Version: "1.0.0", State: pantherclawv1.PackageState_PACKAGE_STATE_ACTIVE,
	})
	if err != nil || act.GetPackage().GetState() != pantherclawv1.PackageState_PACKAGE_STATE_ACTIVE {
		t.Fatalf("TransitionPackage = %v, %v", act, err)
	}
	_, err = admin.packages.TransitionPackage(ctx, &pantherclawv1.TransitionPackageRequest{
		Name: "pc.mock-payments", Version: "1.0.0", State: pantherclawv1.PackageState_PACKAGE_STATE_DRAFT,
	})
	wantCode(t, "an illegal transition", err, connect.CodeFailedPrecondition)
	list, err := admin.packages.ListPackages(ctx, &pantherclawv1.ListPackagesRequest{})
	if err != nil || len(list.GetPackages()) != 1 {
		t.Fatalf("ListPackages = %v, %v", list, err)
	}
	digest := imp.GetPackage().GetDefinitions()[0].GetDigest()
	def, err := admin.packages.GetDefinition(ctx, &pantherclawv1.GetDefinitionRequest{Digest: digest})
	if err != nil || def.GetPackage() != "pc.mock-payments" || len(def.GetDefinition()) == 0 {
		t.Fatalf("GetDefinition = %v, %v", def, err)
	}

	// Policies: create (compiled), publish by a person only.
	_, err = admin.policies.CreatePolicyVersion(ctx, &pantherclawv1.CreatePolicyVersionRequest{
		Bundle: []byte(strings.Replace(bundle, `"reason": "REFUND_REVIEW"`, `"reason": "REFUND_REVIEW", "extra": true`, 1)),
	})
	wantCode(t, "an unknown member in a bundle", err, connect.CodeInvalidArgument)
	_, err = admin.policies.CreatePolicyVersion(ctx, &pantherclawv1.CreatePolicyVersionRequest{
		Bundle: []byte(strings.Replace(bundle, `action.params.amount`, `action.params.nope`, 1)),
	})
	wantCode(t, "a bundle that does not compile", err, connect.CodeInvalidArgument)
	created, err := admin.policies.CreatePolicyVersion(ctx, &pantherclawv1.CreatePolicyVersionRequest{Bundle: []byte(bundle)})
	if err != nil || created.GetVersion().GetState() != "DRAFT" || created.GetVersion().GetVersion() != 1 {
		t.Fatalf("CreatePolicyVersion = %v, %v", created, err)
	}
	id := created.GetVersion().GetId()
	_, err = sa.policies.PublishPolicyVersion(ctx, &pantherclawv1.PublishPolicyVersionRequest{Id: id})
	wantCode(t, "a service account publishes", err, connect.CodePermissionDenied)
	pub, err := admin.policies.PublishPolicyVersion(ctx, &pantherclawv1.PublishPolicyVersionRequest{Id: id})
	if err != nil || pub.GetVersion().GetState() != "PUBLISHED" || pub.GetVersion().GetPublishTime() == nil {
		t.Fatalf("PublishPolicyVersion = %v, %v", pub, err)
	}
	_, err = admin.policies.PublishPolicyVersion(ctx, &pantherclawv1.PublishPolicyVersionRequest{Id: id})
	wantCode(t, "publish twice", err, connect.CodeFailedPrecondition)
	got, err := sa.policies.GetPublishedPolicy(ctx, &pantherclawv1.GetPublishedPolicyRequest{})
	if err != nil || got.GetVersion().GetId() != id || len(got.GetVersion().GetBundle()) == 0 {
		t.Fatalf("GetPublishedPolicy = %v, %v", got, err)
	}
	versions, err := admin.policies.ListPolicyVersions(ctx, &pantherclawv1.ListPolicyVersionsRequest{})
	if err != nil || len(versions.GetVersions()) != 1 || len(versions.GetVersions()[0].GetBundle()) != 0 {
		t.Fatalf("ListPolicyVersions = %v, %v", versions, err)
	}

	// Facts: a person registers a provider for a service account; only that
	// account reports facts, and only the ones registered.
	providerSA, providerKey := s.serviceAccount(t, org, []string{"fact.write"}, td.RoleFactProvider)
	_, otherKey := s.serviceAccount(t, org, []string{"fact.write"}, td.RoleFactProvider)
	reg := &pantherclawv1.RegisterProviderRequest{
		Name: "crm", ServiceAccountId: providerSA.String(), Facts: []*pantherclawv1.FactDeclaration{{
			Name: "crm.customer.vip", Type: pantherclawv1.FactType_FACT_TYPE_BOOLEAN, SubjectType: "payments.charge",
			MaxLag: durationpb.New(time.Hour),
		}},
	}
	_, err = sa.facts.RegisterProvider(ctx, reg)
	wantCode(t, "a service account registers a provider", err, connect.CodePermissionDenied)
	prov, err := admin.facts.RegisterProvider(ctx, reg)
	if err != nil || prov.GetProvider().GetState() != pantherclawv1.ProviderState_PROVIDER_STATE_ACTIVE {
		t.Fatalf("RegisterProvider = %v, %v", prov, err)
	}
	reg.ServiceAccountId = ids.NewV7().String()
	reg.Name = "ghost"
	reg.Facts[0].Name = "crm.customer.tier"
	_, err = admin.facts.RegisterProvider(ctx, reg)
	wantCode(t, "a provider for an unknown service account", err, connect.CodeFailedPrecondition)

	obs := func(name string, at time.Time) *pantherclawv1.FactObservation {
		return &pantherclawv1.FactObservation{
			Name: name, SubjectType: "payments.charge", SubjectId: "ch_1", Value: []byte(`{"bool": true}`), ObserveTime: timestamppb.New(at),
		}
	}
	put, err := s.clients(providerKey).facts.PutFacts(ctx, &pantherclawv1.PutFactsRequest{Observations: []*pantherclawv1.FactObservation{
		obs("crm.customer.vip", time.Now()), obs("crm.customer.blocked", time.Now()), obs("crm.customer.vip", time.Now().Add(-2*time.Hour)),
	}})
	if err != nil || len(put.GetResults()) != 3 || !put.GetResults()[0].GetAccepted() ||
		put.GetResults()[1].GetCode() != "FACT_UNTRUSTED" || put.GetResults()[2].GetCode() != "FACT_STALE" {
		t.Fatalf("PutFacts = %v, %v", put, err)
	}
	_, err = s.clients(otherKey).facts.PutFacts(ctx, &pantherclawv1.PutFactsRequest{Observations: []*pantherclawv1.FactObservation{
		obs("crm.customer.vip", time.Now()),
	}})
	wantCode(t, "another service account reports a fact", err, connect.CodePermissionDenied)
	_, err = admin.facts.PutFacts(ctx, &pantherclawv1.PutFactsRequest{Observations: []*pantherclawv1.FactObservation{
		obs("crm.customer.vip", time.Now()),
	}})
	wantCode(t, "a person reports a fact", err, connect.CodePermissionDenied)
	facts, err := admin.facts.ListFacts(ctx, &pantherclawv1.ListFactsRequest{SubjectType: "payments.charge", SubjectId: "ch_1"})
	if err != nil || len(facts.GetFacts()) != 1 || facts.GetFacts()[0].GetName() != "crm.customer.vip" {
		t.Fatalf("ListFacts = %v, %v", facts, err)
	}
	if _, err := admin.facts.DisableProvider(ctx, &pantherclawv1.DisableProviderRequest{Id: prov.GetProvider().GetId()}); err != nil {
		t.Fatal(err)
	}
	facts, err = admin.facts.ListFacts(ctx, &pantherclawv1.ListFactsRequest{SubjectType: "payments.charge", SubjectId: "ch_1"})
	if err != nil || len(facts.GetFacts()) != 0 {
		t.Fatalf("ListFacts after disabling = %v, %v", facts, err)
	}
	provs, err := admin.facts.ListProviders(ctx, &pantherclawv1.ListProvidersRequest{IncludeDisabled: true})
	if err != nil || len(provs.GetProviders()) != 1 || provs.GetProviders()[0].GetState() != pantherclawv1.ProviderState_PROVIDER_STATE_DISABLED ||
		len(provs.GetProviders()[0].GetFacts()) != 1 {
		t.Fatalf("ListProviders = %v, %v", provs, err)
	}

	// Another org sees none of it.
	other := s.clients(s.login(t, s.org(t), "eve", td.RoleOrgAdmin, td.RolePolicyPublisher))
	_, err = other.packages.GetDefinition(ctx, &pantherclawv1.GetDefinitionRequest{Digest: digest})
	wantCode(t, "another org reads the definition", err, connect.CodeNotFound)
	_, err = other.policies.GetPolicyVersion(ctx, &pantherclawv1.GetPolicyVersionRequest{Id: id})
	wantCode(t, "another org reads the policy", err, connect.CodeNotFound)
	_, err = other.policies.PublishPolicyVersion(ctx, &pantherclawv1.PublishPolicyVersionRequest{Id: id})
	wantCode(t, "another org publishes the policy", err, connect.CodeNotFound)
	_, err = other.facts.DisableProvider(ctx, &pantherclawv1.DisableProviderRequest{Id: prov.GetProvider().GetId()})
	wantCode(t, "another org disables the provider", err, connect.CodeNotFound)
}

// passingGate stands in for the publish gate's validator and test runner:
// this test is about who may publish over the API, and the gate itself is
// tested in internal/policy (HR-230).
type passingGate struct{}

func (passingGate) Validate(context.Context, ids.OrgID, *pdomain.Bundle) (pdomain.ValidationResult, error) {
	return pdomain.ValidationResult{Passed: true}, nil
}

func (passingGate) Run(context.Context, ids.OrgID, *pdomain.Bundle) (pdomain.TestResult, error) {
	return pdomain.TestResult{Passed: true}, nil
}
