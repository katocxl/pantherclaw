// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Keys of memRepo, with the semantics the Keys port promises.

func (r *memRepo) keyByID(org ids.OrgID, id ids.UUID) *SigningKey {
	for k, v := range r.keys {
		if strings.HasPrefix(k, org.String()) && v.ID == id {
			return v
		}
	}
	return nil
}

func (r *memRepo) SigningKey(_ context.Context, org ids.OrgID, kid string) (SigningKey, error) {
	k, ok := r.keys[org.String()+kid]
	if !ok {
		return SigningKey{}, ErrMissing
	}
	return *k, nil
}

func (r *memRepo) ListSigningKeys(_ context.Context, org ids.OrgID) ([]SigningKey, error) {
	var out []SigningKey
	for k, v := range r.keys {
		if strings.HasPrefix(k, org.String()) {
			out = append(out, *v)
		}
	}
	return out, nil
}

func (r *memRepo) RegisterSigningKey(ctx context.Context, org ids.OrgID, k SigningKey, _ *audit.Event) error {
	if _, ok := r.keys[org.String()+k.KID]; ok {
		return ErrKeyRegistered
	}
	keys, _ := r.ListSigningKeys(ctx, org)
	if len(slices.DeleteFunc(keys, func(k SigningKey) bool { return k.State != KeyActive })) >= MaxActiveSigningKeys {
		return ErrKeyLimit
	}
	r.keys[org.String()+k.KID] = &k
	return nil
}

func (r *memRepo) RevokeSigningKey(_ context.Context, org ids.OrgID, kid string, reason RevokeReason, by string, _ *audit.Event) ([]VersionChange, error) {
	k, ok := r.keys[org.String()+kid]
	if !ok || k.State != KeyActive {
		return nil, ErrConflict
	}
	k.State, k.Reason, k.RevokedBy = KeyRevoked, reason, by
	if reason != RevokeCompromised {
		return nil, nil
	}
	r.epochs[org]++
	var moved []VersionChange
	for vk, signer := range r.signedBy {
		if signer == nil || *signer != k.ID || !strings.HasPrefix(vk, org.String()) {
			continue
		}
		if to, ok := Withdrawn(r.states[vk]); ok {
			moved = append(moved, VersionChange{Name: vk, From: r.states[vk], To: to})
			r.states[vk] = to
		}
	}
	return moved, nil
}

func (r *memRepo) VersionSigner(_ context.Context, org ids.OrgID, pkg, version string) (*SigningKey, error) {
	signer, ok := r.signedBy[org.String()+pkg+version]
	if !ok {
		return nil, ErrMissing
	}
	if signer == nil {
		return nil, nil
	}
	return r.keyByID(org, *signer), nil
}

// ListVersions and DefinitionByDigest make memRepo the Admin's Reads.
func (r *memRepo) ListVersions(_ context.Context, org ids.OrgID, name string) ([]VersionInfo, error) {
	var out []VersionInfo
	for vk, s := range r.states {
		if rest, ok := strings.CutPrefix(vk, org.String()+name); ok && strings.Count(rest, ".") == 2 {
			out = append(out, VersionInfo{Name: name, Version: rest, State: s})
		}
	}
	return out, nil
}

func (r *memRepo) DefinitionByDigest(context.Context, ids.OrgID, string) (DefinitionInfo, error) {
	return DefinitionInfo{}, ErrNotFound
}

type allowAll struct{}

func (allowAll) Require(tapp.Caller, tdomain.Permission, tdomain.Path) error { return nil }

type ents struct{ e billing.Entitlements }

func (e *ents) Current(context.Context) (billing.Entitlements, error) { return e.e, nil }

var team = billing.Entitlements{Edition: billing.Team, Status: billing.StatusValid}

// orgFixture is an Admin over memRepo with an org package-signing key.
type orgFixture struct {
	*fixture
	admin *Admin
	ents  *ents
	key   *jws.Signer
}

func newOrgFixture(t *testing.T) *orgFixture {
	t.Helper()
	f := newFixture(t)
	f.im.Keys = f.repo
	e := &ents{e: team}
	return &orgFixture{fixture: f, ents: e, key: newOrgKey(t), admin: &Admin{Importer: f.im, Reads: f.repo, Authz: allowAll{}, Ents: e}}
}

func newOrgKey(t *testing.T) *jws.Signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jws.NewSigner(trust.OrgKID(pub), priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func asUser(org ids.OrgID) context.Context {
	return tapp.WithCaller(context.Background(), tapp.Caller{Subject: tdomain.Subject{Org: org, Principal: tdomain.PrincipalRef{Kind: tdomain.KindUser, ID: ids.NewV7()}}})
}

func asServiceAccount(org ids.OrgID) context.Context {
	return tapp.WithCaller(context.Background(), tapp.Caller{Subject: tdomain.Subject{Org: org, Principal: tdomain.PrincipalRef{Kind: tdomain.KindServiceAccount, ID: ids.NewV7()}}})
}

func jwkOf(t *testing.T, s *jws.Signer) []byte {
	t.Helper()
	b, err := json.Marshal(jws.PublicJWK(s.Public(), s.KeyID()))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (f *orgFixture) register(org ids.OrgID, s *jws.Signer) error {
	_, err := f.admin.RegisterKey(asUser(org), "release key", jwkOf(f.t, s))
	return err
}

// orgPackage is the reference package renamed into the org's namespace.
// With ownOps its operations are renamed too; without, it redefines the
// PantherClaw operations.
func (f *orgFixture) orgPackage(version string, ownOps bool) []byte {
	raw := bytes.Replace(f.files["1.0.0"], []byte("name: pc.mock-payments"), []byte("name: acme.payments"), 1)
	raw = bytes.Replace(raw, []byte("version: 1.0.0"), []byte("version: "+version), 1)
	if ownOps {
		raw = bytes.ReplaceAll(raw, []byte("payments.refund."), []byte("acmepay.refund."))
		raw = bytes.ReplaceAll(raw, []byte("payments.account."), []byte("acmepay.account."))
	}
	return raw
}

func signTargets(t *testing.T, s *jws.Signer, v int64, files map[string][]byte) string {
	t.Helper()
	tg := trust.Targets{Version: v, Expires: "2027-04-08T00:00:00Z", Targets: map[string]trust.Target{}}
	for key, raw := range files {
		sum := sha256.Sum256(raw)
		tg.Targets[key] = trust.Target{Length: int64(len(raw)), Hashes: map[string]string{"sha256": hex.EncodeToString(sum[:])}}
	}
	doc, err := trust.Sign(tg, s)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func (f *orgFixture) importOrg(org ids.OrgID, s *jws.Signer, v int64, version string, raw []byte) (VersionInfo, error) {
	doc := signTargets(f.t, s, v, map[string][]byte{trust.Key("acme.payments", version): raw})
	got, _, err := f.admin.Import(asUser(org), "acme.payments", version, doc, raw)
	return got, err
}

func reason(err error) string {
	if e, ok := errors.AsType[*pcerr.Error](err); ok {
		return e.Reason()
	}
	return ""
}

func TestHR162_OrgSignedPackagesHaveTheirOwnRollbackState(t *testing.T) {
	f := newOrgFixture(t)
	if err := f.register(f.org, f.key); err != nil {
		t.Fatal(err)
	}
	raw := f.orgPackage("1.0.0", true)
	v, err := f.importOrg(f.org, f.key, 1, "1.0.0", raw)
	if err != nil {
		t.Fatal(err)
	}
	if v.State != domain.StateReviewed {
		t.Fatalf("an org-signed version starts %s, want REVIEWED (activation is separate)", v.State)
	}
	k, _ := f.repo.SigningKey(context.Background(), f.org, f.key.KeyID())
	if k.Metadata == nil || k.Metadata.Version != 1 || f.repo.meta[f.org] != nil {
		t.Fatalf("the key's metadata advanced to %+v, root state %+v", k.Metadata, f.repo.meta[f.org])
	}
	// PantherClaw's root keeps its own, independent version sequence.
	if _, err := f.importVersion("1.0.0", f.targets(7, "1.0.0")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.importOrg(f.org, f.key, 2, "1.1.0", f.orgPackage("1.1.0", true)); err != nil {
		t.Fatalf("org targets version 2 after root version 7: %v", err)
	}
	// Rollback under the org key: an older version, or other content under
	// the same version.
	if _, err := f.importOrg(f.org, f.key, 1, "1.2.0", f.orgPackage("1.2.0", true)); reason(err) != "PACKAGE_METADATA_ROLLBACK" {
		t.Fatalf("older org metadata: %v", err)
	}
	if _, err := f.importOrg(f.org, f.key, 2, "1.2.0", f.orgPackage("1.2.0", true)); reason(err) != "PACKAGE_METADATA_ROLLBACK" {
		t.Fatalf("different org metadata under the same version: %v", err)
	}
}

func TestT056_OnlyTheOrgsOwnActiveKeysVerify(t *testing.T) {
	f := newOrgFixture(t)
	raw := f.orgPackage("1.0.0", true)
	if _, err := f.importOrg(f.org, f.key, 1, "1.0.0", raw); reason(err) != "PACKAGE_UNTRUSTED" {
		t.Fatalf("unregistered key: %v", err)
	}
	other := ids.New[ids.Org]()
	if err := f.register(other, f.key); err != nil {
		t.Fatal(err)
	}
	if _, err := f.importOrg(f.org, f.key, 1, "1.0.0", raw); reason(err) != "PACKAGE_UNTRUSTED" {
		t.Fatalf("a key registered by another org: %v", err)
	}
	if err := f.register(f.org, f.key); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.admin.RevokeKey(asUser(f.org), f.key.KeyID(), RevokeRotated); err != nil {
		t.Fatal(err)
	}
	if _, err := f.importOrg(f.org, f.key, 1, "1.0.0", raw); reason(err) != "PACKAGE_UNTRUSTED" {
		t.Fatalf("a revoked key: %v", err)
	}
	// An importer without org keys trusts only package roots.
	f.im.Keys = nil
	if _, err := f.importOrg(other, f.key, 1, "1.0.0", raw); reason(err) != "PACKAGE_UNTRUSTED" {
		t.Fatalf("no org keys configured: %v", err)
	}
	// A root kid never routes to the org's keys, so naming the root does not
	// skip the edition check or the root's signature.
	f.im.Keys, f.ents.e = f.repo, billing.CommunityEntitlements()
	if _, _, err := f.admin.Import(asUser(f.org), "pc.mock-payments", "1.0.0", f.targets(1, "1.0.0"), f.files["1.0.0"]); err != nil {
		t.Fatalf("package root on Community: %v", err)
	}
}

func TestT056_OrgKeysNeverRedefinePantherClawOperations(t *testing.T) {
	f := newOrgFixture(t)
	if err := f.register(f.org, f.key); err != nil {
		t.Fatal(err)
	}
	if _, err := f.importVersion("1.0.0", f.targets(1, "1.0.0")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.importOrg(f.org, f.key, 1, "1.0.0", f.orgPackage("1.0.0", false)); reason(err) != "PACKAGE_OPERATION_TAKEN" {
		t.Fatalf("org package redefining payments.refund.create: %v", err)
	}
	if _, err := f.importOrg(f.org, f.key, 1, "1.0.0", f.orgPackage("1.0.0", true)); err != nil {
		t.Fatalf("org package with its own operations: %v", err)
	}

	// The reverse: an org package first, then PantherClaw's.
	g := newOrgFixture(t)
	if err := g.register(g.org, g.key); err != nil {
		t.Fatal(err)
	}
	if _, err := g.importOrg(g.org, g.key, 1, "1.0.0", g.orgPackage("1.0.0", false)); err != nil {
		t.Fatal(err)
	}
	if _, err := g.importVersion("1.0.0", g.targets(1, "1.0.0")); !errors.Is(err, ErrOperationTaken) {
		t.Fatalf("PantherClaw package after an org package with its operations: %v", err)
	}
	// Retiring the org's version frees the operations.
	if err := g.im.Transition(context.Background(), g.org, "acme.payments", "1.0.0", domain.StateRetired, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := g.importVersion("1.0.0", g.targets(1, "1.0.0")); err != nil {
		t.Fatal(err)
	}
}

func TestHR162_RegisteringAKeyNeedsAPersonTeamAndAValidKey(t *testing.T) {
	f := newOrgFixture(t)
	jwk := jwkOf(t, f.key)
	if _, err := f.admin.RegisterKey(asServiceAccount(f.org), "ci", jwk); !errors.Is(err, ErrHumanOnly) {
		t.Fatalf("service account: %v", err)
	}
	f.ents.e = billing.CommunityEntitlements()
	if _, err := f.admin.RegisterKey(asUser(f.org), "release", jwk); !errors.Is(err, ErrEditionRequired) {
		t.Fatalf("Community: %v", err)
	}
	f.ents.e = team
	for name, in := range map[string]struct {
		name string
		jwk  []byte
	}{
		"empty name":   {"", jwk},
		"long name":    {strings.Repeat("k", 65), jwk},
		"control char": {"release\nkey", jwk},
		"bidi":         {"release" + string(rune(0x202e)) + "key", jwk},
		"private key":  {"release", []byte(`{"kty":"OKP","crv":"Ed25519","x":"` + jws.PublicJWK(f.key.Public(), "").X + `","d":"c2VjcmV0"}`)},
		"root kid":     {"release", mustJSON(t, jws.PublicJWK(f.key.Public(), trust.RootKID(f.key.Public())))},
	} {
		if _, err := f.admin.RegisterKey(asUser(f.org), in.name, in.jwk); reason(err) != "SIGNING_KEY_INVALID" {
			t.Errorf("%s: %v", name, err)
		}
	}
	k, err := f.admin.RegisterKey(asUser(f.org), "release 2026", jwk)
	if err != nil || k.State != KeyActive || k.KID != f.key.KeyID() || !strings.HasPrefix(k.CreatedBy, "user:") {
		t.Fatalf("register: %+v %v", k, err)
	}
	if _, err := f.admin.RegisterKey(asUser(f.org), "again", jwk); reason(err) != "SIGNING_KEY_EXISTS" {
		t.Fatalf("duplicate: %v", err)
	}
	for range MaxActiveSigningKeys - 1 {
		if err := f.register(f.org, newOrgKey(t)); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.register(f.org, newOrgKey(t)); reason(err) != "SIGNING_KEY_LIMIT" {
		t.Fatalf("one key over the limit: %v", err)
	}
	// Revoking frees a place, but the revoked key never comes back.
	if _, _, err := f.admin.RevokeKey(asServiceAccount(f.org), f.key.KeyID(), RevokeRotated); err != nil {
		t.Fatalf("a service account may revoke: %v", err)
	}
	if err := f.register(f.org, f.key); reason(err) != "SIGNING_KEY_EXISTS" {
		t.Fatalf("re-registering a revoked key: %v", err)
	}
	if err := f.register(f.org, newOrgKey(t)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.admin.RevokeKey(asUser(f.org), f.key.KeyID(), RevokeRotated); reason(err) != "SIGNING_KEY_REVOKED" {
		t.Fatalf("revoking twice: %v", err)
	}
	if _, _, err := f.admin.RevokeKey(asUser(f.org), "org-packages-nope", RevokeRotated); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("unknown key: %v", err)
	}
	if _, _, err := f.admin.RevokeKey(asUser(f.org), f.key.KeyID(), "LOST"); reason(err) != "SIGNING_KEY_INVALID" {
		t.Fatalf("unknown reason: %v", err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestHR162_ALapsedLicenceBlocksNewOrgPackagesOnly(t *testing.T) {
	f := newOrgFixture(t)
	if err := f.register(f.org, f.key); err != nil {
		t.Fatal(err)
	}
	if _, err := f.importOrg(f.org, f.key, 1, "1.0.0", f.orgPackage("1.0.0", true)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.importOrg(f.org, f.key, 2, "1.1.0", f.orgPackage("1.1.0", true)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Transition(asUser(f.org), "acme.payments", "1.0.0", domain.StateActive); err != nil {
		t.Fatal(err)
	}
	f.ents.e = billing.CommunityEntitlements()
	if _, err := f.importOrg(f.org, f.key, 3, "1.2.0", f.orgPackage("1.2.0", true)); !errors.Is(err, ErrEditionRequired) {
		t.Fatalf("org-signed import on Community: %v", err)
	}
	if s, _ := f.repo.State(context.Background(), f.org, "acme.payments", "1.0.0"); s != domain.StateActive {
		t.Fatalf("an active org package went %s on Community", s)
	}
	if _, err := f.admin.Transition(asUser(f.org), "acme.payments", "1.1.0", domain.StateActive); err != nil {
		t.Fatalf("activating an already-imported version on Community: %v", err)
	}
	if keys, err := f.admin.ListKeys(asUser(f.org)); err != nil || len(keys) != 1 {
		t.Fatalf("list on Community: %v %v", keys, err)
	}
	if _, _, err := f.admin.RevokeKey(asUser(f.org), f.key.KeyID(), RevokeRotated); err != nil {
		t.Fatalf("revoke on Community: %v", err)
	}
	f.admin.Ents = nil
	if _, err := f.admin.RegisterKey(asUser(f.org), "release", jwkOf(t, newOrgKey(t))); !errors.Is(err, ErrEditionRequired) {
		t.Fatalf("no entitlements wired: %v", err)
	}
}

func TestT056_RevokingACompromisedKeyWithdrawsWhatItSigned(t *testing.T) {
	f := newOrgFixture(t)
	ctx := asUser(f.org)
	if err := f.register(f.org, f.key); err != nil {
		t.Fatal(err)
	}
	for i, v := range []string{"1.0.0", "1.1.0"} {
		if _, err := f.importOrg(f.org, f.key, int64(i+1), v, f.orgPackage(v, true)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.admin.Transition(ctx, "acme.payments", "1.0.0", domain.StateActive); err != nil {
		t.Fatal(err)
	}
	if _, err := f.importVersion("1.0.0", f.targets(1, "1.0.0")); err != nil {
		t.Fatal(err)
	}
	k, moved, err := f.admin.RevokeKey(ctx, f.key.KeyID(), RevokeCompromised)
	if err != nil {
		t.Fatal(err)
	}
	if k.State != KeyRevoked || k.Reason != RevokeCompromised || len(moved) != 2 || f.repo.epochs[f.org] != 1 {
		t.Fatalf("revoked %+v, moved %+v, epoch %d", k, moved, f.repo.epochs[f.org])
	}
	for v, want := range map[string]domain.State{"1.0.0": domain.StateQuarantined, "1.1.0": domain.StateRetired} {
		if s, _ := f.repo.State(context.Background(), f.org, "acme.payments", v); s != want {
			t.Errorf("acme.payments@%s is %s, want %s", v, s, want)
		}
	}
	if s, _ := f.repo.State(context.Background(), f.org, "pc.mock-payments", "1.0.0"); s != domain.StateReviewed {
		t.Fatalf("a root-signed version moved to %s", s)
	}
	// A quarantined version may go back to review, but never to ACTIVE.
	if _, err := f.admin.Transition(ctx, "acme.payments", "1.0.0", domain.StateReviewed); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Transition(ctx, "acme.payments", "1.0.0", domain.StateActive); reason(err) != "PACKAGE_KEY_COMPROMISED" {
		t.Fatalf("re-activating a compromised key's version: %v", err)
	}
	// PantherClaw's versions are unaffected.
	if _, err := f.admin.Transition(ctx, "pc.mock-payments", "1.0.0", domain.StateActive); err != nil {
		t.Fatal(err)
	}
}

func TestHR162_RotatedKeysVersionsKeepWorking(t *testing.T) {
	f := newOrgFixture(t)
	ctx := asUser(f.org)
	if err := f.register(f.org, f.key); err != nil {
		t.Fatal(err)
	}
	for i, v := range []string{"1.0.0", "1.1.0"} {
		if _, err := f.importOrg(f.org, f.key, int64(i+1), v, f.orgPackage(v, true)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.admin.Transition(ctx, "acme.payments", "1.0.0", domain.StateActive); err != nil {
		t.Fatal(err)
	}
	if _, moved, err := f.admin.RevokeKey(ctx, f.key.KeyID(), RevokeRotated); err != nil || len(moved) != 0 || f.repo.epochs[f.org] != 0 {
		t.Fatalf("rotation moved %v (%v), epoch %d", moved, err, f.repo.epochs[f.org])
	}
	if _, err := f.admin.Transition(ctx, "acme.payments", "1.1.0", domain.StateActive); err != nil {
		t.Fatalf("activating a rotated key's version: %v", err)
	}
	// The new key starts its own metadata sequence.
	next := newOrgKey(t)
	if err := f.register(f.org, next); err != nil {
		t.Fatal(err)
	}
	if _, err := f.importOrg(f.org, next, 1, "1.2.0", f.orgPackage("1.2.0", true)); err != nil {
		t.Fatal(err)
	}
}

func TestWithdrawnFollowsTheLifecycle(t *testing.T) {
	for _, s := range []domain.State{
		domain.StateUnclassified, domain.StateDraft, domain.StateReviewed, domain.StateActive,
		domain.StateStale, domain.StateQuarantined, domain.StateRetired,
	} {
		to, moves := Withdrawn(s)
		if moves && domain.Lifecycle.Check(s, to) != nil {
			t.Errorf("%s → %s is not a lifecycle transition", s, to)
		}
		if to.Usable() || (!moves && s.Usable()) {
			t.Errorf("%s: a compromised key's version stays usable (%s)", s, to)
		}
	}
}
