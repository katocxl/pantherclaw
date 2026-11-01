// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
	"github.com/katocxl/pantherclaw/internal/platform/statemachine"
)

// memRepo is an in-memory Repository (and Keys, orgkeys_test.go) with the
// same conditional semantics.
type memRepo struct {
	meta   map[ids.OrgID]*trust.State
	pins   map[string]domain.Pin
	states map[string]domain.State
	files  map[string][]byte
	// Org package-signing keys (HR-162), by org and kid; the key that
	// signed each version (nil: a package root); each version's operations.
	keys     map[string]*SigningKey
	signedBy map[string]*ids.UUID
	ops      map[string][]string
	epochs   map[ids.OrgID]int
}

func newRepo() *memRepo {
	return &memRepo{
		meta: map[ids.OrgID]*trust.State{}, pins: map[string]domain.Pin{}, states: map[string]domain.State{}, files: map[string][]byte{},
		keys: map[string]*SigningKey{}, signedBy: map[string]*ids.UUID{}, ops: map[string][]string{}, epochs: map[ids.OrgID]int{},
	}
}

func (r *memRepo) TrustedMetadata(_ context.Context, org ids.OrgID) (*trust.State, error) {
	return r.meta[org], nil
}

func (r *memRepo) CurrentPin(_ context.Context, org ids.OrgID, pkg string) (*domain.Pin, error) {
	p, ok := r.pins[org.String()+pkg]
	if !ok {
		return nil, nil
	}
	return &p, nil
}

func (r *memRepo) Import(ctx context.Context, org ids.OrgID, rec Record) error {
	cur, _ := r.CurrentPin(ctx, org, rec.Pin.Package)
	prev := r.meta[org]
	var key *SigningKey
	if rec.SigningKey != nil {
		if key = r.keyByID(org, *rec.SigningKey); key == nil || key.State != KeyActive {
			return ErrConflict
		}
		prev = key.Metadata
	}
	if (prev == nil) != (rec.PreviousMetadata == nil) || (prev != nil && *prev != *rec.PreviousMetadata) ||
		(cur == nil) != (rec.PreviousPin == nil) || (cur != nil && *cur != *rec.PreviousPin) {
		return ErrConflict
	}
	var ops []string
	for _, d := range rec.Package.Definitions {
		ops = append(ops, d.Operation)
	}
	for vk, theirs := range r.ops {
		if !strings.HasPrefix(vk, org.String()) || r.states[vk] == domain.StateRetired || (r.signedBy[vk] == nil) == (rec.SigningKey == nil) {
			continue
		}
		for _, op := range ops {
			if slices.Contains(theirs, op) {
				return ErrOperationTaken
			}
		}
	}
	meta := rec.Metadata
	if key != nil {
		key.Metadata = &meta
	} else {
		r.meta[org] = &meta
	}
	vk := org.String() + rec.Pin.Package + rec.Pin.Version
	r.pins[org.String()+rec.Pin.Package] = rec.Pin
	r.states[vk] = rec.State
	r.signedBy[vk] = rec.SigningKey
	r.ops[vk] = ops
	r.files[rec.FileDigest] = rec.Raw
	return nil
}

func (r *memRepo) State(_ context.Context, org ids.OrgID, pkg, version string) (domain.State, error) {
	s, ok := r.states[org.String()+pkg+version]
	if !ok {
		return "", errors.New("not imported")
	}
	return s, nil
}

func (r *memRepo) Transition(_ context.Context, org ids.OrgID, pkg, version string, from, to domain.State, _ *audit.Event) error {
	key := org.String() + pkg + version
	if r.states[key] != from {
		return ErrConflict
	}
	r.states[key] = to
	return nil
}

type fixture struct {
	t      *testing.T
	signer *jws.Signer
	im     *Importer
	repo   *memRepo
	org    ids.OrgID
	files  map[string][]byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	priv, kid, err := rootkey.Generate(rootkey.PurposePackages)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := jws.NewSigner(kid, priv)
	raw, err := os.ReadFile("../../../packages/mock-payments/package.yaml")
	if err != nil {
		t.Fatal(err)
	}
	repo := newRepo()
	return &fixture{
		t: t, signer: s, repo: repo, org: ids.New[ids.Org](),
		im:    &Importer{Roots: trust.Roots{kid: s.Public()}, Repo: repo, Clock: clock.NewFake(time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC))},
		files: map[string][]byte{"1.0.0": raw, "1.1.0": bytes.Replace(raw, []byte("version: 1.0.0"), []byte("version: 1.1.0"), 1)},
	}
}

// targets signs metadata version v listing the given package versions.
func (f *fixture) targets(v int64, versions ...string) string {
	tg := trust.Targets{Version: v, Expires: "2027-04-08T00:00:00Z", Targets: map[string]trust.Target{}}
	for _, ver := range versions {
		sum := sha256.Sum256(f.files[ver])
		tg.Targets[trust.Key("pc.mock-payments", ver)] = trust.Target{
			Length: int64(len(f.files[ver])), Hashes: map[string]string{"sha256": hex.EncodeToString(sum[:])},
		}
	}
	doc, err := trust.Sign(tg, f.signer)
	if err != nil {
		f.t.Fatal(err)
	}
	return doc
}

func (f *fixture) importVersion(version, targets string) (Result, error) {
	return f.im.Import(context.Background(), f.org, "pc.mock-payments", version, targets, f.files[version], nil)
}

func TestHR123_ImportVerifiesPinsAndStartsReviewed(t *testing.T) {
	f := newFixture(t)
	res, err := f.importVersion("1.0.0", f.targets(1, "1.0.0"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Unchanged || res.Pin.Version != "1.0.0" || res.Package.Definitions[0].Digest == "" {
		t.Fatalf("result %+v", res)
	}
	if s, _ := f.repo.State(context.Background(), f.org, "pc.mock-payments", "1.0.0"); s != domain.StateReviewed {
		t.Fatalf("a new version starts %s, want REVIEWED (activation is separate, F395)", s)
	}
	again, err := f.importVersion("1.0.0", f.targets(1, "1.0.0"))
	if err != nil || !again.Unchanged {
		t.Fatalf("re-import: %+v %v", again, err)
	}
	if _, err := f.importVersion("1.1.0", f.targets(2, "1.0.0", "1.1.0")); err != nil {
		t.Fatal(err)
	}
	// Downgrade attempts: an older package under newer metadata, then
	// older metadata.
	if _, err := f.importVersion("1.0.0", f.targets(3, "1.0.0", "1.1.0")); !errors.Is(err, domain.ErrPinRollback) {
		t.Fatalf("package downgrade: %v, want ErrPinRollback", err)
	}
	if _, err := f.importVersion("1.1.0", f.targets(1, "1.1.0")); !errors.Is(err, trust.ErrRollback) {
		t.Fatalf("metadata rollback: %v, want ErrRollback", err)
	}
}

func TestT036_ImportRefusesUnsignedOrSwappedBytes(t *testing.T) {
	f := newFixture(t)
	doc := f.targets(1, "1.0.0")
	tampered := bytes.Replace(f.files["1.0.0"], []byte("max: \"1000000\""), []byte("max: \"9999999\""), 1)
	if _, err := f.im.Import(context.Background(), f.org, "pc.mock-payments", "1.0.0", doc, tampered, nil); !errors.Is(err, trust.ErrUntrusted) {
		t.Fatalf("tampered bytes: %v", err)
	}
	// Bytes signed as 1.0.0 but declaring 1.1.0 inside.
	f.files["1.0.0"] = f.files["1.1.0"]
	if _, err := f.importVersion("1.0.0", f.targets(2, "1.0.0")); !errors.Is(err, trust.ErrUntrusted) {
		t.Fatalf("name/version mismatch: %v", err)
	}
	if len(f.repo.files) != 0 || len(f.repo.meta) != 0 {
		t.Fatal("nothing may be stored after a failed import")
	}
	f.im.Clock = clock.NewFake(time.Date(2027, 4, 8, 0, 0, 0, 0, time.UTC))
	if _, err := f.importVersion("1.1.0", f.targets(3, "1.1.0")); !errors.Is(err, trust.ErrExpired) {
		t.Fatalf("expired metadata: %v", err)
	}
}

// A REVIEWED version reaches QUARANTINED only through a server's revoke, which
// moves it in its own transaction (G0 M24 D267): by hand it stays illegal.
func TestF875_NoOneQuarantinesAReviewedVersionByHand(t *testing.T) {
	f := newFixture(t)
	if _, err := f.importVersion("1.0.0", f.targets(1, "1.0.0")); err != nil {
		t.Fatal(err)
	}
	err := f.im.Transition(context.Background(), f.org, "pc.mock-payments", "1.0.0", domain.StateQuarantined, nil)
	if !errors.Is(err, statemachine.ErrIllegalTransition) {
		t.Fatalf("REVIEWED → QUARANTINED: %v", err)
	}
}

func TestTransitionFollowsTheLifecycle(t *testing.T) {
	f := newFixture(t)
	if _, err := f.importVersion("1.0.0", f.targets(1, "1.0.0")); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := f.im.Transition(ctx, f.org, "pc.mock-payments", "1.0.0", domain.StateActive, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.im.Transition(ctx, f.org, "pc.mock-payments", "1.0.0", domain.StateDraft, nil); !errors.Is(err, statemachine.ErrIllegalTransition) {
		t.Fatalf("ACTIVE → DRAFT: %v", err)
	}
	if err := f.im.Transition(ctx, f.org, "pc.mock-payments", "1.0.0", domain.StateQuarantined, nil); err != nil {
		t.Fatal(err)
	}
}
