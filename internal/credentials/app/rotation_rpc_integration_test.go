// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/katocxl/pantherclaw/internal/connections/adapters/connectionsrpc"
	"github.com/katocxl/pantherclaw/internal/credentials/app"
	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// audits counts a ledger kind in the org.
func (e *rotationEnv) audits(t *testing.T, kind string) int {
	t.Helper()
	var n int
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT count(*)::int FROM pc.ledger_entries WHERE kind = $1", kind).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// walk visits a message's fields and those of the messages it holds.
func walk(m protoreflect.MessageDescriptor, seen map[protoreflect.FullName]bool, visit func(protoreflect.FieldDescriptor)) {
	if seen[m.FullName()] || m.FullName() == "google.protobuf.Timestamp" {
		return
	}
	seen[m.FullName()] = true
	for i := range m.Fields().Len() {
		f := m.Fields().Get(i)
		visit(f)
		if f.Message() != nil {
			walk(f.Message(), seen, visit)
		}
	}
}

// TestHR553_RotationOverRPCKeepsItsGatesAndReturnsNoSecret: the RPCs refuse
// who the use cases refuse, confirm the preview, audit, and no response of
// the service can carry a key: no bytes field and no secret's name, and the
// sealed bytes do not come back.
//
// Covers: F831
func TestHR553_RotationOverRPCKeepsItsGatesAndReturnsNoSecret(t *testing.T) {
	e := newRotationEnv(t)
	h := connectionsrpc.NewRotations(e.svc)

	req := &pb.RequestRotationRequest{ConnectionId: e.conn.ID.String(), PreviewDigest: hex.EncodeToString(e.digest)}
	if _, err := h.RequestRotation(e.caller(td.KindUser, td.RoleViewer), req); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("a viewer: %v", err)
	}
	stale := &pb.RequestRotationRequest{ConnectionId: e.conn.ID.String(), PreviewDigest: strings.Repeat("0", 64)}
	if _, err := h.RequestRotation(e.person, stale); !is(err, app.ErrRotationPreview) {
		t.Fatalf("a stale preview: %v", err)
	}
	res, err := h.RequestRotation(e.person, req)
	if err != nil {
		t.Fatal(err)
	}
	if res.GetRotation().GetState() != string(domain.RotationRequested) {
		t.Fatalf("rotation: %v", res.GetRotation())
	}
	if n := e.audits(t, "audit.credential.rotation_requested"); n != 1 {
		t.Fatalf("request audits: %d", n)
	}

	_, in := e.seal(t, `{"v":1,"new":true}`)
	put := &pb.PutCredentialRequest{
		ConnectionId: in.Connection.String(), Version: in.Version, BrokerKeyId: in.BrokerKey.String(), Sealed: in.Sealed,
		AllowedHosts: in.AllowedHosts, Header: in.Header, Scheme: in.Scheme, Kind: domain.KindGitHubApp,
		Github: &pb.GitHubInstallation{AppClientId: rotationGitHub.AppClientID, InstallationId: rotationGitHub.ID, AccountLogin: rotationGitHub.Account},
	}
	sealed, err := h.SealRotationCandidate(e.person, &pb.SealRotationCandidateRequest{RotationId: res.GetRotation().GetId(), Credential: put})
	if err != nil {
		t.Fatal(err)
	}
	if sealed.GetCredential().GetState() != pb.SealedCredentialState_SEALED_CREDENTIAL_STATE_CANDIDATE {
		t.Fatalf("state: %v", sealed.GetCredential().GetState())
	}
	wire, err := proto.Marshal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, in.Sealed) {
		t.Fatal("the sealed bytes came back")
	}

	methods := pb.File_pantherclaw_v1_credential_rotation_proto.Services().Get(0).Methods()
	for i := range methods.Len() {
		walk(methods.Get(i).Output(), map[protoreflect.FullName]bool{}, func(f protoreflect.FieldDescriptor) {
			name := strings.ToLower(string(f.Name()))
			if f.Kind() == protoreflect.BytesKind || strings.Contains(name, "secret") || strings.Contains(name, "sealed") || strings.Contains(name, "private") {
				t.Errorf("%s can carry a secret: %s", methods.Get(i).Name(), f.FullName())
			}
		})
	}
}

// TestT240_RotationRPCSkipsStepUp: over RPC neither activating nor rolling
// back can skip the security key, for a person who holds every other
// requirement: both refuse and change nothing.
//
// Covers: F831
func TestT240_RotationRPCSkipsStepUp(t *testing.T) {
	e := newRotationEnv(t)
	h := connectionsrpc.NewRotations(e.svc)
	r := e.tested(t)

	if _, err := h.ActivateRotation(e.person, &pb.ActivateRotationRequest{Id: r.ID.String()}); !stepup.Is(err) {
		t.Fatalf("activation over RPC: %v", err)
	}
	if got := e.get(t, r.ID); got.State != r.State || got.ActivatedAt != nil {
		t.Fatalf("after the refusal: %+v", got)
	}
	if n := e.audits(t, "audit.credential.rotation_activated"); n != 0 {
		t.Fatalf("activation audits: %d", n)
	}

	if _, err := e.svc.ActivateRotation(e.person, r.ID, e.stepUp()); err != nil {
		t.Fatal(err)
	}
	active := e.get(t, r.ID)
	if _, err := h.RollBackRotation(e.person, &pb.RollBackRotationRequest{Id: r.ID.String(), Reason: "dispatches fail"}); !stepup.Is(err) {
		t.Fatalf("rollback over RPC: %v", err)
	}
	if got := e.get(t, r.ID); got.State != active.State {
		t.Fatalf("after the refusal: %+v", got)
	}
	if n := e.audits(t, "audit.credential.rotation_rolled_back"); n != 0 {
		t.Fatalf("rollback audits: %d", n)
	}
}
