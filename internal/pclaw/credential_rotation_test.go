// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
)

type rotationServer struct {
	pantherclawv1connect.UnimplementedCredentialRotationServiceHandler
	seal    *pb.SealRotationCandidateRequest
	request *pb.RequestRotationRequest
}

func (s *rotationServer) RequestRotation(_ context.Context, r *pb.RequestRotationRequest) (*pb.RequestRotationResponse, error) {
	s.request = r
	return &pb.RequestRotationResponse{Rotation: &pb.CredentialRotation{Id: "r-1", State: "REQUESTED"}}, nil
}

func (s *rotationServer) SealRotationCandidate(_ context.Context, r *pb.SealRotationCandidateRequest) (*pb.SealRotationCandidateResponse, error) {
	s.seal = r
	return &pb.SealRotationCandidateResponse{Credential: &pb.ConnectionCredential{Id: "c-2"}}, nil
}

func (s *rotationServer) ActivateRotation(context.Context, *pb.ActivateRotationRequest) (*pb.ActivateRotationResponse, error) {
	return nil, connect.NewError(connect.CodePermissionDenied, "STEP_UP_REQUIRED")
}

// TestF831_RotationCommands: request sends the digest, seal uploads only
// sealed bytes bound to a GitHub App, and an activation the server refuses
// for its security key names the page.
//
// Covers: F831
func TestF831_RotationCommands(t *testing.T) {
	key, err := pccrypto.GenerateSealKey()
	if err != nil {
		t.Fatal(err)
	}
	srv := &rotationServer{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterConnectionServiceHandler(cs, &sealServer{key: key, fingerprint: fingerprintOf(key)})
	pantherclawv1connect.RegisterCredentialRotationServiceHandler(cs, srv)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})
	conn := "0192aaaa-bbbb-7ccc-8ddd-000000000002"

	digest := strings.Repeat("a", 64)
	if code, out, errs := run(t, env, "credential", "rotation", "request", conn, "--preview-digest", digest); code != 0 || srv.request.GetPreviewDigest() != digest {
		t.Fatalf("request = %d %q %q", code, out, errs)
	}
	if code, _, _ := run(t, env, "credential", "rotation", "request", conn); code == 0 {
		t.Fatal("request without a digest")
	}

	app, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "app.pem")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(app)}), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"credential", "rotation", "seal", "r-1", "--connection", conn, "--from-file", file, "--github-app", "Iv23liExample", "--installation", "7", "--account", "acme"}
	code, out, errs := run(t, env, args...)
	if code != 0 || srv.seal.GetRotationId() != "r-1" || srv.seal.GetCredential().GetKind() != domain.KindGitHubApp {
		t.Fatalf("seal = %d %q %q", code, out, errs)
	}
	if bytes.Contains(srv.seal.GetCredential().GetSealed(), []byte("PRIVATE KEY")) || strings.Contains(out+errs, "PRIVATE KEY") {
		t.Fatal("the key left in the clear")
	}

	if code, _, errs := run(t, env, "credential", "rotation", "activate", "r-1"); code == 0 || !strings.Contains(errs, "/integrations/credential-rotations/r-1") {
		t.Fatalf("activate = %d %q", code, errs)
	}
}
