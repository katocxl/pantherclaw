// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
)

// sealServer hands out a real broker key and keeps what is uploaded.
type sealServer struct {
	pantherclawv1connect.UnimplementedConnectionServiceHandler
	key         *pccrypto.SealPrivateKey
	fingerprint string
	put         *pantherclawv1.PutCredentialRequest
	// hosts, header and scheme override the defaults (tests of other kinds).
	hosts          []string
	header, scheme string
}

func (s *sealServer) GetSealingKey(_ context.Context, req *pantherclawv1.GetSealingKeyRequest) (*pantherclawv1.GetSealingKeyResponse, error) {
	pub := s.key.PublicKey().Bytes()
	hosts, header, scheme := s.hosts, s.header, s.scheme
	if hosts == nil {
		hosts, header, scheme = []string{"payments.example.test"}, "Authorization", "Bearer"
	}
	return &pantherclawv1.GetSealingKeyResponse{
		OrgId: "0192aaaa-bbbb-7ccc-8ddd-000000000001", ConnectionId: req.GetConnectionId(), Version: 2,
		BrokerKeyId: "0192aaaa-bbbb-7ccc-8ddd-000000000003", PublicKey: pub, Fingerprint: s.fingerprint,
		GatewayId: "0192aaaa-bbbb-7ccc-8ddd-000000000004", AllowedHosts: hosts,
		Header: header, Scheme: scheme,
	}, nil
}

func (s *sealServer) PutCredential(_ context.Context, req *pantherclawv1.PutCredentialRequest) (*pantherclawv1.PutCredentialResponse, error) {
	s.put = req
	return &pantherclawv1.PutCredentialResponse{Credential: &pantherclawv1.ConnectionCredential{Version: req.GetVersion()}}, nil
}

func fingerprintOf(k *pccrypto.SealPrivateKey) string {
	sum := sha256.Sum256(k.PublicKey().Bytes())
	return "sha256:" + hex.EncodeToString(sum[:])
}

// TestHR060_SealEncryptsLocallyAndUploadsOnlySealedBytes: pclaw seal sends
// the server nothing it could open, binds exactly what GetSealingKey said,
// never prints the credential, and stops before sealing when the broker
// key does not match its fingerprint or the one the operator gave.
func TestHR060_SealEncryptsLocallyAndUploadsOnlySealedBytes(t *testing.T) {
	key, err := pccrypto.GenerateSealKey()
	if err != nil {
		t.Fatal(err)
	}
	srv := &sealServer{key: key, fingerprint: fingerprintOf(key)}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterConnectionServiceHandler(cs, srv)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})

	const secret = "pc-test-credential-not-real"
	file := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(file, []byte(secret+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conn := "0192aaaa-bbbb-7ccc-8ddd-000000000002"
	code, out, errs := run(t, env, "seal", "--connection", conn, "--from-file", file, "--fingerprint", strings.ToUpper(srv.fingerprint))
	if code != 0 || srv.put == nil {
		t.Fatalf("seal = %d %q %q", code, out, errs)
	}
	if strings.Contains(out+errs, secret) || bytes.Contains(srv.put.GetSealed(), []byte(secret)) {
		t.Fatal("the credential left the machine in plaintext")
	}
	if !strings.Contains(errs, srv.fingerprint) {
		t.Fatalf("the fingerprint is not shown: %q", errs)
	}
	b := domain.Binding{
		Org: "0192aaaa-bbbb-7ccc-8ddd-000000000001", Connection: conn, Version: 2, AllowedHosts: []string{"payments.example.test"},
		BrokerKey: "0192aaaa-bbbb-7ccc-8ddd-000000000003", Header: "Authorization", Scheme: "Bearer",
	}
	got, err := pccrypto.Open(key, b.Info(), domain.AAD, srv.put.GetSealed())
	if err != nil || string(got) != secret {
		t.Fatalf("the gateway could not open it: %q %v", got, err)
	}
	if p := srv.put; p.GetVersion() != 2 || p.GetBrokerKeyId() != b.BrokerKey || p.GetHeader() != "Authorization" || p.GetScheme() != "Bearer" {
		t.Fatalf("upload %v", p)
	}

	srv.put = nil
	if code, _, errs := run(t, env, "seal", "--connection", conn, "--from-file", file, "--fingerprint", "sha256:"+strings.Repeat("0", 64)); code == 0 ||
		!strings.Contains(errs, "nothing was sealed") || srv.put != nil {
		t.Fatalf("an unexpected broker key = %d %q", code, errs)
	}
	srv.fingerprint = "sha256:" + strings.Repeat("1", 64)
	if code, _, errs := run(t, env, "seal", "--connection", conn, "--from-file", file); code == 0 || srv.put != nil {
		t.Fatalf("a key that does not match its fingerprint = %d %q", code, errs)
	}
	srv.fingerprint = fingerprintOf(key)
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := run(t, env, "seal", "--connection", conn, "--from-file", empty); code == 0 || srv.put != nil {
		t.Fatal("an empty credential was sealed")
	}
}
