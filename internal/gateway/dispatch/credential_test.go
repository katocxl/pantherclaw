// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	credentials "github.com/katocxl/pantherclaw/internal/credentials/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// TestHR204_AnAppKeyIsNeverPlaced: on the paths that place a credential as
// sealed, a GitHub App credential is refused before anything is decrypted,
// and a static credential holding a PEM block (an App's private key sealed
// without --github-app) is never placed on a request.
func TestHR204_AnAppKeyIsNeverPlaced(t *testing.T) {
	conn := func(kind string) *control.Connection {
		return &control.Connection{GatewayConnection: &pb.GatewayConnection{Id: "c"}, Credential: &pb.SealedCredential{
			Kind: kind, AllowedHosts: []string{"api.github.com"}, Header: "Authorization", Scheme: "Bearer",
		}}
	}
	app, static := conn(credentials.KindGitHubApp), conn("")
	e := &Engine{} // no broker: a credential that were opened would answer ErrNoBroker
	if _, err := e.openStatic(context.Background(), app); !errors.Is(err, errKind) {
		t.Fatalf("an App credential reached the broker: %v", err)
	}
	if _, err := e.openStatic(context.Background(), static); !errors.Is(err, broker.ErrNoBroker) {
		t.Fatalf("a static credential was not opened: %v", err)
	}

	begin := "-----" + "BEGIN"
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	file := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	for _, secret := range []string{
		begin + " RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
		"Iv23li " + begin + " PRIVATE KEY----- x",
		begin + " OPENSSH PRIVATE KEY-----",
		base64.StdEncoding.EncodeToString(file), // an environment variable's form (#257)
		base64.StdEncoding.EncodeToString(der),  // a PEM block's bare body
		string(der),
	} {
		req := httptest.NewRequest(http.MethodGet, "https://api.github.com/repos/acme/payments", nil)
		if err := placeCredential(static, req, []byte(secret)); !errors.Is(err, errPEM) || req.Header.Get("Authorization") != "" {
			t.Fatalf("a PEM block was placed: %v %q", err, req.Header.Get("Authorization"))
		}
	}
	req := httptest.NewRequest(http.MethodGet, "https://api.github.com/repos/acme/payments", nil)
	if err := placeCredential(app, req, []byte("x")); !errors.Is(err, errKind) || req.Header.Get("Authorization") != "" {
		t.Fatalf("an App credential was placed: %v", err)
	}
	if err := placeCredential(static, req, []byte("ghp_static")); err != nil || req.Header.Get("Authorization") != "Bearer ghp_static" {
		t.Fatalf("a static credential: %v %q", err, req.Header.Get("Authorization"))
	}
}

// TestHR203_AReadGetsAReadOnlyToken: a read operation (a verification or
// fact read included) whose package declares a write permission gets no
// token at all, and the App's key is not even opened.
func TestHR203_AReadGetsAReadOnlyToken(t *testing.T) {
	conn := &control.Connection{GatewayConnection: &pb.GatewayConnection{Id: "c"}, Credential: &pb.SealedCredential{
		Kind: credentials.KindGitHubApp, AllowedHosts: []string{"api.github.com"}, Header: "Authorization", Scheme: "Bearer",
	}}
	e := &Engine{} // no broker: a credential that were opened would answer ErrNoBroker
	read := func(scope map[string]string) *defs.Definition {
		return &defs.Definition{Operation: "github.contents.read", Access: defs.AccessRead, Dispatch: &defs.Dispatch{CredentialScope: scope}}
	}
	req := httptest.NewRequest(http.MethodGet, "https://api.github.com/repos/acme/payments/contents/README.md", nil)
	target := actionir.Target{Type: "github.repository", ID: "acme/payments"}
	for _, scope := range []map[string]string{{"contents": "write"}, {"contents": "read", "pull_requests": "admin"}} {
		if _, _, _, err := e.credential(t.Context(), conn, read(scope), target, req, nil, "verification"); !errors.Is(err, broker.ErrScope) {
			t.Errorf("%v: %v", scope, err)
		}
	}
	if _, _, _, err := e.credential(t.Context(), conn, read(map[string]string{"contents": "read"}), target, req, nil, "verification"); !errors.Is(err, broker.ErrNoBroker) {
		t.Fatalf("a read-only read was refused before opening: %v", err)
	}
}

type countingOpener struct{ opens int }

func (o *countingOpener) Open(string, string, []string, broker.Sealed) ([]byte, error) {
	o.opens++
	return []byte("ghp_static_secret"), nil
}

// TestHR225_ACallOpensItsStaticCredentialOnce: the outbound check and the
// injection share one decryption per call; each caller gets its own copy,
// so clearing one does not blank the other, and the call's copy is cleared
// when it ends.
func TestHR225_ACallOpensItsStaticCredentialOnce(t *testing.T) {
	op := &countingOpener{}
	e := &Engine{broker: op, org: "o"}
	conn := &control.Connection{GatewayConnection: &pb.GatewayConnection{Id: "c"}, Credential: &pb.SealedCredential{}}
	cs := &callSecret{conn: "c"}
	ctx := context.WithValue(context.Background(), callSecretKey{}, cs)
	a, err := e.openStatic(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	clear(a)
	b, err := e.openStatic(ctx, conn)
	if err != nil || string(b) != "ghp_static_secret" || op.opens != 1 {
		t.Fatalf("%q %v after %d opens", b, err, op.opens)
	}
	cs.clear()
	if string(cs.b) == "ghp_static_secret" {
		t.Fatal("the call's copy outlived the call")
	}
	// Another connection in the same context gets its own secret.
	other := &control.Connection{GatewayConnection: &pb.GatewayConnection{Id: "d"}, Credential: &pb.SealedCredential{}}
	if _, err := e.openStatic(ctx, other); err != nil || op.opens != 2 {
		t.Fatalf("another connection used the cache: %v %d", err, op.opens)
	}
	// Outside a call every open decrypts.
	if _, err := e.openStatic(context.Background(), conn); err != nil || op.opens != 3 {
		t.Fatalf("%v %d", err, op.opens)
	}
}
