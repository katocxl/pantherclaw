// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"errors"
	"net/http/httptest"
	"testing"

	credentials "github.com/katocxl/pantherclaw/internal/credentials/domain"
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
	if _, err := e.openStatic(app); !errors.Is(err, errKind) {
		t.Fatalf("an App credential reached the broker: %v", err)
	}
	if _, err := e.openStatic(static); !errors.Is(err, broker.ErrNoBroker) {
		t.Fatalf("a static credential was not opened: %v", err)
	}

	begin := "-----" + "BEGIN"
	for _, secret := range []string{
		begin + " RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
		"Iv23li " + begin + " PRIVATE KEY----- x",
		begin + " OPENSSH PRIVATE KEY-----",
	} {
		req := httptest.NewRequest("GET", "https://api.github.com/repos/acme/payments", nil)
		if err := placeCredential(static, req, []byte(secret)); !errors.Is(err, errPEM) || req.Header.Get("Authorization") != "" {
			t.Fatalf("a PEM block was placed: %v %q", err, req.Header.Get("Authorization"))
		}
	}
	req := httptest.NewRequest("GET", "https://api.github.com/repos/acme/payments", nil)
	if err := placeCredential(app, req, []byte("x")); !errors.Is(err, errKind) || req.Header.Get("Authorization") != "" {
		t.Fatalf("an App credential was placed: %v", err)
	}
	if err := placeCredential(static, req, []byte("ghp_static")); err != nil || req.Header.Get("Authorization") != "Bearer ghp_static" {
		t.Fatalf("a static credential: %v %q", err, req.Header.Get("Authorization"))
	}
}
